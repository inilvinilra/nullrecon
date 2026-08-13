package correlate

import (
	"context"
	"time"

	"github.com/nullrecon/nullrecon/analysis/normalize"
	"github.com/nullrecon/nullrecon/analysis/ownership"
	"github.com/nullrecon/nullrecon/core/scopeguard"
	"github.com/nullrecon/nullrecon/domain/asset"
	"github.com/nullrecon/nullrecon/platform/database"
	"github.com/nullrecon/nullrecon/providers/registry"
)

type Stats struct {
	Assets    int `json:"assets"`
	Claims    int `json:"claims"`
	Relations int `json:"relations"`
	Skipped   int `json:"skipped"`
}

type Ingestor struct {
	db       *database.DB
	snapshot scopeguard.Snapshot
	resolver *ownership.Resolver
	now      func() time.Time
}

func NewIngestor(db *database.DB, snapshot scopeguard.Snapshot) *Ingestor {
	return &Ingestor{db: db, snapshot: snapshot, resolver: ownership.NewResolver(snapshot), now: time.Now}
}

func (in *Ingestor) upsert(ctx context.Context, projectID string, kind asset.Kind, value string) (asset.Asset, error) {
	a := asset.New(projectID, kind, value)
	if in.resolver != nil {
		switch kind {
		case asset.KindDomain, asset.KindHostname:
			switch in.resolver.ResolveHost(value) {
			case asset.OwnExact, asset.OwnInherited:
				a.Class = asset.ClassActive
			default:
				a.Class = asset.ClassUnknown
			}
		case asset.KindIP:
			if in.resolver.ResolveIP(value) == asset.OwnExact {
				a.Class = asset.ClassActive
			} else {
				a.Class = asset.ClassUnknown
			}
		}
		if ownership.IsCDNEdge(value) {
			a.Class = asset.ClassWatchOnly
		}
	}
	return in.db.Assets().Upsert(ctx, a)
}

func (in *Ingestor) Ingest(ctx context.Context, projectID, source string, records []registry.Record) (Stats, error) {
	var stats Stats
	for _, rec := range records {
		if err := in.ingestOne(ctx, projectID, source, rec, &stats); err != nil {
			stats.Skipped++
			continue
		}
	}
	return stats, nil
}

func isHostKind(kind string) bool {
	switch kind {
	case "hostname", "subdomain", "domain":
		return true
	}
	return false
}

func (in *Ingestor) ingestOne(ctx context.Context, projectID, source string, rec registry.Record, stats *Stats) error {
	now := in.now().UTC()
	var ipAsset, hostAsset *asset.Asset
	if rawIP := rec.Fields["ip"]; rawIP != "" {
		ip, err := normalize.IP(rawIP)
		if err != nil {
			return err
		}
		a, err := in.upsert(ctx, projectID, asset.KindIP, ip)
		if err != nil {
			return err
		}
		ipAsset = &a
		stats.Assets++
	}
	rawHost := rec.Fields["host"]
	if rawHost == "" {
		rawHost = rec.Fields["hostname"]
	}
	if rawHost == "" && isHostKind(rec.Kind) {
		rawHost = rec.Value
	}
	if rawHost != "" {
		host, err := normalize.Host(rawHost)
		if err == nil {
			if _, ipErr := normalize.IP(host); ipErr != nil {
				kind, kerr := normalize.KindForValue(host)
				if kerr == nil {
					a, err := in.upsert(ctx, projectID, kind, host)
					if err == nil {
						hostAsset = &a
						stats.Assets++
					}
				}
			}
		}
	}
	for _, a := range []*asset.Asset{ipAsset, hostAsset} {
		if a == nil {
			continue
		}
		confidence := asset.ClaimConfidence{
			Parse:      1,
			Freshness:  FreshnessScore(rec.FreshnessClass, rec.ObservedAt, now),
			Directness: 0.5,
		}
		claim := asset.AssetClaim{
			ProjectID:  projectID,
			AssetID:    a.ID,
			Source:     source,
			SourceID:   rec.SourceID,
			SourceURL:  rec.SourceURL,
			ObservedAt: rec.ObservedAt,
			FetchedAt:  rec.FetchedAt,
			RawRef:     rec.RawRef,
			RawHash:    rec.RawHash,
			Confidence: confidence,
			Ownership:  asset.OwnUnknown,
		}
		if claim.ObservedAt.IsZero() {
			claim.ObservedAt = now
		}
		if claim.FetchedAt.IsZero() {
			claim.FetchedAt = now
		}
		if err := in.db.Assets().PutClaim(ctx, claim); err != nil {
			return err
		}
		stats.Claims++
	}
	if ipAsset != nil && hostAsset != nil {
		rel := asset.AssetRelation{
			ProjectID:   projectID,
			FromAssetID: hostAsset.ID,
			ToAssetID:   ipAsset.ID,
			Kind:        asset.RelResolvesTo,
			ObservedAt:  rec.ObservedAt,
		}
		if rel.ObservedAt.IsZero() {
			rel.ObservedAt = now
		}
		if err := in.db.Assets().PutRelation(ctx, rel); err != nil {
			return err
		}
		stats.Relations++
	}
	return nil
}
