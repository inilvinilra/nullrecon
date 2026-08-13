package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/nullrecon/nullrecon/core/workflow"
	"github.com/nullrecon/nullrecon/domain/endpoint"
	"github.com/nullrecon/nullrecon/domain/evidence"
	"github.com/nullrecon/nullrecon/engines/fingerprint"
	"github.com/nullrecon/nullrecon/engines/honeysense"
	"github.com/nullrecon/nullrecon/engines/webprobe"
	"github.com/nullrecon/nullrecon/platform/database"
	"github.com/nullrecon/nullrecon/reporting/redaction"
)

type openPort struct {
	AssetID string `json:"assetId"`
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Banner  string `json:"banner,omitempty"`
}

func webScheme(port int) (string, bool) {
	switch port {
	case 80, 8080, 8000, 8008:
		return "http", true
	case 443, 8443, 4443, 9443:
		return "https", true
	}
	return "", false
}

func (o *Orchestrator) discoverServices(ctx context.Context, nc *workflow.NodeContext) (json.RawMessage, []byte, error) {
	var probeOut struct {
		Open []openPort `json:"open"`
	}
	if err := inputAt(nc, "ProbeHosts", &probeOut); err != nil {
		return nil, nil, err
	}
	red, err := redaction.New(nil)
	if err != nil {
		return nil, nil, err
	}
	engine := webprobe.New(nc.Snapshot, nc.Budget, red)
	probed := 0
	for _, op := range probeOut.Open {
		scheme, ok := webScheme(op.Port)
		if !ok {
			continue
		}
		rawURL := fmt.Sprintf("%s://%s:%d/", scheme, op.Host, op.Port)
		res, err := engine.Probe(ctx, rawURL)
		if err != nil || res.Status == 0 {
			continue
		}
		ep := endpoint.New(nc.Run.ProjectID, op.AssetID, res.FinalURL, "GET", "webprobe", o.now())
		ep.Status = res.Status
		ep.ContentHash = res.ContentHash
		ep.ContentType = res.Headers["content-type"]
		if err := o.deps.DB.Endpoints().Upsert(ctx, ep); err != nil {
			return nil, nil, err
		}
		if err := o.storeProbeEvidence(ctx, nc, op, res); err != nil {
			return nil, nil, err
		}
		probed++
	}
	return out(map[string]any{"probed": probed})
}

func (o *Orchestrator) storeProbeEvidence(ctx context.Context, nc *workflow.NodeContext, op openPort, res webprobe.Result) error {
	redacted := res
	redacted.BodySnippet = ""
	payload, err := json.Marshal(redacted)
	if err != nil {
		return err
	}
	ref := ""
	if o.deps.Raw != nil {
		ref, err = o.deps.Raw.Put(payload)
		if err != nil {
			return err
		}
	}
	ev := evidence.Evidence{
		ProjectID:  nc.Run.ProjectID,
		RunID:      nc.Run.ID,
		Kind:       evidence.KindHTTPTranscript,
		CapturedAt: o.now(),
		Tool:       "webprobe",
		RequestMeta: map[string]string{
			"url": res.URL,
		},
		ResponseMeta: map[string]string{
			"status":   strconv.Itoa(res.Status),
			"finalUrl": res.FinalURL,
		},
		Hashes:         map[string]string{"content": res.ContentHash},
		StorageRef:     ref,
		SizeBytes:      int64(len(payload)),
		RedactionState: "redacted",
		Provenance:     evidence.Provenance{SourceID: op.AssetID},
	}
	return o.deps.DB.Evidence().Put(ctx, ev)
}

func (o *Orchestrator) fingerprintTechnologies(ctx context.Context, nc *workflow.NodeContext) (json.RawMessage, []byte, error) {
	if o.deps.Fingerprints == nil {
		return out(map[string]any{"technologies": 0, "note": "no fingerprint ruleset loaded"})
	}
	evs, err := o.deps.DB.Evidence().ForRun(ctx, nc.Run.ID)
	if err != nil {
		return nil, nil, err
	}
	count := 0
	for _, ev := range evs {
		if ev.Kind != evidence.KindHTTPTranscript || o.deps.Raw == nil || ev.StorageRef == "" {
			continue
		}
		payload, err := o.deps.Raw.Get(ev.StorageRef)
		if err != nil {
			continue
		}
		var res webprobe.Result
		if err := json.Unmarshal(payload, &res); err != nil {
			continue
		}
		features := fingerprint.Features{
			Headers:     res.Headers,
			Cookies:     res.Cookies,
			Title:       res.Title,
			BodySnippet: res.BodySnippet,
			FaviconMMH3: res.FaviconMMH3,
		}
		if res.TLS != nil {
			features.TLSIssuer = res.TLS.IssuerCN
		}
		for _, tech := range o.deps.Fingerprints.Apply(features) {
			tech.ProjectID = nc.Run.ProjectID
			tech.ObservedAt = o.now()
			if err := o.deps.DB.Technologies().Upsert(ctx, tech); err != nil {
				return nil, nil, err
			}
			count++
		}
	}
	return out(map[string]any{"technologies": count})
}

func (o *Orchestrator) assessDeception(ctx context.Context, nc *workflow.NodeContext) (json.RawMessage, []byte, error) {
	var probeOut struct {
		Open []openPort `json:"open"`
	}
	if err := inputAt(nc, "ProbeHosts", &probeOut); err != nil {
		return out(map[string]any{"verdicts": 0})
	}
	byHost := map[string][]openPort{}
	for _, op := range probeOut.Open {
		byHost[op.Host] = append(byHost[op.Host], op)
	}
	review := 0
	for host, ports := range byHost {
		signals := honeysense.Signals{ObservedAt: o.now()}
		banners := map[int]string{}
		for _, op := range ports {
			signals.OpenPorts = append(signals.OpenPorts, op.Port)
			if op.Banner != "" {
				banners[op.Port] = op.Banner
			}
		}
		signals.Banners = banners
		verdict := honeysense.Score(signals)
		if verdict.RequiresReview {
			review++
		}
		obs := database.Observation{
			ProjectID:  nc.Run.ProjectID,
			Source:     "honeysense",
			Kind:       "deception",
			Data:       string(mustMarshal(map[string]any{"host": host, "verdict": verdict})),
			ObservedAt: o.now().Format(time.RFC3339Nano),
			FetchedAt:  o.now().Format(time.RFC3339Nano),
		}
		if err := o.deps.DB.Observations().Append(ctx, obs); err != nil {
			return nil, nil, err
		}
	}
	return out(map[string]any{"hosts": len(byHost), "requiresReview": review})
}

func mustMarshal(v any) []byte {
	data, err := json.Marshal(v)
	if err != nil {
		return []byte("{}")
	}
	return data
}
