package ownership

import (
	"strings"
	"time"

	"github.com/nullrecon/nullrecon/core/scopeguard"
	"github.com/nullrecon/nullrecon/domain/asset"
)

type Resolver struct {
	snapshot scopeguard.Snapshot
}

func NewResolver(snapshot scopeguard.Snapshot) *Resolver {
	return &Resolver{snapshot: snapshot}
}

func (r *Resolver) ResolveHost(host string) asset.OwnershipState {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	for _, exact := range r.snapshot.Scope.ExactDomains {
		if host == exact {
			return asset.OwnExact
		}
	}
	for _, root := range r.snapshot.Scope.RootDomains {
		if host == root {
			return asset.OwnExact
		}
		if strings.HasSuffix(host, "."+root) {
			return asset.OwnInherited
		}
	}
	return asset.OwnUnknown
}

func (r *Resolver) ResolveIP(ip string) asset.OwnershipState {
	d := r.snapshot.Evaluate(scopeguard.Target{IP: ip}, time.Now().UTC())
	if d.Allowed {
		return asset.OwnExact
	}
	return asset.OwnUnknown
}

func SharedInfraState(relatedHostCount int, inScopeHostCount int) asset.OwnershipState {
	if relatedHostCount > 50 && inScopeHostCount <= relatedHostCount/10 {
		return asset.OwnSharedInfra
	}
	if relatedHostCount > 20 {
		return asset.OwnCloudShared
	}
	return asset.OwnUnknown
}

var cdnSuffixes = []string{
	".cloudfront.net",
	".akamaiedge.net",
	".akamai.net",
	".fastly.net",
	".cdn.cloudflare.net",
	".azureedge.net",
	".edgesuite.net",
	".edgekey.net",
	".cloudflare.com",
}

func IsCDNEdge(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	for _, suffix := range cdnSuffixes {
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}
	return false
}

func Combine(states []asset.OwnershipState) asset.OwnershipState {
	if len(states) == 0 {
		return asset.OwnUnknown
	}
	order := []asset.OwnershipState{
		asset.OwnExact,
		asset.OwnInherited,
		asset.OwnHistorical,
		asset.OwnCDNEdge,
		asset.OwnSharedInfra,
		asset.OwnCloudShared,
		asset.OwnUnknown,
	}
	best := asset.OwnUnknown
	for _, candidate := range order {
		for _, s := range states {
			if s == candidate {
				best = candidate
			}
		}
		if best == candidate {
			return best
		}
	}
	return best
}
