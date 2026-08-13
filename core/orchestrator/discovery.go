package orchestrator

import (
	"context"
	"encoding/json"
	"net/url"
	"sort"
	"strconv"

	"github.com/nullrecon/nullrecon/core/policy"
	"github.com/nullrecon/nullrecon/core/scopeguard"
	"github.com/nullrecon/nullrecon/core/workflow"
	"github.com/nullrecon/nullrecon/domain/endpoint"
	"github.com/nullrecon/nullrecon/engines/contentdiscovery"
)

type discoveryTarget struct {
	AssetID string `json:"assetId"`
	Host    string `json:"host"`
	BaseURL string `json:"baseUrl"`
}

func (o *Orchestrator) planContentDiscovery(ctx context.Context, nc *workflow.NodeContext) (json.RawMessage, []byte, error) {
	assets, err := o.deps.DB.Assets().List(ctx, nc.Run.ProjectID, "")
	if err != nil {
		return nil, nil, err
	}
	seen := map[string]bool{}
	var targets []discoveryTarget
	for _, a := range assets {
		eps, err := o.deps.DB.Endpoints().ForAsset(ctx, a.ID)
		if err != nil {
			return nil, nil, err
		}
		for _, ep := range eps {
			if ep.Source != "webprobe" {
				continue
			}
			parsed, err := url.Parse(ep.URL)
			if err != nil || parsed.Host == "" {
				continue
			}
			base := parsed.Scheme + "://" + parsed.Host
			if seen[base] {
				continue
			}
			decision := nc.Snapshot.EvaluateAction(scopeguard.Target{Host: parsed.Hostname(), Port: portOfURL(parsed), Protocol: "tcp", Path: "/"}, policy.ActionContentDiscovery, o.now())
			if !decision.Allowed {
				continue
			}
			seen[base] = true
			targets = append(targets, discoveryTarget{AssetID: a.ID, Host: parsed.Hostname(), BaseURL: base})
		}
	}
	sort.SliceStable(targets, func(i, j int) bool { return targets[i].BaseURL < targets[j].BaseURL })
	if len(targets) == 0 {
		return out(map[string]any{"targets": targets, "note": "content discovery not authorized or no web targets"})
	}
	return out(map[string]any{"targets": targets, "wordlistSize": len(contentdiscovery.DefaultWords())})
}

func portOfURL(u *url.URL) int {
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			return n
		}
	}
	switch u.Scheme {
	case "https":
		return 443
	case "http":
		return 80
	}
	return 0
}

func (o *Orchestrator) runContentDiscovery(ctx context.Context, nc *workflow.NodeContext) (json.RawMessage, []byte, error) {
	var plan struct {
		Targets []discoveryTarget `json:"targets"`
	}
	if err := inputAt(nc, "PlanContentDiscovery", &plan); err != nil {
		return out(map[string]any{"candidates": 0})
	}
	if len(plan.Targets) == 0 {
		return out(map[string]any{"candidates": 0, "note": "no authorized web targets"})
	}
	engine := contentdiscovery.New(nc.Snapshot, nc.Budget)
	candidates := 0
	noise := 0
	perTarget := []map[string]any{}
	for _, target := range plan.Targets {
		words := o.wordlistFor(ctx, target.AssetID)
		opt := contentdiscovery.Options{Words: words, Extensions: contentdiscovery.DefaultExtensions()}
		res, err := engine.Scan(ctx, target.BaseURL, opt)
		if err != nil {
			continue
		}
		targetCandidates := 0
		for _, hit := range res.Hits {
			if hit.Class == "noise" || hit.Class == "filtered" {
				noise++
				continue
			}
			ep := endpoint.New(nc.Run.ProjectID, target.AssetID, hit.URL, "GET", "contentdiscovery", o.now())
			ep.Status = hit.Status
			ep.ContentType = hit.ContentType
			ep.ContentHash = hit.BodyHash
			if hit.Status == 401 || hit.Status == 403 {
				ep.Auth = endpoint.AuthRequired
			}
			if err := o.deps.DB.Endpoints().Upsert(ctx, ep); err != nil {
				return nil, nil, err
			}
			candidates++
			targetCandidates++
		}
		perTarget = append(perTarget, map[string]any{
			"baseUrl":    target.BaseURL,
			"candidates": targetCandidates,
			"requested":  res.Requested,
			"blocked":    res.Blocked,
			"catchAll":   res.Baseline.CatchAll,
		})
	}
	return out(map[string]any{"candidates": candidates, "noise": noise, "targets": perTarget})
}

func (o *Orchestrator) wordlistFor(ctx context.Context, assetID string) []string {
	techs, err := o.deps.DB.Technologies().ForAsset(ctx, assetID)
	if err != nil || len(techs) == 0 {
		return contentdiscovery.DefaultWords()
	}
	products := make([]string, 0, len(techs))
	for _, t := range techs {
		products = append(products, t.Product)
	}
	return contentdiscovery.WordsForTechnologies(products)
}
