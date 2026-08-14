package contentdiscovery

import (
	"context"
	"crypto/rand"
	"net/url"

	"github.com/nullrecon/nullrecon/core/budgetguard"
	"github.com/nullrecon/nullrecon/core/scopeguard"
)

type Baseline struct {
	CatchAll     bool     `json:"catchAll"`
	Status       int      `json:"status,omitempty"`
	StableLength bool     `json:"stableLength"`
	Length       int64    `json:"length,omitempty"`
	StableShape  bool     `json:"stableShape"`
	Words        int      `json:"words,omitempty"`
	Lines        int      `json:"lines,omitempty"`
	BodyHashes   []string `json:"bodyHashes,omitempty"`
	NormHashes   []string `json:"-"`
	Probes       int      `json:"probes"`
}

const defaultCalibrateProbes = 3

func (e *Engine) calibrate(ctx context.Context, base *url.URL, opt Options) (Baseline, int, error) {
	count := opt.CalibrateProbes
	if count <= 0 {
		count = defaultCalibrateProbes
	}
	var (
		probes    []probe
		requested int
		lastErr   error
	)
	for i := 0; i < count; i++ {
		path := randomSegment()
		full := base.String() + "/" + path
		parsed, err := url.Parse(full)
		if err != nil {
			continue
		}
		if d := e.snapshot.EvaluateAction(scopeguard.Target{Host: parsed.Hostname(), Path: parsed.Path}, "httpget", e.now()); !d.Allowed {
			continue
		}
		if e.budget != nil {
			if err := e.budget.Acquire(ctx, budgetguard.Cost{Requests: 1}); err != nil {
				break
			}
		}
		requested++
		pr, err := e.request(ctx, full, path)
		if err != nil {
			lastErr = err
			continue
		}
		probes = append(probes, pr)
	}
	return summarize(probes), requested, lastErr
}

func summarize(probes []probe) Baseline {
	baseline := Baseline{Probes: len(probes)}
	if len(probes) == 0 {
		return baseline
	}
	status := probes[0].status
	sameStatus := true
	for _, pr := range probes {
		if pr.status != status {
			sameStatus = false
			break
		}
	}
	if !sameStatus || status >= 400 {
		return baseline
	}
	baseline.CatchAll = true
	baseline.Status = status
	baseline.StableLength = true
	baseline.StableShape = true
	length := probes[0].length
	words := probes[0].words
	lines := probes[0].lines
	seenHash := map[string]bool{}
	seenNorm := map[string]bool{}
	for _, pr := range probes {
		if pr.length != length {
			baseline.StableLength = false
		}
		if pr.words != words || pr.lines != lines {
			baseline.StableShape = false
		}
		if !seenHash[pr.bodyHash] {
			seenHash[pr.bodyHash] = true
			baseline.BodyHashes = append(baseline.BodyHashes, pr.bodyHash)
		}
		if !seenNorm[pr.normHash] {
			seenNorm[pr.normHash] = true
			baseline.NormHashes = append(baseline.NormHashes, pr.normHash)
		}
	}
	if baseline.StableLength {
		baseline.Length = length
	}
	if baseline.StableShape {
		baseline.Words = words
		baseline.Lines = lines
	}
	return baseline
}

const segmentAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789"

func randomSegment() string {
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		for i := range raw {
			raw[i] = byte(i * 7)
		}
	}
	out := make([]byte, len(raw))
	for i, b := range raw {
		out[i] = segmentAlphabet[int(b)%len(segmentAlphabet)]
	}
	return "nr404-" + string(out)
}
