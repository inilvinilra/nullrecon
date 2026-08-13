package budgetguard

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

type Dimension string

const (
	DimRPS          Dimension = "rps"
	DimRPM          Dimension = "rpm"
	DimConcurrency  Dimension = "concurrency"
	DimRequests     Dimension = "requests"
	DimBytes        Dimension = "bytes"
	DimCredits      Dimension = "credits"
	DimDuration     Dimension = "durationseconds"
	DimRetries      Dimension = "retries"
	DimRedirects    Dimension = "redirects"
	DimEvidenceSize Dimension = "evidencebytes"
)

var ErrExhausted = errors.New("budgetguard: budget exhausted")

type Budget map[Dimension]int64

type Cost struct {
	Requests    int64 `json:"requests"`
	Bytes       int64 `json:"bytes"`
	Credits     int64 `json:"credits"`
	Concurrency int64 `json:"concurrency"`
}

type bucket struct {
	rate     float64
	capacity float64
	tokens   float64
	last     time.Time
}

func (b *bucket) take(now time.Time) bool {
	elapsed := now.Sub(b.last).Seconds()
	b.tokens += elapsed * b.rate
	if b.tokens > b.capacity {
		b.tokens = b.capacity
	}
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

func (b *bucket) wait(now time.Time) time.Duration {
	elapsed := now.Sub(b.last).Seconds()
	tokens := b.tokens + elapsed*b.rate
	if tokens >= 1 {
		return 0
	}
	return time.Duration((1 - tokens) / b.rate * float64(time.Second))
}

func (b *bucket) ready(now time.Time) bool {
	return b.tokens+now.Sub(b.last).Seconds()*b.rate >= 1
}

type Guard struct {
	name     string
	parent   *Guard
	limits   Budget
	mu       sync.Mutex
	buckets  map[Dimension]*bucket
	used     map[Dimension]int64
	inflight int64
	deadline time.Time
	now      func() time.Time
}

func New(name string, limits Budget, parent *Guard) *Guard {
	g := &Guard{
		name:    name,
		parent:  parent,
		limits:  limits,
		buckets: map[Dimension]*bucket{},
		used:    map[Dimension]int64{},
		now:     time.Now,
	}
	if rate, ok := limits[DimRPS]; ok && rate > 0 {
		g.buckets[DimRPS] = &bucket{rate: float64(rate), capacity: float64(rate), tokens: float64(rate), last: g.now()}
	}
	if rate, ok := limits[DimRPM]; ok && rate > 0 {
		g.buckets[DimRPM] = &bucket{rate: float64(rate) / 60.0, capacity: float64(rate), tokens: float64(rate), last: g.now()}
	}
	if seconds, ok := limits[DimDuration]; ok && seconds > 0 {
		g.deadline = g.now().Add(time.Duration(seconds) * time.Second)
	}
	return g
}

func (g *Guard) Child(name string, limits Budget) *Guard {
	return New(name, limits, g)
}

func (g *Guard) Name() string {
	return g.name
}

func (g *Guard) Acquire(ctx context.Context, cost Cost) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	for node := g; node != nil; node = node.parent {
		if err := node.check(cost); err != nil {
			return err
		}
	}
	for node := g; node != nil; node = node.parent {
		if err := node.waitBuckets(ctx); err != nil {
			return err
		}
	}
	for node := g; node != nil; node = node.parent {
		node.consume(cost)
	}
	return nil
}

func (g *Guard) Release(cost Cost) {
	for node := g; node != nil; node = node.parent {
		node.mu.Lock()
		node.inflight -= cost.Concurrency
		if node.inflight < 0 {
			node.inflight = 0
		}
		node.mu.Unlock()
	}
}

func (g *Guard) Report(dim Dimension, amount int64) error {
	for node := g; node != nil; node = node.parent {
		node.mu.Lock()
		if limit, ok := node.limits[dim]; ok && limit >= 0 && node.used[dim]+amount > limit {
			node.mu.Unlock()
			return fmt.Errorf("%w: %s dimension %s", ErrExhausted, node.name, dim)
		}
		node.used[dim] += amount
		node.mu.Unlock()
	}
	return nil
}

func (g *Guard) check(cost Cost) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.deadline.IsZero() && g.now().After(g.deadline) {
		return fmt.Errorf("%w: %s execution time budget", ErrExhausted, g.name)
	}
	checks := []struct {
		dim   Dimension
		extra int64
	}{
		{DimRequests, cost.Requests},
		{DimBytes, cost.Bytes},
		{DimCredits, cost.Credits},
	}
	for _, c := range checks {
		if limit, ok := g.limits[c.dim]; ok && limit >= 0 && g.used[c.dim]+c.extra > limit {
			return fmt.Errorf("%w: %s dimension %s", ErrExhausted, g.name, c.dim)
		}
	}
	if limit, ok := g.limits[DimConcurrency]; ok && limit > 0 && g.inflight+cost.Concurrency > limit {
		return fmt.Errorf("%w: %s concurrency", ErrExhausted, g.name)
	}
	return nil
}

func (g *Guard) waitBuckets(ctx context.Context) error {
	for {
		g.mu.Lock()
		var wait time.Duration
		now := g.now()
		ready := true
		for _, b := range g.buckets {
			if !b.ready(now) {
				ready = false
				if d := b.wait(now); d > wait {
					wait = d
				}
			}
		}
		if ready {
			for _, b := range g.buckets {
				b.take(now)
			}
		}
		g.mu.Unlock()
		if ready {
			return nil
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (g *Guard) consume(cost Cost) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.used[DimRequests] += cost.Requests
	g.used[DimBytes] += cost.Bytes
	g.used[DimCredits] += cost.Credits
	g.inflight += cost.Concurrency
}

type PlanDecision struct {
	Node    string `json:"node"`
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason,omitempty"`
}

func (g *Guard) Plan(cost Cost) []PlanDecision {
	var out []PlanDecision
	for node := g; node != nil; node = node.parent {
		err := node.check(cost)
		if err != nil {
			out = append(out, PlanDecision{Node: node.name, Allowed: false, Reason: err.Error()})
			continue
		}
		out = append(out, PlanDecision{Node: node.name, Allowed: true})
	}
	return out
}

func (g *Guard) Used(dim Dimension) int64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.used[dim]
}
