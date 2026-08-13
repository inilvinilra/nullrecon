package budgetguard

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRequestBudgetExhaustion(t *testing.T) {
	g := New("global", Budget{DimRequests: 3}, nil)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := g.Acquire(ctx, Cost{Requests: 1}); err != nil {
			t.Fatalf("acquire %d: %v", i, err)
		}
	}
	if err := g.Acquire(ctx, Cost{Requests: 1}); !errors.Is(err, ErrExhausted) {
		t.Fatalf("fourth acquire must exhaust budget, got %v", err)
	}
}

func TestHierarchyEnforcesParentLimits(t *testing.T) {
	global := New("global", Budget{DimRequests: 5}, nil)
	project := global.Child("project", Budget{DimRequests: 100})
	host := project.Child("host", Budget{DimRequests: 100})
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		if err := host.Acquire(ctx, Cost{Requests: 1}); err != nil {
			t.Fatalf("acquire %d: %v", i, err)
		}
	}
	if err := host.Acquire(ctx, Cost{Requests: 1}); !errors.Is(err, ErrExhausted) {
		t.Fatal("parent budget must limit children")
	}
}

func TestChildStricterThanParent(t *testing.T) {
	global := New("global", Budget{DimRequests: 100}, nil)
	host := global.Child("host", Budget{DimRequests: 2})
	ctx := context.Background()
	host.Acquire(ctx, Cost{Requests: 1})
	host.Acquire(ctx, Cost{Requests: 1})
	if err := host.Acquire(ctx, Cost{Requests: 1}); !errors.Is(err, ErrExhausted) {
		t.Fatal("child limit must be enforced")
	}
	if err := global.Acquire(ctx, Cost{Requests: 1}); err != nil {
		t.Fatalf("sibling capacity in parent must remain: %v", err)
	}
}

func TestConcurrencyRelease(t *testing.T) {
	g := New("global", Budget{DimConcurrency: 1}, nil)
	ctx := context.Background()
	if err := g.Acquire(ctx, Cost{Concurrency: 1}); err != nil {
		t.Fatal(err)
	}
	if err := g.Acquire(ctx, Cost{Concurrency: 1}); !errors.Is(err, ErrExhausted) {
		t.Fatal("second concurrent acquire must be rejected")
	}
	g.Release(Cost{Concurrency: 1})
	if err := g.Acquire(ctx, Cost{Concurrency: 1}); err != nil {
		t.Fatalf("released slot must be reusable: %v", err)
	}
}

func TestRateLimitCancellation(t *testing.T) {
	g := New("global", Budget{DimRPS: 1}, nil)
	ctx := context.Background()
	if err := g.Acquire(ctx, Cost{Requests: 1}); err != nil {
		t.Fatal(err)
	}
	cancelCtx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := g.Acquire(cancelCtx, Cost{Requests: 1})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("rate-limited acquire must respect cancellation, got %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("cancellation must abort the wait promptly")
	}
}

func TestCreditBudget(t *testing.T) {
	g := New("provider", Budget{DimCredits: 10}, nil)
	ctx := context.Background()
	if err := g.Acquire(ctx, Cost{Credits: 10}); err != nil {
		t.Fatal(err)
	}
	if err := g.Acquire(ctx, Cost{Credits: 1}); !errors.Is(err, ErrExhausted) {
		t.Fatal("credit budget must be enforced")
	}
}

func TestPlanIsDryRun(t *testing.T) {
	g := New("global", Budget{DimRequests: 1}, nil)
	child := g.Child("target", Budget{DimRequests: 10})
	decisions := child.Plan(Cost{Requests: 5})
	if len(decisions) != 2 {
		t.Fatalf("expected 2 plan decisions, got %d", len(decisions))
	}
	if decisions[0].Node != "target" || !decisions[0].Allowed {
		t.Fatalf("child with capacity must be allowed: %+v", decisions)
	}
	if decisions[1].Node != "global" || decisions[1].Allowed {
		t.Fatalf("plan must report global rejection: %+v", decisions)
	}
	if g.Used(DimRequests) != 0 {
		t.Fatal("dry-run plan must not consume budget")
	}
}

func TestExecutionTimeBudget(t *testing.T) {
	g := New("global", Budget{DimDuration: 1}, nil)
	g.deadline = time.Now().Add(-time.Second)
	if err := g.Acquire(context.Background(), Cost{Requests: 1}); !errors.Is(err, ErrExhausted) {
		t.Fatal("expired execution budget must reject")
	}
}
