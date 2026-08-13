package dnscan

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"time"

	"github.com/nullrecon/nullrecon/core/budgetguard"
	"github.com/nullrecon/nullrecon/core/scopeguard"
)

type Resolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
	LookupCNAME(ctx context.Context, host string) (string, error)
	LookupMX(ctx context.Context, host string) ([]*net.MX, error)
	LookupNS(ctx context.Context, host string) ([]*net.NS, error)
	LookupTXT(ctx context.Context, host string) ([]string, error)
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}

type Result struct {
	Host    string   `json:"host"`
	A       []string `json:"a,omitempty"`
	AAAA    []string `json:"aaaa,omitempty"`
	CNAME   string   `json:"cname,omitempty"`
	MX      []string `json:"mx,omitempty"`
	NS      []string `json:"ns,omitempty"`
	TXT     []string `json:"txt,omitempty"`
	PTR     []string `json:"ptr,omitempty"`
	Blocked []string `json:"blockedPivots,omitempty"`
	Errors  []string `json:"errors,omitempty"`
}

type Engine struct {
	snapshot scopeguard.Snapshot
	budget   *budgetguard.Guard
	resolver Resolver
	queries  int
}

func New(snapshot scopeguard.Snapshot, budget *budgetguard.Guard, resolver Resolver) *Engine {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	return &Engine{snapshot: snapshot, budget: budget, resolver: resolver}
}

func (e *Engine) acquire(ctx context.Context) error {
	if e.budget == nil {
		return nil
	}
	return e.budget.Acquire(ctx, budgetguard.Cost{Requests: 1})
}

func (e *Engine) Resolve(ctx context.Context, host string, maxQueries int) (Result, error) {
	res := Result{Host: host}
	e.queries = 0
	e.resolveInto(ctx, &res, host, maxQueries, 0)
	return res, nil
}

func (e *Engine) resolveInto(ctx context.Context, res *Result, host string, maxQueries, depth int) {
	if depth > 3 || e.queries >= maxQueries {
		return
	}
	lookup := func(f func() error) {
		if e.queries >= maxQueries {
			return
		}
		if err := e.acquire(ctx); err != nil {
			res.Errors = append(res.Errors, "budget: "+err.Error())
			return
		}
		e.queries++
		if err := f(); err != nil {
			res.Errors = append(res.Errors, err.Error())
		}
	}
	lookup(func() error {
		addrs, err := e.resolver.LookupHost(ctx, host)
		if err != nil {
			return fmt.Errorf("a/aaaa: %w", err)
		}
		for _, addr := range addrs {
			ip := addr
			pivot := e.snapshot.EvaluatePivot(scopeguard.Target{Host: host}, scopeguard.Target{IP: ip}, timeNow())
			if !pivot.Allowed {
				res.Blocked = append(res.Blocked, fmt.Sprintf("resolved ip %s out of scope", ip))
				continue
			}
			if isV6(ip) {
				res.AAAA = appendUnique(res.AAAA, ip)
			} else {
				res.A = appendUnique(res.A, ip)
			}
		}
		return nil
	})
	lookup(func() error {
		cname, err := e.resolver.LookupCNAME(ctx, host)
		if err != nil {
			return fmt.Errorf("cname: %w", err)
		}
		cname = trimDot(cname)
		if cname == "" || cname == host {
			return nil
		}
		pivot := e.snapshot.EvaluatePivot(scopeguard.Target{Host: host}, scopeguard.Target{Host: cname}, timeNow())
		if !pivot.Allowed {
			res.Blocked = append(res.Blocked, fmt.Sprintf("cname %s out of scope", cname))
			return nil
		}
		res.CNAME = cname
		return nil
	})
	lookup(func() error {
		mxs, err := e.resolver.LookupMX(ctx, host)
		if err != nil {
			return fmt.Errorf("mx: %w", err)
		}
		for _, mx := range mxs {
			res.MX = appendUnique(res.MX, trimDot(mx.Host))
		}
		return nil
	})
	lookup(func() error {
		nss, err := e.resolver.LookupNS(ctx, host)
		if err != nil {
			return fmt.Errorf("ns: %w", err)
		}
		for _, ns := range nss {
			res.NS = appendUnique(res.NS, trimDot(ns.Host))
		}
		return nil
	})
	lookup(func() error {
		txts, err := e.resolver.LookupTXT(ctx, host)
		if err != nil {
			return fmt.Errorf("txt: %w", err)
		}
		for _, txt := range txts {
			res.TXT = appendUnique(res.TXT, txt)
		}
		return nil
	})
	for _, ip := range append(append([]string{}, res.A...), res.AAAA...) {
		lookup(func() error {
			names, err := e.resolver.LookupAddr(ctx, ip)
			if err != nil {
				return fmt.Errorf("ptr %s: %w", ip, err)
			}
			for _, name := range names {
				res.PTR = appendUnique(res.PTR, trimDot(name))
			}
			return nil
		})
	}
	sort.Strings(res.A)
	sort.Strings(res.AAAA)
}

func trimDot(v string) string {
	for len(v) > 0 && v[len(v)-1] == '.' {
		v = v[:len(v)-1]
	}
	return v
}

func appendUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

func isV6(ip string) bool {
	addr, err := netip.ParseAddr(ip)
	return err == nil && addr.Is6()
}

var timeNow = func() time.Time { return time.Now().UTC() }
