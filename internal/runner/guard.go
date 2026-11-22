package runner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/TroubieD3v/photofinish/internal/scenario"
)

var (
	// errScope marks a request to a host outside scope.allow_hosts.
	errScope = errors.New("out of scope")
	// errBudget marks a request beyond scope.budget.requests.
	errBudget = errors.New("request budget exhausted")
)

// guard enforces the scenario scope, the total request budget and the
// request rate of setup, check and reset steps. It implements engine.Guard;
// the engine only calls Allow and Spend, so the race itself is not rate
// limited: it is a single burst by design.
type guard struct {
	scope scenario.Scope
	limit int     // total request budget
	rps   float64 // steps per second

	now   func() time.Time
	sleep func(ctx context.Context, d time.Duration) error

	mu        sync.Mutex
	ports     map[string]string // lowercased host without port -> default port
	spent     int
	tokens    float64 // rate-limiter tokens; negative values are reservations
	last      time.Time
	denied    error // first scope denial, if any
	exhausted error // first budget refusal, if any
}

// newGuard returns a guard for scope with a full one-token bucket.
func newGuard(scope scenario.Scope, limit int, rps float64) *guard {
	return &guard{
		scope:  scope,
		ports:  map[string]string{},
		limit:  limit,
		rps:    rps,
		now:    time.Now,
		sleep:  sleepCtx,
		tokens: 1,
	}
}

// sleepCtx waits for d or until ctx is done, whichever comes first.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Allow returns an error unless host (as in URL.Host) is in scope. A host
// without a port is checked with the default port of the scheme it was
// last seen with (see noteURL), like scenario.Scope.AllowsURL does.
func (g *guard) Allow(host string) error {
	g.mu.Lock()
	check := host
	if !hasPort(host) {
		if p, ok := g.ports[strings.ToLower(host)]; ok {
			check = net.JoinHostPort(strings.Trim(host, "[]"), p)
		}
	}
	g.mu.Unlock()
	if g.scope.Allows(check) {
		return nil
	}
	err := fmt.Errorf("%w: host %q is not in scope.allow_hosts %v", errScope, host, g.scope.AllowHosts)
	g.mu.Lock()
	if g.denied == nil {
		g.denied = err
	}
	g.mu.Unlock()
	return err
}

// hasPort reports whether host ends in a port.
func hasPort(host string) bool {
	_, _, err := net.SplitHostPort(host)
	return err == nil
}

// noteURL remembers the default port of u's scheme for u.Host when the URL
// has no explicit port, so that Allow(u.Host) checks the port that will
// actually be dialed.
func (g *guard) noteURL(u *url.URL) {
	if u == nil || u.Port() != "" {
		return
	}
	var p string
	switch strings.ToLower(u.Scheme) {
	case "https":
		p = "443"
	case "http":
		p = "80"
	default:
		return
	}
	g.mu.Lock()
	g.ports[strings.ToLower(u.Host)] = p
	g.mu.Unlock()
}

// Spend reserves n requests of the budget, or refuses all of them.
func (g *guard) Spend(n int) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if n < 0 {
		return fmt.Errorf("invalid request count %d", n)
	}
	if g.spent+n > g.limit {
		err := fmt.Errorf("%w: %d requests needed, %d of %d left", errBudget, n, g.limit-g.spent, g.limit)
		if g.exhausted == nil {
			g.exhausted = err
		}
		return err
	}
	g.spent += n
	return nil
}

// Spent returns the number of requests spent so far.
func (g *guard) Spent() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.spent
}

// remaining returns the number of requests left in the budget.
func (g *guard) remaining() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.limit - g.spent
}

// failures returns the first scope denial and the first budget refusal.
func (g *guard) failures() (denied, exhausted error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.denied, g.exhausted
}

// wait blocks until the rate limit allows one more step request. It is a
// token bucket holding at most one token, refilled at rps tokens per second;
// a caller that finds no token reserves the next one and sleeps until it is
// due, so concurrent callers queue up instead of polling.
func (g *guard) wait(ctx context.Context) error {
	if g.rps <= 0 {
		return ctx.Err()
	}
	g.mu.Lock()
	now := g.now()
	if !g.last.IsZero() {
		g.tokens += now.Sub(g.last).Seconds() * g.rps
		if g.tokens > 1 {
			g.tokens = 1
		}
	}
	g.last = now
	g.tokens--
	var delay time.Duration
	if g.tokens < 0 {
		delay = time.Duration(-g.tokens / g.rps * float64(time.Second))
	}
	g.mu.Unlock()
	return g.sleep(ctx, delay)
}
