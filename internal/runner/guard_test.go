package runner

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/TroubieD3v/photofinish/internal/scenario"
)

func TestGuardAllow(t *testing.T) {
	g := newGuard(scenario.Scope{AllowHosts: []string{"127.0.0.1:8443", "Example.COM", "[::1]:9000"}}, 10, 1)
	g.noteURL(&url.URL{Scheme: "https", Host: "127.0.0.1"})
	tests := []struct {
		host string
		ok   bool
	}{
		{"127.0.0.1:8443", true},
		{"127.0.0.1:8444", false},
		{"127.0.0.1", false}, // dialed on 443, not 8443
		{"example.com", true},
		{"EXAMPLE.com:8080", true},
		{"api.example.com", false},
		{"[::1]:9000", true},
		{"[::1]:9001", false},
		{"", false},
	}
	for _, tt := range tests {
		err := g.Allow(tt.host)
		if (err == nil) != tt.ok {
			t.Errorf("Allow(%q) = %v, want ok=%v", tt.host, err, tt.ok)
		}
		if err != nil && !errors.Is(err, errScope) {
			t.Errorf("Allow(%q) error %v is not errScope", tt.host, err)
		}
	}
	if denied, _ := g.failures(); denied == nil {
		t.Error("a denial was not recorded")
	}
}

func TestGuardBudget(t *testing.T) {
	g := newGuard(scenario.Scope{AllowHosts: []string{"h"}}, 10, 1)
	if err := g.Spend(7); err != nil {
		t.Fatal(err)
	}
	if err := g.Spend(4); !errors.Is(err, errBudget) {
		t.Fatalf("Spend(4) with 3 left = %v", err)
	}
	if g.Spent() != 7 || g.remaining() != 3 {
		t.Errorf("a refused Spend must not spend: spent %d remaining %d", g.Spent(), g.remaining())
	}
	if err := g.Spend(3); err != nil || g.remaining() != 0 {
		t.Errorf("Spend(3) = %v, remaining %d", err, g.remaining())
	}
	if _, exhausted := g.failures(); exhausted == nil {
		t.Error("the refusal was not recorded")
	}
}

// fakeClock drives the rate limiter: sleeping advances the clock.
type fakeClock struct {
	now    time.Time
	sleeps []time.Duration
}

func (c *fakeClock) Now() time.Time { return c.now }

func (c *fakeClock) Sleep(_ context.Context, d time.Duration) error {
	c.sleeps = append(c.sleeps, d)
	if d > 0 {
		c.now = c.now.Add(d)
	}
	return nil
}

func TestGuardRate(t *testing.T) {
	c := &fakeClock{now: time.Unix(1000, 0)}
	g := newGuard(scenario.Scope{AllowHosts: []string{"h"}}, 100, 4) // one step per 250ms
	g.now, g.sleep = c.Now, c.Sleep
	ctx := context.Background()

	for range 3 {
		if err := g.wait(ctx); err != nil {
			t.Fatal(err)
		}
	}
	// A full bucket lets the first step through; the next ones wait.
	want := []time.Duration{0, 250 * time.Millisecond, 250 * time.Millisecond}
	if len(c.sleeps) != len(want) {
		t.Fatalf("sleeps %v", c.sleeps)
	}
	for i := range want {
		if c.sleeps[i] != want[i] {
			t.Errorf("sleeps %v, want %v", c.sleeps, want)
			break
		}
	}

	// After a long pause (the race, say) the bucket holds one token again,
	// not a burst of them.
	c.now = c.now.Add(10 * time.Second)
	c.sleeps = nil
	g.wait(ctx)
	g.wait(ctx)
	if c.sleeps[0] != 0 || c.sleeps[1] != 250*time.Millisecond {
		t.Errorf("after idle: sleeps %v", c.sleeps)
	}
}

func TestGuardRateHonoursContext(t *testing.T) {
	g := newGuard(scenario.Scope{AllowHosts: []string{"h"}}, 100, 0.001)
	ctx, cancel := context.WithCancel(context.Background())
	if err := g.wait(ctx); err != nil {
		t.Fatal(err)
	}
	cancel()
	// The second step would wait 1000s; a cancelled context ends it at once.
	if err := g.wait(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("wait = %v", err)
	}
}

func TestMedian(t *testing.T) {
	for _, tt := range []struct {
		in   []int64
		want int64
	}{{nil, 0}, {[]int64{5}, 5}, {[]int64{9, 1, 5}, 5}, {[]int64{4, 1, 3, 2}, 2}} {
		if got := median(tt.in); got != tt.want {
			t.Errorf("median(%v) = %d, want %d", tt.in, got, tt.want)
		}
	}
}
