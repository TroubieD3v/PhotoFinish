package engine

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestBurstCouponRace(t *testing.T) {
	s := h1ServeShop(t, 0)
	cart := s.newCart(t, "vuln")
	reqs := s.couponRequests(t, "vuln", cart, 10)
	g := &h1TestGuard{}

	race, err := Run(t.Context(), reqs, Options{Kind: Burst, TLS: s.tls, Guard: g})
	if err != nil {
		t.Fatal(err)
	}
	h1CheckResults(t, race, reqs, "HTTP/2.0")
	if race.Kind != Burst || race.ALPN != "h2" || race.TLSVersion == "" || race.Connections < 1 {
		t.Errorf("race: kind %s, ALPN %q, TLS %q, %d connections", race.Kind, race.ALPN, race.TLSVersion, race.Connections)
	}
	if race.Release.Writes != 0 || race.Release.Bytes != 0 || race.Release.SpreadNs < 0 {
		t.Errorf("release %+v", race.Release)
	}
	if g.total() != 10 {
		t.Errorf("guard spent %d, want 10", g.total())
	}
	applied := 0
	for i, r := range race.Results {
		if r.PreSentNs != r.ReleasedNs || r.FirstByteNs < r.ReleasedNs || r.EarlyResponse {
			t.Errorf("result %d: pre-sent %d released %d first byte %d", i, r.PreSentNs, r.ReleasedNs, r.FirstByteNs)
		}
		if r.ServerArrivalNs == 0 || r.Conn >= race.Connections {
			t.Errorf("result %d: server arrival %d, conn %d", i, r.ServerArrivalNs, r.Conn)
		}
		switch r.Status {
		case http.StatusOK:
			applied++
		case http.StatusConflict:
		default:
			t.Errorf("result %d: status %d: %s", i, r.Status, r.Body)
		}
	}
	if applied < 1 || s.discounts(t, "vuln", cart) != applied {
		t.Errorf("%d copies applied, cart disagrees or none did", applied)
	}
}

func TestBurstCouponFixedHolds(t *testing.T) {
	s := h1ServeShop(t, 0)
	cart := s.newCart(t, "fixed")
	reqs := s.couponRequests(t, "fixed", cart, 10)
	race, err := Run(t.Context(), reqs, Options{Kind: Burst, TLS: s.tls, Guard: AllowAll()})
	if err != nil {
		t.Fatal(err)
	}
	h1CheckResults(t, race, reqs, "HTTP/2.0")
	applied := 0
	for _, r := range race.Results {
		if r.Status == http.StatusOK {
			applied++
		}
	}
	if applied != 1 || s.discounts(t, "fixed", cart) != 1 {
		t.Errorf("%d copies applied the coupon on /fixed", applied)
	}
}

func TestBurstOverHTTP1(t *testing.T) {
	s := h1Serve(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "ok")
	}), true, false)
	reqs := h1Copies(s.url(t, "/"), 4)
	race, err := Run(t.Context(), reqs, Options{Kind: Burst, TLS: s.tls, Guard: AllowAll()})
	if err != nil {
		t.Fatal(err)
	}
	h1CheckResults(t, race, reqs, "HTTP/1.1")
	if race.ALPN == "h2" || race.Connections < 1 || race.Connections > 4 {
		t.Errorf("race: ALPN %q, %d connections", race.ALPN, race.Connections)
	}
}

func TestBurstDoesNotFollowRedirects(t *testing.T) {
	var followed atomic.Int64
	s := h1Serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/target" {
			followed.Add(1)
			return
		}
		http.Redirect(w, r, "/target", http.StatusFound)
	}), true, true)
	reqs := h1Copies(s.url(t, "/start"), 3)
	race, err := Run(t.Context(), reqs, Options{Kind: Burst, TLS: s.tls, Guard: AllowAll()})
	if err != nil {
		t.Fatal(err)
	}
	h1CheckResults(t, race, reqs, "HTTP/2.0")
	for i, r := range race.Results {
		if r.Status != http.StatusFound || r.Header.Get("Location") != "/target" {
			t.Errorf("result %d: status %d, location %q", i, r.Status, r.Header.Get("Location"))
		}
	}
	if n := followed.Load(); n != 0 {
		t.Errorf("the redirect was followed %d times", n)
	}
}

func TestBurstWarmupAndBudget(t *testing.T) {
	var warm atomic.Int64
	s := h1Serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			warm.Add(1)
		}
		io.WriteString(w, "ok")
	}), true, true)
	reqs := h1Copies(s.url(t, "/race"), 5)
	g := &h1TestGuard{}
	race, err := Run(t.Context(), reqs, Options{Kind: Burst, Warmup: 2, TLS: s.tls, Guard: g})
	if err != nil {
		t.Fatal(err)
	}
	h1CheckResults(t, race, reqs, "HTTP/2.0")
	if g.total() != 5+2 || g.spends != 1 {
		t.Errorf("guard spent %d in %d calls, want 7 in 1", g.total(), g.spends)
	}
	if n := warm.Load(); n != 2 || race.Warmup != 2 {
		t.Errorf("server saw %d warm-up requests, race says %d; want 2", n, race.Warmup)
	}
}

func TestBurstGuardAbortsBeforeConnecting(t *testing.T) {
	denied := errors.New("budget exhausted")
	for _, g := range []*h1TestGuard{{denyHost: denied}, {denySpend: denied}} {
		s := h1ServeShop(t, 0)
		reqs := h1Copies(s.url(t, "/healthz"), 3)
		race, err := Run(t.Context(), reqs, Options{Kind: Burst, Warmup: 1, TLS: s.tls, Guard: g})
		if !errors.Is(err, denied) || race != nil {
			t.Errorf("Run = %v, %v; want the guard error", race, err)
		}
		if n := s.conns.Load(); n != 0 {
			t.Errorf("%d connections opened despite the guard", n)
		}
	}
}

func TestBurstTruncatesAndTimesOut(t *testing.T) {
	big := strings.Repeat("y", 5000)
	block := make(chan struct{})
	s := h1Serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			select {
			case <-block:
			case <-r.Context().Done():
			}
			return
		}
		io.WriteString(w, big)
	}), true, true)
	t.Cleanup(func() { close(block) })

	reqs := h1Copies(s.url(t, "/big"), 2)
	race, err := Run(t.Context(), reqs, Options{Kind: Burst, MaxBody: 10, TLS: s.tls, Guard: AllowAll()})
	if err != nil {
		t.Fatal(err)
	}
	for i, r := range race.Results {
		if string(r.Body) != "yyyyyyyyyy" || !r.Truncated {
			t.Errorf("result %d: body %q, truncated %v", i, r.Body, r.Truncated)
		}
	}

	reqs = h1Copies(s.url(t, "/slow"), 2)
	race, err = Run(t.Context(), reqs, Options{Kind: Burst, Timeout: 300 * time.Millisecond, TLS: s.tls, Guard: AllowAll()})
	if err != nil {
		t.Fatal(err)
	}
	for i, r := range race.Results {
		if r.Status != 0 || r.Err == "" {
			t.Errorf("result %d: status %d, error %q; want a timeout", i, r.Status, r.Err)
		}
	}
}
