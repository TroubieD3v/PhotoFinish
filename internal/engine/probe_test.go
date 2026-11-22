package engine

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

func TestProbeHTTP2(t *testing.T) {
	s := h1ServeShop(t, 0)
	g := &h1TestGuard{}
	u := s.url(t, "/healthz")
	rep, err := Probe(t.Context(), u, Options{TLS: s.tls, Guard: g})
	if err != nil {
		t.Fatal(err)
	}
	if rep.URL != u.String() || rep.ALPN != "h2" || !rep.HTTP2 || rep.TLSVersion == "" || rep.Recommended != H2 {
		t.Errorf("report %+v", rep)
	}
	if rep.MaxConcurrentStreams == 0 || rep.InitialWindowSize == 0 || rep.MaxFrameSize < 16384 {
		t.Errorf("settings: streams %d, window %d, frame %d", rep.MaxConcurrentStreams, rep.InitialWindowSize, rep.MaxFrameSize)
	}
	if len(rep.RTTs) != probeGETs {
		t.Fatalf("%d RTTs, want %d", len(rep.RTTs), probeGETs)
	}
	for i, d := range rep.RTTs {
		if d <= 0 {
			t.Errorf("RTT %d is %s", i, d)
		}
	}
	if !rep.ArrivalHeader {
		t.Error("the demo's arrival header was not detected")
	}
	if g.total() != probeGETs || len(g.hosts) != 1 || g.hosts[0] != u.Host {
		t.Errorf("guard: spent %d, hosts %v", g.total(), g.hosts)
	}
	if n := s.conns.Load(); n != 1 {
		t.Errorf("probe opened %d connections, want 1", n)
	}
	if !h1HasNote(rep.Notes, "concurrent streams") {
		t.Errorf("no note on the stream limit: %q", rep.Notes)
	}
}

func TestProbeHTTP1OverTLS(t *testing.T) {
	var gets atomic.Int64
	s := h1Serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/p" {
			gets.Add(1)
		}
		w.Header().Set("Server", "test-server")
		io.WriteString(w, strings.Repeat("z", 1000))
	}), true, false)
	rep, err := Probe(t.Context(), s.url(t, "/p"), Options{TLS: s.tls, MaxBody: 10, Guard: AllowAll()})
	if err != nil {
		t.Fatal(err)
	}
	if rep.HTTP2 || rep.ALPN == "h2" || rep.Recommended != H1 || rep.Server != "test-server" || rep.TLSVersion == "" {
		t.Errorf("report %+v", rep)
	}
	if rep.MaxConcurrentStreams != 0 || rep.InitialWindowSize != 0 || rep.MaxFrameSize != 0 {
		t.Errorf("HTTP/2 settings reported without HTTP/2: %+v", rep)
	}
	if len(rep.RTTs) != probeGETs || gets.Load() != probeGETs {
		t.Errorf("%d RTTs, server saw %d GETs; want %d", len(rep.RTTs), gets.Load(), probeGETs)
	}
	if n := s.conns.Load(); n != 1 {
		t.Errorf("probe opened %d connections, want 1 (keep-alive)", n)
	}
	if rep.ArrivalHeader || !h1HasNote(rep.Notes, "X-Arrival-Ns") || !h1HasNote(rep.Notes, "does not speak HTTP/2") {
		t.Errorf("arrival header %v, notes %q", rep.ArrivalHeader, rep.Notes)
	}
}

func TestProbePlainHTTP(t *testing.T) {
	s := h1Serve(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Arrival-Ns", "1700000000000000000")
		w.Header().Set("Connection", "close")
	}), false, false)
	rep, err := Probe(t.Context(), s.url(t, "/"), Options{Guard: AllowAll()})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Recommended != H1 || rep.TLSVersion != "" || rep.ALPN != "" || !rep.ArrivalHeader || len(rep.RTTs) != probeGETs {
		t.Errorf("report %+v", rep)
	}
	if !h1HasNote(rep.Notes, "plain http") {
		t.Errorf("notes %q", rep.Notes)
	}
	// The server closes after every response, so each GET needs its own
	// connection.
	if n := s.conns.Load(); n != probeGETs {
		t.Errorf("probe opened %d connections, want %d", n, probeGETs)
	}
}

func TestProbeArrivalHeaderDisabled(t *testing.T) {
	s := h1ServeShop(t, 0)
	rep, err := Probe(t.Context(), s.url(t, "/healthz"), Options{TLS: s.tls, ArrivalHeader: "-", Guard: AllowAll()})
	if err != nil {
		t.Fatal(err)
	}
	if rep.ArrivalHeader || h1HasNote(rep.Notes, "header: reports") {
		t.Errorf("arrival header %v, notes %q", rep.ArrivalHeader, rep.Notes)
	}
}

func TestProbeGuardAbortsBeforeConnecting(t *testing.T) {
	denied := errors.New("not in scope")
	for _, g := range []*h1TestGuard{{denyHost: denied}, {denySpend: denied}} {
		s := h1ServeShop(t, 0)
		rep, err := Probe(t.Context(), s.url(t, "/"), Options{TLS: s.tls, Guard: g})
		if !errors.Is(err, denied) || rep != nil {
			t.Errorf("Probe = %v, %v; want the guard error", rep, err)
		}
		if n := s.conns.Load(); n != 0 {
			t.Errorf("%d connections opened despite the guard", n)
		}
	}
	if _, err := Probe(t.Context(), h1ServeShop(t, 0).url(t, "/"), Options{}); err == nil {
		t.Error("Probe without a Guard succeeded")
	}
}

func TestProbeUntrustedCertificateFails(t *testing.T) {
	s := h1ServeShop(t, 0)
	if _, err := Probe(t.Context(), s.url(t, "/"), Options{Guard: AllowAll()}); err == nil {
		t.Error("Probe accepted the test server's self-signed certificate without a TLS config")
	}
}

// h1HasNote reports whether one of notes contains sub.
func h1HasNote(notes []string, sub string) bool {
	for _, n := range notes {
		if strings.Contains(n, sub) {
			return true
		}
	}
	return false
}
