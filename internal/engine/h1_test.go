package engine

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TroubieD3v/photofinish/internal/clock"
	"github.com/TroubieD3v/photofinish/internal/demo"
)

// The helpers in this file are shared by h1_test.go, burst_test.go and
// probe_test.go. Their names carry an h1 prefix so they cannot collide with
// the helpers of the h2 engine tests.

const h1TestAlice = "Bearer demo-alice"

// h1TestServer is a test server with a TLS configuration that trusts it and
// a count of the connections it accepted.
type h1TestServer struct {
	srv   *httptest.Server
	tls   *tls.Config // nil for plain http
	conns atomic.Int64
}

// h1Serve starts h over TLS (offering HTTP/2 when enableH2) or, when tlsOn
// is false, over plain http.
func h1Serve(t *testing.T, h http.Handler, tlsOn, enableH2 bool) *h1TestServer {
	t.Helper()
	s := &h1TestServer{}
	s.srv = httptest.NewUnstartedServer(h)
	s.srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.srv.Config.ConnState = func(_ net.Conn, st http.ConnState) {
		if st == http.StateNew {
			s.conns.Add(1)
		}
	}
	if tlsOn {
		s.srv.EnableHTTP2 = enableH2
		s.srv.StartTLS()
		pool := x509.NewCertPool()
		pool.AddCert(s.srv.Certificate())
		s.tls = &tls.Config{RootCAs: pool}
	} else {
		s.srv.Start()
	}
	t.Cleanup(s.srv.Close)
	return s
}

// h1ServeShop starts the demo shop with the given race window over TLS with
// HTTP/2 enabled, exactly like the real demo target.
func h1ServeShop(t *testing.T, window time.Duration) *h1TestServer {
	t.Helper()
	shop, err := demo.New(demo.Config{Window: window})
	if err != nil {
		t.Fatal(err)
	}
	s := h1Serve(t, shop.Handler(), true, true)
	t.Cleanup(func() { shop.Close() })
	return s
}

// url returns the absolute URL of path on the server.
func (s *h1TestServer) url(t *testing.T, path string) *url.URL {
	t.Helper()
	u, err := url.Parse(s.srv.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// do sends a setup request with the test server's own client and returns the
// status and the body.
func (s *h1TestServer) do(t *testing.T, method, path, auth string, body string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, s.srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := s.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, b
}

// h1Cart is the part of the demo cart the tests look at.
type h1Cart struct {
	ID        string            `json:"id"`
	Discounts []json.RawMessage `json:"discounts"`
}

// newCart creates a cart for alice in variant ("vuln" or "fixed").
func (s *h1TestServer) newCart(t *testing.T, variant string) string {
	t.Helper()
	status, body := s.do(t, http.MethodPost, "/"+variant+"/api/carts", h1TestAlice, "")
	if status != http.StatusCreated {
		t.Fatalf("create cart: status %d: %s", status, body)
	}
	var c h1Cart
	if err := json.Unmarshal(body, &c); err != nil {
		t.Fatal(err)
	}
	return c.ID
}

// discounts returns the number of discounts on the cart.
func (s *h1TestServer) discounts(t *testing.T, variant, id string) int {
	t.Helper()
	status, body := s.do(t, http.MethodGet, "/"+variant+"/api/carts/"+id, h1TestAlice, "")
	if status != http.StatusOK {
		t.Fatalf("get cart: status %d: %s", status, body)
	}
	var c h1Cart
	if err := json.Unmarshal(body, &c); err != nil {
		t.Fatal(err)
	}
	return len(c.Discounts)
}

// couponRequests returns n copies of the coupon request for the cart.
func (s *h1TestServer) couponRequests(t *testing.T, variant, cartID string, n int) []Request {
	t.Helper()
	u := s.url(t, "/"+variant+"/api/carts/"+cartID+"/coupons")
	reqs := make([]Request, n)
	for i := range reqs {
		reqs[i] = Request{
			Label:  fmt.Sprintf("copy %d", i+1),
			Method: http.MethodPost,
			URL:    u,
			Header: http.Header{"Authorization": {h1TestAlice}, "Content-Type": {"application/json"}},
			Body:   []byte(`{"code":"WELCOME10"}`),
		}
	}
	return reqs
}

// h1Copies returns n copies of a bodyless GET of u.
func h1Copies(u *url.URL, n int) []Request {
	reqs := make([]Request, n)
	for i := range reqs {
		reqs[i] = Request{Label: fmt.Sprintf("copy %d", i+1), Method: http.MethodGet, URL: u,
			Header: http.Header{"X-Copy": {fmt.Sprint(i)}}}
	}
	return reqs
}

// h1TestGuard records what an engine asks for and can deny either step.
type h1TestGuard struct {
	mu        sync.Mutex
	hosts     []string
	spent     int
	spends    int
	denyHost  error
	denySpend error
}

func (g *h1TestGuard) Allow(host string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.hosts = append(g.hosts, host)
	return g.denyHost
}

func (g *h1TestGuard) Spend(n int) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.spends++
	if g.denySpend != nil {
		return g.denySpend
	}
	g.spent += n
	return nil
}

func (g *h1TestGuard) total() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.spent
}

// h1SetReleaseHook installs fn as the release hook for races against
// target only, and removes it when the test ends.
func h1SetReleaseHook(t *testing.T, target string, fn func()) {
	t.Helper()
	hook := func(got string) {
		if got == target {
			fn()
		}
	}
	if !h1ReleaseHook.CompareAndSwap(nil, &hook) {
		t.Fatal("another test installed an h1 release hook")
	}
	t.Cleanup(func() { h1ReleaseHook.Store(nil) })
}

// h1CheckResults asserts the invariants every Result of a completed race
// must satisfy, whatever the engine.
func h1CheckResults(t *testing.T, race *Race, reqs []Request, proto string) {
	t.Helper()
	if len(race.Results) != len(reqs) {
		t.Fatalf("got %d results for %d requests", len(race.Results), len(reqs))
	}
	if race.StartedNs == 0 || race.FinishedNs < race.StartedNs {
		t.Errorf("race times: started %d finished %d", race.StartedNs, race.FinishedNs)
	}
	for i, r := range race.Results {
		switch {
		case r.Index != i:
			t.Errorf("result %d: index %d", i, r.Index)
		case r.Label != reqs[i].Label:
			t.Errorf("result %d: label %q, want %q", i, r.Label, reqs[i].Label)
		case r.Err != "":
			t.Errorf("result %d: error %s", i, r.Err)
		case r.Status == 0:
			t.Errorf("result %d: no status", i)
		case r.Proto != proto:
			t.Errorf("result %d: proto %q, want %q", i, r.Proto, proto)
		case r.PreSentNs == 0 || r.PreSentNs > r.ReleasedNs:
			t.Errorf("result %d: pre-sent %d, released %d", i, r.PreSentNs, r.ReleasedNs)
		case r.FirstByteNs == 0 || r.DoneNs < r.FirstByteNs:
			t.Errorf("result %d: first byte %d, done %d", i, r.FirstByteNs, r.DoneNs)
		case r.FirstByteNs < race.StartedNs || r.DoneNs > race.FinishedNs:
			t.Errorf("result %d: times outside the race", i)
		}
	}
}

func TestH1CouponRaceVuln(t *testing.T) {
	// A wide artificial window makes the double spend deterministic, so the
	// test can show that the h1 engine really races and is not serialized.
	s := h1ServeShop(t, 50*time.Millisecond)
	cart := s.newCart(t, "vuln")
	reqs := s.couponRequests(t, "vuln", cart, 10)
	g := &h1TestGuard{}

	race, err := Run(t.Context(), reqs, Options{Kind: H1, TLS: s.tls, Guard: g})
	if err != nil {
		t.Fatal(err)
	}
	h1CheckResults(t, race, reqs, "HTTP/1.1")
	if race.Kind != H1 || race.Connections != 10 || (race.ALPN != "" && race.ALPN != "http/1.1") || race.TLSVersion == "" {
		t.Errorf("race: kind %s, %d connections, ALPN %q, TLS %q", race.Kind, race.Connections, race.ALPN, race.TLSVersion)
	}
	if race.Target != s.srv.URL {
		t.Errorf("target %q, want %q", race.Target, s.srv.URL)
	}
	if race.Release.Bytes != 10 || race.Release.Writes != 10 || race.Release.SpreadNs < 0 {
		t.Errorf("release %+v", race.Release)
	}
	if g.total() != 10 || len(g.hosts) == 0 || g.hosts[0] != s.url(t, "/").Host {
		t.Errorf("guard: spent %d, hosts %v", g.total(), g.hosts)
	}

	applied := 0
	conns := map[int]bool{}
	for i, r := range race.Results {
		conns[r.Conn] = true
		if r.ServerArrivalNs == 0 {
			t.Errorf("result %d: no server arrival time", i)
		}
		if r.EarlyResponse || r.FirstByteNs < r.ReleasedNs {
			t.Errorf("result %d: response before release", i)
		}
		switch r.Status {
		case http.StatusOK:
			applied++
		case http.StatusConflict:
		default:
			t.Errorf("result %d: status %d: %s", i, r.Status, r.Body)
		}
	}
	if len(conns) != 10 {
		t.Errorf("results use %d distinct connections, want 10", len(conns))
	}
	if applied < 2 {
		t.Errorf("only %d of 10 copies applied the coupon; the h1 race did not overlap", applied)
	}
	if n := s.discounts(t, "vuln", cart); n != applied {
		t.Errorf("cart has %d discounts, %d responses said applied", n, applied)
	}
}

func TestH1CouponFixedHolds(t *testing.T) {
	s := h1ServeShop(t, 0)
	for trial := range 3 {
		cart := s.newCart(t, "fixed")
		reqs := s.couponRequests(t, "fixed", cart, 10)
		race, err := Run(t.Context(), reqs, Options{Kind: H1, TLS: s.tls, Guard: AllowAll()})
		if err != nil {
			t.Fatal(err)
		}
		h1CheckResults(t, race, reqs, "HTTP/1.1")
		applied := 0
		for _, r := range race.Results {
			if r.Status == http.StatusOK {
				applied++
			}
		}
		if applied != 1 || s.discounts(t, "fixed", cart) != 1 {
			t.Errorf("trial %d: %d copies applied the coupon on /fixed", trial, applied)
		}
	}
}

func TestH1BodylessRequestIsHeldUntilRelease(t *testing.T) {
	s := h1ServeShop(t, 0)
	reqs := h1Copies(s.url(t, "/healthz"), 5)
	var heldNs int64
	h1SetReleaseHook(t, s.srv.URL, func() { heldNs = clock.UnixNano() })

	race, err := Run(t.Context(), reqs, Options{Kind: H1, TLS: s.tls, Guard: AllowAll()})
	if err != nil {
		t.Fatal(err)
	}
	h1CheckResults(t, race, reqs, "HTTP/1.1")
	if heldNs == 0 {
		t.Fatal("release hook did not run")
	}
	for i, r := range race.Results {
		// The server can only start the handler once the final "\n" of the
		// header block has arrived, and that byte is written after the hook.
		if r.ServerArrivalNs <= heldNs {
			t.Errorf("result %d: server saw the request at %d, before the release phase began at %d", i, r.ServerArrivalNs, heldNs)
		}
		if r.Status != http.StatusOK {
			t.Errorf("result %d: status %d", i, r.Status)
		}
	}
}

// h1RawServer is a plain TCP server that records the bytes of every
// connection and lets the test see the withheld state.
type h1RawServer struct {
	ln       net.Listener
	want     int         // full request length
	presend  chan int    // bytes seen once the request is complete but for one byte
	complete chan []byte // the complete request
	stop     chan struct{}
	wg       sync.WaitGroup
}

// h1StartRawServer serves ln; every connection must carry exactly want
// request bytes.
func h1StartRawServer(t *testing.T, ln net.Listener, want int) *h1RawServer {
	t.Helper()
	s := &h1RawServer{ln: ln, want: want, presend: make(chan int, 64), complete: make(chan []byte, 64), stop: make(chan struct{})}
	s.wg.Go(func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.wg.Go(func() { s.serve(c) })
		}
	})
	t.Cleanup(func() {
		close(s.stop)
		ln.Close()
		s.wg.Wait()
	})
	return s
}

func (s *h1RawServer) serve(c net.Conn) {
	defer c.Close()
	go func() {
		<-s.stop
		c.Close()
	}()
	var got []byte
	buf := make([]byte, 4096)
	signalled := false
	for len(got) < s.want {
		n, err := c.Read(buf)
		got = append(got, buf[:n]...)
		if !signalled && len(got) >= s.want-1 {
			signalled = true
			s.presend <- len(got)
		}
		if err != nil {
			return
		}
	}
	s.complete <- got
	io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
}

func TestH1WithholdsOnlyTheLastByte(t *testing.T) {
	cases := []struct {
		name string
		req  Request
		last byte
	}{
		{"body", Request{Method: http.MethodPost, Header: http.Header{"Content-Type": {"application/json"}}, Body: []byte(`{"code":"X"}`)}, '}'},
		{"no body", Request{Method: http.MethodGet}, '\n'},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			const copies = 4
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			u := &url.URL{Scheme: "http", Host: ln.Addr().String(), Path: "/x"}
			wire, err := h1Wire(Request{Method: tc.req.Method, URL: u, Header: tc.req.Header, Body: tc.req.Body}, false)
			if err != nil {
				t.Fatal(err)
			}
			srv := h1StartRawServer(t, ln, len(wire))
			reqs := make([]Request, copies)
			for i := range reqs {
				reqs[i] = tc.req
				reqs[i].URL = u
				reqs[i].Label = fmt.Sprint(i)
			}

			hookRan := false
			h1SetReleaseHook(t, "http://"+u.Host, func() {
				hookRan = true
				for range copies {
					select {
					case n := <-srv.presend:
						if n != srv.want-1 {
							t.Errorf("before release the server had %d bytes, want %d", n, srv.want-1)
						}
					case <-time.After(10 * time.Second):
						t.Error("server never saw the pre-sent requests")
						return
					}
				}
				select {
				case <-srv.complete:
					t.Error("a request was complete before the release")
				default:
				}
			})

			race, err := Run(t.Context(), reqs, Options{Kind: H1, Guard: AllowAll(), Gate: time.Millisecond})
			if err != nil {
				t.Fatal(err)
			}
			if !hookRan {
				t.Fatal("release hook did not run")
			}
			h1CheckResults(t, race, reqs, "HTTP/1.1")
			for i := range copies {
				got := <-srv.complete
				if !bytes.Equal(got, wire) {
					t.Errorf("request %d on the wire:\n%q\nwant\n%q", i, got, wire)
				}
				if got[len(got)-1] != tc.last {
					t.Errorf("last byte %q, want %q", got[len(got)-1], tc.last)
				}
			}
			for i, r := range race.Results {
				if r.Status != http.StatusOK || string(r.Body) != "ok" {
					t.Errorf("result %d: status %d body %q", i, r.Status, r.Body)
				}
			}
			if race.Release.Bytes != copies || race.ALPN != "" || race.TLSVersion != "" {
				t.Errorf("race: release %+v, ALPN %q, TLS %q", race.Release, race.ALPN, race.TLSVersion)
			}
		})
	}
}

func TestH1WarmupUsesTheRaceConnection(t *testing.T) {
	var mu sync.Mutex
	type seen struct{ addr, path, copy string }
	var log []seen
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		log = append(log, seen{r.RemoteAddr, r.URL.Path, r.Header.Get("X-Copy")})
		mu.Unlock()
		io.WriteString(w, "hi")
	})
	s := h1Serve(t, h, true, true)
	reqs := h1Copies(s.url(t, "/race"), 3)
	g := &h1TestGuard{}

	race, err := Run(t.Context(), reqs, Options{Kind: H1, Warmup: 2, TLS: s.tls, Guard: g})
	if err != nil {
		t.Fatal(err)
	}
	h1CheckResults(t, race, reqs, "HTTP/1.1")
	if g.total() != 3*(1+2) || g.spends != 1 {
		t.Errorf("guard spent %d in %d calls, want 9 in 1", g.total(), g.spends)
	}
	if race.Warmup != 2 {
		t.Errorf("race warm-up %d", race.Warmup)
	}
	if n := s.conns.Load(); n != 3 {
		t.Errorf("server accepted %d connections, want 3", n)
	}
	mu.Lock()
	defer mu.Unlock()
	for i := range reqs {
		addr := ""
		for _, e := range log {
			if e.path == "/race" && e.copy == fmt.Sprint(i) {
				addr = e.addr
			}
		}
		warm := 0
		for _, e := range log {
			if e.addr == addr && e.path == "/" {
				warm++
			}
		}
		if addr == "" || warm != 2 {
			t.Errorf("copy %d: %d warm-up requests on its connection %q, want 2", i, warm, addr)
		}
	}
}

func TestH1GuardAbortsBeforeConnecting(t *testing.T) {
	denied := errors.New("out of scope")
	for _, g := range []*h1TestGuard{{denyHost: denied}, {denySpend: denied}} {
		s := h1ServeShop(t, 0)
		reqs := h1Copies(s.url(t, "/healthz"), 3)
		race, err := Run(t.Context(), reqs, Options{Kind: H1, TLS: s.tls, Guard: g})
		if !errors.Is(err, denied) || race != nil {
			t.Errorf("Run = %v, %v; want the guard error", race, err)
		}
		if n := s.conns.Load(); n != 0 {
			t.Errorf("%d connections opened despite the guard", n)
		}
	}
}

func TestH1TruncatesLargeBodies(t *testing.T) {
	big := strings.Repeat("x", 10000)
	s := h1Serve(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, big)
	}), false, false)
	reqs := h1Copies(s.url(t, "/big"), 2)
	race, err := Run(t.Context(), reqs, Options{Kind: H1, MaxBody: 100, Guard: AllowAll()})
	if err != nil {
		t.Fatal(err)
	}
	h1CheckResults(t, race, reqs, "HTTP/1.1")
	for i, r := range race.Results {
		if len(r.Body) != 100 || !r.Truncated {
			t.Errorf("result %d: %d body bytes, truncated %v", i, len(r.Body), r.Truncated)
		}
		if r.ServerArrivalNs != 0 {
			t.Errorf("result %d: server arrival %d without the header", i, r.ServerArrivalNs)
		}
	}
}

func TestH1TimeoutIsReportedPerResult(t *testing.T) {
	block := make(chan struct{})
	s := h1Serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-block:
		case <-r.Context().Done():
		}
	}), false, false)
	t.Cleanup(func() { close(block) }) // runs before the server closes
	reqs := h1Copies(s.url(t, "/slow"), 2)

	race, err := Run(t.Context(), reqs, Options{Kind: H1, Gate: time.Millisecond, Timeout: 300 * time.Millisecond, Guard: AllowAll()})
	if err != nil {
		t.Fatal(err)
	}
	for i, r := range race.Results {
		if r.Status != 0 || !strings.Contains(r.Err, "timeout") || r.ReleasedNs == 0 {
			t.Errorf("result %d: status %d, released %d, error %q", i, r.Status, r.ReleasedNs, r.Err)
		}
	}
}

func TestH1NoConnectionIsAnError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	reqs := h1Copies(&url.URL{Scheme: "http", Host: addr, Path: "/"}, 2)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if race, err := Run(ctx, reqs, Options{Kind: H1, Guard: AllowAll()}); err == nil {
		t.Errorf("Run against a closed port = %+v, want an error", race)
	}
}

func TestH1Wire(t *testing.T) {
	u := &url.URL{Scheme: "https", Host: "shop.test:8443", Path: "/api/carts/1", RawQuery: "a=b"}
	got, err := h1Wire(Request{
		Method: http.MethodPost,
		URL:    u,
		Header: http.Header{
			"X-B":            {"2"},
			"Authorization":  {"Bearer t"},
			"Host":           {"evil.test"},
			"Content-Length": {"99"},
			"Connection":     {"keep-alive"},
		},
		Body: []byte("{}"),
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	want := "POST /api/carts/1?a=b HTTP/1.1\r\nHost: shop.test:8443\r\nAuthorization: Bearer t\r\nX-B: 2\r\n" +
		"Content-Length: 2\r\nConnection: close\r\n\r\n{}"
	if string(got) != want {
		t.Errorf("wire:\n%q\nwant\n%q", got, want)
	}

	got, err = h1Wire(Request{Method: http.MethodPost, URL: &url.URL{Scheme: "http", Host: "h"}}, true)
	if err != nil {
		t.Fatal(err)
	}
	keepAlive := "POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\n\r\n"
	if string(got) != keepAlive {
		t.Errorf("keep-alive bodyless POST:\n%q\nwant\n%q", got, keepAlive)
	}

	// The wire must parse as exactly the request it describes.
	parsed, err := http.ReadRequest(bufio.NewReader(strings.NewReader(keepAlive)))
	if err != nil || parsed.Method != http.MethodPost || parsed.Host != "h" || parsed.Close || parsed.ContentLength != 0 {
		t.Errorf("ReadRequest = %+v, %v", parsed, err)
	}

	for _, bad := range []Request{
		{Method: "GET", URL: u, Header: http.Header{"X-A": {"1\r\nX-Injected: 1"}}},
		{Method: "GET", URL: u, Header: http.Header{"Bad Name": {"1"}}},
		{Method: "GE T", URL: u},
	} {
		if _, err := h1Wire(bad, false); err == nil {
			t.Errorf("h1Wire(%+v) accepted an invalid request", bad)
		}
	}
}
