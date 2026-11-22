package demo

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestBearerToken(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"Bearer demo-alice", "demo-alice", true},
		{"bearer demo-bob", "demo-bob", true},
		{"Bearer  padded ", "padded", true},
		{"Bearer ", "", false},
		{"Basic abc", "", false},
		{"demo-alice", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		got, ok := bearerToken(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("bearerToken(%q) = %q, %v; want %q, %v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestIsSixDigits(t *testing.T) {
	for in, want := range map[string]bool{
		"000000": true, "482913": true, "12345": false, "1234567": false,
		"12345a": false, "": false, "１２３４５６": false,
	} {
		if got := isSixDigits(in); got != want {
			t.Errorf("isSixDigits(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestVariantOf(t *testing.T) {
	for in, want := range map[string]string{
		"/vuln/api/me": "vuln", "/fixed/x": "fixed", "/vuln": "", "/": "", "/healthz": "", "/vulnx/a": "",
	} {
		if got := variantOf(in); got != want {
			t.Errorf("variantOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestValidateAddr(t *testing.T) {
	ok := []string{"127.0.0.1:8443", "127.1.2.3:1", "[::1]:8443", "localhost:0", "LOCALHOST:80"}
	bad := []string{"0.0.0.0:8443", ":8443", "[::]:8443", "192.168.1.5:8443", "example.com:443"}
	for _, a := range ok {
		if err := ValidateAddr(a, false); err != nil {
			t.Errorf("ValidateAddr(%q, false) = %v, want nil", a, err)
		}
	}
	for _, a := range bad {
		if err := ValidateAddr(a, false); err == nil {
			t.Errorf("ValidateAddr(%q, false) = nil, want error", a)
		}
		if err := ValidateAddr(a, true); err != nil {
			t.Errorf("ValidateAddr(%q, true) = %v, want nil", a, err)
		}
	}
	if err := ValidateAddr("no-port", true); err == nil {
		t.Error("ValidateAddr without port succeeded")
	}
}

func TestSelfSignedCert(t *testing.T) {
	now := time.Now()
	cert, err := selfSignedCert(now)
	if err != nil {
		t.Fatal(err)
	}
	leaf := cert.Leaf
	for _, name := range []string{"localhost", "shop.example.test", "127.0.0.1", "::1"} {
		if err := leaf.VerifyHostname(name); err != nil {
			t.Errorf("certificate does not cover %s: %v", name, err)
		}
	}
	if d := leaf.NotAfter.Sub(now); d > 24*time.Hour || d < 23*time.Hour {
		t.Errorf("validity ends %s after now, want about 24h", d)
	}
	fp := fingerprint(leaf.Raw)
	if len(fp) != 32*3-1 || strings.Count(fp, ":") != 31 {
		t.Errorf("fingerprint %q has the wrong shape", fp)
	}
}

func TestNewRejectsWindow(t *testing.T) {
	for _, w := range []time.Duration{-time.Millisecond, MaxWindow + time.Millisecond} {
		if s, err := New(Config{Window: w}); err == nil {
			s.Close()
			t.Errorf("New(Window: %s) succeeded", w)
		}
	}
}

// call performs one request against h and decodes the JSON response.
func call(t *testing.T, h http.Handler, method, path, token, body string) (int, map[string]any, http.Header) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out map[string]any
	if strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("%s %s: bad JSON %q: %v", method, path, rec.Body.String(), err)
		}
	}
	return rec.Code, out, rec.Header()
}

// status performs one request against h and returns only its status code.
// Unlike call it never stops the test, so burst goroutines may use it.
func status(h http.Handler, method, path, token, body string) int {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

// burst runs n copies of fn at once and returns the status codes. Every
// goroutine is running before any of them is released.
func burst(n int, fn func() int) map[int]int {
	var (
		mu    sync.Mutex
		ready sync.WaitGroup
		done  sync.WaitGroup
		start = make(chan struct{})
		codes = map[int]int{}
	)
	ready.Add(n)
	done.Add(n)
	for range n {
		go func() {
			defer done.Done()
			ready.Done()
			<-start
			c := fn()
			mu.Lock()
			codes[c]++
			mu.Unlock()
		}()
	}
	ready.Wait()
	close(start)
	done.Wait()
	return codes
}

func newTestShop(t *testing.T, window time.Duration) *Shop {
	t.Helper()
	s, err := New(Config{Window: window})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// vulnOps returns the scenario implementation of the vulnerable variant.
func vulnOps(t *testing.T, s *Shop) *vulnScenarios {
	t.Helper()
	for _, v := range s.variants {
		if v.name == Vulnerable {
			return v.ops.(*vulnScenarios)
		}
	}
	t.Fatal("shop has no vulnerable variant")
	return nil
}

// holdTimeout bounds how long holdChecks keeps a request waiting.
const holdTimeout = 10 * time.Second

// holdChecks returns a beforeWrite hook that holds every request which has
// passed its check until k requests have, and a function reporting whether
// that happened. No request writes before k checks have read the unchanged
// state, so every /vuln scenario loses the race however the goroutines are
// scheduled. A request is held at most holdTimeout.
func holdChecks(k int) (hook func(), reached func() bool) {
	var (
		mu  sync.Mutex
		n   int
		all = make(chan struct{})
	)
	hook = func() {
		mu.Lock()
		n++
		if n == k {
			close(all)
		}
		mu.Unlock()
		select {
		case <-all:
		case <-time.After(holdTimeout):
		}
	}
	reached = func() bool {
		select {
		case <-all:
			return true
		default:
			return false
		}
	}
	return hook, reached
}

func TestScenarioRaces(t *testing.T) {
	s := newTestShop(t, 0)
	h := s.Handler()
	vops := vulnOps(t, s)
	const n = 10

	// race runs one burst. On /vuln it holds requests between check and
	// write until k of them have passed the check, which makes the lost race
	// deterministic instead of a matter of timing.
	race := func(t *testing.T, v string, k int, fn func() int) map[int]int {
		t.Helper()
		if v != "vuln" {
			return burst(n, fn)
		}
		hook, reached := holdChecks(k)
		vops.beforeWrite = hook
		codes := burst(n, fn)
		vops.beforeWrite = nil
		if !reached() {
			t.Fatalf("fewer than %d requests passed the check within %v; codes %v", k, holdTimeout, codes)
		}
		return codes
	}

	for _, v := range []string{"vuln", "fixed"} {
		p := "/" + v + "/api"
		t.Run(v+"/coupon", func(t *testing.T) {
			_, c, _ := call(t, h, "POST", p+"/carts", "demo-alice", "")
			id := c["id"].(string)
			codes := race(t, v, 2, func() int {
				return status(h, "POST", p+"/carts/"+id+"/coupons", "demo-alice", `{"code":"WELCOME10"}`)
			})
			_, c, _ = call(t, h, "GET", p+"/carts/"+id, "demo-alice", "")
			got := len(c["discounts"].([]any))
			if v == "fixed" && (got != 1 || codes[200] != 1 || codes[409] != n-1) {
				t.Errorf("fixed: %d discounts, codes %v", got, codes)
			}
			if v == "vuln" && (got < 2 || codes[200] < 2) {
				t.Errorf("vuln: race not reproduced, %d discounts, codes %v", got, codes)
			}
		})
		t.Run(v+"/transfer", func(t *testing.T) {
			race(t, v, 2, func() int {
				return status(h, "POST", p+"/transfers", "demo-alice", `{"to":"bob","amount_cents":6000}`)
			})
			_, a, _ := call(t, h, "GET", p+"/me", "demo-alice", "")
			_, b, _ := call(t, h, "GET", p+"/me", "demo-bob", "")
			ab, bb := a["balance_cents"].(float64), b["balance_cents"].(float64)
			if ab+bb != 20000 {
				t.Errorf("total money changed: %v + %v", ab, bb)
			}
			if v == "fixed" && ab != 4000 {
				t.Errorf("fixed: alice balance %v, want 4000", ab)
			}
			if v == "vuln" && ab >= 0 {
				t.Errorf("vuln: race not reproduced, alice balance %v", ab)
			}
		})
		t.Run(v+"/2fa", func(t *testing.T) {
			race(t, v, twofaLimit+1, func() int {
				return status(h, "POST", p+"/2fa/verify", "demo-alice", `{"code":"000000"}`)
			})
			_, st, _ := call(t, h, "GET", p+"/2fa/status", "demo-alice", "")
			checks := st["checks"].(float64)
			if v == "fixed" && checks != 3 {
				t.Errorf("fixed: %v checks, want 3", checks)
			}
			if v == "vuln" && checks <= 3 {
				t.Errorf("vuln: race not reproduced, %v checks", checks)
			}
		})
		t.Run(v+"/giftcard", func(t *testing.T) {
			_, before, _ := call(t, h, "GET", p+"/me", "demo-bob", "")
			race(t, v, 2, func() int {
				return status(h, "POST", p+"/giftcards/GIFT-BOB-50/redeem", "demo-bob", "")
			})
			_, after, _ := call(t, h, "GET", p+"/me", "demo-bob", "")
			gained := after["balance_cents"].(float64) - before["balance_cents"].(float64)
			if v == "fixed" && gained != 5000 {
				t.Errorf("fixed: credited %v, want 5000", gained)
			}
			if v == "vuln" && gained <= 5000 {
				t.Errorf("vuln: race not reproduced, credited %v", gained)
			}
		})
	}

	if err := s.Reset(); err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"vuln", "fixed"} {
		_, me, _ := call(t, h, "GET", "/"+v+"/api/me", "demo-alice", "")
		if me["balance_cents"].(float64) != 10000 {
			t.Errorf("%s: balance after Reset = %v", v, me["balance_cents"])
		}
	}
}

func TestProtocolDetails(t *testing.T) {
	h := newTestShop(t, 0).Handler()

	code, body, hdr := call(t, h, "GET", "/healthz", "", "")
	if code != 200 || body["status"] != "ok" || hdr.Get(headerArrival) == "" || hdr.Get(headerVariant) != "" ||
		hdr.Get("Cache-Control") != "no-store" {
		t.Errorf("healthz: %d %v %v", code, body, hdr)
	}
	if code, _, _ := call(t, h, "GET", "/vuln/api/me", "", ""); code != 401 {
		t.Errorf("no token: %d", code)
	}
	if code, _, _ := call(t, h, "GET", "/vuln/api/me", "nope", ""); code != 401 {
		t.Errorf("bad token: %d", code)
	}
	code, body, hdr = call(t, h, "GET", "/fixed/api/nothing", "demo-alice", "")
	if code != 404 || body["error"] != "not found" || hdr.Get(headerVariant) != "fixed" {
		t.Errorf("unknown route: %d %v %v", code, body, hdr)
	}
	code, body, hdr = call(t, h, "DELETE", "/vuln/api/me", "demo-alice", "")
	if code != 405 || body["error"] == nil || !strings.Contains(hdr.Get("Allow"), "GET") {
		t.Errorf("wrong method: %d %v %v", code, body, hdr)
	}
	code, body, _ = call(t, h, "POST", "/vuln/api/transfers", "demo-alice", `{"to":"bob","amount_cents":1,"x":1}`)
	if code != 400 {
		t.Errorf("unknown field: %d %v", code, body)
	}
	big := `{"code":"` + strings.Repeat("a", 70<<10) + `"}`
	if code, body, _ = call(t, h, "POST", "/vuln/api/2fa/verify", "demo-alice", big); code != 413 ||
		body["error"] != "body too large" {
		t.Errorf("large body: %d %v", code, body)
	}
	if code, _, _ = call(t, h, "POST", "/vuln/api/transfers", "demo-alice", `{"to":"alice","amount_cents":1}`); code != 400 {
		t.Errorf("self transfer: %d", code)
	}
	if code, _, _ = call(t, h, "POST", "/vuln/api/transfers", "demo-alice", `{"to":"carol","amount_cents":1}`); code != 404 {
		t.Errorf("unknown recipient: %d", code)
	}
	if code, _, _ = call(t, h, "POST", "/fixed/api/giftcards/NOPE/redeem", "demo-alice", ""); code != 404 {
		t.Errorf("unknown gift card: %d", code)
	}
	_, c, _ := call(t, h, "POST", "/fixed/api/carts", "demo-alice", "{}")
	if code, _, _ = call(t, h, "GET", "/fixed/api/carts/"+c["id"].(string), "demo-bob", ""); code != 404 {
		t.Errorf("other owner's cart: %d", code)
	}
	if code, _, _ = call(t, h, "POST", "/fixed/api/2fa/verify", "demo-bob", `{"code":"482913"}`); code != 200 {
		t.Errorf("right 2fa code: %d", code)
	}
}

// startServe runs Serve for s on a free loopback port and returns the bound
// address, a function that stops it, and the channel Serve's result
// arrives on.
func startServe(t *testing.T, s *Shop) (addr string, stop context.CancelFunc, done <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	addrc := make(chan string, 1)
	errc := make(chan error, 1)
	go func() {
		errc <- Serve(ctx, "127.0.0.1:0", s, func(addr, _ string) { addrc <- addr })
	}()
	select {
	case addr = <-addrc:
	case err := <-errc:
		t.Fatalf("Serve returned before ready: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("Serve did not call ready within 10s")
	}
	return addr, cancel, errc
}

// waitServe waits for Serve to return after it was stopped.
func waitServe(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve returned %v after cancel", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Serve did not return within 10s of cancellation")
	}
}

// tlsClient returns a client for the self-signed demo certificate that
// speaks HTTP/2 when h2 is true and HTTP/1.1 otherwise.
func tlsClient(t *testing.T, h2 bool) *http.Client {
	t.Helper()
	var protos http.Protocols
	protos.SetHTTP1(!h2)
	protos.SetHTTP2(h2)
	tr := &http.Transport{
		Protocols:       &protos,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, RootCAs: x509.NewCertPool()},
		DialContext:     (&net.Dialer{}).DialContext,
	}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: 10 * time.Second}
}

func TestServeHTTP2(t *testing.T) {
	addr, stop, done := startServe(t, newTestShop(t, 0))
	resp, err := tlsClient(t, true).Get("https://" + addr + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.ProtoMajor != 2 || resp.StatusCode != 200 {
		t.Errorf("got %s %d, want HTTP/2 200", resp.Proto, resp.StatusCode)
	}
	stop()
	waitServe(t, done)
}

func TestServerSettings(t *testing.T) {
	s := newTestShop(t, 0)
	cert, err := selfSignedCert(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	srv := newServer(s, cert)
	for _, c := range []struct {
		name      string
		got, want time.Duration
	}{
		{"ReadHeaderTimeout", srv.ReadHeaderTimeout, 5 * time.Second},
		{"ReadTimeout", srv.ReadTimeout, 15 * time.Second},
		{"WriteTimeout", srv.WriteTimeout, 15 * time.Second},
		{"IdleTimeout", srv.IdleTimeout, 60 * time.Second},
		{"shutdown timeout", shutdownTimeout, 5 * time.Second},
	} {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}
	if srv.WriteTimeout <= MaxWindow {
		t.Errorf("WriteTimeout %v must exceed the maximum window %v", srv.WriteTimeout, MaxWindow)
	}
	if srv.MaxHeaderBytes != 16<<10 {
		t.Errorf("MaxHeaderBytes = %d, want %d", srv.MaxHeaderBytes, 16<<10)
	}
	if got := srv.TLSConfig.NextProtos; len(got) != 2 || got[0] != "h2" || got[1] != "http/1.1" {
		t.Errorf("NextProtos = %v, want [h2 http/1.1]", got)
	}
}

func TestServeRejectsLargeHeaders(t *testing.T) {
	addr, stop, done := startServe(t, newTestShop(t, 0))
	get := func(c *http.Client, pad int) (int, error) {
		req, err := http.NewRequest(http.MethodGet, "https://"+addr+"/healthz", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Pad", strings.Repeat("a", pad))
		resp, err := c.Do(req)
		if err != nil {
			return 0, err
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp.StatusCode, nil
	}

	if code, err := get(tlsClient(t, false), 8<<10); err != nil || code != http.StatusOK {
		t.Errorf("8 KiB of headers over HTTP/1.1: %d %v, want 200", code, err)
	}
	// The server allows MaxHeaderBytes plus a fixed 4 KiB of slack, far below
	// the 1 MiB default.
	if code, err := get(tlsClient(t, false), 24<<10); err != nil || code != http.StatusRequestHeaderFieldsTooLarge {
		t.Errorf("24 KiB of headers over HTTP/1.1: %d %v, want 431", code, err)
	}
	// Over HTTP/2 the limit is advertised in SETTINGS: the client refuses to
	// send the request or the server rejects it.
	if code, err := get(tlsClient(t, true), 24<<10); err == nil && code != http.StatusRequestHeaderFieldsTooLarge {
		t.Errorf("24 KiB of headers over HTTP/2: status %d, want an error or 431", code)
	}
	stop()
	waitServe(t, done)
}

// TestServeDrainsInFlightRequests cancels Serve while a /vuln request is
// inside its window and expects the request to complete and Serve to return
// cleanly.
func TestServeDrainsInFlightRequests(t *testing.T) {
	const window = 300 * time.Millisecond
	s := newTestShop(t, window)
	inWindow := make(chan struct{})
	var once sync.Once
	vulnOps(t, s).beforeWrite = func() { once.Do(func() { close(inWindow) }) }
	addr, stop, done := startServe(t, s)

	type result struct {
		code int
		err  error
	}
	resc := make(chan result, 1)
	client := tlsClient(t, true)
	go func() {
		req, err := http.NewRequest(http.MethodPost, "https://"+addr+"/vuln/api/transfers",
			strings.NewReader(`{"to":"bob","amount_cents":100}`))
		if err != nil {
			resc <- result{err: err}
			return
		}
		req.Header.Set("Authorization", "Bearer demo-alice")
		resp, err := client.Do(req)
		if err != nil {
			resc <- result{err: err}
			return
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		resc <- result{code: resp.StatusCode}
	}()

	select {
	case <-inWindow:
	case r := <-resc:
		t.Fatalf("request finished before it reached the window: %+v", r)
	case <-time.After(10 * time.Second):
		t.Fatal("request did not reach the window within 10s")
	}
	stop()
	select {
	case r := <-resc:
		if r.err != nil || r.code != http.StatusOK {
			t.Errorf("in-flight request during shutdown: %d %v, want 200", r.code, r.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("in-flight request did not finish within 10s")
	}
	waitServe(t, done)
}

// logLine is the access log line for a successful GET /vuln/api/me.
var logLine = regexp.MustCompile(`^GET /vuln/api/me variant=vuln status=200 dur=[0-9.]+(ns|µs|ms|s)\n$`)

func TestLoggerAndInternalErrors(t *testing.T) {
	var buf strings.Builder
	s, err := New(Config{Logger: log.New(&buf, "", 0)})
	if err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	call(t, h, "GET", "/vuln/api/me", "demo-alice", "")
	if line := buf.String(); !logLine.MatchString(line) {
		t.Errorf("log line = %q, want it to match %s", line, logLine)
	}

	// A closed database must surface as a generic 500 without SQLite details.
	s.Close()
	buf.Reset()
	code, body, _ := call(t, h, "GET", "/fixed/api/me", "demo-alice", "")
	if code != 500 || body["error"] != "internal error" {
		t.Errorf("closed store: %d %v", code, body)
	}
	if !strings.Contains(buf.String(), "internal error: GET /fixed/api/me") {
		t.Errorf("internal error not logged: %q", buf.String())
	}

	// Control characters in the decoded path stay percent-encoded in both
	// the internal-error line and the access line.
	buf.Reset()
	call(t, h, "GET", "/fixed/api/carts/x%0Aforged%1B[31m", "demo-alice", "")
	out := buf.String()
	if strings.Count(out, "\n") != 2 || strings.ContainsAny(out, "\x1b\r") ||
		strings.Count(out, "/fixed/api/carts/x%0Aforged%1B") != 2 {
		t.Errorf("log output = %q, want two lines with the newline and ESC still encoded", out)
	}
}

func TestNonCanonicalPathsAreNotRedirected(t *testing.T) {
	h := newTestShop(t, 0).Handler()
	for _, p := range []string{
		"/fixed/../vuln/api/me",
		"/fixed/./api/me",
		"/vuln//api/me",
		"//vuln/api/me",
		"/fixed/api/me/.",
		"/fixed%2F..%2Fvuln/api/me",
	} {
		code, body, hdr := call(t, h, "GET", p, "demo-alice", "")
		if code != http.StatusNotFound || body["error"] != "not found" || hdr.Get("Location") != "" ||
			hdr.Get(headerVariant) != "" {
			t.Errorf("GET %s: %d %v %v, want a JSON 404 without Location or variant", p, code, body, hdr)
		}
	}
	for _, p := range []string{"/vuln/api/me", "/fixed/api/me", "/healthz", "/"} {
		if code := status(h, "GET", p, "demo-alice", ""); code != http.StatusOK {
			t.Errorf("GET %s: %d, want 200", p, code)
		}
	}
}

func TestCleanPath(t *testing.T) {
	for in, want := range map[string]string{
		"": "/", "/": "/", "a": "/a", "/a/../b": "/b", "/a//b/": "/a/b/", "/a/./": "/a/", "/a/b": "/a/b",
	} {
		if got := cleanPath(in); got != want {
			t.Errorf("cleanPath(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestWindowOnlyInVuln proves structurally that the pause between check and
// write is reached by every /vuln scenario request and by no /fixed one.
func TestWindowOnlyInVuln(t *testing.T) {
	s := newTestShop(t, 0)
	h := s.Handler()
	var mu sync.Mutex
	pauses := 0
	vulnOps(t, s).beforeWrite = func() {
		mu.Lock()
		pauses++
		mu.Unlock()
	}
	for _, v := range []string{"vuln", "fixed"} {
		p := "/" + v + "/api"
		_, c, _ := call(t, h, "POST", p+"/carts", "demo-alice", "")
		mu.Lock()
		pauses = 0
		mu.Unlock()
		reqs := []struct{ path, body string }{
			{p + "/carts/" + c["id"].(string) + "/coupons", `{"code":"WELCOME10"}`},
			{p + "/transfers", `{"to":"bob","amount_cents":100}`},
			{p + "/2fa/verify", `{"code":"000000"}`},
			{p + "/giftcards/GIFT-ALICE-50/redeem", ""},
		}
		for _, rq := range reqs {
			if code := status(h, "POST", rq.path, "demo-alice", rq.body); code != 200 && code != 401 {
				t.Errorf("POST %s: status %d", rq.path, code)
			}
		}
		mu.Lock()
		got := pauses
		mu.Unlock()
		want := 0
		if v == "vuln" {
			want = len(reqs)
		}
		if got != want {
			t.Errorf("%s: %d scenario requests reached the window, want %d", v, got, want)
		}
	}
}

// TestCouponAfterResetLeavesNoOrphan applies a coupon to a cart that a reset
// removed after the handler looked it up. Neither variant may store a
// discount for a cart the caller does not have.
func TestCouponAfterResetLeavesNoOrphan(t *testing.T) {
	s := newTestShop(t, 0)
	ctx := context.Background()
	for _, v := range s.variants {
		t.Run(string(v.name), func(t *testing.T) {
			c, err := v.st.createCart(ctx, "alice")
			if err != nil {
				t.Fatal(err)
			}
			if err := v.st.reset(ctx); err != nil {
				t.Fatal(err)
			}
			if err := v.ops.applyCoupon(ctx, c.ID, "alice", welcomeCouponCode, 810); !errors.Is(err, errCartNotFound) {
				t.Errorf("applyCoupon on a removed cart = %v, want errCartNotFound", err)
			}
			c2, err := v.st.createCart(ctx, "alice")
			if err != nil {
				t.Fatal(err)
			}
			if err := v.ops.applyCoupon(ctx, c2.ID, "bob", welcomeCouponCode, 810); !errors.Is(err, errCartNotFound) {
				t.Errorf("applyCoupon on another owner's cart = %v, want errCartNotFound", err)
			}
			var n int
			if err := v.st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM cart_discounts`).Scan(&n); err != nil {
				t.Fatal(err)
			}
			if n != 0 {
				t.Errorf("%d discount rows written for carts the caller does not have", n)
			}
		})
	}
}
