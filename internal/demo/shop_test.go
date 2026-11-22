// Black-box tests for the demo shop. They exercise only the exported API of
// package demo and the HTTP contract, served over TLS with HTTP/2 exactly like
// the real target, and prove both halves of every scenario: the /vuln variant
// loses the race and the /fixed variant never does.
package demo_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TroubieD3v/photofinish/internal/demo"
)

const (
	aliceToken = "demo-alice"
	bobToken   = "demo-bob"

	// alice and bob are ready-made Authorization header values.
	alice = "Bearer " + aliceToken
	bob   = "Bearer " + bobToken

	twoFACode   = "482913"
	wrongCode   = "000000"
	twoFALimit  = 3
	seedBalance = 10000
	cartTotal   = 8100
	welcomeOff  = 810
	giftValue   = 5000
	coupon      = "WELCOME10"
	aliceGift   = "GIFT-ALICE-50"
	bobGift     = "GIFT-BOB-50"
	transferAmt = 6000

	// burstSize is the number of requests released together in a race burst.
	burstSize = 12
	// raceWindow is the artificial check-then-act pause used by race tests.
	raceWindow = 40 * time.Millisecond
	// fixedRounds is how many bursts the fixed variant must survive per scenario.
	fixedRounds = 15
	// vulnRaceWindow is the pause used when /vuln must lose the race. The
	// invariant breaks as soon as a second request (a fourth for 2FA) reaches
	// its check while the first one is still paused, so the window is the
	// margin the test has against a slow scheduler. The client-side barrier
	// cannot guarantee that the requests reach the server within one window,
	// so this black-box proof stays statistical: a burst rarely misses on a
	// saturated machine, and the test allows vulnAttempts bursts before it
	// fails. The deterministic proof is TestScenarioRaces in internal_test.go,
	// which holds requests between check and write.
	vulnRaceWindow = 250 * time.Millisecond
	// vulnAttempts is how many bursts may hold the invariant before the
	// /vuln test fails.
	vulnAttempts = 5
	// clockSlack tolerates the coarse wall clock of some platforms when comparing
	// X-Arrival-Ns with client-side timestamps.
	clockSlack = 20 * time.Millisecond
)

var variants = []demo.Variant{demo.Vulnerable, demo.Fixed}

// api returns the path of route under the base path of variant v.
func api(v demo.Variant, route string) string {
	return "/" + string(v) + "/api" + route
}

// other returns the variant that is not v.
func other(v demo.Variant) demo.Variant {
	if v == demo.Vulnerable {
		return demo.Fixed
	}
	return demo.Vulnerable
}

// testServer is a demo shop behind an HTTP/2 TLS test server.
type testServer struct {
	shop   *demo.Shop
	srv    *httptest.Server
	client *http.Client
}

func newTestServer(t *testing.T, cfg demo.Config) *testServer {
	t.Helper()
	shop, err := demo.New(cfg)
	if err != nil {
		t.Fatalf("demo.New(Window=%v): %v", cfg.Window, err)
	}
	srv := httptest.NewUnstartedServer(shop.Handler())
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(func() {
		srv.Close()
		if err := shop.Close(); err != nil {
			t.Errorf("Shop.Close: %v", err)
		}
	})
	return &testServer{shop: shop, srv: srv, client: srv.Client()}
}

// response is a fully read HTTP response plus client-side timing.
type response struct {
	method   string
	path     string
	status   int
	proto    int
	alpn     string
	header   http.Header
	body     []byte
	sent     time.Time
	received time.Time
}

func (r *response) String() string {
	return fmt.Sprintf("%s %s -> %d %s", r.method, r.path, r.status, bytes.TrimSpace(r.body))
}

func (ts *testServer) newRequest(method, path, auth, body string) (*http.Request, error) {
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, ts.srv.URL+path, rd)
	if err != nil {
		return nil, err
	}
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

func (ts *testServer) roundTrip(req *http.Request) (*response, error) {
	sent := time.Now()
	resp, err := ts.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	received := time.Now()
	if err != nil {
		return nil, fmt.Errorf("%s %s: reading body: %w", req.Method, req.URL.Path, err)
	}
	r := &response{
		method:   req.Method,
		path:     req.URL.Path,
		status:   resp.StatusCode,
		proto:    resp.ProtoMajor,
		header:   resp.Header,
		body:     body,
		sent:     sent,
		received: received,
	}
	if resp.TLS != nil {
		r.alpn = resp.TLS.NegotiatedProtocol
	}
	return r, nil
}

// do sends one request; auth is the full Authorization header value or "".
func (ts *testServer) do(t *testing.T, method, path, auth, body string) *response {
	t.Helper()
	req, err := ts.newRequest(method, path, auth, body)
	if err != nil {
		t.Fatalf("building %s %s: %v", method, path, err)
	}
	r, err := ts.roundTrip(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	return r
}

// burst sends n requests released together through a barrier and returns the
// responses in request order.
func (ts *testServer) burst(t *testing.T, n int, build func(i int) (method, path, auth, body string)) []*response {
	t.Helper()
	// Establish the HTTP/2 connection first so every request of the burst is a
	// stream on the same, already open connection.
	ts.do(t, http.MethodGet, "/healthz", "", "")

	reqs := make([]*http.Request, n)
	for i := range n {
		method, path, auth, body := build(i)
		req, err := ts.newRequest(method, path, auth, body)
		if err != nil {
			t.Fatalf("building burst request %d: %v", i, err)
		}
		reqs[i] = req
	}

	res := make([]*response, n)
	errs := make([]error, n)
	start := make(chan struct{})
	var ready, done sync.WaitGroup
	ready.Add(n)
	done.Add(n)
	for i := range n {
		go func() {
			defer done.Done()
			ready.Done()
			<-start
			res[i], errs[i] = ts.roundTrip(reqs[i])
		}()
	}
	ready.Wait()
	close(start)
	done.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("burst request %d: %v", i, err)
		}
	}
	return res
}

// object decodes the body as a JSON object; numbers stay json.Number.
func (r *response) object(t *testing.T) map[string]any {
	t.Helper()
	var m map[string]any
	dec := json.NewDecoder(bytes.NewReader(r.body))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil || m == nil {
		t.Fatalf("%s: body is not a JSON object: %v", r, err)
	}
	return m
}

func str(t *testing.T, m map[string]any, key string) string {
	t.Helper()
	s, ok := m[key].(string)
	if !ok {
		t.Fatalf("field %q = %#v, want a string (object %v)", key, m[key], m)
	}
	return s
}

func num(t *testing.T, m map[string]any, key string) int64 {
	t.Helper()
	n, ok := m[key].(json.Number)
	if !ok {
		t.Fatalf("field %q = %#v, want a number (object %v)", key, m[key], m)
	}
	i, err := n.Int64()
	if err != nil {
		t.Fatalf("field %q = %s, want an integer: %v", key, n, err)
	}
	return i
}

func expectStatus(t *testing.T, r *response, want int) {
	t.Helper()
	if r.status != want {
		t.Fatalf("%s: status %d, want %d", r, r.status, want)
	}
}

// expectError checks status and a JSON error body; msg "" accepts any non-empty message.
func expectError(t *testing.T, r *response, status int, msg string) map[string]any {
	t.Helper()
	expectStatus(t, r, status)
	checkJSON(t, r)
	m := r.object(t)
	got := str(t, m, "error")
	if msg == "" && got == "" {
		t.Errorf("%s: empty error message", r)
	}
	if msg != "" && got != msg {
		t.Errorf("%s: error %q, want %q", r, got, msg)
	}
	return m
}

// checkArrival validates X-Arrival-Ns and returns it.
func checkArrival(t *testing.T, r *response) int64 {
	t.Helper()
	raw := r.header.Get("X-Arrival-Ns")
	if raw == "" {
		t.Errorf("%s: missing X-Arrival-Ns", r)
		return 0
	}
	ns, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || ns <= 0 {
		t.Errorf("%s: X-Arrival-Ns %q is not a positive decimal integer", r, raw)
		return 0
	}
	lo := r.sent.Add(-clockSlack).UnixNano()
	hi := r.received.Add(clockSlack).UnixNano()
	if ns < lo || ns > hi {
		t.Errorf("%s: X-Arrival-Ns %d outside the request lifetime [%d, %d]", r, ns, lo, hi)
	}
	return ns
}

// checkVariant checks X-PhotoFinish-Variant; want "" means the header must be absent.
func checkVariant(t *testing.T, r *response, want string) {
	t.Helper()
	vals := r.header.Values("X-PhotoFinish-Variant")
	switch {
	case want == "" && len(vals) != 0:
		t.Errorf("%s: unexpected X-PhotoFinish-Variant %q", r, vals)
	case want != "" && (len(vals) != 1 || vals[0] != want):
		t.Errorf("%s: X-PhotoFinish-Variant %q, want %q", r, vals, want)
	}
}

func checkNoStore(t *testing.T, r *response) {
	t.Helper()
	if cc := r.header.Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("%s: Cache-Control %q, want no-store", r, cc)
	}
}

func checkMediaType(t *testing.T, r *response, want string) {
	t.Helper()
	ct := r.header.Get("Content-Type")
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil || mt != want {
		t.Errorf("%s: Content-Type %q, want %s", r, ct, want)
	}
}

func checkJSON(t *testing.T, r *response) {
	t.Helper()
	checkMediaType(t, r, "application/json")
}

// checkAPIHeaders checks every header the contract requires on an API response.
func checkAPIHeaders(t *testing.T, r *response, v demo.Variant) {
	t.Helper()
	checkArrival(t, r)
	checkVariant(t, r, string(v))
	checkNoStore(t, r)
	checkJSON(t, r)
	if r.proto != 2 {
		t.Errorf("%s: served over HTTP/%d, want HTTP/2", r, r.proto)
	}
}

func countStatus(res []*response, status int) int {
	n := 0
	for _, r := range res {
		if r.status == status {
			n++
		}
	}
	return n
}

// checkBurst validates every response of a burst against the contract.
func checkBurst(t *testing.T, res []*response, v demo.Variant, allowed []int) {
	t.Helper()
	for _, r := range res {
		if !slices.Contains(allowed, r.status) {
			t.Fatalf("%s: status %d not in %v", r, r.status, allowed)
		}
		checkAPIHeaders(t, r, v)
	}
}

func reset(t *testing.T, ts *testServer, v demo.Variant) {
	t.Helper()
	r := ts.do(t, http.MethodPost, api(v, "/reset"), "", "")
	expectStatus(t, r, http.StatusOK)
	checkAPIHeaders(t, r, v)
	if got := str(t, r.object(t), "status"); got != "reset" {
		t.Fatalf("%s: status %q, want reset", r, got)
	}
}

func balance(t *testing.T, ts *testServer, v demo.Variant, auth string) int64 {
	t.Helper()
	r := ts.do(t, http.MethodGet, api(v, "/me"), auth, "")
	expectStatus(t, r, http.StatusOK)
	checkAPIHeaders(t, r, v)
	return num(t, r.object(t), "balance_cents")
}

type twoFAStatus struct {
	attempts, checks, limit int64
}

func twoFA(t *testing.T, ts *testServer, v demo.Variant, auth string) twoFAStatus {
	t.Helper()
	r := ts.do(t, http.MethodGet, api(v, "/2fa/status"), auth, "")
	expectStatus(t, r, http.StatusOK)
	checkAPIHeaders(t, r, v)
	m := r.object(t)
	return twoFAStatus{attempts: num(t, m, "attempts"), checks: num(t, m, "checks"), limit: num(t, m, "limit")}
}

type discount struct {
	code   string
	amount int64
}

type cart struct {
	id, owner      string
	total, payable int64
	discounts      []discount
}

func (c cart) count(code string) int {
	n := 0
	for _, d := range c.discounts {
		if d.code == code {
			n++
		}
	}
	return n
}

// decodeCart decodes cart JSON and checks its internal consistency.
func decodeCart(t *testing.T, r *response) cart {
	t.Helper()
	m := r.object(t)
	raw, ok := m["discounts"].([]any)
	if !ok {
		t.Fatalf("%s: discounts = %#v, want a JSON array", r, m["discounts"])
	}
	c := cart{
		id:      str(t, m, "id"),
		owner:   str(t, m, "owner"),
		total:   num(t, m, "total_cents"),
		payable: num(t, m, "payable_cents"),
	}
	var sum int64
	for _, d := range raw {
		dm, ok := d.(map[string]any)
		if !ok {
			t.Fatalf("%s: discount %#v is not an object", r, d)
		}
		dd := discount{code: str(t, dm, "code"), amount: num(t, dm, "amount_cents")}
		sum += dd.amount
		c.discounts = append(c.discounts, dd)
	}
	if want := max(0, c.total-sum); c.payable != want {
		t.Errorf("%s: payable_cents %d, want max(0, %d - %d) = %d", r, c.payable, c.total, sum, want)
	}
	return c
}

func createCart(t *testing.T, ts *testServer, v demo.Variant, auth string) cart {
	t.Helper()
	r := ts.do(t, http.MethodPost, api(v, "/carts"), auth, "")
	expectStatus(t, r, http.StatusCreated)
	checkAPIHeaders(t, r, v)
	return decodeCart(t, r)
}

func getCart(t *testing.T, ts *testServer, v demo.Variant, auth, id string) cart {
	t.Helper()
	r := ts.do(t, http.MethodGet, api(v, "/carts/"+id), auth, "")
	expectStatus(t, r, http.StatusOK)
	checkAPIHeaders(t, r, v)
	return decodeCart(t, r)
}

func transferBody(to string, amount int64) string {
	return fmt.Sprintf(`{"to":%q,"amount_cents":%d}`, to, amount)
}

func codeBody(code string) string {
	return fmt.Sprintf(`{"code":%q}`, code)
}

// assertSeedState checks the observable seed state of variant v without consuming it.
func assertSeedState(t *testing.T, ts *testServer, v demo.Variant) {
	t.Helper()
	for _, auth := range []string{alice, bob} {
		if got := balance(t, ts, v, auth); got != seedBalance {
			t.Errorf("%s: %s balance %d, want %d", v, auth, got, seedBalance)
		}
		if got := twoFA(t, ts, v, auth); got != (twoFAStatus{0, 0, twoFALimit}) {
			t.Errorf("%s: %s 2fa status %+v, want attempts 0, checks 0, limit 3", v, auth, got)
		}
	}
}

// assertGiftCardsRedeemable consumes both seed gift cards of variant v.
func assertGiftCardsRedeemable(t *testing.T, ts *testServer, v demo.Variant) {
	t.Helper()
	for _, code := range []string{aliceGift, bobGift} {
		r := ts.do(t, http.MethodPost, api(v, "/giftcards/"+code+"/redeem"), bob, "")
		if r.status != http.StatusOK {
			t.Errorf("%s: gift card %s not redeemable: %s", v, code, r)
		}
	}
}

// mutate changes every kind of state in variant v and returns the created cart id.
func mutate(t *testing.T, ts *testServer, v demo.Variant) string {
	t.Helper()
	expectStatus(t, ts.do(t, http.MethodPost, api(v, "/transfers"), alice, transferBody("bob", transferAmt)), http.StatusOK)
	c := createCart(t, ts, v, alice)
	expectStatus(t, ts.do(t, http.MethodPost, api(v, "/carts/"+c.id+"/coupons"), alice, codeBody(coupon)), http.StatusOK)
	expectStatus(t, ts.do(t, http.MethodPost, api(v, "/2fa/verify"), alice, codeBody(wrongCode)), http.StatusUnauthorized)
	expectStatus(t, ts.do(t, http.MethodPost, api(v, "/giftcards/"+aliceGift+"/redeem"), alice, ""), http.StatusOK)
	return c.id
}

func TestNewRejectsWindowAboveCap(t *testing.T) {
	for _, w := range []time.Duration{2*time.Second + time.Nanosecond, 3 * time.Second, time.Hour} {
		s, err := demo.New(demo.Config{Window: w})
		if err == nil {
			s.Close()
			t.Errorf("New(Window=%v) succeeded, want an error (cap is 2s)", w)
		}
	}
	for _, w := range []time.Duration{0, raceWindow, 2 * time.Second} {
		s, err := demo.New(demo.Config{Window: w})
		if err != nil {
			t.Errorf("New(Window=%v): %v", w, err)
			continue
		}
		if err := s.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	}
}

func TestHTTP2OverTLS(t *testing.T) {
	ts := newTestServer(t, demo.Config{})
	for _, path := range []string{"/healthz", "/", api(demo.Vulnerable, "/me"), api(demo.Fixed, "/me")} {
		r := ts.do(t, http.MethodGet, path, alice, "")
		expectStatus(t, r, http.StatusOK)
		if r.proto != 2 || r.alpn != "h2" {
			t.Errorf("%s: HTTP/%d with ALPN %q, want HTTP/2 negotiated as h2", r, r.proto, r.alpn)
		}
	}
}

func TestHealthz(t *testing.T) {
	ts := newTestServer(t, demo.Config{})
	r := ts.do(t, http.MethodGet, "/healthz", "", "")
	expectStatus(t, r, http.StatusOK)
	checkArrival(t, r)
	checkVariant(t, r, "")
	checkNoStore(t, r)
	checkJSON(t, r)
	m := r.object(t)
	if len(m) != 1 || str(t, m, "status") != "ok" {
		t.Errorf("%s: want exactly {\"status\":\"ok\"}", r)
	}
}

func TestIndex(t *testing.T) {
	ts := newTestServer(t, demo.Config{})
	r := ts.do(t, http.MethodGet, "/", "", "")
	expectStatus(t, r, http.StatusOK)
	checkArrival(t, r)
	checkVariant(t, r, "")
	checkNoStore(t, r)
	checkMediaType(t, r, "text/plain")
	body := string(r.body)
	for _, want := range []string{
		"intentionally vulnerable to race conditions - local testing only",
		"vuln", "fixed",
		aliceToken, bobToken,
		"/api/me", "/api/carts", "/api/transfers", "/api/2fa/verify", "/api/2fa/status", "/api/giftcards", "/api/reset",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("index does not mention %q:\n%s", want, body)
		}
	}
}

func TestUnknownRoutes(t *testing.T) {
	ts := newTestServer(t, demo.Config{})
	for _, tc := range []struct{ path, variant string }{
		{"/nope", ""},
		{"/other/api/me", ""},
		{api(demo.Vulnerable, "/nope"), "vuln"},
		{api(demo.Fixed, "/nope"), "fixed"},
		{api(demo.Vulnerable, "/giftcards/"+aliceGift), "vuln"},
		{api(demo.Fixed, "/carts/x/y/z"), "fixed"},
	} {
		r := ts.do(t, http.MethodGet, tc.path, alice, "")
		expectError(t, r, http.StatusNotFound, "")
		checkArrival(t, r)
		checkNoStore(t, r)
		if tc.variant != "" {
			checkVariant(t, r, tc.variant)
		}
	}
}

func TestMethodNotAllowed(t *testing.T) {
	ts := newTestServer(t, demo.Config{})
	for _, tc := range []struct {
		method, path, allow, variant string
	}{
		{http.MethodPost, "/healthz", http.MethodGet, ""},
		{http.MethodPost, "/", http.MethodGet, ""},
		{http.MethodGet, api(demo.Vulnerable, "/reset"), http.MethodPost, "vuln"},
		{http.MethodDelete, api(demo.Vulnerable, "/me"), http.MethodGet, "vuln"},
		{http.MethodGet, api(demo.Vulnerable, "/carts"), http.MethodPost, "vuln"},
		{http.MethodPost, api(demo.Fixed, "/carts/c_00000000"), http.MethodGet, "fixed"},
		{http.MethodGet, api(demo.Fixed, "/carts/c_00000000/coupons"), http.MethodPost, "fixed"},
		{http.MethodGet, api(demo.Fixed, "/transfers"), http.MethodPost, "fixed"},
		{http.MethodPut, api(demo.Fixed, "/2fa/verify"), http.MethodPost, "fixed"},
		{http.MethodPost, api(demo.Vulnerable, "/2fa/status"), http.MethodGet, "vuln"},
		{http.MethodGet, api(demo.Vulnerable, "/giftcards/"+aliceGift+"/redeem"), http.MethodPost, "vuln"},
	} {
		r := ts.do(t, tc.method, tc.path, alice, "")
		expectError(t, r, http.StatusMethodNotAllowed, "")
		checkArrival(t, r)
		checkNoStore(t, r)
		if tc.variant != "" {
			checkVariant(t, r, tc.variant)
		}
		if allow := r.header.Get("Allow"); !strings.Contains(allow, tc.allow) {
			t.Errorf("%s: Allow %q, want it to list %s", r, allow, tc.allow)
		}
	}
}

func TestAuthRequired(t *testing.T) {
	ts := newTestServer(t, demo.Config{})
	badAuth := []string{"", "Bearer ", "Bearer nope", "Bearer " + aliceToken + "x", "Basic ZGVtbzpkZW1v", aliceToken}
	for _, v := range variants {
		t.Run(string(v), func(t *testing.T) {
			c := createCart(t, ts, v, alice)
			routes := []struct{ method, path, body string }{
				{http.MethodGet, api(v, "/me"), ""},
				{http.MethodPost, api(v, "/carts"), ""},
				{http.MethodGet, api(v, "/carts/"+c.id), ""},
				{http.MethodPost, api(v, "/carts/"+c.id+"/coupons"), codeBody(coupon)},
				{http.MethodPost, api(v, "/transfers"), transferBody("bob", transferAmt)},
				{http.MethodPost, api(v, "/2fa/verify"), codeBody(twoFACode)},
				{http.MethodGet, api(v, "/2fa/status"), ""},
				{http.MethodPost, api(v, "/giftcards/"+aliceGift+"/redeem"), ""},
			}
			for _, rt := range routes {
				for _, auth := range badAuth {
					r := ts.do(t, rt.method, rt.path, auth, rt.body)
					expectError(t, r, http.StatusUnauthorized, "unauthorized")
					checkAPIHeaders(t, r, v)
				}
			}
			// Rejected requests must not have touched any state.
			assertSeedState(t, ts, v)
			if got := getCart(t, ts, v, alice, c.id); len(got.discounts) != 0 {
				t.Errorf("unauthenticated coupon apply changed the cart: %+v", got)
			}
			assertGiftCardsRedeemable(t, ts, v)
		})
	}
}

func TestMe(t *testing.T) {
	ts := newTestServer(t, demo.Config{})
	for _, v := range variants {
		for _, tc := range []struct{ auth, user string }{{alice, "alice"}, {bob, "bob"}} {
			r := ts.do(t, http.MethodGet, api(v, "/me"), tc.auth, "")
			expectStatus(t, r, http.StatusOK)
			checkAPIHeaders(t, r, v)
			m := r.object(t)
			if len(m) != 2 || str(t, m, "user") != tc.user || num(t, m, "balance_cents") != seedBalance {
				t.Errorf("%s: want exactly {\"user\":%q,\"balance_cents\":%d}", r, tc.user, seedBalance)
			}
		}
	}
}

var cartID = regexp.MustCompile(`^c_[0-9a-f]{8}$`)

func TestCouponFlow(t *testing.T) {
	ts := newTestServer(t, demo.Config{})
	for _, v := range variants {
		t.Run(string(v), func(t *testing.T) {
			c := createCart(t, ts, v, alice)
			if !cartID.MatchString(c.id) {
				t.Errorf("cart id %q does not match %s", c.id, cartID)
			}
			if c.owner != "alice" || c.total != cartTotal || c.payable != cartTotal || len(c.discounts) != 0 {
				t.Errorf("new cart %+v, want owner alice, total %d, payable %d, no discounts", c, cartTotal, cartTotal)
			}

			r := ts.do(t, http.MethodPost, api(v, "/carts"), alice, "{}")
			expectStatus(t, r, http.StatusCreated)
			if c2 := decodeCart(t, r); c2.id == c.id || !cartID.MatchString(c2.id) {
				t.Errorf("second cart id %q, want a fresh id distinct from %q", c2.id, c.id)
			}

			if got := getCart(t, ts, v, alice, c.id); got.id != c.id || got.owner != "alice" || got.total != cartTotal || len(got.discounts) != 0 {
				t.Errorf("GET cart = %+v, want %+v", got, c)
			}

			// Not found and other owner's cart are indistinguishable.
			for _, tc := range []struct{ method, path, auth, body string }{
				{http.MethodGet, api(v, "/carts/"+c.id), bob, ""},
				{http.MethodGet, api(v, "/carts/c_00000000x"), alice, ""},
				{http.MethodPost, api(v, "/carts/"+c.id+"/coupons"), bob, codeBody(coupon)},
				{http.MethodPost, api(v, "/carts/does-not-exist/coupons"), alice, codeBody(coupon)},
				{http.MethodPost, api(v, "/carts/"+c.id+"/coupons"), alice, codeBody("NOPE10")},
			} {
				r := ts.do(t, tc.method, tc.path, tc.auth, tc.body)
				expectError(t, r, http.StatusNotFound, "")
				checkAPIHeaders(t, r, v)
			}

			r = ts.do(t, http.MethodPost, api(v, "/carts/"+c.id+"/coupons"), alice, codeBody(coupon))
			expectStatus(t, r, http.StatusOK)
			checkAPIHeaders(t, r, v)
			applied := decodeCart(t, r)
			wantDiscounts := []discount{{coupon, welcomeOff}}
			if applied.id != c.id || applied.owner != "alice" || applied.total != cartTotal ||
				applied.payable != cartTotal-welcomeOff || !slices.Equal(applied.discounts, wantDiscounts) {
				t.Errorf("after coupon: %+v, want one %s discount of %d and payable %d", applied, coupon, welcomeOff, cartTotal-welcomeOff)
			}

			r = ts.do(t, http.MethodPost, api(v, "/carts/"+c.id+"/coupons"), alice, codeBody(coupon))
			expectError(t, r, http.StatusConflict, "coupon already applied")
			checkAPIHeaders(t, r, v)

			if got := getCart(t, ts, v, alice, c.id); !slices.Equal(got.discounts, wantDiscounts) || got.payable != cartTotal-welcomeOff {
				t.Errorf("GET cart after duplicate apply = %+v, want exactly one discount", got)
			}

			if bc := createCart(t, ts, v, bob); bc.owner != "bob" {
				t.Errorf("bob's cart owner %q", bc.owner)
			}
		})
	}
}

func TestTransferFlow(t *testing.T) {
	ts := newTestServer(t, demo.Config{})
	for _, v := range variants {
		t.Run(string(v), func(t *testing.T) {
			for _, tc := range []struct {
				body   string
				status int
				msg    string
			}{
				{transferBody("bob", 0), http.StatusBadRequest, ""},
				{transferBody("bob", -1), http.StatusBadRequest, ""},
				{transferBody("bob", 1000001), http.StatusBadRequest, ""},
				{transferBody("alice", 100), http.StatusBadRequest, ""},
				{transferBody("mallory", 100), http.StatusNotFound, ""},
				{transferBody("bob", 1000000), http.StatusConflict, "insufficient funds"},
				{transferBody("bob", seedBalance+1), http.StatusConflict, "insufficient funds"},
			} {
				r := ts.do(t, http.MethodPost, api(v, "/transfers"), alice, tc.body)
				expectError(t, r, tc.status, tc.msg)
				checkAPIHeaders(t, r, v)
			}
			if a, b := balance(t, ts, v, alice), balance(t, ts, v, bob); a != seedBalance || b != seedBalance {
				t.Fatalf("rejected transfers moved money: alice %d, bob %d", a, b)
			}

			r := ts.do(t, http.MethodPost, api(v, "/transfers"), alice, transferBody("bob", transferAmt))
			expectStatus(t, r, http.StatusOK)
			checkAPIHeaders(t, r, v)
			m := r.object(t)
			if str(t, m, "from") != "alice" || str(t, m, "to") != "bob" ||
				num(t, m, "amount_cents") != transferAmt || num(t, m, "balance_cents") != seedBalance-transferAmt {
				t.Errorf("%s: unexpected transfer receipt", r)
			}
			if got := balance(t, ts, v, bob); got != seedBalance+transferAmt {
				t.Errorf("bob balance %d, want %d", got, seedBalance+transferAmt)
			}

			r = ts.do(t, http.MethodPost, api(v, "/transfers"), alice, transferBody("bob", transferAmt))
			expectError(t, r, http.StatusConflict, "insufficient funds")
			checkAPIHeaders(t, r, v)

			// Spending the exact balance is allowed; one more cent is not.
			r = ts.do(t, http.MethodPost, api(v, "/transfers"), alice, transferBody("bob", seedBalance-transferAmt))
			expectStatus(t, r, http.StatusOK)
			if got := num(t, r.object(t), "balance_cents"); got != 0 {
				t.Errorf("%s: balance_cents %d, want 0", r, got)
			}
			expectError(t, ts.do(t, http.MethodPost, api(v, "/transfers"), alice, transferBody("bob", 1)), http.StatusConflict, "insufficient funds")

			r = ts.do(t, http.MethodPost, api(v, "/transfers"), bob, transferBody("alice", 1))
			expectStatus(t, r, http.StatusOK)
			if m := r.object(t); str(t, m, "from") != "bob" || num(t, m, "balance_cents") != 2*seedBalance-1 {
				t.Errorf("%s: unexpected receipt for bob", r)
			}
			if a, b := balance(t, ts, v, alice), balance(t, ts, v, bob); a != 1 || b != 2*seedBalance-1 {
				t.Errorf("final balances alice %d, bob %d, want 1 and %d", a, b, 2*seedBalance-1)
			}
		})
	}
}

func TestTwoFactorFlow(t *testing.T) {
	ts := newTestServer(t, demo.Config{})
	for _, v := range variants {
		t.Run(string(v), func(t *testing.T) {
			verify := func(auth, body string) *response {
				t.Helper()
				r := ts.do(t, http.MethodPost, api(v, "/2fa/verify"), auth, body)
				checkAPIHeaders(t, r, v)
				return r
			}
			if got := twoFA(t, ts, v, alice); got != (twoFAStatus{0, 0, twoFALimit}) {
				t.Fatalf("initial status %+v", got)
			}

			for _, body := range []string{codeBody("12345"), codeBody("1234567"), codeBody("12a456"), codeBody(""), codeBody(" 48291"), `{"code":482913}`} {
				expectError(t, verify(alice, body), http.StatusBadRequest, "")
			}
			if got := twoFA(t, ts, v, alice); got != (twoFAStatus{0, 0, twoFALimit}) {
				t.Fatalf("malformed codes were counted: %+v", got)
			}

			r := verify(alice, codeBody(twoFACode))
			expectStatus(t, r, http.StatusOK)
			if got := str(t, r.object(t), "status"); got != "verified" {
				t.Errorf("%s: status %q, want verified", r, got)
			}
			if got := twoFA(t, ts, v, alice); got != (twoFAStatus{1, 1, twoFALimit}) {
				t.Errorf("after success: %+v, want attempts 1, checks 1", got)
			}

			for want := int64(2); want <= twoFALimit; want++ {
				m := expectError(t, verify(alice, codeBody(wrongCode)), http.StatusUnauthorized, "invalid code")
				if got := num(t, m, "attempts"); got != want {
					t.Errorf("attempts %d, want %d", got, want)
				}
			}
			expectError(t, verify(alice, codeBody(wrongCode)), http.StatusTooManyRequests, "too many attempts")
			expectError(t, verify(alice, codeBody(twoFACode)), http.StatusTooManyRequests, "too many attempts")
			if got := twoFA(t, ts, v, alice); got != (twoFAStatus{twoFALimit, twoFALimit, twoFALimit}) {
				t.Errorf("locked status %+v, want attempts 3, checks 3, limit 3", got)
			}

			// Counters are per user.
			if got := twoFA(t, ts, v, bob); got != (twoFAStatus{0, 0, twoFALimit}) {
				t.Errorf("bob status %+v, want untouched", got)
			}
			m := expectError(t, verify(bob, codeBody(wrongCode)), http.StatusUnauthorized, "invalid code")
			if got := num(t, m, "attempts"); got != 1 {
				t.Errorf("bob attempts %d, want 1", got)
			}
		})
	}
}

func TestGiftCardFlow(t *testing.T) {
	ts := newTestServer(t, demo.Config{})
	for _, v := range variants {
		t.Run(string(v), func(t *testing.T) {
			redeem := func(auth, code string) *response {
				t.Helper()
				r := ts.do(t, http.MethodPost, api(v, "/giftcards/"+code+"/redeem"), auth, "")
				checkAPIHeaders(t, r, v)
				return r
			}
			r := redeem(alice, aliceGift)
			expectStatus(t, r, http.StatusOK)
			m := r.object(t)
			if str(t, m, "code") != aliceGift || num(t, m, "credited_cents") != giftValue || num(t, m, "balance_cents") != seedBalance+giftValue {
				t.Errorf("%s: unexpected redeem receipt", r)
			}
			expectError(t, redeem(alice, aliceGift), http.StatusConflict, "gift card already redeemed")
			expectError(t, redeem(bob, aliceGift), http.StatusConflict, "gift card already redeemed")
			expectError(t, redeem(alice, "GIFT-NOPE-00"), http.StatusNotFound, "")

			// Any authenticated user may redeem any card.
			r = redeem(alice, bobGift)
			expectStatus(t, r, http.StatusOK)
			if got := num(t, r.object(t), "balance_cents"); got != seedBalance+2*giftValue {
				t.Errorf("%s: balance_cents %d, want %d", r, got, seedBalance+2*giftValue)
			}
			if a, b := balance(t, ts, v, alice), balance(t, ts, v, bob); a != seedBalance+2*giftValue || b != seedBalance {
				t.Errorf("balances alice %d, bob %d", a, b)
			}
		})
	}
}

func TestMalformedBodies(t *testing.T) {
	ts := newTestServer(t, demo.Config{})
	for _, v := range variants {
		t.Run(string(v), func(t *testing.T) {
			c := createCart(t, ts, v, alice)
			coupons := api(v, "/carts/"+c.id+"/coupons")
			for _, tc := range []struct{ path, body string }{
				{api(v, "/transfers"), ""},
				{api(v, "/transfers"), "{"},
				{api(v, "/transfers"), "not json"},
				{api(v, "/transfers"), "[]"},
				{api(v, "/transfers"), `{"to":"bob","amount_cents":"6000"}`},
				{api(v, "/transfers"), `{"to":"bob","amount_cents":60.5}`},
				{api(v, "/transfers"), `{"to":"bob","amount_cents":6000,"memo":"x"}`},
				{coupons, "{"},
				{coupons, `{"code":10}`},
				{coupons, `{"code":"WELCOME10","extra":true}`},
				{api(v, "/2fa/verify"), "{"},
				{api(v, "/2fa/verify"), `{"code":"482913","user":"bob"}`},
			} {
				r := ts.do(t, http.MethodPost, tc.path, alice, tc.body)
				expectError(t, r, http.StatusBadRequest, "")
				checkAPIHeaders(t, r, v)
			}
			assertSeedState(t, ts, v)
			if got := getCart(t, ts, v, alice, c.id); len(got.discounts) != 0 {
				t.Errorf("malformed coupon request changed the cart: %+v", got)
			}
		})
	}
}

func TestBodyTooLarge(t *testing.T) {
	ts := newTestServer(t, demo.Config{})
	pad := strings.Repeat("a", 70<<10)
	for _, v := range variants {
		t.Run(string(v), func(t *testing.T) {
			c := createCart(t, ts, v, alice)
			for _, tc := range []struct{ path, body string }{
				{api(v, "/transfers"), `{"to":"` + pad + `","amount_cents":1}`},
				{api(v, "/carts/"+c.id+"/coupons"), codeBody(pad)},
				{api(v, "/2fa/verify"), codeBody(pad)},
			} {
				r := ts.do(t, http.MethodPost, tc.path, alice, tc.body)
				expectError(t, r, http.StatusRequestEntityTooLarge, "body too large")
				checkAPIHeaders(t, r, v)
			}
			assertSeedState(t, ts, v)

			// A body comfortably under 64 KiB is accepted.
			body := strings.Repeat(" ", 60<<10) + transferBody("bob", 1)
			r := ts.do(t, http.MethodPost, api(v, "/transfers"), alice, body)
			expectStatus(t, r, http.StatusOK)
		})
	}
}

func TestResetEndpoint(t *testing.T) {
	ts := newTestServer(t, demo.Config{})
	for _, v := range variants {
		t.Run(string(v), func(t *testing.T) {
			id := mutate(t, ts, v)
			mutate(t, ts, other(v))

			reset(t, ts, v) // no Authorization header
			assertSeedState(t, ts, v)
			r := ts.do(t, http.MethodGet, api(v, "/carts/"+id), alice, "")
			expectError(t, r, http.StatusNotFound, "")
			assertGiftCardsRedeemable(t, ts, v)

			// The other variant keeps its own state.
			if got := balance(t, ts, other(v), alice); got != seedBalance-transferAmt+giftValue {
				t.Errorf("reset of %s changed %s: alice balance %d", v, other(v), got)
			}
			reset(t, ts, v)
			reset(t, ts, other(v))
		})
	}
}

func TestShopReset(t *testing.T) {
	ts := newTestServer(t, demo.Config{})
	ids := map[demo.Variant]string{}
	for _, v := range variants {
		ids[v] = mutate(t, ts, v)
	}
	if err := ts.shop.Reset(); err != nil {
		t.Fatalf("Shop.Reset: %v", err)
	}
	for _, v := range variants {
		assertSeedState(t, ts, v)
		expectError(t, ts.do(t, http.MethodGet, api(v, "/carts/"+ids[v]), alice, ""), http.StatusNotFound, "")
		assertGiftCardsRedeemable(t, ts, v)
	}
}

func TestVariantsAreIndependent(t *testing.T) {
	ts := newTestServer(t, demo.Config{})
	id := mutate(t, ts, demo.Vulnerable)
	for i := 0; i < twoFALimit; i++ {
		ts.do(t, http.MethodPost, api(demo.Vulnerable, "/2fa/verify"), alice, codeBody(wrongCode))
	}
	if got := twoFA(t, ts, demo.Vulnerable, alice); got.attempts != twoFALimit {
		t.Fatalf("vuln 2fa not locked: %+v", got)
	}
	assertSeedState(t, ts, demo.Fixed)
	expectError(t, ts.do(t, http.MethodGet, api(demo.Fixed, "/carts/"+id), alice, ""), http.StatusNotFound, "")
	assertGiftCardsRedeemable(t, ts, demo.Fixed)
}

func TestInternalErrorsDoNotLeak(t *testing.T) {
	shop, err := demo.New(demo.Config{})
	if err != nil {
		t.Fatalf("demo.New: %v", err)
	}
	srv := httptest.NewUnstartedServer(shop.Handler())
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	ts := &testServer{shop: shop, srv: srv, client: srv.Client()}
	if err := shop.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	for _, v := range variants {
		r := ts.do(t, http.MethodPost, api(v, "/reset"), "", "")
		expectError(t, r, http.StatusInternalServerError, "internal error")
		checkAPIHeaders(t, r, v)
		if strings.Contains(strings.ToLower(string(r.body)), "sql") {
			t.Errorf("%s: database detail leaked to the client", r)
		}
	}
}

// syncBuffer is an io.Writer safe for concurrent use.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) lines() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return strings.Split(strings.TrimSpace(b.buf.String()), "\n")
}

func TestRequestLogging(t *testing.T) {
	var buf syncBuffer
	ts := newTestServer(t, demo.Config{Logger: log.New(&buf, "", 0)})
	ts.do(t, http.MethodGet, api(demo.Vulnerable, "/me"), alice, "")
	ts.do(t, http.MethodGet, api(demo.Fixed, "/me"), "", "")

	find := func(lines []string, parts ...string) int {
		n := 0
		for _, l := range lines {
			ok := true
			for _, p := range parts {
				ok = ok && strings.Contains(l, p)
			}
			if ok {
				n++
			}
		}
		return n
	}
	// Close blocks until every outstanding request has completed, so all log
	// lines are written by the time it returns, however the shop emits them.
	ts.srv.Close()
	lines := buf.lines()
	if n := find(lines, "GET", "/vuln/api/me", "vuln", "200"); n != 1 {
		t.Errorf("want exactly one log line with method, path, variant and status for /vuln/api/me, got %d:\n%s", n, strings.Join(lines, "\n"))
	}
	if n := find(lines, "GET", "/fixed/api/me", "fixed", "401"); n != 1 {
		t.Errorf("want exactly one log line for the rejected /fixed/api/me request, got %d:\n%s", n, strings.Join(lines, "\n"))
	}
	for _, l := range lines {
		if !durField.MatchString(l) {
			t.Errorf("log line %q has no dur=<duration> field", l)
		}
	}
}

// durField matches the request duration in an access log line.
var durField = regexp.MustCompile(` dur=[0-9.]+(ns|µs|ms|s)$`)

// TestLogLinesCannotBeForged sends paths whose percent-encoding decodes to a
// line break or a terminal escape and expects exactly one, still encoded,
// log line per request.
func TestLogLinesCannotBeForged(t *testing.T) {
	var buf syncBuffer
	ts := newTestServer(t, demo.Config{Logger: log.New(&buf, "", 0)})
	paths := []string{
		"/vuln/api/me%0Afake-line%20GET%20/fixed/api/me%20variant=fixed%20status=200",
		"/vuln/api/carts/x%0D%0Afake",
		"/fixed/api/carts/%1B[2J%1B[31mred",
	}
	for _, p := range paths {
		ts.do(t, http.MethodGet, p, alice, "")
	}
	ts.srv.Close()
	lines := buf.lines()
	if len(lines) != len(paths) {
		t.Fatalf("%d requests produced %d log lines:\n%s", len(paths), len(lines), strings.Join(lines, "\n"))
	}
	for _, l := range lines {
		if strings.ContainsAny(l, "\r\x1b") || strings.HasPrefix(l, "fake") {
			t.Errorf("log line %q carries a decoded control character", l)
		}
		if !strings.Contains(l, "%0A") && !strings.Contains(l, "%0D") && !strings.Contains(l, "%1B") {
			t.Errorf("log line %q lost the percent-encoding of the path", l)
		}
	}
}

// TestNonCanonicalPathsAreNotRedirected checks that dot segments and repeated
// slashes get a JSON 404 instead of a redirect, which could lead into the
// other variant and replay a POST there.
func TestNonCanonicalPathsAreNotRedirected(t *testing.T) {
	ts := newTestServer(t, demo.Config{})
	mutate(t, ts, demo.Vulnerable)
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/fixed/../vuln/api/me"},
		{http.MethodPost, "/fixed/../vuln/api/reset"},
		{http.MethodPost, "/fixed/./api/reset"},
		{http.MethodGet, "/vuln//api/me"},
		{http.MethodGet, "//vuln/api/me"},
		{http.MethodPost, "/vuln/api/../../vuln/api/reset"},
	} {
		r := ts.do(t, tc.method, tc.path, alice, "")
		expectError(t, r, http.StatusNotFound, "not found")
		checkArrival(t, r)
		checkNoStore(t, r)
		checkVariant(t, r, "")
		if loc := r.header.Get("Location"); loc != "" {
			t.Errorf("%s: Location %q, want no redirect", r, loc)
		}
	}
	// None of the POSTs reached /vuln/api/reset.
	if want, got := int64(seedBalance-transferAmt+giftValue), balance(t, ts, demo.Vulnerable, alice); got != want {
		t.Errorf("/vuln alice balance %d after the non-canonical resets, want %d (state untouched)", got, want)
	}
}

// raceScenario describes one check-then-act scenario attacked by a burst.
type raceScenario struct {
	name string
	// prepare runs on a freshly reset variant before each burst and returns
	// scenario state such as a cart id.
	prepare func(t *testing.T, ts *testServer, v demo.Variant) string
	// request describes the i-th request of a burst.
	request func(v demo.Variant, state string, i int) (method, path, auth, body string)
	// first is the status of a single request on fresh state.
	first int
	// allowed lists every status a burst response may have.
	allowed []int
	// violation inspects the state after a burst and describes how the
	// business invariant was broken, or returns "" if it holds.
	violation func(t *testing.T, ts *testServer, v demo.Variant, state string, res []*response) string
	// exact asserts the precise outcome an atomic implementation must produce.
	exact func(t *testing.T, ts *testServer, v demo.Variant, state string, res []*response)
}

func raceScenarios() []raceScenario {
	noState := func(*testing.T, *testServer, demo.Variant) string { return "" }
	return []raceScenario{
		{
			name: "coupon",
			prepare: func(t *testing.T, ts *testServer, v demo.Variant) string {
				return createCart(t, ts, v, alice).id
			},
			request: func(v demo.Variant, id string, _ int) (string, string, string, string) {
				return http.MethodPost, api(v, "/carts/"+id+"/coupons"), alice, codeBody(coupon)
			},
			first:   http.StatusOK,
			allowed: []int{http.StatusOK, http.StatusConflict},
			violation: func(t *testing.T, ts *testServer, v demo.Variant, id string, res []*response) string {
				c := getCart(t, ts, v, alice, id)
				if n := c.count(coupon); n > 1 || countStatus(res, http.StatusOK) > 1 {
					return fmt.Sprintf("cart %s carries %d %s discounts (%d requests got 200), payable %d",
						id, n, coupon, countStatus(res, http.StatusOK), c.payable)
				}
				return ""
			},
			exact: func(t *testing.T, ts *testServer, v demo.Variant, id string, res []*response) {
				if ok, conflict := countStatus(res, http.StatusOK), countStatus(res, http.StatusConflict); ok != 1 || conflict != burstSize-1 {
					t.Errorf("got %d x 200 and %d x 409, want 1 and %d", ok, conflict, burstSize-1)
				}
				for _, r := range res {
					if r.status == http.StatusConflict {
						expectError(t, r, http.StatusConflict, "coupon already applied")
					}
				}
				if c := getCart(t, ts, v, alice, id); len(c.discounts) != 1 || c.payable != cartTotal-welcomeOff {
					t.Errorf("cart after burst %+v, want one discount and payable %d", c, cartTotal-welcomeOff)
				}
			},
		},
		{
			name:    "transfer",
			prepare: noState,
			request: func(v demo.Variant, _ string, _ int) (string, string, string, string) {
				return http.MethodPost, api(v, "/transfers"), alice, transferBody("bob", transferAmt)
			},
			first:   http.StatusOK,
			allowed: []int{http.StatusOK, http.StatusConflict},
			violation: func(t *testing.T, ts *testServer, v demo.Variant, _ string, res []*response) string {
				a, b := balance(t, ts, v, alice), balance(t, ts, v, bob)
				if a < 0 || b < 0 || a+b != 2*seedBalance {
					return fmt.Sprintf("balances alice %d, bob %d (sum %d, want >= 0 each and sum %d); %d transfers of %d accepted",
						a, b, a+b, 2*seedBalance, countStatus(res, http.StatusOK), transferAmt)
				}
				return ""
			},
			exact: func(t *testing.T, ts *testServer, v demo.Variant, _ string, res []*response) {
				if ok, conflict := countStatus(res, http.StatusOK), countStatus(res, http.StatusConflict); ok != 1 || conflict != burstSize-1 {
					t.Errorf("got %d x 200 and %d x 409, want 1 and %d", ok, conflict, burstSize-1)
				}
				for _, r := range res {
					switch r.status {
					case http.StatusOK:
						m := r.object(t)
						if len(m) != 4 || str(t, m, "from") != "alice" || str(t, m, "to") != "bob" ||
							num(t, m, "amount_cents") != transferAmt || num(t, m, "balance_cents") != seedBalance-transferAmt {
							t.Errorf("%s: want receipt from alice to bob, amount %d, balance %d",
								r, transferAmt, seedBalance-transferAmt)
						}
					case http.StatusConflict:
						expectError(t, r, http.StatusConflict, "insufficient funds")
					}
				}
				if a, b := balance(t, ts, v, alice), balance(t, ts, v, bob); a != seedBalance-transferAmt || b != seedBalance+transferAmt {
					t.Errorf("balances alice %d, bob %d, want %d and %d", a, b, seedBalance-transferAmt, seedBalance+transferAmt)
				}
			},
		},
		{
			name:    "2fa",
			prepare: noState,
			request: func(v demo.Variant, _ string, _ int) (string, string, string, string) {
				return http.MethodPost, api(v, "/2fa/verify"), alice, codeBody(wrongCode)
			},
			first:   http.StatusUnauthorized,
			allowed: []int{http.StatusUnauthorized, http.StatusTooManyRequests},
			violation: func(t *testing.T, ts *testServer, v demo.Variant, _ string, res []*response) string {
				for _, r := range res {
					if r.status == http.StatusUnauthorized {
						expectError(t, r, http.StatusUnauthorized, "invalid code")
					}
				}
				if s := twoFA(t, ts, v, alice); s.checks > twoFALimit {
					return fmt.Sprintf("%d codes were checked against a limit of %d (attempts %d, %d responses said invalid code)",
						s.checks, twoFALimit, s.attempts, countStatus(res, http.StatusUnauthorized))
				}
				return ""
			},
			exact: func(t *testing.T, ts *testServer, v demo.Variant, _ string, res []*response) {
				if bad, locked := countStatus(res, http.StatusUnauthorized), countStatus(res, http.StatusTooManyRequests); bad != twoFALimit || locked != burstSize-twoFALimit {
					t.Errorf("got %d x 401 and %d x 429, want %d and %d", bad, locked, twoFALimit, burstSize-twoFALimit)
				}
				// Each accepted guess used its own attempt, so the counters the
				// 401 responses report are exactly 1, 2 and 3 in some order.
				var attempts []int64
				for _, r := range res {
					switch r.status {
					case http.StatusUnauthorized:
						m := expectError(t, r, http.StatusUnauthorized, "invalid code")
						attempts = append(attempts, num(t, m, "attempts"))
					case http.StatusTooManyRequests:
						expectError(t, r, http.StatusTooManyRequests, "too many attempts")
					}
				}
				slices.Sort(attempts)
				if want := []int64{1, 2, twoFALimit}; !slices.Equal(attempts, want) {
					t.Errorf("attempts reported by the 401 responses %v, want %v", attempts, want)
				}
				if s := twoFA(t, ts, v, alice); s != (twoFAStatus{twoFALimit, twoFALimit, twoFALimit}) {
					t.Errorf("status after burst %+v, want attempts 3, checks 3, limit 3", s)
				}
			},
		},
		{
			name:    "giftcard",
			prepare: noState,
			request: func(v demo.Variant, _ string, i int) (string, string, string, string) {
				auth := alice
				if i%2 == 1 {
					auth = bob
				}
				return http.MethodPost, api(v, "/giftcards/"+aliceGift+"/redeem"), auth, ""
			},
			first:   http.StatusOK,
			allowed: []int{http.StatusOK, http.StatusConflict},
			violation: func(t *testing.T, ts *testServer, v demo.Variant, _ string, res []*response) string {
				sum := balance(t, ts, v, alice) + balance(t, ts, v, bob)
				if credited := sum - 2*seedBalance; credited > giftValue || countStatus(res, http.StatusOK) > 1 {
					return fmt.Sprintf("gift card worth %d credited %d in total (%d redemptions accepted)",
						giftValue, credited, countStatus(res, http.StatusOK))
				}
				return ""
			},
			exact: func(t *testing.T, ts *testServer, v demo.Variant, _ string, res []*response) {
				if ok, conflict := countStatus(res, http.StatusOK), countStatus(res, http.StatusConflict); ok != 1 || conflict != burstSize-1 {
					t.Errorf("got %d x 200 and %d x 409, want 1 and %d", ok, conflict, burstSize-1)
				}
				for _, r := range res {
					switch r.status {
					case http.StatusOK:
						// Both redeemers start with the seed balance.
						m := r.object(t)
						if len(m) != 3 || str(t, m, "code") != aliceGift || num(t, m, "credited_cents") != giftValue ||
							num(t, m, "balance_cents") != seedBalance+giftValue {
							t.Errorf("%s: want receipt for %s crediting %d with balance %d",
								r, aliceGift, giftValue, seedBalance+giftValue)
						}
					case http.StatusConflict:
						expectError(t, r, http.StatusConflict, "gift card already redeemed")
					}
				}
				if sum := balance(t, ts, v, alice) + balance(t, ts, v, bob); sum != 2*seedBalance+giftValue {
					t.Errorf("total balance %d, want %d", sum, 2*seedBalance+giftValue)
				}
			},
		},
	}
}

func runBurst(t *testing.T, ts *testServer, v demo.Variant, sc raceScenario) (string, []*response) {
	t.Helper()
	reset(t, ts, v)
	state := sc.prepare(t, ts, v)
	res := ts.burst(t, burstSize, func(i int) (string, string, string, string) {
		return sc.request(v, state, i)
	})
	checkBurst(t, res, v, sc.allowed)
	return state, res
}

func TestRaceVulnerableViolatesInvariant(t *testing.T) {
	ts := newTestServer(t, demo.Config{Window: vulnRaceWindow})
	for _, sc := range raceScenarios() {
		t.Run(sc.name, func(t *testing.T) {
			for attempt := 1; attempt <= vulnAttempts; attempt++ {
				state, res := runBurst(t, ts, demo.Vulnerable, sc)
				if msg := sc.violation(t, ts, demo.Vulnerable, state, res); msg != "" {
					t.Logf("burst %d broke the invariant as intended: %s", attempt, msg)
					return
				}
				t.Logf("burst %d of %d held the invariant; the requests did not overlap within the window", attempt, vulnAttempts)
			}
			t.Fatalf("invariant held in %d bursts of %d requests with Window=%v; /vuln must lose the race",
				vulnAttempts, burstSize, vulnRaceWindow)
		})
	}
}

func TestRaceFixedAlwaysHolds(t *testing.T) {
	ts := newTestServer(t, demo.Config{Window: raceWindow})
	for _, sc := range raceScenarios() {
		t.Run(sc.name, func(t *testing.T) {
			for round := 1; round <= fixedRounds; round++ {
				state, res := runBurst(t, ts, demo.Fixed, sc)
				if msg := sc.violation(t, ts, demo.Fixed, state, res); msg != "" {
					t.Fatalf("round %d: invariant broken on /fixed: %s", round, msg)
				}
				sc.exact(t, ts, demo.Fixed, state, res)
				if t.Failed() {
					t.Fatalf("round %d failed", round)
				}
			}
		})
	}
}

func TestVulnerableHandlersPauseForWindow(t *testing.T) {
	ts := newTestServer(t, demo.Config{Window: raceWindow})
	for _, sc := range raceScenarios() {
		t.Run(sc.name, func(t *testing.T) {
			reset(t, ts, demo.Vulnerable)
			state := sc.prepare(t, ts, demo.Vulnerable)
			method, path, auth, body := sc.request(demo.Vulnerable, state, 0)
			r := ts.do(t, method, path, auth, body)
			expectStatus(t, r, sc.first)
			checkAPIHeaders(t, r, demo.Vulnerable)
			if elapsed := r.received.Sub(r.sent); elapsed < raceWindow {
				t.Errorf("%s took %v, want at least the %v window", r, elapsed, raceWindow)
			}
			// The arrival stamp is taken before the pause, not when the response is written.
			arrival := checkArrival(t, r)
			if gap := time.Duration(r.received.UnixNano() - arrival); gap < raceWindow-clockSlack {
				t.Errorf("X-Arrival-Ns is only %v before the response arrived; want about %v or more", gap, raceWindow)
			}
		})
	}
}

// TestFixedHandlersHaveNoWindow is the black-box check that the window does
// not slow down /fixed. Wall-clock latency includes scheduling, so a request
// counts as paused only if it takes the full maximum window in every one of
// fixedLatencyAttempts tries. TestWindowOnlyInVuln in internal_test.go proves
// the same structurally.
func TestFixedHandlersHaveNoWindow(t *testing.T) {
	const (
		window               = demo.MaxWindow
		fixedLatencyAttempts = 3
	)
	ts := newTestServer(t, demo.Config{Window: window})
	for _, sc := range raceScenarios() {
		t.Run(sc.name, func(t *testing.T) {
			var slowest *response
			for range fixedLatencyAttempts {
				reset(t, ts, demo.Fixed)
				state := sc.prepare(t, ts, demo.Fixed)
				method, path, auth, body := sc.request(demo.Fixed, state, 0)
				r := ts.do(t, method, path, auth, body)
				expectStatus(t, r, sc.first)
				checkAPIHeaders(t, r, demo.Fixed)
				if r.received.Sub(r.sent) < window {
					return
				}
				slowest = r
			}
			t.Errorf("%s took at least the %v window in %d tries; the window must apply only to /vuln",
				slowest, window, fixedLatencyAttempts)
		})
	}
}

func TestValidateAddr(t *testing.T) {
	loopback := []string{
		"127.0.0.1:8443",
		"127.0.0.1:0",
		"127.10.20.30:8443",
		"[::1]:8443",
		"localhost:8443",
	}
	exposed := []string{
		"0.0.0.0:8443",
		":8443",
		"[::]:8443",
		"192.168.1.10:8443",
		"10.0.0.1:443",
		"128.0.0.1:8443",
		"[2001:db8::1]:8443",
		"example.com:443",
		"localhost.example.test:8443",
	}
	for _, addr := range loopback {
		if err := demo.ValidateAddr(addr, false); err != nil {
			t.Errorf("ValidateAddr(%q, false) = %v, want nil", addr, err)
		}
		if err := demo.ValidateAddr(addr, true); err != nil {
			t.Errorf("ValidateAddr(%q, true) = %v, want nil", addr, err)
		}
	}
	for _, addr := range exposed {
		if err := demo.ValidateAddr(addr, false); err == nil {
			t.Errorf("ValidateAddr(%q, false) = nil, want an error", addr)
		}
		if err := demo.ValidateAddr(addr, true); err != nil {
			t.Errorf("ValidateAddr(%q, true) = %v, want nil", addr, err)
		}
	}
	if err := demo.ValidateAddr("not an address", false); err == nil {
		t.Error("ValidateAddr of a malformed address = nil, want an error")
	}
}

// fingerprint formats the SHA-256 of der as colon-separated hex.
func fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02x", b)
	}
	return strings.Join(parts, ":")
}

var fingerprintFormat = regexp.MustCompile(`^([0-9A-Fa-f]{2}:){31}[0-9A-Fa-f]{2}$`)

func TestServe(t *testing.T) {
	shop, err := demo.New(demo.Config{})
	if err != nil {
		t.Fatalf("demo.New: %v", err)
	}
	defer shop.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type readyInfo struct{ addr, fp string }
	readyCh := make(chan readyInfo, 4)
	errCh := make(chan error, 1)
	go func() {
		errCh <- demo.Serve(ctx, "127.0.0.1:0", shop, func(addr, fp string) { readyCh <- readyInfo{addr, fp} })
	}()

	var info readyInfo
	select {
	case info = <-readyCh:
	case err := <-errCh:
		t.Fatalf("Serve returned before ready: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("ready was not called within 10s")
	}
	host, port, err := net.SplitHostPort(info.addr)
	if err != nil || host != "127.0.0.1" || port == "0" || port == "" {
		t.Fatalf("ready addr %q, want the bound 127.0.0.1:<port>", info.addr)
	}
	if !fingerprintFormat.MatchString(info.fp) {
		t.Errorf("fingerprint %q is not colon-separated SHA-256 hex", info.fp)
	}

	var (
		mu   sync.Mutex
		leaf *x509.Certificate
	)
	newClient := func(h2 bool) *http.Client {
		var protos http.Protocols
		protos.SetHTTP1(!h2)
		protos.SetHTTP2(h2)
		tr := &http.Transport{
			Protocols: &protos,
			TLSClientConfig: &tls.Config{
				// The certificate is freshly self-signed; it is pinned by the
				// fingerprint Serve reported instead of a CA chain.
				InsecureSkipVerify: true,
				VerifyConnection: func(cs tls.ConnectionState) error {
					if len(cs.PeerCertificates) == 0 {
						return errors.New("no peer certificate")
					}
					cert := cs.PeerCertificates[0]
					if got := fingerprint(cert.Raw); !strings.EqualFold(got, info.fp) {
						return fmt.Errorf("certificate fingerprint %s, Serve reported %s", got, info.fp)
					}
					mu.Lock()
					leaf = cert
					mu.Unlock()
					return nil
				},
			},
		}
		t.Cleanup(tr.CloseIdleConnections)
		return &http.Client{Transport: tr, Timeout: 10 * time.Second}
	}

	get := func(c *http.Client, path, auth string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, "https://"+info.addr+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp
	}

	h2 := newClient(true)
	resp := get(h2, "/healthz", "")
	if resp.StatusCode != http.StatusOK || resp.ProtoMajor != 2 || resp.TLS == nil || resp.TLS.NegotiatedProtocol != "h2" {
		t.Errorf("GET /healthz over h2: status %d, HTTP/%d", resp.StatusCode, resp.ProtoMajor)
	}
	if resp := get(h2, api(demo.Vulnerable, "/me"), alice); resp.StatusCode != http.StatusOK || resp.Header.Get("X-PhotoFinish-Variant") != "vuln" {
		t.Errorf("GET /vuln/api/me through Serve: status %d", resp.StatusCode)
	}
	if resp := get(newClient(false), "/healthz", ""); resp.StatusCode != http.StatusOK || resp.ProtoMajor != 1 {
		t.Errorf("HTTP/1.1 fallback: status %d, HTTP/%d", resp.StatusCode, resp.ProtoMajor)
	}

	mu.Lock()
	cert := leaf
	mu.Unlock()
	if cert == nil {
		t.Fatal("no certificate captured")
	}
	if pub, ok := cert.PublicKey.(*ecdsa.PublicKey); !ok || pub.Curve != elliptic.P256() {
		t.Errorf("certificate key %T, want ECDSA P-256", cert.PublicKey)
	}
	for _, name := range []string{"localhost", "shop.example.test"} {
		if !slices.Contains(cert.DNSNames, name) {
			t.Errorf("certificate DNS SANs %v lack %q", cert.DNSNames, name)
		}
	}
	for _, ip := range []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")} {
		if !slices.ContainsFunc(cert.IPAddresses, ip.Equal) {
			t.Errorf("certificate IP SANs %v lack %s", cert.IPAddresses, ip)
		}
	}
	now := time.Now()
	if cert.NotBefore.After(now) || cert.NotAfter.Before(now.Add(22*time.Hour)) || cert.NotAfter.After(now.Add(25*time.Hour)) {
		t.Errorf("certificate valid %v - %v, want about 24h from now", cert.NotBefore, cert.NotAfter)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, context.Canceled) {
			t.Errorf("Serve after cancel: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Serve did not return within 10s of cancellation")
	}
	if n := len(readyCh); n != 0 {
		t.Errorf("ready called %d extra times", n)
	}
	if conn, err := net.DialTimeout("tcp", info.addr, 3*time.Second); err == nil {
		conn.Close()
		t.Error("listener still accepts connections after Serve returned")
	}
}

func TestServeReportsListenError(t *testing.T) {
	shop, err := demo.New(demo.Config{})
	if err != nil {
		t.Fatalf("demo.New: %v", err)
	}
	defer shop.Close()
	called := false
	done := make(chan error, 1)
	go func() {
		done <- demo.Serve(context.Background(), "127.0.0.1:99999", shop, func(string, string) { called = true })
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Error("Serve on an invalid port returned nil")
		}
		if called {
			t.Error("ready was called although the listener could not be bound")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Serve on an invalid port did not return")
	}
}
