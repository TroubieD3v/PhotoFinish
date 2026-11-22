package engine

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/TroubieD3v/photofinish/internal/demo"
)

const h2TestAlice = "Bearer demo-alice"

// h2Shop is the demo shop served by httptest over TLS with HTTP/2, plus a
// TLS configuration that trusts its certificate.
type h2Shop struct {
	srv *httptest.Server
	tls *tls.Config
}

// h2StartShop starts the demo shop with the given race window.
func h2StartShop(t *testing.T, window time.Duration) *h2Shop {
	t.Helper()
	shop, err := demo.New(demo.Config{Window: window})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(shop.Handler())
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(func() {
		srv.Close()
		shop.Close()
	})
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return &h2Shop{srv: srv, tls: &tls.Config{RootCAs: pool}}
}

func (s *h2Shop) url(t *testing.T, path string) *url.URL {
	t.Helper()
	u, err := url.Parse(s.srv.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// call sends a setup or check request with the test server's own client.
func (s *h2Shop) call(t *testing.T, method, path string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, s.srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", h2TestAlice)
	resp, err := s.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, body
}

// h2Cart is the part of a demo cart the tests read.
type h2Cart struct {
	ID        string            `json:"id"`
	Discounts []json.RawMessage `json:"discounts"`
}

func (s *h2Shop) cart(t *testing.T, method, path string, want int) h2Cart {
	t.Helper()
	status, body := s.call(t, method, path)
	if status != want {
		t.Fatalf("%s %s: status %d, want %d: %s", method, path, status, want, body)
	}
	var c h2Cart
	if err := json.Unmarshal(body, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

// couponTrial resets the variant, creates a cart, races copies coupon
// applications with the engine kind and returns the race and the number of
// discounts on the cart afterwards.
func (s *h2Shop) couponTrial(t *testing.T, variant string, kind Kind, copies int) (*Race, int) {
	t.Helper()
	base := "/" + variant + "/api"
	if status, body := s.call(t, http.MethodPost, base+"/reset"); status != http.StatusOK {
		t.Fatalf("reset: status %d: %s", status, body)
	}
	c := s.cart(t, http.MethodPost, base+"/carts", http.StatusCreated)
	u := s.url(t, base+"/carts/"+c.ID+"/coupons")
	reqs := make([]Request, copies)
	for i := range reqs {
		reqs[i] = Request{
			Label:  fmt.Sprintf("copy %d", i+1),
			Method: http.MethodPost,
			URL:    u,
			Header: http.Header{"Authorization": {h2TestAlice}, "Content-Type": {"application/json"}},
			Body:   []byte(`{"code":"WELCOME10"}`),
		}
	}
	race, err := Run(context.Background(), reqs, Options{Kind: kind, TLS: s.tls, Guard: AllowAll()})
	if err != nil {
		t.Fatalf("%s race: %v", kind, err)
	}
	after := s.cart(t, http.MethodGet, base+"/carts/"+c.ID, http.StatusOK)
	return race, len(after.Discounts)
}

// h2CheckRace checks the evidence every h2 race against the demo shop must
// carry.
func h2CheckRace(t *testing.T, race *Race, copies int) {
	t.Helper()
	if race.Kind != H2 || race.ALPN != "h2" || race.Connections != 1 || race.TLSVersion == "" {
		t.Errorf("race: engine %q alpn %q conns %d tls %q", race.Kind, race.ALPN, race.Connections, race.TLSVersion)
	}
	if race.Release.Writes != 1 || race.Release.Bytes != copies*10 || race.Release.SpreadNs != 0 {
		t.Errorf("Release = %+v, want 1 write of %d bytes", race.Release, copies*10)
	}
	if len(race.Results) != copies {
		t.Fatalf("%d results, want %d", len(race.Results), copies)
	}
	// Every response carries its own arrival time. Ties are allowed: the
	// server clock ticks every 100 ns on Windows and handlers of one burst run
	// in parallel, so two copies can share a tick.
	arrivals := map[int64]bool{}
	for i, r := range race.Results {
		if r.Index != i || r.Proto != "HTTP/2.0" || r.Err != "" || r.Conn != 0 {
			t.Errorf("result %d: index %d proto %q err %q conn %d", i, r.Index, r.Proto, r.Err, r.Conn)
		}
		if r.Status != http.StatusOK && r.Status != http.StatusConflict {
			t.Errorf("result %d: status %d: %s", i, r.Status, r.Body)
		}
		if r.Stream != uint32(1+2*i) {
			t.Errorf("result %d: stream %d", i, r.Stream)
		}
		if r.ServerArrivalNs == 0 {
			t.Errorf("result %d: server arrival is missing", i)
		}
		arrivals[r.ServerArrivalNs] = true
		if r.ReleasedNs != race.Results[0].ReleasedNs || r.PreSentNs > r.ReleasedNs || r.FirstByteNs == 0 {
			t.Errorf("result %d: pre %d released %d first byte %d", i, r.PreSentNs, r.ReleasedNs, r.FirstByteNs)
		}
		if r.EarlyResponse {
			t.Errorf("result %d: early response from an endpoint that waits for the body", i)
		}
	}
	if len(arrivals) < 2 {
		t.Errorf("%d distinct server arrival times over %d copies", len(arrivals), copies)
	}
	if _, ok := race.ServerArrivalSpread(); !ok {
		t.Error("no server arrival spread")
	}
	if race.ResponseSpread() <= 0 {
		t.Errorf("response spread %v", race.ResponseSpread())
	}
}

// h2Applied counts the 200 responses of a coupon race.
func h2Applied(race *Race) int {
	n := 0
	for _, r := range race.Results {
		if r.Status == http.StatusOK {
			n++
		}
	}
	return n
}

func TestH2DemoVulnCouponBreaksInvariant(t *testing.T) {
	// With Window=0 the gap between the shop's check and its write is a few
	// microseconds of CPU work with no blocking call in between. With a single
	// P the in-process handlers then run one after another and no engine can
	// interleave them, so the assertion would only measure the scheduler.
	if n := runtime.GOMAXPROCS(0); n < 2 {
		t.Skipf("GOMAXPROCS=%d: the in-process shop needs parallel handlers to race at Window=0", n)
	}
	shop := h2StartShop(t, 0)
	const trials, copies = 30, 20
	h2Broken := 0
	for range trials {
		race, discounts := shop.couponTrial(t, "vuln", H2, copies)
		h2CheckRace(t, race, copies)
		if t.Failed() {
			t.FailNow()
		}
		if applied := h2Applied(race); applied != discounts {
			t.Errorf("%d responses applied the coupon but the cart has %d discounts", applied, discounts)
		}
		if discounts > 1 {
			h2Broken++
		}
	}
	burstBroken := 0
	for range trials {
		_, discounts := shop.couponTrial(t, "vuln", Burst, copies)
		if discounts > 1 {
			burstBroken++
		}
	}
	// The comparison is logged, not asserted: hit rates depend on the
	// machine and the scheduler.
	t.Logf("invariant broken in %d/%d h2 trials and %d/%d burst trials (window 0)", h2Broken, trials, burstBroken, trials)
	if h2Broken == 0 {
		t.Errorf("h2 never broke the invariant in %d trials of %d copies", trials, copies)
	}
}

func TestH2DemoFixedCouponHolds(t *testing.T) {
	shop := h2StartShop(t, 0)
	const trials, copies = 20, 20
	for range trials {
		race, discounts := shop.couponTrial(t, "fixed", H2, copies)
		h2CheckRace(t, race, copies)
		if applied := h2Applied(race); discounts != 1 || applied != 1 {
			t.Fatalf("fixed variant: %d discounts, %d applied responses; want 1 and 1", discounts, applied)
		}
	}
}

func TestH2DemoWarmupAndBodyLimits(t *testing.T) {
	shop := h2StartShop(t, 0)
	u := shop.url(t, "/")
	reqs := []Request{
		{Method: http.MethodGet, URL: u},
		{Method: http.MethodGet, URL: u},
	}
	race, err := Run(context.Background(), reqs, Options{
		Kind: H2, Warmup: 2, Gate: 10 * time.Millisecond, TLS: shop.tls, Guard: AllowAll(),
		MaxBody: 16, ArrivalHeader: "-",
	})
	if err != nil {
		t.Fatal(err)
	}
	if race.Warmup != 2 {
		t.Errorf("Warmup = %d", race.Warmup)
	}
	for i, r := range race.Results {
		if r.Stream != uint32(5+2*i) {
			t.Errorf("result %d: stream %d, want %d after two warm-up streams", i, r.Stream, 5+2*i)
		}
		if r.Status != http.StatusOK || len(r.Body) != 16 || !r.Truncated {
			t.Errorf("result %d: status %d, %d body bytes, truncated %v; want 16 bytes truncated", i, r.Status, len(r.Body), r.Truncated)
		}
		if r.ServerArrivalNs != 0 || r.Header.Get("X-Arrival-Ns") == "" {
			t.Errorf("result %d: arrival %d with the header disabled", i, r.ServerArrivalNs)
		}
	}
	if _, ok := race.ServerArrivalSpread(); ok {
		t.Error("arrival spread reported with the header disabled")
	}
}

func TestH2AutoUsesH2WhenNegotiated(t *testing.T) {
	shop := h2StartShop(t, 0)
	race, err := Run(context.Background(), []Request{{Method: http.MethodGet, URL: shop.url(t, "/healthz")}},
		Options{Kind: Auto, Gate: time.Millisecond, TLS: shop.tls, Guard: AllowAll()})
	if err != nil {
		t.Fatal(err)
	}
	if race.Kind != H2 || race.Results[0].Status != http.StatusOK {
		t.Errorf("auto: engine %q status %d", race.Kind, race.Results[0].Status)
	}
}

func TestH2AutoFallsBackToH1(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, r.Proto)
	}))
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	cfg := &tls.Config{RootCAs: pool}
	u, err := url.Parse(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	reqs := []Request{{Method: http.MethodGet, URL: u}}

	_, err = Run(context.Background(), reqs, Options{Kind: H2, TLS: cfg, Guard: AllowAll()})
	if !errors.Is(err, errNoH2) || !strings.Contains(err.Error(), "server did not negotiate h2") {
		t.Fatalf("h2 against an HTTP/1.1 server: err = %v", err)
	}

	guard := &fakeGuard{}
	race, err := Run(context.Background(), reqs, Options{Kind: Auto, Gate: time.Millisecond, TLS: cfg, Guard: guard})
	if err != nil {
		t.Fatal(err)
	}
	if race.Kind != H1 || race.Results[0].Proto != "HTTP/1.1" || race.Results[0].Status != http.StatusOK {
		t.Errorf("auto fallback: engine %q proto %q status %d", race.Kind, race.Results[0].Proto, race.Results[0].Status)
	}
	noted := false
	for _, n := range race.Notes {
		noted = noted || strings.Contains(n, "did not negotiate h2")
	}
	if !noted {
		t.Errorf("notes %q do not explain the fallback", race.Notes)
	}
	total := 0
	for _, n := range guard.spent {
		total += n
	}
	if total != 1 {
		t.Errorf("auto fallback spent %v, want 1 request in total", guard.spent)
	}
}

func TestH2AutoUsesH1ForPlainHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	race, err := Run(context.Background(), []Request{{Method: http.MethodGet, URL: u}},
		Options{Gate: time.Millisecond, Guard: AllowAll()})
	if err != nil {
		t.Fatal(err)
	}
	if race.Kind != H1 {
		t.Errorf("engine %q, want h1 for plain http", race.Kind)
	}
	if _, err := Run(context.Background(), []Request{{Method: http.MethodGet, URL: u}},
		Options{Kind: H2, Guard: AllowAll()}); err == nil || !strings.Contains(err.Error(), "https") {
		t.Errorf("h2 on plain http: err = %v", err)
	}
}

func TestRunValidatesInput(t *testing.T) {
	a, _ := url.Parse("https://a.example:8443/x")
	b, _ := url.Parse("https://b.example:8443/x")
	ftp, _ := url.Parse("ftp://a.example/x")
	rel := &url.URL{Path: "/x"}
	get := func(u *url.URL) Request { return Request{Method: http.MethodGet, URL: u} }
	cases := []struct {
		name string
		reqs []Request
		opts Options
		want string
	}{
		{"no requests", nil, Options{Guard: AllowAll()}, "no requests"},
		{"no guard", []Request{get(a)}, Options{}, "Guard is required"},
		{"mixed hosts", []Request{get(a), get(b)}, Options{Guard: AllowAll()}, "must share scheme and host"},
		{"bad scheme", []Request{get(ftp)}, Options{Guard: AllowAll()}, "scheme must be https or http"},
		{"relative URL", []Request{get(rel)}, Options{Guard: AllowAll()}, "scheme must be https or http"},
		{"nil URL", []Request{{Method: http.MethodGet}}, Options{Guard: AllowAll()}, "URL is nil"},
		{"no method", []Request{{URL: a}}, Options{Guard: AllowAll()}, "method is empty"},
		{"unknown engine", []Request{get(a)}, Options{Kind: "h3", Guard: AllowAll()}, `unknown engine "h3"`},
		{"negative warmup", []Request{get(a)}, Options{Warmup: -1, Guard: AllowAll()}, "warmup must not be negative"},
		{"warm-up elsewhere", []Request{get(a)}, Options{Warmup: 1, WarmupRequest: &Request{Method: http.MethodGet, URL: b}, Guard: AllowAll()}, "warm-up request"},
		{"bad header", []Request{{Method: http.MethodGet, URL: a, Header: http.Header{"Bad Name": {"x"}}}}, Options{Kind: H2, Guard: AllowAll()}, "invalid header field name"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Run(context.Background(), tc.reqs, tc.opts)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

func TestRaceSpreads(t *testing.T) {
	r := &Race{Results: []Result{
		{Status: 200, FirstByteNs: 1_000, ServerArrivalNs: 500},
		{Status: 409, FirstByteNs: 4_000, ServerArrivalNs: 900},
		{Status: 0, FirstByteNs: 0},                           // no response: ignored
		{Status: 200, FirstByteNs: 2_500, ServerArrivalNs: 0}, // no arrival header
	}}
	if got := r.ResponseSpread(); got != 3_000 {
		t.Errorf("ResponseSpread = %v, want 3µs", got)
	}
	if got, ok := r.ServerArrivalSpread(); !ok || got != 400 {
		t.Errorf("ServerArrivalSpread = %v, %v; want 400ns, true", got, ok)
	}
	one := &Race{Results: []Result{{Status: 200, FirstByteNs: 7, ServerArrivalNs: 7}}}
	if got := one.ResponseSpread(); got != 0 {
		t.Errorf("single result ResponseSpread = %v", got)
	}
	if _, ok := one.ServerArrivalSpread(); ok {
		t.Error("single result ServerArrivalSpread ok")
	}
}

func TestOptionsDefaults(t *testing.T) {
	o := Options{}.withDefaults()
	if o.Kind != Auto || o.Gate != DefaultGate || o.Timeout != DefaultTimeout ||
		o.ArrivalHeader != DefaultArrivalHeader || o.MaxBody != DefaultMaxBody {
		t.Errorf("defaults = %+v", o)
	}
	u, _ := url.Parse("https://shop.example.test:8443/vuln/api/carts?x=1")
	w := o.warmupRequest([]Request{{Method: http.MethodPost, URL: u}})
	if w.Method != http.MethodGet || w.URL.String() != "https://shop.example.test:8443/" {
		t.Errorf("default warm-up = %s %s", w.Method, w.URL)
	}
}
