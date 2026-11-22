// Package engine sends a race: a set of HTTP requests delivered to a server
// as close together as the transport allows, with timing evidence for every
// request.
//
// Three engines are available. The HTTP/2 single-packet engine (H2) pre-sends
// every request except its final frame and then releases all final frames in
// one write. The HTTP/1.1 last-byte engine (H1) opens one connection per
// request, withholds the last byte of each request and writes the last bytes
// in a tight loop. The burst engine (Burst) sends plain concurrent requests
// without synchronization and serves as a baseline. Auto picks H2 when the
// server negotiates it and H1 otherwise.
package engine

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Kind names an engine.
type Kind string

// The engines.
const (
	// H2 is the HTTP/2 single-packet attack.
	H2 Kind = "h2"
	// H1 is the HTTP/1.1 last-byte synchronization.
	H1 Kind = "h1"
	// Burst sends plain concurrent requests without synchronization; it is
	// the baseline the synchronized engines are compared against.
	Burst Kind = "burst"
	// Auto uses H2 if the server negotiates ALPN h2, else H1.
	Auto Kind = "auto"
)

// Defaults applied by Run to zero-valued Options fields.
const (
	// DefaultGate is the pause between pre-send and release.
	DefaultGate = 100 * time.Millisecond
	// DefaultTimeout bounds a whole race, responses included.
	DefaultTimeout = 15 * time.Second
	// DefaultArrivalHeader is the response header carrying the server
	// arrival time in Unix nanoseconds.
	DefaultArrivalHeader = "X-Arrival-Ns"
	// DefaultMaxBody is the number of response body bytes kept per response.
	DefaultMaxBody = 64 << 10
	// MaxHeaderBytes caps the response header block the h1 and h2 engines
	// and Probe accept per response; a larger one fails that response.
	MaxHeaderBytes = 1 << 20
)

// Request is one HTTP request of a race. URL must be absolute (https or http).
type Request struct {
	// Label is free text identifying the request, e.g. "copy 3".
	Label  string
	Method string
	URL    *url.URL
	// Header never includes Host, Content-Length or pseudo headers; the
	// engine sets them.
	Header http.Header
	Body   []byte
}

// Guard enforces scope and budget. Engines call Allow(host) before dialing and
// Spend(n) before sending n requests; any error aborts the race before sending.
type Guard interface {
	// Allow returns an error unless host (as in URL.Host, it may include a
	// port) is in scope.
	Allow(host string) error
	// Spend returns an error unless n more requests fit in the budget.
	Spend(n int) error
}

// AllowAll returns a Guard that allows every host and an unlimited budget.
// It is meant for tests and for callers that enforce scope themselves.
func AllowAll() Guard { return allowAll{} }

type allowAll struct{}

func (allowAll) Allow(string) error { return nil }
func (allowAll) Spend(int) error    { return nil }

// Options configures a race.
type Options struct {
	// Kind selects the engine; "" means Auto.
	Kind Kind
	// Warmup is the number of warm-up requests sent first on the SAME
	// connection(s). Default 0.
	Warmup int
	// WarmupRequest is the warm-up request. Default: GET of the first race
	// request's scheme://host/ ("/").
	WarmupRequest *Request
	// Gate is the pause between pre-send and release (h2, h1). Default 100ms.
	Gate time.Duration
	// Timeout bounds the whole race including responses. Default 15s.
	Timeout time.Duration
	// TLS is the client TLS configuration. nil means default verification;
	// ServerName defaults to the URL host. The engine sets NextProtos.
	TLS *tls.Config
	// ArrivalHeader is the response header holding the server arrival time
	// in Unix ns. Default "X-Arrival-Ns"; "-" disables it.
	ArrivalHeader string
	// MaxBody is the number of response body bytes kept per response.
	// Default 64 KiB; the rest is drained and Result.Truncated is set.
	MaxBody int
	// Guard enforces scope and budget. It is required; use AllowAll in
	// tests.
	Guard Guard
}

// Result is the outcome of one request of a race. Timestamps are Unix
// nanoseconds from clock.UnixNano.
type Result struct {
	// Index is the position of the request in the input slice.
	Index int    `json:"index"`
	Label string `json:"label,omitempty"`
	// Stream is the HTTP/2 stream id (h2 only).
	Stream uint32 `json:"stream,omitempty"`
	// Conn is the connection number; always 0 for h2.
	Conn int `json:"conn"`
	// Proto is "HTTP/2.0" or "HTTP/1.1".
	Proto string `json:"proto"`
	// Status is the response status code, 0 if no response arrived.
	Status int         `json:"status"`
	Header http.Header `json:"header,omitempty"`
	// Body holds at most Options.MaxBody bytes of the response body.
	Body      []byte `json:"body,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
	Err       string `json:"error,omitempty"`
	// PreSentNs is when everything but the withheld part was written.
	PreSentNs int64 `json:"pre_sent_ns"`
	// ReleasedNs is when the withheld part was written (h2: the same for
	// all requests released by one write).
	ReleasedNs int64 `json:"released_ns"`
	// FirstByteNs is when the response headers arrived, 0 if none did.
	FirstByteNs int64 `json:"first_byte_ns"`
	DoneNs      int64 `json:"done_ns"`
	// ServerArrivalNs is parsed from Options.ArrivalHeader when present.
	ServerArrivalNs int64 `json:"server_arrival_ns,omitempty"`
	// EarlyResponse reports that the response arrived before release: the
	// endpoint is static or did not wait for the request body.
	EarlyResponse bool `json:"early_response,omitempty"`
}

// Race is the record of one race.
type Race struct {
	// Kind is the engine actually used (Auto resolved).
	Kind Kind `json:"engine"`
	// Target is scheme://host of the requests.
	Target      string   `json:"target"`
	ALPN        string   `json:"alpn,omitempty"`
	TLSVersion  string   `json:"tls_version,omitempty"`
	Connections int      `json:"connections"`
	Warmup      int      `json:"warmup"`
	Release     Release  `json:"release"`
	Results     []Result `json:"results"`
	// Notes explain anything that deviates from a clean race, e.g.
	// "split into 2 writes: 140 streams exceed one segment".
	Notes      []string `json:"notes,omitempty"`
	StartedNs  int64    `json:"started_ns"`
	FinishedNs int64    `json:"finished_ns"`
}

// Release describes how the withheld parts were written.
type Release struct {
	// Writes is the number of Write calls used for the final frames (h2; 1
	// when they fit in one segment).
	Writes int `json:"writes"`
	// Bytes is the number of plaintext bytes of the final frames (h2) or of
	// last bytes (h1).
	Bytes int `json:"bytes"`
	// SpreadNs is the last-byte write spread across connections (h1), or
	// the time between the first and the last release write (h2; 0 for one
	// write).
	SpreadNs int64 `json:"spread_ns"`
}

// ResponseSpread returns max-min FirstByteNs over the results that received
// a response, or 0 if fewer than two did.
func (r *Race) ResponseSpread() time.Duration {
	var vals []int64
	for _, res := range r.Results {
		if res.Status != 0 && res.FirstByteNs != 0 {
			vals = append(vals, res.FirstByteNs)
		}
	}
	if len(vals) < 2 {
		return 0
	}
	return time.Duration(slices.Max(vals) - slices.Min(vals))
}

// ServerArrivalSpread returns max-min ServerArrivalNs over the results that
// carry one. ok is false if fewer than two results do.
func (r *Race) ServerArrivalSpread() (spread time.Duration, ok bool) {
	var vals []int64
	for _, res := range r.Results {
		if res.ServerArrivalNs != 0 {
			vals = append(vals, res.ServerArrivalNs)
		}
	}
	if len(vals) < 2 {
		return 0, false
	}
	return time.Duration(slices.Max(vals) - slices.Min(vals)), true
}

// ProbeReport is what Probe learns about a target without sending race
// traffic.
type ProbeReport struct {
	URL        string
	ALPN       string
	TLSVersion string
	// HTTP2 reports whether an HTTP/2 connection worked.
	HTTP2 bool
	// Server is the Server response header.
	Server string
	// The peer's HTTP/2 SETTINGS (0 when not sent or no HTTP/2).
	MaxConcurrentStreams uint32
	InitialWindowSize    uint32
	MaxFrameSize         uint32
	// RTTs are the round-trip times of three GET requests to the URL.
	RTTs []time.Duration
	// Statuses are the response status codes of those GET requests.
	Statuses []int
	// ArrivalHeader reports whether responses carry the arrival header.
	ArrivalHeader bool
	// Recommended is the engine to use against this target.
	Recommended Kind
	Notes       []string
}

// Run sends reqs as one race with the engine selected by opts.Kind and
// returns the evidence. All requests must share one scheme and host. An
// error means the race was not sent (or was aborted before release); errors
// of individual requests after release are reported in Result.Err instead.
func Run(ctx context.Context, reqs []Request, opts Options) (*Race, error) {
	if err := validate(reqs, &opts); err != nil {
		return nil, err
	}
	opts = opts.withDefaults()
	switch opts.Kind {
	case H2:
		return runH2(ctx, reqs, opts)
	case H1:
		return runH1(ctx, reqs, opts)
	case Burst:
		return runBurst(ctx, reqs, opts)
	case Auto:
		if reqs[0].URL.Scheme != "https" {
			race, err := runH1(ctx, reqs, opts)
			if race != nil {
				race.Notes = append(race.Notes, "auto: plain http target, used h1")
			}
			return race, err
		}
		race, err := runH2(ctx, reqs, opts)
		if !errors.Is(err, errNoH2) {
			return race, err
		}
		race, err = runH1(ctx, reqs, opts)
		if race != nil {
			race.Notes = append(race.Notes, "auto: server did not negotiate h2, used h1")
		}
		return race, err
	default:
		return nil, fmt.Errorf("unknown engine %q (want h2, h1, burst or auto)", opts.Kind)
	}
}

// validate checks the requests and the options that have no default.
func validate(reqs []Request, opts *Options) error {
	if len(reqs) == 0 {
		return errors.New("no requests to race")
	}
	if opts.Guard == nil {
		return errors.New("options: Guard is required (use engine.AllowAll() if scope is enforced elsewhere)")
	}
	if opts.Warmup < 0 {
		return fmt.Errorf("options: warmup must not be negative, got %d", opts.Warmup)
	}
	first := reqs[0].URL
	for i, r := range reqs {
		if err := checkURL(r.URL); err != nil {
			return fmt.Errorf("request %d: %w", i, err)
		}
		if r.Method == "" {
			return fmt.Errorf("request %d: method is empty", i)
		}
		if r.URL.Scheme != first.Scheme || !strings.EqualFold(r.URL.Host, first.Host) {
			return fmt.Errorf("request %d: %s://%s differs from %s://%s: all requests of a race must share scheme and host",
				i, r.URL.Scheme, r.URL.Host, first.Scheme, first.Host)
		}
	}
	if w := opts.WarmupRequest; w != nil && opts.Warmup > 0 {
		if err := checkURL(w.URL); err != nil {
			return fmt.Errorf("warm-up request: %w", err)
		}
		if w.URL.Scheme != first.Scheme || !strings.EqualFold(w.URL.Host, first.Host) {
			return fmt.Errorf("warm-up request: %s://%s differs from the race target %s://%s",
				w.URL.Scheme, w.URL.Host, first.Scheme, first.Host)
		}
	}
	return nil
}

// checkURL reports whether u is an absolute http or https URL with a host.
func checkURL(u *url.URL) error {
	switch {
	case u == nil:
		return errors.New("URL is nil")
	case u.Scheme != "https" && u.Scheme != "http":
		return fmt.Errorf("URL %q: scheme must be https or http", u.Redacted())
	case u.Host == "":
		return fmt.Errorf("URL %q has no host", u.Redacted())
	}
	return nil
}

// withDefaults returns o with defaults applied to zero-valued fields.
func (o Options) withDefaults() Options {
	if o.Kind == "" {
		o.Kind = Auto
	}
	if o.Gate <= 0 {
		o.Gate = DefaultGate
	}
	if o.Timeout <= 0 {
		o.Timeout = DefaultTimeout
	}
	if o.ArrivalHeader == "" {
		o.ArrivalHeader = DefaultArrivalHeader
	}
	if o.MaxBody <= 0 {
		o.MaxBody = DefaultMaxBody
	}
	return o
}

// warmupRequest returns the warm-up request for a race on reqs.
func (o Options) warmupRequest(reqs []Request) Request {
	if o.WarmupRequest != nil {
		return *o.WarmupRequest
	}
	u := reqs[0].URL
	return Request{
		Label:  "warm-up",
		Method: http.MethodGet,
		URL:    &url.URL{Scheme: u.Scheme, Host: u.Host, Path: "/"},
	}
}

// serverArrival parses the arrival header (name "-" disables it) from h and
// returns 0 if it is absent or not an integer.
func serverArrival(h http.Header, name string) int64 {
	if name == "-" || name == "" {
		return 0
	}
	v, err := strconv.ParseInt(strings.TrimSpace(h.Get(name)), 10, 64)
	if err != nil {
		return 0
	}
	return v
}

// target returns scheme://host of u.
func target(u *url.URL) string {
	return u.Scheme + "://" + u.Host
}

// hostPort returns u.Host with the scheme's default port added if it has
// none.
func hostPort(u *url.URL) string {
	if u.Port() != "" {
		return u.Host
	}
	port := "443"
	if u.Scheme == "http" {
		port = "80"
	}
	return net.JoinHostPort(u.Hostname(), port)
}

// clientTLS returns a copy of base (or a new config) with ServerName set to
// the URL host if empty and NextProtos set to protos.
func clientTLS(base *tls.Config, u *url.URL, protos []string) *tls.Config {
	var cfg *tls.Config
	if base != nil {
		cfg = base.Clone()
	} else {
		cfg = &tls.Config{}
	}
	if cfg.ServerName == "" {
		cfg.ServerName = u.Hostname()
	}
	cfg.NextProtos = protos
	return cfg
}

// tlsVersionName returns "TLS 1.3" style names for a TLS version.
func tlsVersionName(v uint16) string {
	if v == 0 {
		return ""
	}
	return tls.VersionName(v)
}
