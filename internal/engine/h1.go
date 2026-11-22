package engine

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http/httpguts"

	"github.com/TroubieD3v/photofinish/internal/clock"
)

// h1ReleaseHook, when set, is called with the race target after every
// connection of an h1 race has pre-sent its request and before the gate
// starts. Tests use it to observe the withheld state on the server side; it
// is never set outside tests. It is atomic because other tests may run h1
// races concurrently.
var h1ReleaseHook atomic.Pointer[func(target string)]

// runH1 sends reqs with HTTP/1.1 last-byte synchronization: one connection
// per request, everything but the final byte written up front, and then the
// final bytes of all connections written back to back after the gate.
//
// Run has validated reqs and applied the Options defaults. runH1 asks
// opts.Guard for the host and for the whole budget (len(reqs) race requests
// plus Warmup warm-up requests on every connection) before dialing, and
// returns an error only when the race cannot start at all; failures of
// single connections are reported in the Err field of their Result.
func runH1(ctx context.Context, reqs []Request, opts Options) (*Race, error) {
	warm := opts.warmupRequest(reqs)
	if err := h1Authorize(opts.Guard, reqs, len(reqs)*(1+opts.Warmup)); err != nil {
		return nil, err
	}

	n := len(reqs)
	wires := make([][]byte, n)
	for i, r := range reqs {
		w, err := h1Wire(r, false)
		if err != nil {
			return nil, fmt.Errorf("request %d: %w", i, err)
		}
		wires[i] = w
	}
	var warmWire []byte
	if opts.Warmup > 0 {
		var err error
		if warmWire, err = h1Wire(warm, true); err != nil {
			return nil, fmt.Errorf("warm-up request: %w", err)
		}
	}

	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	race := &Race{
		Kind:      H1,
		Target:    target(reqs[0].URL),
		Warmup:    opts.Warmup,
		Results:   make([]Result, n),
		StartedNs: clock.UnixNano(),
	}
	for i, r := range reqs {
		race.Results[i] = Result{Index: i, Label: r.Label, Conn: i, Proto: "HTTP/1.1"}
	}

	// Dial every connection before anything is sent, so slow handshakes do
	// not stretch the pre-send phase.
	conns := make([]*h1Conn, n)
	dialErrs := make([]error, n)
	var dials sync.WaitGroup
	for i := range reqs {
		dials.Go(func() {
			conns[i], dialErrs[i] = h1Dial(ctx, reqs[i].URL, opts.TLS, []string{"http/1.1"})
		})
	}
	dials.Wait()
	defer func() {
		for _, c := range conns {
			if c != nil {
				c.conn.Close()
			}
		}
	}()
	stop := context.AfterFunc(ctx, func() {
		for _, c := range conns {
			if c != nil {
				c.conn.Close()
			}
		}
	})
	defer stop()

	var failed []int
	for i, c := range conns {
		if c == nil {
			failed = append(failed, i)
			race.Results[i].Err = "dial: " + dialErrs[i].Error()
			continue
		}
		race.Connections++
		if c.tls != nil && race.TLSVersion == "" {
			race.ALPN = c.tls.NegotiatedProtocol
			race.TLSVersion = tls.VersionName(c.tls.Version)
		}
	}
	if race.Connections == 0 {
		return nil, fmt.Errorf("h1: no connection to %s could be opened: %w", race.Target, dialErrs[0])
	}
	if len(failed) > 0 {
		race.Notes = append(race.Notes, fmt.Sprintf("%d of %d connections could not be opened; first error: %v",
			len(failed), n, dialErrs[failed[0]]))
	}

	// Warm up and pre-send on every connection in parallel, then keep one
	// reader per connection running, so a response that arrives before the
	// release is timestamped as such.
	ready := make([]bool, n)
	var presend, done sync.WaitGroup
	for i, c := range conns {
		if c == nil {
			continue
		}
		presend.Add(1)
		done.Add(1)
		go func() {
			defer done.Done()
			res := &race.Results[i]
			if err := c.warmUp(opts.Warmup, warmWire, warm.Method); err != nil {
				res.Err = h1ErrText("warm-up", h1Cause(ctx, err), opts.Timeout)
				presend.Done()
				return
			}
			c.stamp.first = 0
			wire := wires[i]
			if _, err := c.conn.Write(wire[:len(wire)-1]); err != nil {
				res.Err = h1ErrText("pre-send", h1Cause(ctx, err), opts.Timeout)
				presend.Done()
				return
			}
			res.PreSentNs = clock.UnixNano()
			ready[i] = true
			presend.Done()
			c.readResult(ctx, reqs[i].Method, opts, res)
		}()
	}
	presend.Wait()

	if hook := h1ReleaseHook.Load(); hook != nil {
		(*hook)(race.Target)
	}

	released := make([]int64, n)
	relErrs := make([]error, n)
	gate := time.NewTimer(opts.Gate)
	select {
	case <-ctx.Done():
		gate.Stop()
		for _, c := range conns {
			if c != nil {
				c.conn.Close()
			}
		}
	case <-gate.C:
		// The tight loop: nothing but the final byte and a timestamp per
		// connection.
		for i, c := range conns {
			if !ready[i] {
				continue
			}
			wire := wires[i]
			_, relErrs[i] = c.conn.Write(wire[len(wire)-1:])
			released[i] = clock.UnixNano()
		}
		for i, err := range relErrs {
			if err != nil {
				// The reader cannot get a response on a broken connection;
				// do not let it wait for the timeout.
				conns[i].conn.Close()
			}
		}
	}
	done.Wait()

	var minNs, maxNs int64
	for i := range race.Results {
		res := &race.Results[i]
		if !ready[i] {
			continue
		}
		if released[i] == 0 {
			if res.Status == 0 {
				res.Err = "race aborted before release: " + h1ErrText("", ctx.Err(), opts.Timeout)
			}
			continue
		}
		res.ReleasedNs = released[i]
		if relErrs[i] != nil && res.Status == 0 {
			res.Err = h1ErrText("release", relErrs[i], opts.Timeout)
		}
		res.EarlyResponse = res.FirstByteNs != 0 && res.FirstByteNs < res.ReleasedNs
		race.Release.Writes++
		race.Release.Bytes++
		if minNs == 0 || released[i] < minNs {
			minNs = released[i]
		}
		if released[i] > maxNs {
			maxNs = released[i]
		}
	}
	race.Release.SpreadNs = maxNs - minNs
	race.FinishedNs = clock.UnixNano()
	return race, nil
}

// h1Conn is one connection of an h1 race or of Probe.
type h1Conn struct {
	conn  net.Conn
	tls   *tls.ConnectionState // nil for plain http
	stamp *h1StampReader
	limit *h1LimitReader
	br    *bufio.Reader
}

// h1LimitReader caps the bytes read from the connection while a response
// head is parsed, like net/http's MaxResponseHeaderBytes: http.ReadResponse
// itself reads header lines of any length. It is used by one goroutine at
// a time.
type h1LimitReader struct {
	r   io.Reader
	n   int64 // bytes left; <= 0 makes Read fail
	hit bool  // the limit was reached
}

func (l *h1LimitReader) Read(p []byte) (int, error) {
	if l.n <= 0 {
		l.hit = true
		return 0, errHeaderTooLarge
	}
	if int64(len(p)) > l.n {
		p = p[:l.n]
	}
	n, err := l.r.Read(p)
	l.n -= int64(n)
	return n, err
}

// errHeaderTooLarge reports a response head over MaxHeaderBytes.
var errHeaderTooLarge = fmt.Errorf("response headers exceed %d KiB", MaxHeaderBytes>>10)

// h1StampReader records when the first byte arrives after first was reset
// to 0. It is used by one goroutine at a time.
type h1StampReader struct {
	r     io.Reader
	first int64
}

func (s *h1StampReader) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	if n > 0 && s.first == 0 {
		s.first = clock.UnixNano()
	}
	return n, err
}

// h1Dial opens a TCP connection with TCP_NODELAY to the host of u and, for
// https, completes a TLS handshake offering protos via ALPN. The connection
// deadline is the context deadline.
func h1Dial(ctx context.Context, u *url.URL, base *tls.Config, protos []string) (*h1Conn, error) {
	var d net.Dialer
	raw, err := d.DialContext(ctx, "tcp", hostPort(u))
	if err != nil {
		return nil, err
	}
	if tc, ok := raw.(*net.TCPConn); ok {
		if err := tc.SetNoDelay(true); err != nil {
			raw.Close()
			return nil, fmt.Errorf("set TCP_NODELAY: %w", err)
		}
	}
	if dl, ok := ctx.Deadline(); ok {
		raw.SetDeadline(dl)
	}
	c := &h1Conn{conn: raw}
	if strings.EqualFold(u.Scheme, "https") {
		tc := tls.Client(raw, clientTLS(base, u, protos))
		if err := tc.HandshakeContext(ctx); err != nil {
			raw.Close()
			return nil, fmt.Errorf("TLS handshake: %w", err)
		}
		st := tc.ConnectionState()
		c.conn = tc
		c.tls = &st
	}
	c.stamp = &h1StampReader{r: c.conn}
	c.limit = &h1LimitReader{r: c.stamp, n: math.MaxInt64}
	c.br = bufio.NewReader(c.limit)
	return c, nil
}

// warmUp sends count keep-alive requests (wire, using method) on the
// connection and reads every response completely before the next one.
func (c *h1Conn) warmUp(count int, wire []byte, method string) error {
	for k := range count {
		if _, err := c.conn.Write(wire); err != nil {
			return err
		}
		resp, err := c.readResponse(method)
		if err != nil {
			return err
		}
		_, err = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if err != nil {
			return fmt.Errorf("response %d: %w", k+1, err)
		}
		if resp.Close {
			return fmt.Errorf("response %d (status %d) closed the connection; keep-alive is required for warm-up", k+1, resp.StatusCode)
		}
	}
	return nil
}

// readResult reads the race response of the connection into res.
func (c *h1Conn) readResult(ctx context.Context, method string, opts Options, res *Result) {
	resp, err := c.readResponse(method)
	res.FirstByteNs = c.stamp.first
	if err != nil {
		res.Err = h1ErrText("read response", h1Cause(ctx, err), opts.Timeout)
		res.FirstByteNs = 0
		res.DoneNs = clock.UnixNano()
		return
	}
	res.Status = resp.StatusCode
	res.Proto = resp.Proto
	res.Header = resp.Header
	res.ServerArrivalNs = serverArrival(resp.Header, opts.ArrivalHeader)
	body, truncated, err := h1ReadBody(resp.Body, opts.MaxBody)
	resp.Body.Close()
	res.Body, res.Truncated = body, truncated
	if err != nil {
		res.Err = h1ErrText("read body", h1Cause(ctx, err), opts.Timeout)
	}
	res.DoneNs = clock.UnixNano()
}

// readResponse reads the next final (non-1xx) response from the
// connection. Each response head may span at most MaxHeaderBytes read from
// the connection (bytes buffered beyond it count too); the body is not
// limited here.
func (c *h1Conn) readResponse(method string) (*http.Response, error) {
	if method == "" {
		method = http.MethodGet
	}
	for {
		c.limit.n, c.limit.hit = MaxHeaderBytes, false
		resp, err := http.ReadResponse(c.br, &http.Request{Method: method})
		c.limit.n = math.MaxInt64
		if err != nil {
			if c.limit.hit {
				return nil, errHeaderTooLarge
			}
			return nil, err
		}
		if resp.StatusCode >= 100 && resp.StatusCode < 200 && resp.StatusCode != http.StatusSwitchingProtocols {
			resp.Body.Close()
			continue
		}
		return resp, nil
	}
}

// h1Wire serializes r as an HTTP/1.1 request. The engine sets Host,
// Content-Length (when there is a body, and 0 for bodyless POST, PUT and
// PATCH) and, unless keepAlive, "Connection: close"; the same headers in
// r.Header are ignored, as is Transfer-Encoding. Headers are written in
// sorted order so the bytes are reproducible.
func h1Wire(r Request, keepAlive bool) ([]byte, error) {
	method := r.Method
	if method == "" {
		method = http.MethodGet
	}
	if !h1ValidToken(method) {
		return nil, fmt.Errorf("invalid method %q", method)
	}
	target := r.URL.RequestURI()
	if !strings.HasPrefix(target, "/") && target != "*" {
		target = "/" + target
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\nHost: %s\r\n", method, target, r.URL.Host)
	keys := make([]string, 0, len(r.Header))
	for k := range r.Header {
		switch http.CanonicalHeaderKey(k) {
		case "Host", "Content-Length", "Connection", "Transfer-Encoding":
			continue
		}
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		if !httpguts.ValidHeaderFieldName(k) {
			return nil, fmt.Errorf("invalid header name %q", k)
		}
		for _, v := range r.Header[k] {
			if !httpguts.ValidHeaderFieldValue(v) {
				return nil, fmt.Errorf("invalid value for header %s", k)
			}
			fmt.Fprintf(&b, "%s: %s\r\n", k, v)
		}
	}
	switch {
	case len(r.Body) > 0:
		fmt.Fprintf(&b, "Content-Length: %d\r\n", len(r.Body))
	case method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch:
		b.WriteString("Content-Length: 0\r\n")
	}
	if !keepAlive {
		b.WriteString("Connection: close\r\n")
	}
	b.WriteString("\r\n")
	b.Write(r.Body)
	return b.Bytes(), nil
}

// h1ValidToken reports whether s is a non-empty HTTP token.
func h1ValidToken(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !httpguts.IsTokenRune(r) {
			return false
		}
	}
	return true
}

// h1Authorize asks g for the race host and then spends the whole budget,
// both before any connection is opened. Run has already checked that all
// requests and the warm-up request share one scheme and host.
func h1Authorize(g Guard, reqs []Request, budget int) error {
	if err := g.Allow(reqs[0].URL.Host); err != nil {
		return fmt.Errorf("scope: %w", err)
	}
	if err := g.Spend(budget); err != nil {
		return fmt.Errorf("budget: %w", err)
	}
	return nil
}

// h1ReadBody keeps up to limit bytes of r and drains the rest. truncated
// reports whether anything was dropped.
func h1ReadBody(r io.Reader, limit int) (body []byte, truncated bool, err error) {
	body, err = io.ReadAll(io.LimitReader(r, int64(limit)))
	if err != nil {
		return body, false, err
	}
	n, err := io.Copy(io.Discard, r)
	if len(body) == 0 {
		body = nil
	}
	return body, n > 0, err
}

// h1ErrText formats err for a Result, naming a deadline as the race timeout.
func h1ErrText(stage string, err error, timeout time.Duration) string {
	msg := err.Error()
	if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		msg = fmt.Sprintf("timeout after %s", timeout)
	}
	if stage == "" {
		return msg
	}
	return stage + ": " + msg
}

// h1Cause returns the context error when ctx has ended (the engine closes
// the connections then, so err is only "use of closed network connection"),
// and err otherwise.
func h1Cause(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	return err
}
