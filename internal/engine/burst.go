package engine

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"sync"

	"github.com/TroubieD3v/photofinish/internal/clock"
)

// runBurst sends reqs as plain concurrent requests through one http.Client:
// every request runs in its own goroutine and all goroutines are released at
// once by closing a channel. Nothing is withheld, so this is the baseline the
// synchronized engines are compared against.
//
// The client offers HTTP/2 (ForceAttemptHTTP2), never follows redirects,
// ignores proxy environment variables and does not ask for compressed
// responses, so the Results show exactly what the server sent. PreSentNs and
// ReleasedNs are both the time just before client.Do; FirstByteNs is the time
// Do returned the response headers. Release.SpreadNs is the spread of those
// start times; Release.Writes and Release.Bytes stay 0 because the engine
// does not control the writes.
//
// The budget spent is len(reqs) plus Warmup: the warm-up requests are sent
// one after another through the same client before the race, so the
// connection(s) it pools are reused by the race.
func runBurst(ctx context.Context, reqs []Request, opts Options) (*Race, error) {
	warm := opts.warmupRequest(reqs)
	if err := h1Authorize(opts.Guard, reqs, len(reqs)+opts.Warmup); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	tr := &http.Transport{
		Proxy:               nil,
		DialContext:         (&net.Dialer{}).DialContext,
		TLSClientConfig:     clientTLS(opts.TLS, reqs[0].URL, nil),
		ForceAttemptHTTP2:   true,
		DisableCompression:  true,
		MaxIdleConnsPerHost: len(reqs),
		TLSHandshakeTimeout: opts.Timeout,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{
		Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	race := &Race{
		Kind:      Burst,
		Target:    target(reqs[0].URL),
		Warmup:    opts.Warmup,
		Results:   make([]Result, len(reqs)),
		StartedNs: clock.UnixNano(),
	}

	var (
		mu       sync.Mutex
		connIDs  = map[net.Conn]int{}
		tlsState *tls.ConnectionState
	)
	connOf := func(c net.Conn) int {
		mu.Lock()
		defer mu.Unlock()
		id, ok := connIDs[c]
		if !ok {
			id = len(connIDs)
			connIDs[c] = id
		}
		return id
	}
	noteTLS := func(st *tls.ConnectionState) {
		if st == nil {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if tlsState == nil {
			tlsState = st
		}
	}

	for k := range opts.Warmup {
		req, err := burstHTTPRequest(ctx, warm)
		if err != nil {
			return nil, fmt.Errorf("warm-up request: %w", err)
		}
		req = req.WithContext(httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
			GotConn: func(info httptrace.GotConnInfo) { connOf(info.Conn) },
		}))
		resp, err := client.Do(req)
		if err != nil {
			race.Notes = append(race.Notes, fmt.Sprintf("warm-up request %d failed: %v", k+1, err))
			continue
		}
		noteTLS(resp.TLS)
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}

	start := make(chan struct{})
	var ready, done sync.WaitGroup
	for i, r := range reqs {
		res := &race.Results[i]
		*res = Result{Index: i, Label: r.Label}
		ready.Add(1)
		done.Add(1)
		go func() {
			defer done.Done()
			req, err := burstHTTPRequest(ctx, r)
			if err == nil {
				req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
					GotConn: func(info httptrace.GotConnInfo) { res.Conn = connOf(info.Conn) },
				}))
			}
			ready.Done()
			<-start
			if err != nil {
				res.Err = err.Error()
				return
			}
			res.ReleasedNs = clock.UnixNano()
			res.PreSentNs = res.ReleasedNs
			resp, err := client.Do(req)
			if err != nil {
				res.Err = h1ErrText("request", err, opts.Timeout)
				res.DoneNs = clock.UnixNano()
				return
			}
			res.FirstByteNs = clock.UnixNano()
			noteTLS(resp.TLS)
			res.Status = resp.StatusCode
			res.Proto = resp.Proto
			res.Header = resp.Header
			res.ServerArrivalNs = serverArrival(resp.Header, opts.ArrivalHeader)
			body, truncated, err := h1ReadBody(resp.Body, opts.MaxBody)
			resp.Body.Close()
			res.Body, res.Truncated = body, truncated
			if err != nil {
				res.Err = h1ErrText("read body", err, opts.Timeout)
			}
			res.DoneNs = clock.UnixNano()
		}()
	}
	ready.Wait()
	close(start)
	done.Wait()

	var minNs, maxNs int64
	for i := range race.Results {
		ns := race.Results[i].ReleasedNs
		if ns == 0 {
			continue
		}
		if minNs == 0 || ns < minNs {
			minNs = ns
		}
		if ns > maxNs {
			maxNs = ns
		}
	}
	race.Release.SpreadNs = maxNs - minNs
	race.Connections = len(connIDs)
	if tlsState != nil {
		race.ALPN = tlsState.NegotiatedProtocol
		race.TLSVersion = tls.VersionName(tlsState.Version)
	}
	race.FinishedNs = clock.UnixNano()
	return race, nil
}

// burstHTTPRequest converts r into an *http.Request bound to ctx. Host,
// Content-Length, Connection and Transfer-Encoding in r.Header are ignored:
// the client derives them from the URL and the body.
func burstHTTPRequest(ctx context.Context, r Request) (*http.Request, error) {
	method := r.Method
	if method == "" {
		method = http.MethodGet
	}
	if !h1ValidToken(method) {
		return nil, fmt.Errorf("invalid method %q", method)
	}
	var body io.Reader = http.NoBody
	if len(r.Body) > 0 {
		body = bytes.NewReader(r.Body)
	}
	req, err := http.NewRequestWithContext(ctx, method, r.URL.String(), body)
	if err != nil {
		return nil, err
	}
	for k, vs := range r.Header {
		switch http.CanonicalHeaderKey(k) {
		case "Host", "Content-Length", "Connection", "Transfer-Encoding":
			continue
		}
		req.Header[k] = append([]string(nil), vs...)
	}
	return req, nil
}
