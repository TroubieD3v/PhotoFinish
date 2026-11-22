package runner

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/TroubieD3v/photofinish/internal/clock"
	"github.com/TroubieD3v/photofinish/internal/engine"
	"github.com/TroubieD3v/photofinish/internal/scenario"
)

const (
	// stepTimeout bounds one setup, check or reset request.
	stepTimeout = 30 * time.Second
	// maxStepBody is the largest step response body read; the invariant
	// and the extractors see at most this much.
	maxStepBody = 4 << 20
	// maxRecordBody is the largest step body kept in the report.
	maxRecordBody = 64 << 10
)

// StepRecord is one setup, check or reset request as stored in the report,
// with masking applied. Header and Body are those of the response.
type StepRecord struct {
	ID         string      `json:"id,omitempty"`
	Method     string      `json:"method"`
	URL        string      `json:"url"`
	Status     int         `json:"status"`
	Header     http.Header `json:"header,omitempty"`
	Body       string      `json:"body,omitempty"`
	Err        string      `json:"error,omitempty"`
	DurationNs int64       `json:"duration_ns"`
}

// newStepClient returns the HTTP client for steps. It never follows
// redirects (the target of a redirect would bypass the scope check) and
// does not use proxies from the environment.
func newStepClient(tlsConf *tls.Config) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:     tlsConf.Clone(),
			ForceAttemptHTTP2:   true,
			MaxIdleConnsPerHost: 4,
			IdleConnTimeout:     30 * time.Second,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// step builds and sends one setup, check or reset request under the guard.
// The response is nil when err is non-nil.
func (r *run) step(ctx context.Context, st scenario.Step, vars scenario.Vars) (StepRecord, *scenario.Response, error) {
	rec := StepRecord{ID: st.ID}
	req, err := r.build(st, vars)
	if err != nil {
		rec.Err = err.Error()
		return rec, nil, err
	}
	rec.Method, rec.URL = req.Method, req.URL.String()
	if err := r.guard.Allow(req.URL.Host); err != nil {
		rec.Err = err.Error()
		return rec, nil, err
	}
	if err := r.guard.wait(ctx); err != nil {
		rec.Err = err.Error()
		return rec, nil, err
	}
	if err := r.guard.Spend(1); err != nil {
		rec.Err = err.Error()
		return rec, nil, err
	}
	resp, dur, err := r.send(ctx, req)
	rec.DurationNs = dur.Nanoseconds()
	if err != nil {
		rec.Err = err.Error()
		return rec, nil, err
	}
	r.mask.harvestHeader(resp.Header)
	r.mask.harvestJSON(resp.Body)
	rec.Status = resp.Status
	rec.Header = resp.Header
	body := resp.Body
	if len(body) > maxRecordBody {
		// Mask before cutting: a cut document no longer parses, and a cut
		// secret no longer matches.
		body = r.mask.scrubber().body(body)
		if len(body) > maxRecordBody {
			body = body[:maxRecordBody]
		}
	}
	rec.Body = string(body)
	return rec, resp, nil
}

// build turns a step into a request and registers its secrets: values from
// ${env:...} (also when building fails), identity header values, other
// sensitive header values and the values of sensitive query parameters.
func (r *run) build(st scenario.Step, vars scenario.Vars) (engine.Request, error) {
	req, secrets, err := r.s.BuildRequest(st, vars)
	for _, v := range secrets {
		r.mask.addSecret(v)
	}
	if err != nil {
		if strings.Contains(err.Error(), "not in scope") {
			// BuildRequest checks absolute URLs against the scope itself;
			// its refusal is a scope failure like the guard's.
			return engine.Request{}, fmt.Errorf("%w: %v", errScope, err)
		}
		return engine.Request{}, err
	}
	if req.URL == nil {
		return engine.Request{}, fmt.Errorf("step %s: request has no URL", stepName(st))
	}
	r.guard.noteURL(req.URL)
	// Values of sensitive query parameters are masked wherever they show
	// up, also in error messages that quote the URL.
	for key, vals := range req.URL.Query() {
		if sensitiveKey.MatchString(key) {
			for _, v := range vals {
				r.mask.addHarvested(v)
			}
		}
	}
	if id, ok := r.s.Identities[st.As]; ok {
		for name := range id.Headers {
			r.mask.addHeader(name)
			for _, v := range req.Header.Values(name) {
				r.mask.addSecret(v)
			}
		}
	}
	r.mask.harvestHeader(req.Header)
	r.mask.harvestJSON(req.Body)
	return req, nil
}

// send performs req with the step client.
func (r *run) send(ctx context.Context, req engine.Request) (*scenario.Response, time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, stepTimeout)
	defer cancel()
	hreq, err := http.NewRequestWithContext(ctx, req.Method, req.URL.String(), bytes.NewReader(req.Body))
	if err != nil {
		return nil, 0, err
	}
	hreq.Header = req.Header.Clone()
	if hreq.Header == nil {
		hreq.Header = http.Header{}
	}
	if len(req.Body) == 0 {
		hreq.Body, hreq.ContentLength = http.NoBody, 0
	}
	// The high-resolution clock: on Windows time.Since advances in steps of
	// up to half a millisecond, which reports fast local steps as 0.
	start := clock.UnixNano()
	since := func() time.Duration { return time.Duration(clock.UnixNano() - start) }
	hresp, err := r.client.Do(hreq)
	if err != nil {
		return nil, since(), err
	}
	defer hresp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(hresp.Body, maxStepBody))
	dur := since()
	if err != nil {
		return nil, dur, fmt.Errorf("reading response: %w", err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(hresp.Body, maxStepBody))
	return &scenario.Response{Status: hresp.StatusCode, Header: hresp.Header, Body: body}, dur, nil
}

// statusOK reports whether status is acceptable for a step.
func statusOK(st scenario.Step, status int) bool {
	return len(st.ExpectStatus) == 0 || slices.Contains(st.ExpectStatus, status)
}

// stepName names a step in reasons and errors.
func stepName(st scenario.Step) string {
	if st.ID != "" {
		return st.ID
	}
	if t := st.Text(); t != "" {
		line, _, _ := strings.Cut(t, "\n")
		return strconv.Quote(strings.TrimSpace(line))
	}
	return "(unnamed)"
}
