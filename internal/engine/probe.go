package engine

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/TroubieD3v/photofinish/internal/clock"
)

// probeGETs is the number of GET requests Probe sends to measure round trips.
const probeGETs = 3

// HTTP/2 defaults from RFC 9113 section 6.5.2, reported when the server's
// SETTINGS frame does not carry a value.
const (
	probeDefaultWindow    = 65535
	probeDefaultFrameSize = 16384
)

// probeUserAgent identifies the probe requests in server logs.
const probeUserAgent = "photofinish-probe"

// Probe inspects the target u without sending race traffic. Over https it
// offers h2 and http/1.1 via ALPN and records the TLS version and the
// negotiated protocol. When the server negotiates h2, Probe exchanges
// SETTINGS on that connection (recording max concurrent streams, initial
// window size and max frame size) and sends three GET requests to u as
// HTTP/2 streams; otherwise it sends them over one HTTP/1.1 keep-alive
// connection. RTTs holds, for every GET, the time from writing the request
// to the arrival of the response headers.
//
// Probe asks opts.Guard for u.Host and spends 3 requests before dialing; if
// the HTTP/2 exchange fails and the GETs are repeated over HTTP/1.1, the
// repeated requests are spent again first. Gate, Warmup, WarmupRequest and
// Kind are ignored.
func Probe(ctx context.Context, u *url.URL, opts Options) (*ProbeReport, error) {
	if opts.Guard == nil {
		return nil, errors.New("options: Guard is required (use engine.AllowAll() if scope is enforced elsewhere)")
	}
	if err := checkURL(u); err != nil {
		return nil, fmt.Errorf("probe: %w", err)
	}
	opts = opts.withDefaults()
	if err := opts.Guard.Allow(u.Host); err != nil {
		return nil, fmt.Errorf("scope: %w", err)
	}
	if err := opts.Guard.Spend(probeGETs); err != nil {
		return nil, fmt.Errorf("budget: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	rep := &ProbeReport{URL: u.String()}
	p := &prober{u: u, opts: opts, rep: rep}

	if strings.EqualFold(u.Scheme, "https") {
		c, err := h1Dial(ctx, u, opts.TLS, []string{"h2", "http/1.1"})
		if err != nil {
			return nil, err
		}
		rep.ALPN = c.tls.NegotiatedProtocol
		rep.TLSVersion = tls.VersionName(c.tls.Version)
		if rep.ALPN == "h2" {
			stop := context.AfterFunc(ctx, func() { c.conn.Close() })
			sent, err := p.http2(c)
			stop()
			c.conn.Close()
			if err == nil {
				rep.HTTP2 = true
			} else {
				if ctx.Err() != nil {
					return nil, errors.New(h1ErrText("", ctx.Err(), opts.Timeout))
				}
				rep.Notes = append(rep.Notes, fmt.Sprintf(
					"the server negotiated h2 but the HTTP/2 exchange failed (%s); measured over HTTP/1.1 instead", err))
				rep.RTTs, rep.Statuses = nil, nil
				rep.MaxConcurrentStreams, rep.InitialWindowSize, rep.MaxFrameSize = 0, 0, 0
				if sent > 0 {
					if err := opts.Guard.Spend(sent); err != nil {
						return nil, fmt.Errorf("budget: %w", err)
					}
				}
				if err := p.http1(ctx, nil); err != nil {
					return nil, err
				}
			}
		} else if err := p.http1(ctx, c); err != nil {
			return nil, err
		}
	} else if err := p.http1(ctx, nil); err != nil {
		return nil, err
	}

	p.finish()
	return rep, nil
}

// prober carries the state of one Probe call.
type prober struct {
	u       *url.URL
	opts    Options
	rep     *ProbeReport
	headers bool // a response has been seen
}

// observe records what a probe response reveals about the server.
func (p *prober) observe(status int, h http.Header) {
	p.rep.Statuses = append(p.rep.Statuses, status)
	if !p.headers {
		p.headers = true
		p.rep.Server = h.Get("Server")
	}
	if p.opts.ArrivalHeader != "-" && serverArrival(h, p.opts.ArrivalHeader) != 0 {
		p.rep.ArrivalHeader = true
	}
}

// http1 sends the GETs over HTTP/1.1, reusing c (or a new connection when c
// is nil or the server closes it).
func (p *prober) http1(ctx context.Context, c *h1Conn) error {
	stop := func() bool { return true }
	defer func() {
		stop()
		if c != nil {
			c.conn.Close()
		}
	}()
	fail := func(k int, what string, err error) error {
		return fmt.Errorf("probe request %d: %s%s", k+1, what, h1ErrText("", h1Cause(ctx, err), p.opts.Timeout))
	}
	req := Request{Method: http.MethodGet, URL: p.u, Header: http.Header{
		"User-Agent": {probeUserAgent},
		"Accept":     {"*/*"},
	}}
	for k := range probeGETs {
		if c == nil {
			var err error
			if c, err = h1Dial(ctx, p.u, p.opts.TLS, []string{"http/1.1"}); err != nil {
				return err
			}
			if c.tls != nil && p.rep.TLSVersion == "" {
				p.rep.ALPN = c.tls.NegotiatedProtocol
				p.rep.TLSVersion = tls.VersionName(c.tls.Version)
			}
		}
		stop()
		conn := c.conn
		stop = context.AfterFunc(ctx, func() { conn.Close() })
		wire, err := h1Wire(req, k < probeGETs-1)
		if err != nil {
			return fmt.Errorf("probe: %w", err)
		}
		c.stamp.first = 0
		start := clock.UnixNano()
		if _, err := c.conn.Write(wire); err != nil {
			return fail(k, "", err)
		}
		resp, err := c.readResponse(http.MethodGet)
		if err != nil {
			return fail(k, "", err)
		}
		p.rep.RTTs = append(p.rep.RTTs, time.Duration(c.stamp.first-start))
		p.observe(resp.StatusCode, resp.Header)
		_, _, err = h1ReadBody(resp.Body, p.opts.MaxBody)
		resp.Body.Close()
		if err != nil {
			return fail(k, "read body: ", err)
		}
		if resp.Close {
			c.conn.Close()
			c = nil
		}
	}
	return nil
}

// http2 speaks HTTP/2 on c: preface, SETTINGS exchange and the GETs as
// streams 1, 3 and 5, one after another. It returns how many GET requests
// were written, so a fallback can account for them.
func (p *prober) http2(c *h1Conn) (sent int, err error) {
	fr := http2.NewFramer(c.conn, c.br)
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	if _, err := io.WriteString(c.conn, http2.ClientPreface); err != nil {
		return 0, err
	}
	if err := fr.WriteSettings(
		http2.Setting{ID: http2.SettingEnablePush, Val: 0},
		http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 20},
	); err != nil {
		return 0, err
	}
	if err := fr.WriteWindowUpdate(0, 1<<20); err != nil {
		return 0, err
	}

	// Wait for the server's SETTINGS.
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			return 0, fmt.Errorf("read SETTINGS: %w", err)
		}
		if done, err := p.control(fr, f, true); err != nil {
			return 0, err
		} else if done {
			break
		}
	}

	var hbuf bytes.Buffer
	enc := hpack.NewEncoder(&hbuf)
	for k := range probeGETs {
		id := uint32(2*k + 1)
		hbuf.Reset()
		for _, hf := range []hpack.HeaderField{
			{Name: ":method", Value: http.MethodGet},
			{Name: ":scheme", Value: strings.ToLower(p.u.Scheme)},
			{Name: ":authority", Value: p.u.Host},
			{Name: ":path", Value: p.u.RequestURI()},
			{Name: "user-agent", Value: probeUserAgent},
			{Name: "accept", Value: "*/*"},
		} {
			enc.WriteField(hf)
		}
		start := clock.UnixNano()
		if err := fr.WriteHeaders(http2.HeadersFrameParam{
			StreamID: id, BlockFragment: hbuf.Bytes(), EndStream: true, EndHeaders: true,
		}); err != nil {
			return sent, err
		}
		sent++
		if err := p.awaitStream(fr, id, start); err != nil {
			return sent, fmt.Errorf("probe request %d: %w", k+1, err)
		}
	}
	fr.WriteGoAway(uint32(2*probeGETs-1), http2.ErrCodeNo, nil)
	return sent, nil
}

// awaitStream reads frames until stream id has a final response and has
// ended, recording the round trip from start to the response headers.
// Bodies beyond MaxBody are cut short with RST_STREAM.
func (p *prober) awaitStream(fr *http2.Framer, id uint32, start int64) error {
	gotHeaders := false
	body := 0
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			return err
		}
		if _, err := p.control(fr, f, false); err != nil {
			return err
		}
		switch f := f.(type) {
		case *http2.MetaHeadersFrame:
			if f.StreamID != id {
				continue
			}
			if !gotHeaders {
				status, _ := strconv.Atoi(f.PseudoValue("status"))
				if status >= 100 && status < 200 && !f.StreamEnded() {
					continue // informational response
				}
				gotHeaders = true
				p.rep.RTTs = append(p.rep.RTTs, time.Duration(clock.UnixNano()-start))
				h := make(http.Header)
				for _, hf := range f.RegularFields() {
					h.Add(http.CanonicalHeaderKey(hf.Name), hf.Value)
				}
				p.observe(status, h)
			}
			if f.StreamEnded() {
				return nil
			}
		case *http2.DataFrame:
			if n := len(f.Data()); n > 0 {
				if err := fr.WriteWindowUpdate(0, uint32(n)); err != nil {
					return err
				}
				if !f.StreamEnded() && f.StreamID == id {
					if err := fr.WriteWindowUpdate(id, uint32(n)); err != nil {
						return err
					}
				}
			}
			if f.StreamID != id {
				continue
			}
			if f.StreamEnded() {
				if !gotHeaders {
					return errors.New("stream ended without response headers")
				}
				return nil
			}
			body += len(f.Data())
			if gotHeaders && body > p.opts.MaxBody {
				return fr.WriteRSTStream(id, http2.ErrCodeCancel)
			}
		case *http2.RSTStreamFrame:
			if f.StreamID == id {
				return fmt.Errorf("server reset the stream: %v", f.ErrCode)
			}
		}
	}
}

// control handles connection-level frames: it acknowledges SETTINGS and
// PING and fails on GOAWAY. When record is set, the first non-ack SETTINGS
// frame is recorded in the report and done is true.
func (p *prober) control(fr *http2.Framer, f http2.Frame, record bool) (done bool, err error) {
	switch f := f.(type) {
	case *http2.SettingsFrame:
		if f.IsAck() {
			return false, nil
		}
		if record {
			p.rep.InitialWindowSize = probeDefaultWindow
			p.rep.MaxFrameSize = probeDefaultFrameSize
			if v, ok := f.Value(http2.SettingMaxConcurrentStreams); ok {
				p.rep.MaxConcurrentStreams = v
			}
			if v, ok := f.Value(http2.SettingInitialWindowSize); ok {
				p.rep.InitialWindowSize = v
			}
			if v, ok := f.Value(http2.SettingMaxFrameSize); ok {
				p.rep.MaxFrameSize = v
			}
			if _, ok := f.Value(http2.SettingMaxConcurrentStreams); !ok {
				p.rep.Notes = append(p.rep.Notes, "the server does not limit concurrent streams (SETTINGS_MAX_CONCURRENT_STREAMS absent); MaxConcurrentStreams is reported as 0")
			}
		}
		return record, fr.WriteSettingsAck()
	case *http2.PingFrame:
		if !f.IsAck() {
			return false, fr.WritePing(true, f.Data)
		}
	case *http2.GoAwayFrame:
		return false, fmt.Errorf("server sent GOAWAY (%v)", f.ErrCode)
	}
	return false, nil
}

// finish adds the recommendation and the notes derived from the report.
func (p *prober) finish() {
	rep := p.rep
	switch {
	case rep.HTTP2:
		rep.Recommended = H2
		if n := rep.MaxConcurrentStreams; n > 0 {
			rep.Notes = append(rep.Notes, fmt.Sprintf("the server allows %d concurrent streams: one h2 race can send at most %d copies", n, n))
		}
	case !strings.EqualFold(p.u.Scheme, "https"):
		rep.Recommended = H1
		rep.Notes = append(rep.Notes, "plain http: the h2 single-packet attack needs TLS with ALPN h2 (h2c is not supported); use h1 last-byte sync")
	default:
		rep.Recommended = H1
		alpn := rep.ALPN
		if alpn == "" {
			alpn = "none"
		}
		rep.Notes = append(rep.Notes, fmt.Sprintf("the server does not speak HTTP/2 (ALPN %s): use h1 last-byte sync", alpn))
	}
	if p.opts.ArrivalHeader != "-" && !rep.ArrivalHeader {
		rep.Notes = append(rep.Notes, fmt.Sprintf("responses carry no %s header: reports will not include the server arrival spread", p.opts.ArrivalHeader))
	}
	if len(rep.Statuses) > 0 && !slices.ContainsFunc(rep.Statuses, func(c int) bool { return c < 400 }) {
		rep.Notes = append(rep.Notes, fmt.Sprintf("every probe response was an error (status %d): check the URL and scheme before racing it", rep.Statuses[0]))
	}
	if len(rep.RTTs) > 0 {
		s := slices.Clone(rep.RTTs)
		slices.Sort(s)
		rep.Notes = append(rep.Notes, fmt.Sprintf("median round trip to the response headers: %s", s[len(s)/2]))
	}
}
