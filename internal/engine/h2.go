package engine

import (
	"bytes"
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
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http/httpguts"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/TroubieD3v/photofinish/internal/clock"
)

// The HTTP/2 single-packet engine.
//
// Every race request is pre-sent on its own stream of one connection: the
// HEADERS (without END_STREAM) and all body bytes but the last. After the
// gate, the final DATA frame of every stream (the last body byte, or an empty
// frame, each with END_STREAM) is written with one Write call, so all of
// them travel in one TLS record and, on most paths, one TCP segment. The
// server cannot start processing any request before that record arrives.

// errNoH2 is returned (wrapped) by runH2 when the server does not negotiate
// HTTP/2 via ALPN; Auto falls back to h1 on it.
var errNoH2 = errors.New("server did not negotiate h2")

// Engine constants.
const (
	// h2ReleaseSegment is the most bytes written by one release write. Each
	// withheld frame is 9-10 bytes, so one write carries about 100 streams;
	// the limit keeps the TLS record within one TCP segment on common paths.
	h2ReleaseSegment = 1200
	// h2StreamWindow is the INITIAL_WINDOW_SIZE advertised to the server.
	h2StreamWindow = 1 << 20
	// h2ConnWindow is the connection receive window after the initial
	// WINDOW_UPDATE, so responses are never flow-control blocked.
	h2ConnWindow = 1 << 30
	// h2MaxStreams is the MAX_CONCURRENT_STREAMS advertised to the server.
	h2MaxStreams = 1000
	// Protocol defaults (RFC 9113) that hold until the peer's SETTINGS.
	h2DefaultWindow    = 65535
	h2DefaultMaxFrame  = 16384
	h2DefaultTableSize = 4096
)

// h2PingData is the opaque data of the PING sent after the gate.
var h2PingData = [8]byte{'p', 'f', 'w', 'a', 'r', 'm', 'u', 'p'}

// h2DialHook, when set, replaces the TCP dialer. Tests use it to observe the
// bytes the engine writes; it is never set outside tests.
var h2DialHook atomic.Pointer[func(ctx context.Context, network, addr string) (net.Conn, error)]

// h2ReleaseHook, when set, runs after the gate and before the release with
// the race streams. Tests use it to hold the release until an expected event;
// it is never set outside tests.
var h2ReleaseHook atomic.Pointer[func(streams []*h2stream)]

// h2Hop lists header fields the engine never copies from Request.Header:
// connection-specific fields HTTP/2 forbids, and Host and Content-Length,
// which the engine derives from the URL and the body.
var h2Hop = map[string]bool{
	"connection":        true,
	"keep-alive":        true,
	"proxy-connection":  true,
	"transfer-encoding": true,
	"upgrade":           true,
	"host":              true,
	"content-length":    true,
}

// runH2 sends reqs as an HTTP/2 single-packet race. Options carry defaults.
func runH2(ctx context.Context, reqs []Request, opts Options) (*Race, error) {
	u := reqs[0].URL
	if u.Scheme != "https" {
		return nil, fmt.Errorf("h2 engine needs an https URL, got %s (cleartext HTTP/2 is not supported; use h1)", target(u))
	}
	warm := opts.warmupRequest(reqs)
	if err := checkH2Headers(reqs, warm, opts.Warmup); err != nil {
		return nil, err
	}
	if err := opts.Guard.Allow(u.Host); err != nil {
		return nil, fmt.Errorf("scope: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	race := &Race{
		Kind:        H2,
		Target:      target(u),
		Connections: 1,
		Warmup:      opts.Warmup,
		StartedNs:   clock.UnixNano(),
	}
	c, state, err := dialH2(ctx, u, opts)
	if err != nil {
		return nil, err
	}
	defer c.close()
	race.ALPN = state.NegotiatedProtocol
	race.TLSVersion = tlsVersionName(state.Version)

	if err := c.start(ctx); err != nil {
		return nil, err
	}
	if err := c.checkCapacity(reqs); err != nil {
		return nil, err
	}
	if err := opts.Guard.Spend(len(reqs) + opts.Warmup); err != nil {
		return nil, fmt.Errorf("budget: %w", err)
	}

	for i := range opts.Warmup {
		note, err := c.warmup(ctx, warm)
		if err != nil {
			return nil, fmt.Errorf("warm-up request %d: %w", i+1, err)
		}
		if note != "" {
			race.Notes = append(race.Notes, fmt.Sprintf("warm-up request %d: %s", i+1, note))
		}
	}

	race.Results = make([]Result, len(reqs))
	streams := make([]*h2stream, len(reqs))
	for i, r := range reqs {
		race.Results[i] = Result{Index: i, Label: r.Label, Proto: "HTTP/2.0"}
		st, err := c.preSend(r, &race.Results[i])
		if err != nil {
			return nil, err
		}
		streams[i] = st
	}

	if err := h2Sleep(ctx, opts.Gate); err != nil {
		return nil, fmt.Errorf("race aborted during the gate: %w", err)
	}
	if hook := h2ReleaseHook.Load(); hook != nil {
		(*hook)(streams)
	}
	if err := c.write(func(fr *http2.Framer) error { return fr.WritePing(false, h2PingData) }); err != nil {
		return nil, fmt.Errorf("write PING: %w", err)
	}

	rel, err := c.release(reqs, streams)
	if err != nil {
		return nil, err
	}
	race.Release = rel
	if rel.Writes > 1 {
		race.Notes = append(race.Notes, fmt.Sprintf(
			"split into %d writes: %d streams exceed one segment (%d bytes of final frames, at most %d per write)",
			rel.Writes, len(reqs), rel.Bytes, h2ReleaseSegment))
	}

	c.wait(ctx, streams, opts.Timeout)
	c.close()

	for i := range race.Results {
		res := &race.Results[i]
		res.ServerArrivalNs = serverArrival(res.Header, opts.ArrivalHeader)
		// A response is early if its headers arrived before the release
		// write began. Comparing with the start of the write rather than
		// ReleasedNs (taken after Write returns) keeps a fast answer that
		// overtakes the post-write timestamp from being flagged.
		res.EarlyResponse = res.FirstByteNs != 0 && res.FirstByteNs < streams[i].releaseStartNs
	}
	race.FinishedNs = clock.UnixNano()
	return race, nil
}

// checkH2Headers rejects header fields that cannot be sent over HTTP/2
// before anything is dialed.
func checkH2Headers(reqs []Request, warm Request, warmups int) error {
	check := func(what string, r Request) error {
		if !httpguts.ValidHeaderFieldName(r.Method) {
			return fmt.Errorf("%s: invalid method %q", what, r.Method)
		}
		for k, vs := range r.Header {
			if !httpguts.ValidHeaderFieldName(k) {
				return fmt.Errorf("%s: invalid header field name %q", what, k)
			}
			for _, v := range vs {
				if !httpguts.ValidHeaderFieldValue(v) {
					return fmt.Errorf("%s: invalid value for header %q", what, k)
				}
			}
		}
		return nil
	}
	for i, r := range reqs {
		if err := check(fmt.Sprintf("request %d", i), r); err != nil {
			return err
		}
	}
	if warmups > 0 {
		return check("warm-up request", warm)
	}
	return nil
}

// h2Sleep sleeps for d or until ctx is done.
func h2Sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// h2conn is one client HTTP/2 connection. The reader goroutine owns frame
// reading; every write goes through write or release, which serialize on
// wmu. Stream and peer state is guarded by mu.
type h2conn struct {
	conn    net.Conn
	maxBody int

	wmu  sync.Mutex
	wbuf bytes.Buffer
	wfr  *http2.Framer // writes into wbuf

	// Owned by the sending goroutine.
	hbuf       bytes.Buffer
	henc       *hpack.Encoder
	tableLimit uint32 // dynamic table size limit applied to henc
	nextID     uint32

	gotSettings chan struct{} // closed on the peer's first SETTINGS
	gotAck      chan struct{} // closed when the peer acknowledges ours
	readerDone  chan struct{}
	closeOnce   sync.Once
	stopAfter   func() bool

	mu             sync.Mutex
	settingsSeen   bool
	ackSeen        bool
	peerMaxStreams uint32 // 0 with sawMaxStreams false: unlimited
	sawMaxStreams  bool
	peerWindow     int64 // peer INITIAL_WINDOW_SIZE
	peerMaxFrame   uint32
	peerTableSize  uint32
	connWindow     int64 // send window of the connection
	windowCh       chan struct{}
	streams        map[uint32]*h2stream
	goAway         bool
	goAwayLast     uint32
	goAwayCode     http2.ErrCode
	readErr        error
	closing        bool
}

// h2stream is one stream opened by the client.
type h2stream struct {
	id     uint32
	res    *Result
	window int64 // send window
	// releaseStartNs is when the release write carrying this stream's
	// final frame began.
	releaseStartNs int64
	gotHeaders     bool
	ended          bool
	done           chan struct{}
}

// dialH2 connects, runs the TLS handshake and checks that h2 was
// negotiated. The reader goroutine runs from here on.
func dialH2(ctx context.Context, u *url.URL, opts Options) (*h2conn, tls.ConnectionState, error) {
	dial := (&net.Dialer{}).DialContext
	if hook := h2DialHook.Load(); hook != nil {
		dial = *hook
	}
	raw, err := dial(ctx, "tcp", hostPort(u))
	if err != nil {
		return nil, tls.ConnectionState{}, fmt.Errorf("dial %s: %w", u.Host, err)
	}
	if tc, ok := raw.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}
	// http/1.1 is offered second so that servers which only speak HTTP/1.1
	// complete the handshake and Auto can fall back instead of failing.
	tc := tls.Client(raw, clientTLS(opts.TLS, u, []string{"h2", "http/1.1"}))
	if err := tc.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, tls.ConnectionState{}, fmt.Errorf("TLS handshake with %s: %w", u.Host, err)
	}
	state := tc.ConnectionState()
	if state.NegotiatedProtocol != "h2" {
		tc.Close()
		alpn := state.NegotiatedProtocol
		if alpn == "" {
			alpn = "none"
		}
		return nil, state, fmt.Errorf("%w (ALPN: %s)", errNoH2, alpn)
	}

	c := &h2conn{
		conn:          tc,
		maxBody:       opts.MaxBody,
		nextID:        1,
		gotSettings:   make(chan struct{}),
		gotAck:        make(chan struct{}),
		readerDone:    make(chan struct{}),
		peerWindow:    h2DefaultWindow,
		peerMaxFrame:  h2DefaultMaxFrame,
		peerTableSize: h2DefaultTableSize,
		tableLimit:    h2DefaultTableSize,
		connWindow:    h2DefaultWindow,
		windowCh:      make(chan struct{}),
		streams:       make(map[uint32]*h2stream),
	}
	c.wfr = http2.NewFramer(&c.wbuf, nil)
	c.henc = hpack.NewEncoder(&c.hbuf)
	// The preface must be on the wire before the reader starts: the reader
	// acknowledges the server's SETTINGS as soon as they arrive, and an ACK
	// written ahead of the preface is a protocol error for the server.
	if err := c.writePreface(); err != nil {
		tc.Close()
		return nil, state, err
	}
	c.stopAfter = context.AfterFunc(ctx, func() { tc.Close() })
	go c.readLoop()
	return c, state, nil
}

// close closes the connection once and waits for the reader to exit.
func (c *h2conn) close() {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closing = true
		c.mu.Unlock()
		c.stopAfter()
		c.conn.Close()
		<-c.readerDone
	})
}

// write runs build against a framer that writes into a buffer and sends the
// buffer to the connection with one Write call.
func (c *h2conn) write(build func(fr *http2.Framer) error) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	c.wbuf.Reset()
	if err := build(c.wfr); err != nil {
		return err
	}
	_, err := c.conn.Write(c.wbuf.Bytes())
	return err
}

// writePreface writes the client preface, SETTINGS and the connection
// WINDOW_UPDATE with one Write call.
func (c *h2conn) writePreface() error {
	err := c.write(func(fr *http2.Framer) error {
		c.wbuf.WriteString(http2.ClientPreface)
		if err := fr.WriteSettings(
			http2.Setting{ID: http2.SettingEnablePush, Val: 0},
			http2.Setting{ID: http2.SettingInitialWindowSize, Val: h2StreamWindow},
			http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: h2MaxStreams},
			http2.Setting{ID: http2.SettingMaxHeaderListSize, Val: MaxHeaderBytes},
		); err != nil {
			return err
		}
		return fr.WriteWindowUpdate(0, h2ConnWindow-h2DefaultWindow)
	})
	if err != nil {
		return fmt.Errorf("write HTTP/2 preface: %w", err)
	}
	return nil
}

// start waits for the peer's SETTINGS and for the acknowledgement of ours.
// The preface was written by dialH2.
func (c *h2conn) start(ctx context.Context) error {
	for _, ch := range []chan struct{}{c.gotSettings, c.gotAck} {
		select {
		case <-ch:
		case <-c.readerDone:
			return fmt.Errorf("connection closed during the HTTP/2 handshake: %w", c.lostErr())
		case <-ctx.Done():
			return fmt.Errorf("waiting for the server's HTTP/2 SETTINGS: %w", ctx.Err())
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.goAway {
		return fmt.Errorf("server sent GOAWAY (%v) during the HTTP/2 handshake", c.goAwayCode)
	}
	return nil
}

// lostErr returns why the reader stopped.
func (c *h2conn) lostErr() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.readErr != nil {
		return c.readErr
	}
	return errors.New("connection closed")
}

// checkCapacity refuses a race the server's SETTINGS cannot carry at once:
// more streams than MAX_CONCURRENT_STREAMS, or more body bytes than the
// flow-control windows let the client send.
func (c *h2conn) checkCapacity(reqs []Request) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sawMaxStreams && uint64(len(reqs)) > uint64(c.peerMaxStreams) {
		return fmt.Errorf("%d copies exceed the server's SETTINGS_MAX_CONCURRENT_STREAMS of %d: "+
			"lower the copies to %d or use the h1 engine", len(reqs), c.peerMaxStreams, c.peerMaxStreams)
	}
	return c.checkWindowsLocked(reqs)
}

// checkWindowsLocked reports an error unless every body fits in a stream
// window and all bodies together fit in the connection window.
func (c *h2conn) checkWindowsLocked(reqs []Request) error {
	var total int64
	for i, r := range reqs {
		n := int64(len(r.Body))
		if n > c.peerWindow {
			return fmt.Errorf("request bodies are too large for HTTP/2 pre-sending: request %d has %d body bytes "+
				"but the server's stream flow-control window is %d bytes", i, n, c.peerWindow)
		}
		total += n
	}
	if total > c.connWindow {
		return fmt.Errorf("request bodies are too large for %d copies: %d body bytes must be pre-sent "+
			"but the server's connection flow-control window allows %d; lower the copies or shorten the body",
			len(reqs), total, c.connWindow)
	}
	return nil
}

// open registers a new client stream for res.
func (c *h2conn) open(res *Result) *h2stream {
	id := c.nextID
	c.nextID += 2
	c.mu.Lock()
	defer c.mu.Unlock()
	st := &h2stream{id: id, res: res, window: c.peerWindow, done: make(chan struct{})}
	c.streams[id] = st
	return st
}

// headerBlock HPACK-encodes the request header block of r.
func (c *h2conn) headerBlock(r Request) []byte {
	// The peer's HEADER_TABLE_SIZE bounds the encoder's dynamic table.
	c.mu.Lock()
	limit := c.peerTableSize
	c.mu.Unlock()
	if limit != c.tableLimit {
		c.henc.SetMaxDynamicTableSizeLimit(limit)
		c.tableLimit = limit
	}

	c.hbuf.Reset()
	path := r.URL.RequestURI()
	if path == "" {
		path = "/"
	}
	field := func(name, value string) {
		c.henc.WriteField(hpack.HeaderField{Name: name, Value: value, Sensitive: h2Sensitive(name)})
	}
	field(":method", r.Method)
	field(":scheme", r.URL.Scheme)
	field(":authority", r.URL.Host)
	field(":path", path)
	keys := make([]string, 0, len(r.Header))
	for k := range r.Header {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		name := strings.ToLower(k)
		if h2Hop[name] || strings.HasPrefix(name, ":") {
			continue
		}
		for _, v := range r.Header[k] {
			if name == "te" && !strings.EqualFold(v, "trailers") {
				continue
			}
			field(name, v)
		}
	}
	if len(r.Body) > 0 {
		field("content-length", strconv.Itoa(len(r.Body)))
	}
	return bytes.Clone(c.hbuf.Bytes())
}

// h2Sensitive reports whether a header value must never be added to the
// HPACK dynamic table.
func h2Sensitive(name string) bool {
	switch name {
	case "authorization", "proxy-authorization", "cookie":
		return true
	}
	return false
}

// h2WriteHeaders writes block as HEADERS plus CONTINUATION frames no larger
// than maxFrame, with END_HEADERS on the last one.
func h2WriteHeaders(fr *http2.Framer, id uint32, block []byte, endStream bool, maxFrame int) error {
	first, rest := block, []byte(nil)
	if len(block) > maxFrame {
		first, rest = block[:maxFrame], block[maxFrame:]
	}
	if err := fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      id,
		BlockFragment: first,
		EndStream:     endStream,
		EndHeaders:    len(rest) == 0,
	}); err != nil {
		return err
	}
	for len(rest) > 0 {
		chunk := rest[:min(len(rest), maxFrame)]
		rest = rest[len(chunk):]
		if err := fr.WriteContinuation(id, len(rest) == 0, chunk); err != nil {
			return err
		}
	}
	return nil
}

// maxFrame returns the peer's MAX_FRAME_SIZE.
func (c *h2conn) maxFrame() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return int(c.peerMaxFrame)
}

// usable returns whether new streams may still be opened.
func (c *h2conn) usable() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case c.readErr != nil:
		return fmt.Errorf("connection lost: %w", c.readErr)
	case c.goAway:
		return fmt.Errorf("server sent GOAWAY (%v)", c.goAwayCode)
	}
	return nil
}

// warmup sends one complete request and waits for its response. It returns
// a note when the response was not a clean one.
func (c *h2conn) warmup(ctx context.Context, r Request) (string, error) {
	if err := c.usable(); err != nil {
		return "", err
	}
	res := &Result{}
	st := c.open(res)
	block := c.headerBlock(r)
	mf := c.maxFrame()
	if err := c.write(func(fr *http2.Framer) error {
		return h2WriteHeaders(fr, st.id, block, len(r.Body) == 0, mf)
	}); err != nil {
		return "", err
	}
	if len(r.Body) > 0 {
		if err := c.sendBody(ctx, st, r.Body); err != nil {
			return "", err
		}
	}
	select {
	case <-st.done:
	case <-ctx.Done():
		return "", fmt.Errorf("no response: %w", ctx.Err())
	}
	if err := c.usable(); err != nil {
		return "", err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if res.Err != "" {
		return res.Err, nil
	}
	return "", nil
}

// sendBody writes body on st with END_STREAM, waiting for flow-control
// window as needed.
func (c *h2conn) sendBody(ctx context.Context, st *h2stream, body []byte) error {
	for len(body) > 0 {
		c.mu.Lock()
		n := min(int64(len(body)), int64(c.peerMaxFrame), c.connWindow, st.window)
		if c.readErr != nil {
			c.mu.Unlock()
			return fmt.Errorf("connection lost: %w", c.readErr)
		}
		if n <= 0 {
			ch := c.windowCh
			c.mu.Unlock()
			select {
			case <-ch:
				continue
			case <-ctx.Done():
				return fmt.Errorf("waiting for flow-control window: %w", ctx.Err())
			}
		}
		c.connWindow -= n
		st.window -= n
		c.mu.Unlock()
		chunk := body[:n]
		body = body[n:]
		end := len(body) == 0
		if err := c.write(func(fr *http2.Framer) error { return fr.WriteData(st.id, end, chunk) }); err != nil {
			return err
		}
	}
	return nil
}

// preSend writes the HEADERS of r without END_STREAM and all body bytes
// but the last, and reserves the flow-control window for the last byte.
func (c *h2conn) preSend(r Request, res *Result) (*h2stream, error) {
	if err := c.usable(); err != nil {
		return nil, err
	}
	st := c.open(res)
	res.Stream = st.id
	block := c.headerBlock(r)

	c.mu.Lock()
	n := int64(len(r.Body))
	if n > c.connWindow || n > st.window {
		avail := min(c.connWindow, st.window)
		c.mu.Unlock()
		return nil, fmt.Errorf("request bodies are too large for this many copies: request %d needs %d body bytes "+
			"but only %d remain in the server's flow-control window; lower the copies or shorten the body",
			res.Index, n, avail)
	}
	c.connWindow -= n
	st.window -= n
	mf := int(c.peerMaxFrame)
	c.mu.Unlock()

	err := c.write(func(fr *http2.Framer) error {
		if err := h2WriteHeaders(fr, st.id, block, false, mf); err != nil {
			return err
		}
		if n == 0 {
			return nil
		}
		pre := r.Body[:n-1]
		for len(pre) > 0 {
			chunk := pre[:min(len(pre), mf)]
			pre = pre[len(chunk):]
			if err := fr.WriteData(st.id, false, chunk); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("pre-send request %d: %w", res.Index, err)
	}
	res.PreSentNs = clock.UnixNano()
	return st, nil
}

// release builds the final frame of every stream (the last body byte, or an
// empty DATA frame, with END_STREAM) into one buffer and writes it with one
// Write call, or with several writes of at most h2ReleaseSegment bytes cut
// at frame boundaries when it is larger. It sets ReleasedNs of every stream
// to the time its write returned.
func (c *h2conn) release(reqs []Request, streams []*h2stream) (Release, error) {
	var buf bytes.Buffer
	fr := http2.NewFramer(&buf, nil)
	ends := make([]int, len(streams)) // buffer offset after each frame
	for i, st := range streams {
		var last []byte
		if n := len(reqs[i].Body); n > 0 {
			last = reqs[i].Body[n-1:]
		}
		if err := fr.WriteData(st.id, true, last); err != nil {
			return Release{}, fmt.Errorf("build release frames: %w", err)
		}
		ends[i] = buf.Len()
	}

	// Group the frames into writes: write k carries the frames of streams
	// firsts[k] .. firsts[k+1]-1.
	firsts := []int{0}
	segStart := 0
	for i := 1; i < len(ends); i++ {
		if ends[i]-segStart > h2ReleaseSegment {
			firsts = append(firsts, i)
			segStart = ends[i-1]
		}
	}
	firsts = append(firsts, len(streams))

	data := buf.Bytes()
	starts := make([]int64, len(firsts)-1)
	times := make([]int64, len(firsts)-1)
	c.wmu.Lock()
	var err error
	for k := range times {
		from := 0
		if a := firsts[k]; a > 0 {
			from = ends[a-1]
		}
		to := ends[firsts[k+1]-1]
		starts[k] = clock.UnixNano()
		if _, err = c.conn.Write(data[from:to]); err != nil {
			break
		}
		times[k] = clock.UnixNano()
	}
	c.wmu.Unlock()
	if err != nil {
		return Release{}, fmt.Errorf("release write: %w", err)
	}

	for k, t := range times {
		for i := firsts[k]; i < firsts[k+1]; i++ {
			streams[i].res.ReleasedNs = t
			streams[i].releaseStartNs = starts[k]
		}
	}
	return Release{
		Writes:   len(times),
		Bytes:    len(data),
		SpreadNs: times[len(times)-1] - times[0],
	}, nil
}

// wait blocks until every stream has ended or ctx is done; streams still
// open then are marked as timed out.
func (c *h2conn) wait(ctx context.Context, streams []*h2stream, timeout time.Duration) {
wait:
	for _, st := range streams {
		select {
		case <-st.done:
		case <-ctx.Done():
			break wait
		}
	}
	now := clock.UnixNano()
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, st := range streams {
		if st.ended {
			continue
		}
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			st.res.Err = fmt.Sprintf("no complete response within the race timeout of %s", timeout)
		} else {
			st.res.Err = "race canceled before the response completed"
		}
		c.endLocked(st, now)
	}
}

// endLocked marks st as finished at now. c.mu must be held.
func (c *h2conn) endLocked(st *h2stream, now int64) {
	if st.ended {
		return
	}
	st.ended = true
	st.res.DoneNs = now
	close(st.done)
}

// signalLocked wakes senders waiting for flow-control window. c.mu must be
// held.
func (c *h2conn) signalLocked() {
	close(c.windowCh)
	c.windowCh = make(chan struct{})
}

// readLoop reads frames until the connection fails or is closed.
func (c *h2conn) readLoop() {
	defer close(c.readerDone)
	fr := http2.NewFramer(nil, c.conn)
	fr.ReadMetaHeaders = hpack.NewDecoder(h2DefaultTableSize, nil)
	// Without a cap the Framer decodes header blocks of up to 16 MiB; with
	// it, a larger block is decoded without keeping the fields and comes
	// back marked Truncated.
	fr.MaxHeaderListSize = MaxHeaderBytes
	for {
		f, err := fr.ReadFrame()
		now := clock.UnixNano()
		if err != nil {
			var se http2.StreamError
			if errors.As(err, &se) {
				c.failStream(se.StreamID, fmt.Sprintf("invalid response: %v", se), now)
				continue
			}
			c.fail(err, now)
			return
		}
		switch f := f.(type) {
		case *http2.SettingsFrame:
			c.onSettings(f)
		case *http2.PingFrame:
			if !f.IsAck() {
				data := f.Data
				c.write(func(fr *http2.Framer) error { return fr.WritePing(true, data) })
			}
		case *http2.WindowUpdateFrame:
			c.mu.Lock()
			if f.StreamID == 0 {
				c.connWindow += int64(f.Increment)
			} else if st := c.streams[f.StreamID]; st != nil {
				st.window += int64(f.Increment)
			}
			c.signalLocked()
			c.mu.Unlock()
		case *http2.MetaHeadersFrame:
			c.onHeaders(f, now)
		case *http2.DataFrame:
			c.onData(f, now)
		case *http2.RSTStreamFrame:
			c.failStream(f.StreamID, fmt.Sprintf("stream reset by server: %v", f.ErrCode), now)
		case *http2.GoAwayFrame:
			c.mu.Lock()
			c.goAway = true
			c.goAwayLast = f.LastStreamID
			c.goAwayCode = f.ErrCode
			for id, st := range c.streams {
				if id > f.LastStreamID && !st.ended {
					st.res.Err = fmt.Sprintf("server sent GOAWAY (%v, last stream %d) before processing stream %d",
						f.ErrCode, f.LastStreamID, id)
					c.endLocked(st, now)
				}
			}
			c.mu.Unlock()
		}
	}
}

// onSettings records the peer's SETTINGS and acknowledges them.
func (c *h2conn) onSettings(f *http2.SettingsFrame) {
	if f.IsAck() {
		c.mu.Lock()
		if !c.ackSeen {
			c.ackSeen = true
			close(c.gotAck)
		}
		c.mu.Unlock()
		return
	}
	c.mu.Lock()
	f.ForeachSetting(func(s http2.Setting) error {
		if s.Valid() != nil {
			return nil
		}
		switch s.ID {
		case http2.SettingMaxConcurrentStreams:
			c.peerMaxStreams = s.Val
			c.sawMaxStreams = true
		case http2.SettingInitialWindowSize:
			delta := int64(s.Val) - c.peerWindow
			for _, st := range c.streams {
				st.window += delta
			}
			c.peerWindow = int64(s.Val)
		case http2.SettingMaxFrameSize:
			c.peerMaxFrame = s.Val
		case http2.SettingHeaderTableSize:
			c.peerTableSize = s.Val
		}
		return nil
	})
	c.signalLocked()
	c.mu.Unlock()
	c.write(func(fr *http2.Framer) error { return fr.WriteSettingsAck() })
	c.mu.Lock()
	if !c.settingsSeen {
		c.settingsSeen = true
		close(c.gotSettings)
	}
	c.mu.Unlock()
}

// onHeaders records the response headers (or trailers) of a stream.
func (c *h2conn) onHeaders(f *http2.MetaHeadersFrame, now int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	st := c.streams[f.StreamID]
	if st == nil || st.ended {
		return
	}
	res := st.res
	if f.Truncated {
		res.Err = "invalid response: " + errHeaderTooLarge.Error()
		c.endLocked(st, now)
		return
	}
	if !st.gotHeaders {
		code, err := strconv.Atoi(f.PseudoValue("status"))
		if err == nil && code >= 100 && code < 200 {
			return // interim response; the final one follows
		}
		st.gotHeaders = true
		res.FirstByteNs = now
		res.Header = make(http.Header, len(f.RegularFields()))
		for _, hf := range f.RegularFields() {
			res.Header.Add(http.CanonicalHeaderKey(hf.Name), hf.Value)
		}
		if err != nil || code < 200 || code > 999 {
			res.Err = fmt.Sprintf("response without a valid :status (%q)", f.PseudoValue("status"))
		} else {
			res.Status = code
		}
	} else {
		// One trailer block may follow, and it must end the stream; any
		// other HEADERS frame would let the server grow the header
		// without bound for the whole race timeout.
		if !f.StreamEnded() {
			res.Err = "invalid response: unexpected HEADERS (trailers without END_STREAM)"
			c.endLocked(st, now)
			return
		}
		// Trailers are merged into the header.
		for _, hf := range f.RegularFields() {
			res.Header.Add(http.CanonicalHeaderKey(hf.Name), hf.Value)
		}
	}
	if f.StreamEnded() {
		c.endLocked(st, now)
	}
}

// onData keeps up to maxBody body bytes and returns the consumed bytes to
// the server's flow-control windows.
func (c *h2conn) onData(f *http2.DataFrame, now int64) {
	n := f.Header().Length // padding counts against flow control too
	data := f.Data()
	c.mu.Lock()
	st := c.streams[f.StreamID]
	if st != nil && !st.ended {
		res := st.res
		room := c.maxBody - len(res.Body)
		if len(data) > room {
			res.Body = append(res.Body, data[:max(room, 0)]...)
			res.Truncated = true
		} else {
			res.Body = append(res.Body, data...)
		}
		if f.StreamEnded() {
			c.endLocked(st, now)
		}
	}
	streamOpen := st != nil && !st.ended
	c.mu.Unlock()
	if n == 0 {
		return
	}
	c.write(func(fr *http2.Framer) error {
		if err := fr.WriteWindowUpdate(0, n); err != nil {
			return err
		}
		if streamOpen {
			return fr.WriteWindowUpdate(f.StreamID, n)
		}
		return nil
	})
}

// failStream ends stream id with msg.
func (c *h2conn) failStream(id uint32, msg string, now int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if st := c.streams[id]; st != nil && !st.ended {
		st.res.Err = msg
		c.endLocked(st, now)
	}
}

// fail records the read error and ends every open stream.
func (c *h2conn) fail(err error, now int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closing {
		err = errors.New("connection closed by the client")
	}
	c.readErr = err
	for _, st := range c.streams {
		if !st.ended {
			st.res.Err = fmt.Sprintf("connection lost before the response completed: %v", err)
			c.endLocked(st, now)
		}
	}
	c.signalLocked()
}
