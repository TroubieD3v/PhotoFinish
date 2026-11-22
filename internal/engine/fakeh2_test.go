package engine

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/TroubieD3v/photofinish/internal/clock"
)

// The fake server speaks just enough HTTP/2 (with the x/net Framer) to
// record every frame the engine sends together with the index of the TLS
// read that delivered it. Go's tls.Conn returns the plaintext of at most one
// TLS record per Read (given a buffer larger than a record), so frames that
// share a read index arrived in the same TLS record.

// tls13Overhead is the size a TLS 1.3 AEAD record adds to its plaintext:
// 5 bytes of record header, 1 byte of inner content type, 16 bytes of tag.
const tls13Overhead = 5 + 1 + 16

// fakeH2Config controls the fake server.
type fakeH2Config struct {
	// settings are advertised in the server's SETTINGS frame.
	settings []http2.Setting
	// early makes the server answer on HEADERS, before END_STREAM.
	early bool
	// silent makes the server never answer race streams.
	silent bool
	// reset is a stream the server resets instead of answering.
	reset uint32
	// body is the response body.
	body string
	// respond, when set, writes the answer of a stream instead of the
	// default response.
	respond func(fr *http2.Framer, id uint32) error
}

// fakeFrame is one frame received by the fake server.
type fakeFrame struct {
	typ    http2.FrameType
	flags  http2.Flags
	stream uint32
	length uint32
	data   []byte              // DATA or PING payload
	fields []hpack.HeaderField // decoded HEADERS block
	// first and last are the indexes of the TLS reads that delivered the
	// first and the last byte of the frame.
	first, last int
}

func (f fakeFrame) endStream() bool {
	return (f.typ == http2.FrameData || f.typ == http2.FrameHeaders) && f.flags.Has(http2.FlagDataEndStream)
}

// fakeH2Server is a TLS 1.3 listener on 127.0.0.1 speaking HTTP/2.
type fakeH2Server struct {
	t      *testing.T
	cfg    fakeH2Config
	ln     net.Listener
	url    *url.URL
	client *tls.Config // trusts the server certificate
	done   chan struct{}

	mu     sync.Mutex
	reads  [][]byte // plaintext of every TLS read, in order
	frames []fakeFrame
	err    error
}

// fakeH2Start starts a fake server that serves one connection.
func fakeH2Start(t *testing.T, cfg fakeH2Config) *fakeH2Server {
	t.Helper()
	cert, pool := fakeCert(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &fakeH2Server{
		t:      t,
		cfg:    cfg,
		ln:     ln,
		url:    &url.URL{Scheme: "https", Host: ln.Addr().String(), Path: "/"},
		client: &tls.Config{RootCAs: pool},
		done:   make(chan struct{}),
	}
	go s.serve(&tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2"},
		MinVersion:   tls.VersionTLS13,
	})
	t.Cleanup(func() { ln.Close() })
	return s
}

// wait blocks until the served connection has ended (the client closed
// it) and fails the test on a server error.
func (s *fakeH2Server) wait() {
	s.t.Helper()
	select {
	case <-s.done:
	case <-time.After(10 * time.Second):
		s.t.Fatal("fake server: connection did not end")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		s.t.Fatalf("fake server: %v", s.err)
	}
}

// request returns a request for path on the fake server.
func (s *fakeH2Server) request(method, path string, body []byte) Request {
	u := *s.url
	u.Path = path
	return Request{Method: method, URL: &u, Body: body}
}

func (s *fakeH2Server) serve(cfg *tls.Config) {
	defer close(s.done)
	raw, err := s.ln.Accept()
	if err != nil {
		return // listener closed without a connection
	}
	s.mu.Lock()
	s.mu.Unlock()
	conn := tls.Server(raw, cfg)
	defer conn.Close()
	// The client ends the connection by closing it; depending on the OS and
	// on unread data that shows up as EOF or as a reset. Only protocol
	// errors are failures.
	var netErr *net.OpError
	if err := s.handle(conn); err != nil && !errors.Is(err, io.EOF) && !errors.As(err, &netErr) {
		s.mu.Lock()
		s.err = err
		s.mu.Unlock()
	}
}

// fakeReader feeds the framer from TLS reads and remembers which read each
// byte came from.
type fakeReader struct {
	s   *fakeH2Server
	r   io.Reader
	cur []byte
	idx int // index of the read cur belongs to
}

func (fr *fakeReader) Read(p []byte) (int, error) {
	if len(fr.cur) == 0 {
		buf := make([]byte, 64<<10) // larger than any TLS record
		n, err := fr.r.Read(buf)
		if n == 0 {
			if err == nil {
				err = io.ErrNoProgress
			}
			return 0, err
		}
		fr.cur = buf[:n]
		fr.s.mu.Lock()
		fr.s.reads = append(fr.s.reads, bytes.Clone(fr.cur))
		fr.idx = len(fr.s.reads) - 1
		fr.s.mu.Unlock()
	}
	n := copy(p, fr.cur)
	fr.cur = fr.cur[n:]
	return n, nil
}

// next returns the index of the read that will deliver the next byte.
func (fr *fakeReader) next() int {
	if len(fr.cur) > 0 {
		return fr.idx
	}
	fr.s.mu.Lock()
	defer fr.s.mu.Unlock()
	return len(fr.s.reads)
}

// fakeStream is a request stream as seen by the server.
type fakeStream struct {
	responded bool
}

func (s *fakeH2Server) handle(conn *tls.Conn) error {
	if err := conn.Handshake(); err != nil {
		return err
	}
	if p := conn.ConnectionState().NegotiatedProtocol; p != "h2" {
		return fmt.Errorf("ALPN %q", p)
	}
	rd := &fakeReader{s: s, r: conn, idx: -1}
	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(rd, preface); err != nil {
		return err
	}
	if string(preface) != http2.ClientPreface {
		return fmt.Errorf("bad preface %q", preface)
	}
	fr := http2.NewFramer(conn, rd)
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	var hbuf bytes.Buffer
	enc := hpack.NewEncoder(&hbuf)
	if err := fr.WriteSettings(s.cfg.settings...); err != nil {
		return err
	}

	streams := map[uint32]*fakeStream{}
	respond := func(id uint32) error {
		st := streams[id]
		if st == nil || st.responded {
			return nil
		}
		st.responded = true
		if id == s.cfg.reset {
			return fr.WriteRSTStream(id, http2.ErrCodeRefusedStream)
		}
		if s.cfg.respond != nil {
			return s.cfg.respond(fr, id)
		}
		hbuf.Reset()
		enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
		enc.WriteField(hpack.HeaderField{Name: "content-type", Value: "text/plain"})
		enc.WriteField(hpack.HeaderField{Name: "x-arrival-ns", Value: strconv.FormatInt(clock.UnixNano(), 10)})
		if err := fr.WriteHeaders(http2.HeadersFrameParam{
			StreamID: id, BlockFragment: hbuf.Bytes(), EndHeaders: true, EndStream: s.cfg.body == "",
		}); err != nil {
			return err
		}
		if s.cfg.body != "" {
			return fr.WriteData(id, true, []byte(s.cfg.body))
		}
		return nil
	}

	for {
		first := rd.next()
		f, err := fr.ReadFrame()
		if err != nil {
			return err
		}
		h := f.Header()
		rec := fakeFrame{typ: h.Type, flags: h.Flags, stream: h.StreamID, length: h.Length, first: first, last: rd.idx}
		var answer bool
		switch f := f.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				if err := fr.WriteSettingsAck(); err != nil {
					return err
				}
			}
		case *http2.PingFrame:
			rec.data = bytes.Clone(f.Data[:])
			if !f.IsAck() {
				if err := fr.WritePing(true, f.Data); err != nil {
					return err
				}
			}
		case *http2.MetaHeadersFrame:
			rec.typ = http2.FrameHeaders
			rec.fields = append([]hpack.HeaderField(nil), f.Fields...)
			streams[f.StreamID] = &fakeStream{}
			answer = s.cfg.early || f.StreamEnded()
		case *http2.DataFrame:
			rec.data = bytes.Clone(f.Data())
			answer = f.StreamEnded()
		}
		s.mu.Lock()
		s.frames = append(s.frames, rec)
		s.mu.Unlock()
		// Warm-up streams (odd ids before the race) are always answered.
		if answer && (!s.cfg.silent || rec.endStream() && s.isWarmup(h.StreamID)) {
			if err := respond(h.StreamID); err != nil {
				return err
			}
		}
	}
}

// isWarmup reports whether stream id was sent as a complete request: its
// HEADERS carried END_STREAM.
func (s *fakeH2Server) isWarmup(id uint32) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, f := range s.frames {
		if f.stream == id && f.typ == http2.FrameHeaders {
			return f.endStream()
		}
	}
	return false
}

// streamFrames returns the frames of stream id.
func (s *fakeH2Server) streamFrames(id uint32) []fakeFrame {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []fakeFrame
	for _, f := range s.frames {
		if f.stream == id {
			out = append(out, f)
		}
	}
	return out
}

// headersSeen returns the number of HEADERS frames received.
func (s *fakeH2Server) headersSeen() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, f := range s.frames {
		if f.typ == http2.FrameHeaders {
			n++
		}
	}
	return n
}

// fakeCert returns a throwaway certificate for 127.0.0.1 and a pool that
// trusts it.
func fakeCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "fake h2 server"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

// fakeGuard records Allow and Spend calls and can deny either.
type fakeGuard struct {
	mu        sync.Mutex
	allowed   []string
	spent     []int
	denyHost  error
	denySpend error
}

func (g *fakeGuard) Allow(host string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.allowed = append(g.allowed, host)
	return g.denyHost
}

func (g *fakeGuard) Spend(n int) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.spent = append(g.spent, n)
	return g.denySpend
}

// fakeRecordingConn records the size of every Write to the TCP connection.
// After the handshake, Go's TLS client writes each record with its own
// Write call.
type fakeRecordingConn struct {
	net.Conn
	mu     sync.Mutex
	writes []int
}

func (c *fakeRecordingConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.writes = append(c.writes, len(p))
	c.mu.Unlock()
	return c.Conn.Write(p)
}

func (c *fakeRecordingConn) sizes() []int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]int(nil), c.writes...)
}

// fakeHookDial installs an h2 dial hook for the test and returns the dialed
// connections. Run dials on the calling goroutine, so the test may read the
// slice once Run has returned.
func fakeHookDial(t *testing.T) *[]*fakeRecordingConn {
	t.Helper()
	conns := &[]*fakeRecordingConn{}
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := (&net.Dialer{}).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		rc := &fakeRecordingConn{Conn: c}
		*conns = append(*conns, rc)
		return rc, nil
	}
	h2DialHook.Store(&dial)
	t.Cleanup(func() { h2DialHook.Store(nil) })
	return conns
}

// fakeHoldRelease installs a release hook that waits until every race
// stream has ended before the release is written.
func fakeHoldRelease(t *testing.T) {
	t.Helper()
	hold := func(streams []*h2stream) {
		for _, st := range streams {
			<-st.done
		}
	}
	h2ReleaseHook.Store(&hold)
	t.Cleanup(func() { h2ReleaseHook.Store(nil) })
}

// fakeSettings returns typical server SETTINGS with the given
// MAX_CONCURRENT_STREAMS.
func fakeSettings(maxStreams uint32) []http2.Setting {
	return []http2.Setting{
		{ID: http2.SettingMaxConcurrentStreams, Val: maxStreams},
		{ID: http2.SettingInitialWindowSize, Val: 65535},
		{ID: http2.SettingMaxFrameSize, Val: 16384},
	}
}

func fakeField(fields []hpack.HeaderField, name string) (string, bool) {
	for _, f := range fields {
		if f.Name == name {
			return f.Value, true
		}
	}
	return "", false
}

func TestH2FakeServerAllFinalFramesInOneWrite(t *testing.T) {
	conns := fakeHookDial(t)
	srv := fakeH2Start(t, fakeH2Config{settings: fakeSettings(100), body: "ok"})
	const copies, warmup = 20, 2
	body := []byte(`{"code":"WELCOME10"}`)
	var reqs []Request
	for i := range copies {
		var r Request
		if i%2 == 0 {
			r = srv.request(http.MethodPost, "/apply", body)
			r.Header = http.Header{"Content-Type": {"application/json"}, "X-Copy": {strconv.Itoa(i)}}
		} else {
			r = srv.request(http.MethodGet, "/status", nil)
			r.URL.RawQuery = "copy=" + strconv.Itoa(i)
		}
		r.Label = fmt.Sprintf("copy %d", i)
		reqs = append(reqs, r)
	}
	guard := &fakeGuard{}
	race, err := Run(context.Background(), reqs, Options{
		Kind: H2, Warmup: warmup, Gate: 20 * time.Millisecond, TLS: srv.client, Guard: guard,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv.wait()

	// Guard: scope checked once for the host, budget spent once for all.
	if len(guard.allowed) != 1 || guard.allowed[0] != srv.url.Host {
		t.Errorf("Allow calls = %q, want [%q]", guard.allowed, srv.url.Host)
	}
	if len(guard.spent) != 1 || guard.spent[0] != copies+warmup {
		t.Errorf("Spend calls = %v, want [%d]", guard.spent, copies+warmup)
	}

	// Release record.
	wantBytes := copies/2*(9+1) + copies/2*9
	if race.Release.Writes != 1 || race.Release.Bytes != wantBytes || race.Release.SpreadNs != 0 {
		t.Errorf("Release = %+v, want 1 write of %d bytes, spread 0", race.Release, wantBytes)
	}
	if race.Kind != H2 || race.ALPN != "h2" || race.TLSVersion != "TLS 1.3" || race.Connections != 1 || race.Warmup != warmup {
		t.Errorf("race header = %+v", race)
	}
	for _, n := range race.Notes {
		if strings.Contains(n, "split") {
			t.Errorf("unexpected note %q", n)
		}
	}

	// Warm-up streams 1 and 3 are complete requests sent before the race.
	for _, id := range []uint32{1, 3} {
		fs := srv.streamFrames(id)
		if len(fs) != 1 || fs[0].typ != http2.FrameHeaders || !fs[0].endStream() {
			t.Fatalf("warm-up stream %d frames = %+v, want one HEADERS with END_STREAM", id, fs)
		}
		if p, _ := fakeField(fs[0].fields, ":path"); p != "/" {
			t.Errorf("warm-up stream %d path = %q, want /", id, p)
		}
	}

	// Every race stream: HEADERS without END_STREAM, pre-sent body bytes
	// without END_STREAM, then exactly one END_STREAM frame, all of those
	// in one and the same TLS read.
	releaseRead := -1
	var pingRead = -1
	srv.mu.Lock()
	for _, f := range srv.frames {
		if f.typ == http2.FramePing && !f.flags.Has(http2.FlagPingAck) && string(f.data) == "pfwarmup" {
			pingRead = f.last
		}
	}
	srv.mu.Unlock()
	if pingRead < 0 {
		t.Fatal(`no PING "pfwarmup" received`)
	}
	for i, r := range reqs {
		id := uint32(5 + 2*i)
		res := race.Results[i]
		if res.Stream != id || res.Index != i || res.Label != r.Label {
			t.Errorf("result %d: stream %d index %d label %q, want stream %d", i, res.Stream, res.Index, res.Label, id)
		}
		fs := srv.streamFrames(id)
		if len(fs) == 0 || fs[0].typ != http2.FrameHeaders {
			t.Fatalf("stream %d: first frame is not HEADERS: %+v", id, fs)
		}
		h := fs[0]
		if h.endStream() || !h.flags.Has(http2.FlagHeadersEndHeaders) {
			t.Errorf("stream %d HEADERS flags %v: want END_HEADERS without END_STREAM", id, h.flags)
		}
		wantPath := r.URL.RequestURI()
		for name, want := range map[string]string{
			":method": r.Method, ":scheme": "https", ":authority": srv.url.Host, ":path": wantPath,
		} {
			if got, _ := fakeField(h.fields, name); got != want {
				t.Errorf("stream %d %s = %q, want %q", id, name, got, want)
			}
		}
		cl, hasCL := fakeField(h.fields, "content-length")
		if len(r.Body) > 0 {
			if cl != strconv.Itoa(len(r.Body)) {
				t.Errorf("stream %d content-length = %q, want %d", id, cl, len(r.Body))
			}
			if ct, _ := fakeField(h.fields, "content-type"); ct != "application/json" {
				t.Errorf("stream %d content-type = %q", id, ct)
			}
		} else if hasCL {
			t.Errorf("stream %d: content-length %q on a bodyless request", id, cl)
		}

		var got []byte
		ends := 0
		for _, f := range fs[1:] {
			if f.typ != http2.FrameData {
				t.Errorf("stream %d: unexpected frame type %v", id, f.typ)
				continue
			}
			got = append(got, f.data...)
			if !f.endStream() {
				if f.last >= pingRead {
					t.Errorf("stream %d: pre-sent DATA arrived after the PING", id)
				}
				continue
			}
			ends++
			wantLen := 0
			if len(r.Body) > 0 {
				wantLen = 1
			}
			if len(f.data) != wantLen {
				t.Errorf("stream %d: final DATA carries %d bytes, want %d", id, len(f.data), wantLen)
			}
			if f.first != f.last {
				t.Errorf("stream %d: final frame spans reads %d..%d", id, f.first, f.last)
			}
			if releaseRead == -1 {
				releaseRead = f.first
			} else if f.first != releaseRead {
				t.Errorf("stream %d: final frame in read %d, others in read %d", id, f.first, releaseRead)
			}
		}
		if ends != 1 {
			t.Errorf("stream %d: %d END_STREAM frames, want exactly 1", id, ends)
		}
		if !bytes.Equal(got, r.Body) {
			t.Errorf("stream %d: server reassembled body %q, want %q", id, got, r.Body)
		}
	}
	if releaseRead <= pingRead {
		t.Errorf("release read %d is not after the PING read %d", releaseRead, pingRead)
	}
	// The release read holds the final frames and nothing else.
	srv.mu.Lock()
	if n := len(srv.reads[releaseRead]); n != race.Release.Bytes {
		t.Errorf("release TLS record carries %d bytes, want %d", n, race.Release.Bytes)
	}
	inRelease := 0
	for _, f := range srv.frames {
		if f.first == releaseRead || f.last == releaseRead {
			inRelease++
			if !f.endStream() || f.typ != http2.FrameData {
				t.Errorf("release read also carries %+v", f)
			}
		}
	}
	srv.mu.Unlock()
	if inRelease != copies {
		t.Errorf("release read carries %d frames, want %d", inRelease, copies)
	}

	// Independently, on the client's TCP connection: the write after the
	// PING record is the release, one TLS record of Release.Bytes.
	if len(*conns) != 1 {
		t.Fatalf("dialed %d connections, want 1", len(*conns))
	}
	sizes := (*conns)[0].sizes()
	pingSize := 9 + 8 + tls13Overhead
	releaseSize := race.Release.Bytes + tls13Overhead
	var at []int
	for i, n := range sizes {
		if n == releaseSize {
			at = append(at, i)
		}
	}
	if len(at) != 1 || at[0] == 0 || sizes[at[0]-1] != pingSize {
		t.Errorf("want exactly one %d-byte write (the release record) right after the %d-byte PING record; writes: %v",
			releaseSize, pingSize, sizes)
	}

	// Results.
	rel := race.Results[0].ReleasedNs
	for _, res := range race.Results {
		if res.Status != 200 || res.Proto != "HTTP/2.0" || res.Err != "" || string(res.Body) != "ok" {
			t.Errorf("result %d: status %d proto %q err %q body %q", res.Index, res.Status, res.Proto, res.Err, res.Body)
		}
		if res.ReleasedNs != rel {
			t.Errorf("result %d: ReleasedNs %d differs from %d", res.Index, res.ReleasedNs, rel)
		}
		if res.PreSentNs == 0 || res.PreSentNs > res.ReleasedNs || res.FirstByteNs == 0 || res.DoneNs < res.FirstByteNs {
			t.Errorf("result %d: timestamps pre %d rel %d first %d done %d out of order",
				res.Index, res.PreSentNs, res.ReleasedNs, res.FirstByteNs, res.DoneNs)
		}
		if res.EarlyResponse || res.ServerArrivalNs == 0 || res.Header.Get("Content-Type") != "text/plain" {
			t.Errorf("result %d: early %v arrival %d header %v", res.Index, res.EarlyResponse, res.ServerArrivalNs, res.Header)
		}
	}
	if race.StartedNs == 0 || race.FinishedNs < race.StartedNs {
		t.Errorf("race started %d finished %d", race.StartedNs, race.FinishedNs)
	}
}

func TestH2FakeServerSplitsLargeRelease(t *testing.T) {
	srv := fakeH2Start(t, fakeH2Config{settings: fakeSettings(1000)})
	const copies = 140
	reqs := make([]Request, copies)
	for i := range reqs {
		reqs[i] = srv.request(http.MethodGet, "/", nil)
	}
	race, err := Run(context.Background(), reqs, Options{Kind: H2, Gate: time.Millisecond, TLS: srv.client, Guard: AllowAll()})
	if err != nil {
		t.Fatal(err)
	}
	srv.wait()
	if race.Release.Writes != 2 || race.Release.Bytes != copies*9 {
		t.Fatalf("Release = %+v, want 2 writes of %d bytes in total", race.Release, copies*9)
	}
	split := false
	for _, n := range race.Notes {
		split = split || strings.Contains(n, "split into 2 writes")
	}
	if !split {
		t.Errorf("notes %q do not mention the split", race.Notes)
	}

	perRead := map[int]int{}
	srv.mu.Lock()
	for _, f := range srv.frames {
		if f.endStream() {
			if f.first != f.last {
				t.Errorf("stream %d: final frame spans two reads", f.stream)
			}
			perRead[f.first]++
		}
	}
	for read := range perRead {
		if n := len(srv.reads[read]); n > h2ReleaseSegment {
			t.Errorf("release read %d carries %d bytes, more than %d", read, n, h2ReleaseSegment)
		}
	}
	srv.mu.Unlock()
	if len(perRead) != 2 {
		t.Errorf("final frames arrived in %d reads, want 2: %v", len(perRead), perRead)
	}
	first := h2ReleaseSegment / 9
	for i, res := range race.Results {
		want := race.Results[0].ReleasedNs
		if i >= first {
			want = race.Results[copies-1].ReleasedNs
		}
		if res.ReleasedNs != want || res.Status != 200 {
			t.Errorf("result %d: released %d (want %d) status %d", i, res.ReleasedNs, want, res.Status)
		}
	}
	if spread := race.Results[copies-1].ReleasedNs - race.Results[0].ReleasedNs; race.Release.SpreadNs != spread || spread < 0 {
		t.Errorf("SpreadNs = %d, want %d", race.Release.SpreadNs, spread)
	}
}

func TestH2RefusesMoreCopiesThanMaxConcurrentStreams(t *testing.T) {
	srv := fakeH2Start(t, fakeH2Config{settings: fakeSettings(5)})
	reqs := make([]Request, 6)
	for i := range reqs {
		reqs[i] = srv.request(http.MethodGet, "/", nil)
	}
	guard := &fakeGuard{}
	_, err := Run(context.Background(), reqs, Options{Kind: H2, TLS: srv.client, Guard: guard})
	if err == nil || !strings.Contains(err.Error(), "6 copies") || !strings.Contains(err.Error(), "MAX_CONCURRENT_STREAMS of 5") {
		t.Fatalf("err = %v, want a refusal naming 6 copies and the limit 5", err)
	}
	srv.wait()
	if len(guard.spent) != 0 {
		t.Errorf("budget spent %v on a refused race", guard.spent)
	}
	if n := srv.headersSeen(); n != 0 {
		t.Errorf("server received %d requests", n)
	}
}

func TestH2RefusesBodiesLargerThanFlowControlWindow(t *testing.T) {
	cases := []struct {
		name     string
		settings []http2.Setting
		copies   int
		body     int
		want     string
	}{
		{"stream window", []http2.Setting{{ID: http2.SettingInitialWindowSize, Val: 16}}, 2, 32, "stream flow-control window is 16"},
		{"connection window", fakeSettings(100), 20, 4000, "too large for 20 copies"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := fakeH2Start(t, fakeH2Config{settings: tc.settings})
			reqs := make([]Request, tc.copies)
			for i := range reqs {
				reqs[i] = srv.request(http.MethodPost, "/", bytes.Repeat([]byte("x"), tc.body))
			}
			guard := &fakeGuard{}
			_, err := Run(context.Background(), reqs, Options{Kind: H2, TLS: srv.client, Guard: guard})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to contain %q", err, tc.want)
			}
			srv.wait()
			if len(guard.spent) != 0 || srv.headersSeen() != 0 {
				t.Errorf("spent %v, server saw %d requests; want nothing", guard.spent, srv.headersSeen())
			}
		})
	}
}

func TestH2GuardDenialAbortsBeforeDialing(t *testing.T) {
	conns := fakeHookDial(t)
	srv := fakeH2Start(t, fakeH2Config{settings: fakeSettings(100)})
	denied := errors.New("host not in scope")
	guard := &fakeGuard{denyHost: denied}
	_, err := Run(context.Background(), []Request{srv.request(http.MethodGet, "/", nil)},
		Options{Kind: H2, TLS: srv.client, Guard: guard})
	if !errors.Is(err, denied) {
		t.Fatalf("err = %v, want the guard's error", err)
	}
	if len(*conns) != 0 {
		t.Errorf("dialed %d connections after a scope denial", len(*conns))
	}
	if len(guard.spent) != 0 {
		t.Errorf("budget spent %v after a scope denial", guard.spent)
	}
}

func TestH2BudgetDenialSendsNoRequest(t *testing.T) {
	srv := fakeH2Start(t, fakeH2Config{settings: fakeSettings(100)})
	exhausted := errors.New("budget exhausted")
	guard := &fakeGuard{denySpend: exhausted}
	reqs := []Request{srv.request(http.MethodGet, "/", nil), srv.request(http.MethodGet, "/", nil)}
	_, err := Run(context.Background(), reqs, Options{Kind: H2, Warmup: 3, TLS: srv.client, Guard: guard})
	if !errors.Is(err, exhausted) {
		t.Fatalf("err = %v, want the guard's error", err)
	}
	srv.wait()
	if len(guard.spent) != 1 || guard.spent[0] != 5 {
		t.Errorf("Spend calls = %v, want [5]", guard.spent)
	}
	if n := srv.headersSeen(); n != 0 {
		t.Errorf("server received %d requests after a budget denial", n)
	}
}

func TestH2EarlyResponseIsFlagged(t *testing.T) {
	srv := fakeH2Start(t, fakeH2Config{settings: fakeSettings(100), early: true})
	// The server answers on HEADERS; holding the release until those
	// answers are complete makes the early arrival deterministic.
	fakeHoldRelease(t)
	reqs := []Request{srv.request(http.MethodGet, "/static.css", nil), srv.request(http.MethodGet, "/static.css", nil)}
	race, err := Run(context.Background(), reqs, Options{Kind: H2, Gate: time.Millisecond, TLS: srv.client, Guard: AllowAll()})
	if err != nil {
		t.Fatal(err)
	}
	srv.wait()
	for _, res := range race.Results {
		if res.Status != 200 || !res.EarlyResponse || res.FirstByteNs >= res.ReleasedNs {
			t.Errorf("result %d: status %d early %v first %d released %d; want an early response",
				res.Index, res.Status, res.EarlyResponse, res.FirstByteNs, res.ReleasedNs)
		}
	}
}

func TestH2StreamResetIsReported(t *testing.T) {
	srv := fakeH2Start(t, fakeH2Config{settings: fakeSettings(100), reset: 3})
	reqs := []Request{srv.request(http.MethodGet, "/", nil), srv.request(http.MethodGet, "/", nil)}
	race, err := Run(context.Background(), reqs, Options{Kind: H2, Gate: time.Millisecond, TLS: srv.client, Guard: AllowAll()})
	if err != nil {
		t.Fatal(err)
	}
	srv.wait()
	if r := race.Results[0]; r.Status != 200 || r.Err != "" {
		t.Errorf("result 0: status %d err %q", r.Status, r.Err)
	}
	if r := race.Results[1]; r.Status != 0 || !strings.Contains(r.Err, "reset") || r.DoneNs == 0 {
		t.Errorf("result 1: status %d err %q done %d; want a reset", r.Status, r.Err, r.DoneNs)
	}
}

func TestH2TimeoutIsReportedPerResult(t *testing.T) {
	srv := fakeH2Start(t, fakeH2Config{settings: fakeSettings(100), silent: true})
	reqs := []Request{srv.request(http.MethodGet, "/", nil)}
	race, err := Run(context.Background(), reqs, Options{
		Kind: H2, Gate: time.Millisecond, Timeout: time.Second, TLS: srv.client, Guard: AllowAll(),
	})
	if err != nil {
		t.Fatal(err)
	}
	srv.wait()
	if r := race.Results[0]; r.Status != 0 || !strings.Contains(r.Err, "timeout") {
		t.Errorf("result: status %d err %q; want a timeout", r.Status, r.Err)
	}
}

func TestH2LargeHeaderBlockUsesContinuation(t *testing.T) {
	srv := fakeH2Start(t, fakeH2Config{settings: fakeSettings(100)})
	big := strings.Repeat("a", 40000)
	r := srv.request(http.MethodGet, "/", nil)
	r.Header = http.Header{"X-Big": {big}}
	race, err := Run(context.Background(), []Request{r}, Options{Kind: H2, Gate: time.Millisecond, TLS: srv.client, Guard: AllowAll()})
	if err != nil {
		t.Fatal(err)
	}
	srv.wait()
	if race.Results[0].Status != 200 {
		t.Fatalf("status %d err %q", race.Results[0].Status, race.Results[0].Err)
	}
	fs := srv.streamFrames(1)
	if len(fs) == 0 || fs[0].typ != http2.FrameHeaders {
		t.Fatalf("frames %+v", fs)
	}
	if v, _ := fakeField(fs[0].fields, "x-big"); v != big {
		t.Errorf("x-big arrived with %d bytes, want %d", len(v), len(big))
	}
	if fs[0].length > 16384 {
		t.Errorf("HEADERS frame of %d bytes exceeds the peer max frame size", fs[0].length)
	}
}
