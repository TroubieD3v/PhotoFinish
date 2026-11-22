package engine

import (
	"bufio"
	"bytes"
	"io"
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
)

// endlessHeaderServer answers every connection with a status line and a
// header line that does not end: twice MaxHeaderBytes of 'a', then nothing
// until the client closes the connection.
func endlessHeaderServer(t *testing.T) *url.URL {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	t.Cleanup(func() {
		ln.Close()
		wg.Wait()
	})
	wg.Go(func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Go(func() {
				defer c.Close()
				// Read the request head, then flood the response head.
				br := bufio.NewReader(c)
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					if line == "\r\n" {
						break
					}
				}
				io.WriteString(c, "HTTP/1.1 200 OK\r\nX-A: ")
				chunk := bytes.Repeat([]byte("a"), 64<<10)
				for range 2 * MaxHeaderBytes / len(chunk) {
					if _, err := c.Write(chunk); err != nil {
						return
					}
				}
				io.Copy(io.Discard, c) // until the client closes
			})
		}
	})
	return &url.URL{Scheme: "http", Host: ln.Addr().String(), Path: "/"}
}

func TestH1RejectsOversizedResponseHeaders(t *testing.T) {
	u := endlessHeaderServer(t)
	race, err := Run(t.Context(), h1Copies(u, 2), Options{Kind: H1, Gate: time.Millisecond, Timeout: 10 * time.Second, Guard: AllowAll()})
	if err != nil {
		t.Fatal(err)
	}
	for i, r := range race.Results {
		if r.Status != 0 || !strings.Contains(r.Err, "response headers exceed 1024 KiB") {
			t.Errorf("result %d: status %d error %q", i, r.Status, r.Err)
		}
	}
}

func TestProbeRejectsOversizedResponseHeaders(t *testing.T) {
	u := endlessHeaderServer(t)
	_, err := Probe(t.Context(), u, Options{Timeout: 10 * time.Second, Guard: AllowAll()})
	if err == nil || !strings.Contains(err.Error(), "response headers exceed") {
		t.Errorf("Probe error %v", err)
	}
}

// h2Responder returns a fake server responder that answers a stream with
// the given header blocks, none with END_STREAM, split into CONTINUATION
// frames as needed.
func h2Responder(blocks ...[]hpack.HeaderField) func(fr *http2.Framer, id uint32) error {
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	return func(fr *http2.Framer, id uint32) error {
		for _, fields := range blocks {
			buf.Reset()
			for _, f := range fields {
				f.Sensitive = true // never indexed: the block size is what it says
				enc.WriteField(f)
			}
			block := buf.Bytes()
			const frame = 16384
			first := block[:min(len(block), frame)]
			if err := fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: first, EndHeaders: len(block) <= frame}); err != nil {
				return err
			}
			for rest := block[len(first):]; len(rest) > 0; {
				n := min(len(rest), frame)
				if err := fr.WriteContinuation(id, n == len(rest), rest[:n]); err != nil {
					return err
				}
				rest = rest[n:]
			}
		}
		return nil
	}
}

func TestH2RejectsRepeatedHeaders(t *testing.T) {
	status := []hpack.HeaderField{{Name: ":status", Value: "200"}}
	junk := []hpack.HeaderField{{Name: "x-junk", Value: strings.Repeat("j", 1000)}}
	srv := fakeH2Start(t, fakeH2Config{settings: fakeSettings(100), respond: h2Responder(status, junk, junk, junk)})
	reqs := []Request{srv.request(http.MethodGet, "/", nil)}
	race, err := Run(t.Context(), reqs, Options{Kind: H2, Gate: time.Millisecond, Timeout: 10 * time.Second, TLS: srv.client, Guard: AllowAll()})
	if err != nil {
		t.Fatal(err)
	}
	srv.wait()
	r := race.Results[0]
	if !strings.Contains(r.Err, "unexpected HEADERS") || len(r.Header.Values("X-Junk")) != 0 {
		t.Errorf("status %d err %q header %d values", r.Status, r.Err, len(r.Header.Values("X-Junk")))
	}
}

func TestH2RejectsOversizedHeaders(t *testing.T) {
	block := []hpack.HeaderField{{Name: ":status", Value: "200"}}
	for i := range 300 {
		block = append(block, hpack.HeaderField{Name: "x-f" + strconv.Itoa(i), Value: strings.Repeat("a", 4000)})
	}
	srv := fakeH2Start(t, fakeH2Config{settings: fakeSettings(100), respond: h2Responder(block)})
	reqs := []Request{srv.request(http.MethodGet, "/", nil)}
	race, err := Run(t.Context(), reqs, Options{Kind: H2, Gate: time.Millisecond, Timeout: 10 * time.Second, TLS: srv.client, Guard: AllowAll()})
	if err != nil {
		t.Fatal(err)
	}
	srv.wait()
	r := race.Results[0]
	if r.Status != 0 || r.Err == "" || len(r.Header) != 0 {
		t.Errorf("status %d err %q header fields %d; want the stream to fail", r.Status, r.Err, len(r.Header))
	}
}
