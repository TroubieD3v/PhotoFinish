package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// syncBuffer is a bytes.Buffer safe for the concurrent writes of a running server.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestRunCommands(t *testing.T) {
	cases := []struct {
		name     string
		args     []string
		want     int
		stdout   string
		stderr   string
		noStdout bool
	}{
		{name: "no command", args: nil, want: exitUsage, stderr: "Usage:", noStdout: true},
		{name: "unknown command", args: []string{"race"}, want: exitUsage, stderr: `unknown command "race"`, noStdout: true},
		{name: "help", args: []string{"help"}, want: 0, stdout: "docs/DESIGN.ru.md"},
		{name: "--help", args: []string{"--help"}, want: 0, stdout: "photofinish serve [--addr"},
		{name: "help lists commands", args: []string{"help"}, want: 0, stdout: "photofinish run <scenario.yaml>..."},
		{name: "help lists probe", args: []string{"help"}, want: 0, stdout: "photofinish probe <url>"},
		{name: "help lists import", args: []string{"help"}, want: 0, stdout: "photofinish import <file>"},
		{name: "help states the usage exit code", args: []string{"help"}, want: 0, stdout: "Usage errors exit 64"},
		{name: "version", args: []string{"version"}, want: 0, stdout: "photofinish " + version + "\n"},
		{name: "--version", args: []string{"--version"}, want: 0, stdout: "photofinish " + version + "\n"},
		{name: "demo -h", args: []string{"demo", "-h"}, want: 0, stderr: "--expose"},
		{name: "demo unknown flag", args: []string{"demo", "--fast"}, want: exitUsage, stderr: "flag provided but not defined: -fast"},
		{name: "demo positional argument", args: []string{"demo", "extra"}, want: exitUsage, stderr: `unexpected argument "extra"`},
		{name: "demo bad window", args: []string{"demo", "--window", "soon"}, want: exitUsage, stderr: "--window"},
		{name: "demo negative window", args: []string{"demo", "--window", "-1ms"}, want: exitUsage, stderr: "between 0s and 2s"},
		{name: "demo window too large", args: []string{"demo", "--window", "3s"}, want: exitUsage, stderr: "between 0s and 2s"},
		{name: "demo address without port", args: []string{"demo", "--addr", "127.0.0.1"}, want: exitUsage, stderr: "--addr"},
		{name: "demo non-loopback address", args: []string{"demo", "--addr", "0.0.0.0:8443"}, want: exitUsage, stderr: "intentionally vulnerable"},
		{name: "demo public address", args: []string{"demo", "--addr", "192.0.2.10:8443", "--window", "5ms"}, want: exitUsage, stderr: "--expose"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if got := run(c.args, &stdout, &stderr); got != c.want {
				t.Errorf("exit code %d, want %d\nstdout: %s\nstderr: %s", got, c.want, stdout.String(), stderr.String())
			}
			if c.stdout != "" && !strings.Contains(stdout.String(), c.stdout) {
				t.Errorf("stdout does not contain %q:\n%s", c.stdout, stdout.String())
			}
			if c.stderr != "" && !strings.Contains(stderr.String(), c.stderr) {
				t.Errorf("stderr does not contain %q:\n%s", c.stderr, stderr.String())
			}
			if c.noStdout && stdout.Len() > 0 {
				t.Errorf("unexpected stdout:\n%s", stdout.String())
			}
		})
	}
}

func TestParseDemoDefaults(t *testing.T) {
	var stderr bytes.Buffer
	o, err := parseDemo(nil, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	want := demoOptions{addr: "127.0.0.1:8443"}
	if o != want {
		t.Errorf("defaults %+v, want %+v", o, want)
	}
}

func TestParseDemoFlags(t *testing.T) {
	var stderr bytes.Buffer
	o, err := parseDemo([]string{"--addr", "[::1]:9443", "--window", "5ms", "--quiet"}, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	want := demoOptions{addr: "[::1]:9443", window: 5 * time.Millisecond, quiet: true}
	if o != want {
		t.Errorf("parsed %+v, want %+v", o, want)
	}
	if _, err := parseDemo([]string{"--addr", "localhost:8443", "--window", "2s"}, &stderr); err != nil {
		t.Errorf("localhost with the maximum window rejected: %v", err)
	}
	if _, err := parseDemo([]string{"--addr", "0.0.0.0:8443", "--expose"}, &stderr); err != nil {
		t.Errorf("--expose did not allow a non-loopback address: %v", err)
	}
}

// TestDemoServesHTTP2 starts the shop on a free loopback port and checks the banner against
// what a client actually sees: HTTP/2 over TLS with the announced certificate.
func TestDemoServesHTTP2(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var stdout, stderr syncBuffer
	addrc := make(chan string, 1)
	errc := make(chan error, 1)
	o := demoOptions{addr: "127.0.0.1:0", window: time.Millisecond}
	go func() {
		errc <- runDemo(ctx, o, &stdout, &stderr, func(addr string) { addrc <- addr })
	}()

	var addr string
	select {
	case addr = <-addrc:
	case err := <-errc:
		t.Fatalf("demo stopped before it was ready: %v\n%s", err, stderr.String())
	case <-time.After(10 * time.Second):
		t.Fatal("demo was not ready within 10s")
	}

	banner := stdout.String()
	for _, want := range []string{
		"https://" + addr,
		"curl -k --http2 https://" + addr + "/",
		"demo-alice", "demo-bob",
		"in memory",
		"1ms (artificially widened",
		"intentionally vulnerable to race conditions - local testing only",
		"Ctrl+C to stop",
	} {
		if !strings.Contains(banner, want) {
			t.Errorf("banner does not contain %q:\n%s", want, banner)
		}
	}
	m := regexp.MustCompile(`SHA-256 ([0-9A-Fa-f:]+)`).FindStringSubmatch(banner)
	if m == nil {
		t.Fatalf("banner has no fingerprint:\n%s", banner)
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, // self-signed demo certificate
			ForceAttemptHTTP2: true,
		},
	}
	defer client.CloseIdleConnections()
	resp, err := client.Get("https://" + addr + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("/healthz status %d", resp.StatusCode)
	}
	if resp.ProtoMajor != 2 {
		t.Errorf("protocol %s, want HTTP/2", resp.Proto)
	}
	if resp.Header.Get("X-Arrival-Ns") == "" {
		t.Error("X-Arrival-Ns header missing")
	}
	sum := sha256.Sum256(resp.TLS.PeerCertificates[0].Raw)
	if got := fingerprintHex(sum[:]); !strings.EqualFold(got, m[1]) {
		t.Errorf("banner fingerprint %s, served certificate %s", m[1], got)
	}

	cancel()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("demo did not stop cleanly: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("demo did not stop within 10s")
	}
	if !strings.HasSuffix(stdout.String(), "stopped\n") {
		t.Errorf("no stop message:\n%s", stdout.String())
	}
}

// TestDemoRequestLogging checks that demo logs one line per request to
// stderr, with method, path, variant, status and duration, and that --quiet
// silences it.
func TestDemoRequestLogging(t *testing.T) {
	logLine := regexp.MustCompile(`GET /vuln/api/me variant=vuln status=200 dur=[0-9.]+(ns|µs|ms|s)\n`)
	for _, quiet := range []bool{false, true} {
		t.Run(fmt.Sprintf("quiet=%v", quiet), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var stdout, stderr syncBuffer
			addrc := make(chan string, 1)
			errc := make(chan error, 1)
			o := demoOptions{addr: "127.0.0.1:0", quiet: quiet}
			go func() {
				errc <- runDemo(ctx, o, &stdout, &stderr, func(addr string) { addrc <- addr })
			}()
			var addr string
			select {
			case addr = <-addrc:
			case err := <-errc:
				t.Fatalf("demo stopped before it was ready: %v\n%s", err, stderr.String())
			case <-time.After(10 * time.Second):
				t.Fatal("demo was not ready within 10s")
			}

			tr := &http.Transport{
				TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, // self-signed demo certificate
				ForceAttemptHTTP2: true,
			}
			defer tr.CloseIdleConnections()
			req, err := http.NewRequest(http.MethodGet, "https://"+addr+"/vuln/api/me", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer demo-alice")
			resp, err := (&http.Client{Transport: tr, Timeout: 10 * time.Second}).Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("/vuln/api/me status %d", resp.StatusCode)
			}

			cancel()
			select {
			case err := <-errc:
				if err != nil {
					t.Fatalf("demo did not stop cleanly: %v", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("demo did not stop within 10s")
			}
			logged := stderr.String()
			if quiet && logged != "" {
				t.Errorf("--quiet still wrote to stderr:\n%s", logged)
			}
			if !quiet && len(logLine.FindAllString(logged, -1)) != 1 {
				t.Errorf("want exactly one request log line on stderr matching %s, got:\n%s", logLine, logged)
			}
		})
	}
}

func fingerprintHex(b []byte) string {
	parts := make([]string, len(b))
	for i, c := range b {
		parts[i] = fmt.Sprintf("%02X", c)
	}
	return strings.Join(parts, ":")
}
