package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"
)

// serveToken is the session token of the serve tests; it is not
// secret-shaped on purpose.
const serveToken = "serve-test-token-abcdefghijklmnopqrstuvwxyz"

// withEnv makes getenv return the given variables for the test.
func withEnv(t *testing.T, vars map[string]string) {
	t.Helper()
	old := getenv
	getenv = func(k string) string { return vars[k] }
	t.Cleanup(func() { getenv = old })
}

func TestServeFlags(t *testing.T) {
	withEnv(t, nil)
	dir := t.TempDir()
	file := filepath.Join(dir, "file.yaml")
	if err := os.WriteFile(file, []byte("x: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		args   []string
		want   int
		stderr string
	}{
		{"help", []string{"serve", "-h"}, exitOK, "PHOTOFINISH_TOKEN"},
		{"non-loopback address", []string{"serve", "--addr", "0.0.0.0:7340", "--data", ""}, exitUsage, "--expose"},
		{"public address", []string{"serve", "--addr", "192.0.2.10:7340", "--data", ""}, exitUsage, "loopback"},
		{"host name", []string{"serve", "--addr", "example.test:7340", "--data", ""}, exitUsage, "--expose"},
		{"address without port", []string{"serve", "--addr", "127.0.0.1", "--data", ""}, exitUsage, "--addr"},
		{"positional argument", []string{"serve", "extra", "--data", ""}, exitUsage, `unexpected argument "extra"`},
		{"unknown flag", []string{"serve", "--port", "1"}, exitUsage, "flag provided but not defined"},
		{"missing workspace", []string{"serve", "--workspace", filepath.Join(dir, "missing"), "--data", ""}, exitUsage, "--workspace"},
		{"workspace is a file", []string{"serve", "--workspace", file, "--data", ""}, exitUsage, "not a directory"},
		{"public demo address", []string{"serve", "--demo-addr", "0.0.0.0:8443", "--data", ""}, exitUsage, "loopback only"},
		{"bad demo address", []string{"serve", "--demo-addr", "8443", "--data", ""}, exitUsage, "--demo-addr"},
		{"demo window too large", []string{"serve", "--demo-window", "3s", "--data", ""}, exitUsage, "between 0s and 2s"},
		{"negative demo window", []string{"serve", "--demo-window", "-1ms", "--data", ""}, exitUsage, "--demo-window"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if got := run(c.args, &stdout, &stderr); got != c.want {
				t.Errorf("exit %d, want %d\nstderr: %s", got, c.want, stderr.String())
			}
			if !strings.Contains(stderr.String(), c.stderr) {
				t.Errorf("stderr lacks %q:\n%s", c.stderr, stderr.String())
			}
			if c.want != exitOK && stdout.Len() > 0 {
				t.Errorf("stdout: %s", stdout.String())
			}
		})
	}
}

func TestServeToken(t *testing.T) {
	t.Run("short PHOTOFINISH_TOKEN", func(t *testing.T) {
		withEnv(t, map[string]string{tokenEnv: "too-short"})
		var stdout, stderr bytes.Buffer
		if got := run([]string{"serve", "--data", ""}, &stdout, &stderr); got != exitUsage {
			t.Errorf("exit %d", got)
		}
		if !strings.Contains(stderr.String(), "PHOTOFINISH_TOKEN") || !strings.Contains(stderr.String(), "32") {
			t.Errorf("stderr: %s", stderr.String())
		}
	})
	t.Run("from the environment", func(t *testing.T) {
		withEnv(t, map[string]string{tokenEnv: serveToken})
		o, err := parseServe([]string{"--data", ""}, io.Discard)
		if err != nil || o.token != serveToken {
			t.Errorf("token %q, %v", o.token, err)
		}
	})
	t.Run("generated", func(t *testing.T) {
		withEnv(t, nil)
		a, err := parseServe([]string{"--data", ""}, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := parseServe([]string{"--data", ""}, io.Discard)
		if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(a.token) || a.token == b.token {
			t.Errorf("tokens %q %q", a.token, b.token)
		}
	})
	t.Run("defaults", func(t *testing.T) {
		withEnv(t, nil)
		o, err := parseServe(nil, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		if o.addr != "127.0.0.1:7340" || o.workspace != "." || o.data != defaultDataDir() || o.demo || o.expose || o.open || o.demoAddr != "127.0.0.1:8443" {
			t.Errorf("defaults %+v", o)
		}
	})
}

func TestHelpListsServe(t *testing.T) {
	var stdout bytes.Buffer
	run([]string{"help"}, &stdout, io.Discard)
	if !strings.Contains(stdout.String(), "photofinish serve [--addr 127.0.0.1:7340]") || strings.Contains(stdout.String(), "arrives in milestone M4") {
		t.Errorf("help:\n%s", stdout.String())
	}
}

// served is a running serve command.
type served struct {
	addr   string
	stdout *syncBuffer
	stderr *syncBuffer
	stop   func() error
}

// startServe runs serve with o until the test ends or stop is called.
func startServe(t *testing.T, o serveOptions) *served {
	t.Helper()
	if o.addr == "" {
		o.addr = "127.0.0.1:0"
	}
	if o.workspace == "" {
		o.workspace = t.TempDir()
	}
	if o.token == "" {
		o.token = serveToken
	}
	if o.demoAddr == "" {
		o.demoAddr = "127.0.0.1:0" // never the 8443 of a real demo shop
	}
	s := &served{stdout: &syncBuffer{}, stderr: &syncBuffer{}}
	ctx, cancel := context.WithCancel(context.Background())
	addrc := make(chan string, 1)
	errc := make(chan error, 1)
	go func() { errc <- runServe(ctx, o, s.stdout, s.stderr, func(a string) { addrc <- a }) }()
	stopped := false
	var stopErr error
	s.stop = func() error {
		if !stopped {
			stopped = true
			cancel()
			select {
			case stopErr = <-errc:
			case <-time.After(30 * time.Second):
				stopErr = context.DeadlineExceeded
			}
		}
		return stopErr
	}
	t.Cleanup(func() {
		if err := s.stop(); err != nil {
			t.Errorf("serve: %v", err)
		}
	})
	select {
	case s.addr = <-addrc:
	case err := <-errc:
		stopped = true
		t.Fatalf("serve did not start: %v\n%s", err, s.stderr.String())
	case <-time.After(30 * time.Second):
		t.Fatal("serve did not start")
	}
	return s
}

// call sends one request to a served instance.
func (s *served) call(t *testing.T, method, path, token, body string) (int, []byte) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, "http://"+s.addr+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, data
}

func TestServeStartsAndStops(t *testing.T) {
	ws := t.TempDir()
	s := startServe(t, serveOptions{workspace: ws, data: ""})
	out := s.stdout.String()
	wantLine := "PhotoFinish UI: http://" + s.addr + "/#token=" + serveToken + "\n"
	if !strings.HasPrefix(out, wantLine) {
		t.Errorf("stdout does not start with %q:\n%s", wantLine, out)
	}
	if strings.Count(out, serveToken) != 1 {
		t.Errorf("the token is printed %d times", strings.Count(out, serveToken))
	}
	if !strings.Contains(out, "history    in memory") {
		t.Errorf("stdout: %s", out)
	}

	if code, body := s.call(t, "GET", "/api/health", "", ""); code != 200 || !strings.Contains(string(body), `"status":"ok"`) {
		t.Errorf("health: %d %s", code, body)
	}
	if code, _ := s.call(t, "GET", "/api/info", "", ""); code != http.StatusUnauthorized {
		t.Errorf("info without token: %d", code)
	}
	code, body := s.call(t, "GET", "/api/info", serveToken, "")
	if code != 200 {
		t.Fatalf("info: %d %s", code, body)
	}
	var info struct {
		Workspace string `json:"workspace"`
		DataDir   string `json:"dataDir"`
	}
	if err := json.Unmarshal(body, &info); err != nil {
		t.Fatal(err)
	}
	wantWS, _ := filepath.EvalSymlinks(ws)
	if info.Workspace != wantWS || info.DataDir != "" {
		t.Errorf("info %+v, workspace %s", info, wantWS)
	}
	// The real listener enforces the Host check.
	req, _ := http.NewRequest("GET", "http://"+s.addr+"/api/info", nil)
	req.Host = "rebound.example.test"
	req.Header.Set("Authorization", "Bearer "+serveToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMisdirectedRequest {
		t.Errorf("rebound host: %d", resp.StatusCode)
	}
	if code, body := s.call(t, "GET", "/", "", ""); code != 200 || !strings.Contains(strings.ToLower(string(body)), "<html") {
		t.Errorf("UI: %d %s", code, body)
	}

	if err := s.stop(); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(s.stdout.String(), "stopped\n") {
		t.Errorf("stdout: %s", s.stdout.String())
	}
	if _, err := net.DialTimeout("tcp", s.addr, time.Second); err == nil {
		t.Error("still listening after stop")
	}
}

func TestServeOpenAndExpose(t *testing.T) {
	var opened []string
	old := openBrowser
	openBrowser = func(u string) error { opened = append(opened, u); return nil }
	t.Cleanup(func() { openBrowser = old })

	s := startServe(t, serveOptions{data: "", open: true, expose: true})
	// The token must not be on a command line, where other local users
	// can read it: the browser gets a private redirect page instead.
	if len(opened) != 1 || strings.Contains(opened[0], serveToken) || filepath.Base(opened[0]) != "open.html" {
		t.Fatalf("opened %v", opened)
	}
	page, err := os.ReadFile(opened[0])
	if err != nil {
		t.Fatal(err)
	}
	link := "http://" + s.addr + "/#token=" + serveToken
	if !strings.Contains(string(page), `href="`+link+`"`) || !strings.Contains(string(page), "location.replace(") {
		t.Errorf("redirect page:\n%s", page)
	}
	if fi, err := os.Stat(opened[0]); err != nil {
		t.Fatal(err)
	} else if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Errorf("redirect page mode %v, want 0600", fi.Mode().Perm())
	}
	defer func() {
		if err := s.stop(); err != nil {
			t.Error(err)
		}
		if _, err := os.Stat(filepath.Dir(opened[0])); !os.IsNotExist(err) {
			t.Errorf("the redirect page was not removed on shutdown: %v", err)
		}
	}()
	if !strings.Contains(s.stderr.String(), "warning: --expose") {
		t.Errorf("stderr: %s", s.stderr.String())
	}
	// With --expose any Host header is accepted; the token is still needed.
	req, _ := http.NewRequest("GET", "http://"+s.addr+"/api/info", nil)
	req.Host = "lab.example.test:7340"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("exposed without token: %d", resp.StatusCode)
	}
}

func TestServeDemoAndHistory(t *testing.T) {
	data := t.TempDir()
	s := startServe(t, serveOptions{data: data, demo: true})
	if !strings.Contains(s.stdout.String(), "demo shop  https://127.0.0.1:") {
		t.Errorf("stdout: %s", s.stdout.String())
	}
	code, body := s.call(t, "GET", "/api/info", serveToken, "")
	if code != 200 || !strings.Contains(string(body), `"running":true`) {
		t.Errorf("info: %d %s", code, body)
	}
	// An invalid scenario finishes at once with ERROR and is stored.
	code, body = s.call(t, "POST", "/api/runs", serveToken, `{"content":"version: 1\n"}`)
	if code != http.StatusAccepted {
		t.Fatalf("run: %d %s", code, body)
	}
	var started struct{ ID string }
	json.Unmarshal(body, &started)
	deadline := time.Now().Add(30 * time.Second)
	for {
		_, body = s.call(t, "GET", "/api/runs/"+started.ID, serveToken, "")
		if strings.Contains(string(body), `"status":"finished"`) || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := s.stop(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(data, "photofinish.db")); err != nil {
		t.Fatalf("no database: %v", err)
	}

	// A second instance over the same data directory lists the run.
	s2 := startServe(t, serveOptions{data: data})
	code, body = s2.call(t, "GET", "/api/runs", serveToken, "")
	if code != 200 || !strings.Contains(string(body), started.ID) || !strings.Contains(string(body), `"verdict":"ERROR"`) {
		t.Errorf("history after restart: %d %s", code, body)
	}
}

func TestServePortInUse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var stdout, stderr bytes.Buffer
	o := serveOptions{addr: ln.Addr().String(), workspace: t.TempDir(), token: serveToken, demoAddr: "127.0.0.1:0"}
	err = runServe(context.Background(), o, &stdout, &stderr, nil)
	if err == nil || !strings.Contains(err.Error(), "listen") {
		t.Errorf("err %v", err)
	}
	if strings.Contains(stdout.String(), "PhotoFinish UI") {
		t.Error("printed the UI link without listening")
	}
}

func TestUIURL(t *testing.T) {
	cases := map[string]string{
		"127.0.0.1:7340": "http://127.0.0.1:7340/",
		"0.0.0.0:7340":   "http://127.0.0.1:7340/",
		"[::]:7340":      "http://[::1]:7340/",
		"[::1]:7340":     "http://[::1]:7340/",
		"localhost:80":   "http://localhost:80/",
	}
	for in, want := range cases {
		if got := uiURL(in); got != want {
			t.Errorf("uiURL(%s) = %s, want %s", in, got, want)
		}
	}
}
