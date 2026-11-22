package server

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TroubieD3v/photofinish/examples"
	"github.com/TroubieD3v/photofinish/internal/store"
)

// testToken is the session token of the test servers; it is not
// secret-shaped on purpose.
const testToken = "test-session-token-0123456789abcdef"

// env is a running test server with its workspace and store.
type env struct {
	t         *testing.T
	ts        *httptest.Server
	srv       *Server
	store     *store.Store
	workspace string
	host      string // host:port of ts
}

// option changes the Config of a test server.
type option func(*Config)

// withUI serves fsys as the built UI.
func withUI(fsys fs.FS) option { return func(c *Config) { c.UI = fsys } }

// exposed accepts any Host header.
func exposed() option { return func(c *Config) { c.Expose = true } }

// demoWindow widens the race window of the demo shop, as the example
// tests of the run command do, so that a few trials reliably show the race.
func demoWindow(d time.Duration) option { return func(c *Config) { c.DemoWindow = d } }

// withStore replaces the store.
func withStore(st Store) option { return func(c *Config) { c.Store = st } }

// newEnv starts a test server over a fresh temporary workspace. The demo
// shop of the server listens on a free port, not on 8443.
func newEnv(t *testing.T, opts ...option) *env {
	t.Helper()
	ws := t.TempDir()
	st, err := store.Open(store.Memory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	cfg := Config{
		Version:   "test",
		Workspace: ws,
		Token:     testToken,
		Store:     st,
		DemoAddr:  "127.0.0.1:0",
		Examples:  examples.FS,
	}
	for _, o := range opts {
		o(&cfg)
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() {
		ts.Close()
		if err := srv.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	return &env{t: t, ts: ts, srv: srv, store: st, workspace: srv.Workspace(), host: strings.TrimPrefix(ts.URL, "http://")}
}

// request describes one API call; the zero value is an authorized GET.
type request struct {
	method  string
	path    string
	body    any // string, []byte or a value encoded as JSON
	header  map[string]string
	noToken bool
	host    string // overrides the Host header
}

// response is a finished API call.
type response struct {
	code   int
	header http.Header
	body   []byte
}

// json decodes the body into v.
func (r response) json(t *testing.T, v any) {
	t.Helper()
	if err := json.Unmarshal(r.body, v); err != nil {
		t.Fatalf("decode %s: %v", r.body, err)
	}
}

// errorText returns the "error" field of a JSON error body.
func (r response) errorText(t *testing.T) string {
	t.Helper()
	var e errorBody
	r.json(t, &e)
	if e.Error == "" {
		t.Fatalf("no error message in %s", r.body)
	}
	return e.Error
}

// do sends req and reads the whole response.
func (e *env) do(req request) response {
	e.t.Helper()
	method := req.method
	if method == "" {
		method = http.MethodGet
	}
	var body io.Reader
	var isJSON bool
	switch b := req.body.(type) {
	case nil:
	case string:
		body, isJSON = strings.NewReader(b), true
	case []byte:
		body, isJSON = bytes.NewReader(b), true
	default:
		data, err := json.Marshal(b)
		if err != nil {
			e.t.Fatal(err)
		}
		body, isJSON = bytes.NewReader(data), true
	}
	hr, err := http.NewRequest(method, e.ts.URL+req.path, body)
	if err != nil {
		e.t.Fatal(err)
	}
	if isJSON {
		hr.Header.Set("Content-Type", "application/json")
	}
	if !req.noToken {
		hr.Header.Set("Authorization", "Bearer "+testToken)
	}
	for k, v := range req.header {
		hr.Header.Set(k, v)
	}
	if req.host != "" {
		hr.Host = req.host
	}
	resp, err := e.ts.Client().Do(hr)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		e.t.Fatal(err)
	}
	return response{code: resp.StatusCode, header: resp.Header, body: data}
}

// get is an authorized GET.
func (e *env) get(path string) response {
	e.t.Helper()
	return e.do(request{path: path})
}

// post is an authorized POST with a JSON body.
func (e *env) post(path string, body any) response {
	e.t.Helper()
	return e.do(request{method: http.MethodPost, path: path, body: body})
}

// want fails the test unless r has status code.
func want(t *testing.T, r response, code int) {
	t.Helper()
	if r.code != code {
		t.Fatalf("status %d, want %d: %s", r.code, code, r.body)
	}
}

// write creates a workspace file.
func (e *env) write(rel, content string) {
	e.t.Helper()
	p := filepath.Join(e.workspace, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		e.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		e.t.Fatal(err)
	}
}

// sseEvent is one server-sent event.
type sseEvent struct {
	name string
	data string
}

// readEvents reads server-sent events from r until "done" or EOF.
func readEvents(t *testing.T, r io.Reader) []sseEvent {
	t.Helper()
	var out []sseEvent
	var cur sseEvent
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 1<<20), 16<<20)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			if cur.name != "" {
				out = append(out, cur)
				if cur.name == "done" {
					return out
				}
			}
			cur = sseEvent{}
		case strings.HasPrefix(line, ":"):
		case strings.HasPrefix(line, "event: "):
			cur.name = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			cur.data += strings.TrimPrefix(line, "data: ")
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("read events: %v", err)
	}
	return out
}

// events opens the event stream of a run and reads it to the end.
func (e *env) events(id string) []sseEvent {
	e.t.Helper()
	hr, err := http.NewRequest(http.MethodGet, e.ts.URL+"/api/runs/"+id+"/events", nil)
	if err != nil {
		e.t.Fatal(err)
	}
	hr.Header.Set("Authorization", "Bearer "+testToken)
	resp, err := e.ts.Client().Do(hr)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		e.t.Fatalf("events: %d %s", resp.StatusCode, b)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		e.t.Fatalf("events Content-Type %q", ct)
	}
	return readEvents(e.t, resp.Body)
}

// waitRun polls a run until it finished and returns its detail.
func (e *env) waitRun(id string) runDetail {
	e.t.Helper()
	deadline := time.Now().Add(3 * time.Minute)
	for time.Now().Before(deadline) {
		r := e.get("/api/runs/" + id)
		want(e.t, r, http.StatusOK)
		var d runDetail
		r.json(e.t, &d)
		if d.Run.Status == statusFinished {
			return d
		}
		time.Sleep(20 * time.Millisecond)
	}
	e.t.Fatalf("run %s did not finish", id)
	return runDetail{}
}

// startRun posts a run and returns its id.
func (e *env) startRun(body any) string {
	e.t.Helper()
	r := e.post("/api/runs", body)
	want(e.t, r, http.StatusAccepted)
	var out struct {
		ID string `json:"id"`
	}
	r.json(e.t, &out)
	if !store.ValidID(out.ID) {
		e.t.Fatalf("run id %q", out.ID)
	}
	return out.ID
}
