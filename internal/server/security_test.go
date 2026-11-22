package server

import (
	"net"
	"net/http"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/TroubieD3v/photofinish/internal/store"
)

// apiRoutes are requests to every route that needs the token.
var apiRoutes = []request{
	{method: "GET", path: "/api/info"},
	{method: "GET", path: "/api/scenarios"},
	{method: "GET", path: "/api/scenarios/file?path=a.yaml"},
	{method: "PUT", path: "/api/scenarios/file?path=a.yaml", body: `{"content":"x"}`},
	{method: "DELETE", path: "/api/scenarios/file?path=a.yaml"},
	{method: "POST", path: "/api/scenarios/validate", body: `{"content":"x"}`},
	{method: "POST", path: "/api/examples/coupon-vuln/copy"},
	{method: "POST", path: "/api/import", body: `{"content":"GET / HTTP/1.1\r\nHost: x\r\n\r\n"}`},
	{method: "POST", path: "/api/probe", body: `{"url":"http://127.0.0.1:1/"}`},
	{method: "POST", path: "/api/runs", body: `{"content":"x"}`},
	{method: "GET", path: "/api/runs"},
	{method: "GET", path: "/api/runs/0123456789ab"},
	{method: "DELETE", path: "/api/runs/0123456789ab"},
	{method: "POST", path: "/api/runs/0123456789ab/cancel"},
	{method: "GET", path: "/api/runs/0123456789ab/events"},
	{method: "GET", path: "/api/runs/0123456789ab/report.json"},
	{method: "POST", path: "/api/demo/start"},
	{method: "POST", path: "/api/demo/stop"},
	{method: "GET", path: "/api/no-such-route"},
}

func TestHealthNeedsNoToken(t *testing.T) {
	e := newEnv(t)
	r := e.do(request{path: "/api/health", noToken: true})
	want(t, r, http.StatusOK)
	var h map[string]string
	r.json(t, &h)
	if h["status"] != "ok" || h["version"] != "test" {
		t.Errorf("health %v", h)
	}
}

func TestTokenRequired(t *testing.T) {
	e := newEnv(t)
	for _, rt := range apiRoutes {
		t.Run(rt.method+" "+rt.path, func(t *testing.T) {
			rt.noToken = true
			r := e.do(rt)
			want(t, r, http.StatusUnauthorized)
			if !strings.Contains(r.errorText(t), "session token") {
				t.Errorf("error %s", r.body)
			}
			if r.header.Get("WWW-Authenticate") == "" {
				t.Error("no WWW-Authenticate header")
			}
		})
	}
	// Nothing changed in the workspace or the demo state.
	if r := e.get("/api/info"); !strings.Contains(string(r.body), `"running":false`) {
		t.Errorf("info after unauthorized requests: %s", r.body)
	}
}

func TestWrongToken(t *testing.T) {
	e := newEnv(t)
	cases := map[string]string{
		"wrong":          "Bearer " + strings.Repeat("x", len(testToken)),
		"prefix":         "Bearer " + testToken[:len(testToken)-1],
		"longer":         "Bearer " + testToken + "x",
		"empty bearer":   "Bearer ",
		"no scheme":      testToken,
		"basic scheme":   "Basic " + testToken,
		"token as query": "",
		"case changed":   "Bearer " + strings.ToUpper(testToken),
	}
	for name, auth := range cases {
		t.Run(name, func(t *testing.T) {
			req := request{path: "/api/info?token=" + testToken, noToken: true, header: map[string]string{}}
			if auth != "" {
				req.header["Authorization"] = auth
			}
			want(t, e.do(req), http.StatusUnauthorized)
		})
	}
	t.Run("cookie is ignored", func(t *testing.T) {
		req := request{path: "/api/info", noToken: true, header: map[string]string{"Cookie": "token=" + testToken}}
		want(t, e.do(req), http.StatusUnauthorized)
	})
	t.Run("scheme is case-insensitive", func(t *testing.T) {
		req := request{path: "/api/info", noToken: true, header: map[string]string{"Authorization": "bearer " + testToken}}
		want(t, e.do(req), http.StatusOK)
	})
}

func TestHostCheck(t *testing.T) {
	e := newEnv(t)
	_, port, _ := net.SplitHostPort(e.host)
	good := []string{"127.0.0.1:" + port, "localhost:" + port, "LocalHost:" + port, "[::1]:" + port, "127.0.0.2:" + port}
	for _, h := range good {
		t.Run("allowed "+h, func(t *testing.T) {
			want(t, e.do(request{path: "/api/info", host: h}), http.StatusOK)
		})
	}
	bad := []string{
		"evil.example:" + port,             // DNS rebinding: an attacker's name resolving to 127.0.0.1
		"127.0.0.1.nip.io:" + port,         // wildcard DNS for loopback
		"localhost.:" + port,               // trailing dot
		"localhost.evil.example:" + port,   // prefix match
		"127.0.0.1:1",                      // another port
		"127.0.0.1",                        // no port
		"localhost",                        // no port
		"0.0.0.0:" + port,                  // unspecified address
		"192.168.1.10:" + port,             // LAN address
		"[::ffff:7f00:1]:" + port + "x",    // garbage port
		"[fe80::1%25lo]:" + port,           // zoned
		"127.0.0.1:" + port + "@evil.test", // userinfo trick
	}
	for _, h := range bad {
		t.Run("rejected "+h, func(t *testing.T) {
			r := e.do(request{path: "/api/info", host: h})
			want(t, r, http.StatusMisdirectedRequest)
			if r.header.Get("Content-Security-Policy") != ContentSecurityPolicy {
				t.Error("421 without CSP")
			}
			// The UI and the unauthenticated health route are covered too.
			want(t, e.do(request{path: "/", host: h, noToken: true}), http.StatusMisdirectedRequest)
			want(t, e.do(request{path: "/api/health", host: h, noToken: true}), http.StatusMisdirectedRequest)
			// So are writes with a matching Origin, as a rebound page would send.
			r = e.do(request{method: "POST", path: "/api/demo/start", host: h,
				header: map[string]string{"Origin": "http://" + h}})
			want(t, r, http.StatusMisdirectedRequest)
		})
	}
	if e.srv.demo.status().Running {
		t.Error("a rejected request started the demo shop")
	}
}

func TestExposeAcceptsAnyHostButNeedsToken(t *testing.T) {
	e := newEnv(t, exposed())
	want(t, e.do(request{path: "/api/info", host: "lab.example.test:7340"}), http.StatusOK)
	want(t, e.do(request{path: "/api/info", host: "lab.example.test:7340", noToken: true}), http.StatusUnauthorized)
	// Origin must still match the Host.
	r := e.do(request{method: "POST", path: "/api/scenarios/validate", body: `{"content":""}`, host: "lab.example.test:7340",
		header: map[string]string{"Origin": "http://evil.example"}})
	want(t, r, http.StatusForbidden)
	r = e.do(request{method: "POST", path: "/api/scenarios/validate", body: `{"content":""}`, host: "lab.example.test:7340",
		header: map[string]string{"Origin": "http://lab.example.test:7340"}})
	want(t, r, http.StatusOK)
}

func TestOriginOnWrites(t *testing.T) {
	e := newEnv(t)
	body := `{"content":"version: 1"}`
	rejected := []string{
		"http://evil.example",
		"https://evil.example",
		"null",
		"http://localhost:" + strings.Split(e.host, ":")[1], // same port, different host name
		"http://" + e.host + ".evil.example",
		"file://",
		"http://" + e.host + "/path",
	}
	for _, o := range rejected {
		t.Run("rejected "+o, func(t *testing.T) {
			r := e.do(request{method: "POST", path: "/api/scenarios/validate", body: body, header: map[string]string{"Origin": o}})
			want(t, r, http.StatusForbidden)
			if !strings.Contains(r.errorText(t), "cross-origin") {
				t.Errorf("error %s", r.body)
			}
		})
	}
	for _, m := range []string{"PUT", "DELETE"} {
		r := e.do(request{method: m, path: "/api/scenarios/file?path=x.yaml", body: `{"content":"x"}`,
			header: map[string]string{"Origin": "http://evil.example"}})
		want(t, r, http.StatusForbidden)
	}
	r := e.do(request{method: "POST", path: "/api/runs", body: `{"content":"x"}`, header: map[string]string{"Origin": "http://evil.example"}})
	want(t, r, http.StatusForbidden)
	if runs, _ := e.store.List(0, ""); len(runs) != 0 || e.srv.runs.activeID() != "" {
		t.Error("a cross-origin POST started a run")
	}

	t.Run("same origin", func(t *testing.T) {
		r := e.do(request{method: "POST", path: "/api/scenarios/validate", body: body, header: map[string]string{"Origin": "http://" + e.host}})
		want(t, r, http.StatusOK)
	})
	t.Run("no origin", func(t *testing.T) {
		want(t, e.post("/api/scenarios/validate", body), http.StatusOK)
	})
	t.Run("cross-site fetch metadata", func(t *testing.T) {
		for _, site := range []string{"cross-site", "same-site"} {
			r := e.do(request{method: "POST", path: "/api/scenarios/validate", body: body, header: map[string]string{"Sec-Fetch-Site": site}})
			want(t, r, http.StatusForbidden)
		}
		r := e.do(request{method: "POST", path: "/api/scenarios/validate", body: body, header: map[string]string{"Sec-Fetch-Site": "same-origin"}})
		want(t, r, http.StatusOK)
	})
	t.Run("reads with a foreign origin still need the token", func(t *testing.T) {
		r := e.do(request{path: "/api/info", noToken: true, header: map[string]string{"Origin": "http://evil.example"}})
		want(t, r, http.StatusUnauthorized)
		if r.header.Get("Access-Control-Allow-Origin") != "" {
			t.Error("CORS header sent")
		}
	})
}

func TestNoCORSPreflight(t *testing.T) {
	e := newEnv(t)
	r := e.do(request{method: "OPTIONS", path: "/api/runs", noToken: true, header: map[string]string{
		"Origin": "http://evil.example", "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "authorization",
	}})
	if r.code < 400 {
		t.Errorf("preflight answered %d", r.code)
	}
	for k := range r.header {
		if strings.HasPrefix(k, "Access-Control-") {
			t.Errorf("CORS header %s sent", k)
		}
	}
}

func TestJSONContentTypeOnWrites(t *testing.T) {
	e := newEnv(t)
	for _, ct := range []string{"text/plain", "application/x-www-form-urlencoded", "multipart/form-data; boundary=x", ""} {
		r := e.do(request{method: "POST", path: "/api/scenarios/validate", body: `{"content":""}`, header: map[string]string{"Content-Type": ct}})
		want(t, r, http.StatusUnsupportedMediaType)
	}
	r := e.do(request{method: "POST", path: "/api/scenarios/validate", body: `{"content":""}`, header: map[string]string{"Content-Type": "application/json; charset=utf-8"}})
	want(t, r, http.StatusOK)
}

func TestSecurityHeaders(t *testing.T) {
	ui := fstest.MapFS{"index.html": {Data: []byte("<!doctype html><title>ui</title>")}}
	e := newEnv(t, withUI(ui))
	cases := []request{
		{path: "/api/health", noToken: true},
		{path: "/api/info"},
		{path: "/api/info", noToken: true},
		{path: "/"},
		{path: "/runs"},
		{path: "/api/runs/zzz"},
		{method: "POST", path: "/api/scenarios/validate", body: "{"},
	}
	for _, c := range cases {
		r := e.do(c)
		h := r.header
		if got := h.Get("Content-Security-Policy"); got != ContentSecurityPolicy {
			t.Errorf("%s %s: CSP %q", c.method, c.path, got)
		}
		if h.Get("X-Content-Type-Options") != "nosniff" || h.Get("Referrer-Policy") != "no-referrer" {
			t.Errorf("%s: headers %v", c.path, h)
		}
		if strings.HasPrefix(c.path, "/api/") && h.Get("Cache-Control") != "no-store" {
			t.Errorf("%s: Cache-Control %q", c.path, h.Get("Cache-Control"))
		}
		if h.Get("Set-Cookie") != "" {
			t.Errorf("%s: sets a cookie", c.path)
		}
	}
	for _, d := range []string{"default-src 'self'", "connect-src 'self'", "frame-ancestors 'none'", "base-uri 'none'", "form-action 'none'"} {
		if !strings.Contains(ContentSecurityPolicy, d) {
			t.Errorf("CSP lacks %s", d)
		}
	}
}

func TestErrorsAreJSON(t *testing.T) {
	e := newEnv(t)
	for _, r := range []response{
		e.do(request{path: "/api/info", noToken: true}),
		e.get("/api/no-such-route"),
		e.get("/api/runs/nothex"),
		e.post("/api/scenarios/validate", "{"),
		e.do(request{path: "/api/info", host: "evil.example:1"}),
	} {
		if ct := r.header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
			t.Errorf("%d: Content-Type %q", r.code, ct)
		}
		r.errorText(t)
	}
}

func TestBodyCaps(t *testing.T) {
	e := newEnv(t)
	big := `{"content":"` + strings.Repeat("a", MaxBodyBytes) + `"}`
	for _, p := range []string{"/api/scenarios/validate", "/api/runs", "/api/import", "/api/probe"} {
		r := e.post(p, big)
		want(t, r, http.StatusRequestEntityTooLarge)
	}
	r := e.do(request{method: "PUT", path: "/api/scenarios/file?path=big.yaml", body: big})
	want(t, r, http.StatusRequestEntityTooLarge)

	// Scenario content is capped at MaxFileBytes, below the body cap.
	file := map[string]string{"content": strings.Repeat("#", MaxFileBytes+1)}
	want(t, e.do(request{method: "PUT", path: "/api/scenarios/file?path=big.yaml", body: file}), http.StatusRequestEntityTooLarge)
	want(t, e.post("/api/scenarios/validate", file), http.StatusRequestEntityTooLarge)
	want(t, e.post("/api/runs", file), http.StatusRequestEntityTooLarge)
	if r := e.get("/api/scenarios/file?path=big.yaml"); r.code != http.StatusNotFound {
		t.Errorf("oversized file was written: %d", r.code)
	}
	ok := map[string]string{"content": strings.Repeat("#", MaxFileBytes)}
	want(t, e.do(request{method: "PUT", path: "/api/scenarios/file?path=big.yaml", body: ok}), http.StatusOK)
}

func TestMalformedJSON(t *testing.T) {
	e := newEnv(t)
	for _, b := range []string{"{", "[]", `{"content": 1}`, `{"content":""} {"content":""}`, "null x"} {
		r := e.post("/api/scenarios/validate", b)
		want(t, r, http.StatusBadRequest)
	}
	want(t, e.do(request{method: "POST", path: "/api/runs", header: map[string]string{"Content-Type": "application/json"}}), http.StatusBadRequest)
}

func TestCheckToken(t *testing.T) {
	for _, tok := range []string{"", "short", strings.Repeat("a", MinTokenLength-1), strings.Repeat("a", 31) + " b",
		strings.Repeat("a", 40) + "#x", strings.Repeat("a", 40) + "\n", strings.Repeat("é", 20)} {
		if CheckToken(tok) == nil {
			t.Errorf("CheckToken(%q) accepted", tok)
		}
	}
	for _, tok := range []string{strings.Repeat("a", MinTokenLength), testToken, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"} {
		if err := CheckToken(tok); err != nil {
			t.Errorf("CheckToken(%q): %v", tok, err)
		}
	}
}

func TestNewRejectsBadConfig(t *testing.T) {
	st, err := store.Open(store.Memory)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ws := t.TempDir()
	cases := map[string]Config{
		"no store":         {Workspace: ws, Token: testToken},
		"short token":      {Workspace: ws, Token: "abc", Store: st},
		"missing ws":       {Workspace: ws + "/missing", Token: testToken, Store: st},
		"public demo addr": {Workspace: ws, Token: testToken, Store: st, DemoAddr: "0.0.0.0:8443"},
		"demo window":      {Workspace: ws, Token: testToken, Store: st, DemoWindow: 3 * time.Second},
	}
	for name, cfg := range cases {
		if s, err := New(cfg); err == nil {
			s.Close()
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestLoopbackHost(t *testing.T) {
	for _, h := range []string{"localhost", "LOCALHOST", "127.0.0.1", "127.1.2.3", "::1", "[::1]"} {
		if !IsLoopbackHost(h) {
			t.Errorf("%s is loopback", h)
		}
	}
	for _, h := range []string{"", "0.0.0.0", "::", "192.168.0.1", "localhost.example", "example.test"} {
		if IsLoopbackHost(h) {
			t.Errorf("%s is not loopback", h)
		}
	}
}
