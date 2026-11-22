package server

import (
	"net/http"
	"os"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/TroubieD3v/photofinish/internal/engine"
)

func TestInfo(t *testing.T) {
	e := newEnv(t)
	r := e.get("/api/info")
	want(t, r, http.StatusOK)
	var info infoResponse
	r.json(t, &info)
	if info.Version != "test" || info.Workspace != e.workspace || info.Demo.Running || info.Demo.URL == "" || info.RunningRun != "" || info.DataDir != "" {
		t.Errorf("info %+v", info)
	}
}

func TestValidate(t *testing.T) {
	e := newEnv(t)
	validate := func(content string) validateResponse {
		t.Helper()
		r := e.post("/api/scenarios/validate", map[string]string{"content": content, "path": "x.yaml"})
		want(t, r, http.StatusOK)
		var v validateResponse
		r.json(t, &v)
		return v
	}

	v := validate(minimal)
	if !v.Valid || len(v.Errors) != 0 || v.Scenario == nil {
		t.Fatalf("minimal: %+v", v)
	}
	sum := v.Scenario
	if sum.Name != "minimal" || sum.Engine != engine.H2 || sum.Copies != 5 || sum.Trials != 3 || !sum.Insecure ||
		sum.Invariant != "size(race) == 5" || len(sum.Scope.AllowHosts) != 1 || sum.Scope.Requests == 0 || sum.Target == "" {
		t.Errorf("summary %+v", sum)
	}

	cases := []struct {
		name, content string
		line          int
		field, msg    string
	}{
		{"yaml syntax", strings.Replace(minimal, "copies: 5", "copies: [5", 1), 0, "", "invalid YAML"},
		{"bad name", strings.Replace(minimal, "name: minimal", "name: Not Valid", 1), 2, "name", "lowercase"},
		{"unknown field", strings.Replace(minimal, "trials: 3", "trails: 3", 1), 14, "", "unknown field"},
		{"bad copies", strings.Replace(minimal, "copies: 5", "copies: 5000", 1), 10, "race.copies", ""},
		{"invariant does not compile", strings.Replace(minimal, "size(race) == 5", "size(race) ==", 1), 13, "check.invariant", "invariant"},
		{"invariant not bool", strings.Replace(minimal, "size(race) == 5", "size(race)", 1), 13, "check.invariant", ""},
		{"no check", strings.Replace(minimal, "check:\n  invariant: size(race) == 5\n", "", 1), 0, "check", "required"},
		{"empty", "", 0, "", "empty"},
		{"placeholder", strings.Replace(minimal, "size(race) == 5", "'TODO: write the rule that must hold after the race as a CEL expression'", 1), 13, "check.invariant", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := validate(c.content)
			if v.Valid || len(v.Errors) == 0 {
				t.Fatalf("valid: %+v", v)
			}
			p := v.Errors[0]
			if c.line > 0 && p.Line != c.line {
				t.Errorf("line %d, want %d: %+v", p.Line, c.line, v.Errors)
			}
			if c.field != "" && !hasField(v.Errors, c.field) {
				t.Errorf("no error for %s: %+v", c.field, v.Errors)
			}
			if c.msg != "" && !strings.Contains(p.Message, c.msg) {
				t.Errorf("message %q lacks %q", p.Message, c.msg)
			}
			if p.Message == "" {
				t.Error("empty message")
			}
		})
	}

	t.Run("syntax error line", func(t *testing.T) {
		v := validate("version: 1\nname: x\ntarget: [unclosed\nrace: {}\n")
		if len(v.Errors) == 0 || v.Errors[0].Line < 2 || !strings.Contains(v.Errors[0].Message, "YAML") {
			t.Errorf("errors %+v", v.Errors)
		}
	})
	t.Run("column of a one-line invariant", func(t *testing.T) {
		v := validate(strings.Replace(minimal, "size(race) == 5", "size(race) == )", 1))
		var p *problem
		for i := range v.Errors {
			if v.Errors[i].Field == "check.invariant" {
				p = &v.Errors[i]
			}
		}
		if p == nil || p.Line != 13 {
			t.Fatalf("errors %+v", v.Errors)
		}
		// "  invariant: size(race) == )": the ")" is at column 28.
		if p.Column != 28 {
			t.Errorf("column %d", p.Column)
		}
	})
	t.Run("invalid path", func(t *testing.T) {
		want(t, e.post("/api/scenarios/validate", map[string]string{"content": minimal, "path": "../x.yaml"}), http.StatusBadRequest)
	})
}

// hasField reports whether a problem names field.
func hasField(ps []problem, field string) bool {
	for _, p := range ps {
		if p.Field == field {
			return true
		}
	}
	return false
}

func TestImport(t *testing.T) {
	e := newEnv(t)
	raw := "POST /vuln/api/carts/c-1/coupons HTTP/2\r\nHost: 127.0.0.1:8443\r\nAuthorization: Bearer demo-alice\r\n" +
		"Content-Type: application/json\r\n\r\n{\"code\":\"WELCOME10\"}"
	for _, kind := range []string{"auto", "burp", ""} {
		r := e.post("/api/import", map[string]any{"kind": kind, "content": raw})
		want(t, r, http.StatusOK)
		var resp importResponse
		r.json(t, &resp)
		if resp.Kind != "burp" || !strings.Contains(resp.Content, "race:") || !strings.Contains(resp.Content, "127.0.0.1:8443") || resp.Name == "" {
			t.Errorf("%s: %+v", kind, resp)
		}
		if len(resp.Todo) < 3 || !strings.Contains(strings.Join(resp.Todo, "\n"), "authorization") {
			t.Errorf("todo %v", resp.Todo)
		}
		// The skeleton fails validation on the placeholder only.
		v := validateContent([]byte(resp.Content), "")
		if v.Valid || !hasField(v.Errors, "check.invariant") {
			t.Errorf("skeleton validation %+v", v)
		}
	}

	har, err := os.ReadFile("../scenario/testdata/coupon.har")
	if err != nil {
		t.Fatal(err)
	}
	r := e.post("/api/import", map[string]any{"kind": "auto", "content": string(har), "harEntry": 1})
	want(t, r, http.StatusOK)
	var resp importResponse
	r.json(t, &resp)
	if resp.Kind != "har" || len(resp.Entries) != 3 || resp.Entries[1].Method != "POST" || !strings.Contains(resp.Content, "coupons") {
		t.Errorf("har: kind %s entries %+v", resp.Kind, resp.Entries)
	}
	want(t, e.post("/api/import", map[string]any{"kind": "har", "content": string(har), "harEntry": 7}), http.StatusUnprocessableEntity)
	want(t, e.post("/api/import", map[string]any{"kind": "har", "content": raw}), http.StatusUnprocessableEntity)
	want(t, e.post("/api/import", map[string]any{"kind": "har", "content": string(har), "harEntry": -1}), http.StatusBadRequest)
	want(t, e.post("/api/import", map[string]any{"kind": "curl", "content": raw}), http.StatusBadRequest)
	want(t, e.post("/api/import", map[string]any{"content": "  "}), http.StatusBadRequest)
	want(t, e.post("/api/import", map[string]any{"content": "not a request"}), http.StatusUnprocessableEntity)
}

func TestDemoStartStop(t *testing.T) {
	e := newEnv(t)
	r := e.post("/api/demo/start", nil)
	want(t, r, http.StatusOK)
	var st demoStatus
	r.json(t, &st)
	if !st.Running || !strings.HasPrefix(st.URL, "https://127.0.0.1:") || strings.HasSuffix(st.URL, ":0") {
		t.Fatalf("start: %+v", st)
	}
	// Starting again keeps the running shop.
	r = e.post("/api/demo/start", nil)
	var again demoStatus
	r.json(t, &again)
	if again != st {
		t.Errorf("second start %+v, first %+v", again, st)
	}
	var info infoResponse
	e.get("/api/info").json(t, &info)
	if info.Demo != st {
		t.Errorf("info demo %+v", info.Demo)
	}

	// The shop answers over HTTP/2 like "photofinish demo".
	r = e.post("/api/probe", map[string]any{"url": st.URL + "/", "insecure": true})
	want(t, r, http.StatusOK)
	var probe probeJSON
	r.json(t, &probe)
	if !probe.HTTP2 || probe.Recommended != engine.H2 || probe.ALPN != "h2" || len(probe.RTTsNs) == 0 || probe.TLSVersion == "" {
		t.Errorf("probe %+v", probe)
	}

	r = e.post("/api/demo/stop", nil)
	want(t, r, http.StatusOK)
	r.json(t, &st)
	if st.Running {
		t.Errorf("stop: %+v", st)
	}
	want(t, e.post("/api/demo/stop", nil), http.StatusOK)
}

func TestProbeErrors(t *testing.T) {
	e := newEnv(t)
	for _, u := range []string{"", "ftp://127.0.0.1/", "127.0.0.1:8443", "https://", "::"} {
		want(t, e.post("/api/probe", map[string]any{"url": u}), http.StatusBadRequest)
	}
	// Nothing listens on port 1.
	want(t, e.post("/api/probe", map[string]any{"url": "http://127.0.0.1:1/"}), http.StatusBadGateway)
}

func TestSPA(t *testing.T) {
	t.Run("not built", func(t *testing.T) {
		e := newEnv(t, withUI(fstest.MapFS{}))
		for _, p := range []string{"/", "/scenarios", "/index.html"} {
			r := e.do(request{path: p, noToken: true})
			want(t, r, http.StatusOK)
			if !strings.Contains(string(r.body), "make ui") {
				t.Errorf("%s: %s", p, r.body)
			}
		}
		e = newEnv(t) // nil UI
		if r := e.do(request{path: "/", noToken: true}); !strings.Contains(string(r.body), "not built") {
			t.Errorf("nil UI: %s", r.body)
		}
	})
	t.Run("built", func(t *testing.T) {
		ui := fstest.MapFS{
			"index.html":         {Data: []byte("<!doctype html><title>PhotoFinish</title>")},
			"assets/app-abc.js":  {Data: []byte("console.log(1)")},
			"assets/app-abc.css": {Data: []byte("body{}")},
			"favicon.svg":        {Data: []byte("<svg/>")},
		}
		e := newEnv(t, withUI(ui))
		for _, p := range []string{"/", "/scenario", "/runs/abc", "/index.html", "/assets/", "/%2e%2e/secret"} {
			r := e.do(request{path: p, noToken: true})
			want(t, r, http.StatusOK)
			if !strings.Contains(string(r.body), "<title>PhotoFinish</title>") {
				t.Errorf("%s: %s", p, r.body)
			}
			if r.header.Get("Cache-Control") != "no-cache" {
				t.Errorf("%s: Cache-Control %q", p, r.header.Get("Cache-Control"))
			}
		}
		r := e.do(request{path: "/assets/app-abc.js", noToken: true})
		want(t, r, http.StatusOK)
		if string(r.body) != "console.log(1)" || !strings.Contains(r.header.Get("Cache-Control"), "immutable") ||
			!strings.Contains(r.header.Get("Content-Type"), "javascript") {
			t.Errorf("asset: %q %v", r.body, r.header)
		}
		want(t, e.do(request{path: "/assets/missing.js", noToken: true}), http.StatusNotFound)
		want(t, e.do(request{method: "POST", path: "/", noToken: true}), http.StatusMethodNotAllowed)
		// Unknown API routes are JSON errors, not the SPA.
		r = e.get("/api/nothing")
		want(t, r, http.StatusNotFound)
		if strings.Contains(string(r.body), "<title>") {
			t.Error("API 404 served the SPA")
		}
	})
}
