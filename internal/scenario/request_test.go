package scenario

import (
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func TestExpand(t *testing.T) {
	t.Setenv("PF_TEST_TOKEN", "s3cret")
	t.Setenv("PF_TEST_EMPTY", "")
	vars := Vars{"id": "42", "brace": "{{id}}", "env": "${env:PF_TEST_TOKEN}"}
	cases := []struct {
		in, want, err string
	}{
		{in: "no placeholders", want: "no placeholders"},
		{in: "/carts/{{id}}", want: "/carts/42"},
		{in: "{{ id }}-{{id}}", want: "42-42"},
		{in: "Bearer ${env:PF_TEST_TOKEN}", want: "Bearer s3cret"},
		{in: "[${env:PF_TEST_EMPTY}]", want: "[]"},
		{in: "${HOME} and ${ env } stay", want: "${HOME} and ${ env } stay"},
		{in: "{{brace}}", want: "{{id}}"},             // values are not expanded again
		{in: "{{env}}", want: "${env:PF_TEST_TOKEN}"}, // nor env references inside values
		{in: "a } b }} c", want: "a } b }} c"},        // lone closers are literal
		{in: `{{"{{"}}7*7}}`, want: "{{7*7}}"},        // quoted literals
		{in: `{{ "${env:" }}X} {{"{{"}}id}}`, want: "${env:X} {{id}}"},
		{in: `{{"a}}"}}`, want: "a}}"},
		{in: `{{""}}`, want: ""},
		{in: "{{missing}}", err: "unknown variable {{missing}} (known: brace, env, id)"},
		{in: "${env:PF_TEST_UNSET_VAR}", err: "environment variable PF_TEST_UNSET_VAR is not set"},
		{in: "{{id", err: "unterminated {{ placeholder"},
		{in: "${env:PF_TEST_TOKEN", err: "unterminated ${env:...} placeholder"},
		{in: "{{a-b}}", err: `invalid variable name "a-b"`},
		{in: "{{}}", err: `invalid variable name ""`},
		{in: "${env:A B}", err: `invalid environment variable name "A B"`},
	}
	for _, c := range cases {
		got, err := Expand(c.in, vars)
		switch {
		case c.err != "" && (err == nil || !strings.Contains(err.Error(), c.err)):
			t.Errorf("Expand(%q) error = %v, want %q", c.in, err, c.err)
		case c.err == "" && err != nil:
			t.Errorf("Expand(%q): %v", c.in, err)
		case c.err == "" && got != c.want:
			t.Errorf("Expand(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	if _, err := Expand("{{x}}", nil); err == nil || !strings.Contains(err.Error(), "no variables are defined") {
		t.Errorf("nil vars: %v", err)
	}
}

func TestInitialVars(t *testing.T) {
	t.Setenv("PF_TEST_CODE", "SECRET10")
	s := &Scenario{Vars: Vars{"code": "${env:PF_TEST_CODE}", "plain": "x"}}
	v, sec, err := s.InitialVars()
	if err != nil {
		t.Fatal(err)
	}
	if v["code"] != "SECRET10" || v["plain"] != "x" || !slices.Equal(sec, []string{"SECRET10"}) {
		t.Errorf("vars %v secrets %v", v, sec)
	}
	s.Vars["bad"] = "{{code}}"
	if _, _, err := s.InitialVars(); err == nil || !strings.Contains(err.Error(), "vars.bad: initial values cannot use {{code}}") {
		t.Errorf("err = %v", err)
	}
	s = &Scenario{Vars: Vars{"tok": "${env:PF_TEST_NOT_SET_EVER}"}}
	if _, _, err := s.InitialVars(); err == nil || !strings.Contains(err.Error(), "vars.tok: environment variable PF_TEST_NOT_SET_EVER is not set") {
		t.Errorf("err = %v", err)
	}
	c := Vars{"a": "1"}.Clone()
	c["b"] = "2"
	if len(Vars(nil).Clone()) != 0 || len(c) != 2 {
		t.Error("Clone")
	}
}

func TestScopeAllows(t *testing.T) {
	sc := Scope{AllowHosts: []string{"127.0.0.1:8443", "Shop.Example.TEST", "[::1]:9000", "api.test."}}
	cases := []struct {
		host string
		want bool
	}{
		{"127.0.0.1:8443", true},
		{"127.0.0.1:8444", false},
		{"127.0.0.1", false}, // entry has a port, the host does not
		{"shop.example.test", true},
		{"SHOP.example.test:1234", true}, // bare entry: any port
		{"shop.example.test.", true},
		{"evil.example.test", false},
		{"example.test", false},
		{"[::1]:9000", true},
		{"[::1]:9001", false},
		{"api.test:443", true},
		{"", false},
	}
	for _, c := range cases {
		if got := sc.Allows(c.host); got != c.want {
			t.Errorf("Allows(%q) = %v, want %v", c.host, got, c.want)
		}
	}
	urls := []struct {
		u    string
		want bool
	}{
		{"https://127.0.0.1:8443/x", true},
		{"https://shop.example.test/x", true},
		{"http://evil.test/", false},
		{"https://[::1]:9000/", true},
	}
	for _, c := range urls {
		u, _ := url.Parse(c.u)
		if got := sc.AllowsURL(u); got != c.want {
			t.Errorf("AllowsURL(%q) = %v, want %v", c.u, got, c.want)
		}
	}
	if !(Scope{AllowHosts: []string{"h:443"}}).AllowsURL(mustURL(t, "https://h/")) {
		t.Error("default https port not applied")
	}
	if (Scope{AllowHosts: []string{"h:443"}}).AllowsURL(mustURL(t, "http://h/")) {
		t.Error("http default port must be 80")
	}
	if (Scope{}).AllowsURL(nil) {
		t.Error("nil URL allowed")
	}
}

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestParseRaw(t *testing.T) {
	cases := []struct {
		name, in           string
		method, target     string
		headers            []string // "Name: value"
		body, err, version string
	}{
		{name: "short", in: "GET /", method: "GET", target: "/"},
		{name: "version", in: "POST /a?b=1 HTTP/2\n", method: "POST", target: "/a?b=1", version: "HTTP/2"},
		{name: "headers no body", in: "GET / HTTP/1.1\nA: 1\nB:2\n", method: "GET", target: "/", headers: []string{"A: 1", "B: 2"}, version: "HTTP/1.1"},
		{name: "body trailing newline removed once", in: "POST /\nA: 1\n\n{\"x\":1}\n\n", method: "POST", target: "/", headers: []string{"A: 1"}, body: "{\"x\":1}\n"},
		{name: "body without trailing newline", in: "POST /\n\nabc", method: "POST", target: "/", body: "abc"},
		{name: "crlf", in: "POST / HTTP/1.1\r\nA: 1\r\n\r\nbody", method: "POST", target: "/", headers: []string{"A: 1"}, body: "body", version: "HTTP/1.1"},
		{name: "crlf trailing newline removed once", in: "POST /c HTTP/1.1\r\nA: b\r\n\r\n{\"a\":1}\r\n", method: "POST", target: "/c", headers: []string{"A: b"}, body: "{\"a\":1}", version: "HTTP/1.1"},
		{name: "crlf two trailing newlines", in: "POST /c\r\n\r\nx\r\n\r\n", method: "POST", target: "/c", body: "x\r\n"},
		{name: "crlf body lines kept", in: "POST /c\r\n\r\na\r\nb", method: "POST", target: "/c", body: "a\r\nb"},
		{name: "leading blank lines", in: "\n\n  GET /x\n", method: "GET", target: "/x"},
		{name: "pseudo header", in: "GET /\n:authority: h\n", method: "GET", target: "/", headers: []string{":authority: h"}},
		{name: "value with colon", in: "GET /\nX-Time: 12:30\n", method: "GET", target: "/", headers: []string{"X-Time: 12:30"}},
		{name: "empty", in: "  \n", err: "the request is empty"},
		{name: "one word", in: "GET\n", err: `request line 1: want "METHOD /path [HTTP/version]", got "GET"`},
		{name: "four words", in: "GET / HTTP/1.1 x", err: "request line 1: want"},
		{name: "bad version", in: "GET / x", err: "the third word must be an HTTP version"},
		{name: "no colon", in: "\nGET /\nA 1\n", err: `request line 3: want "Name: value"`},
		{name: "folded", in: "GET /\nA: 1\n  continued\n", err: "request line 3: folded"},
		{name: "space before colon", in: "GET /\nA : 1\n", err: "no spaces are allowed around the header name"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, err := parseRaw(c.in)
			if c.err != "" {
				if err == nil || !strings.Contains(err.Error(), c.err) {
					t.Fatalf("err = %v, want %q", err, c.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var hs []string
			for _, h := range r.headers {
				hs = append(hs, h.name+": "+h.value)
			}
			if r.method != c.method || r.target != c.target || r.body != c.body || r.version != c.version || !slices.Equal(hs, c.headers) {
				t.Errorf("got %q %q %q %q body %q", r.method, r.target, r.version, hs, r.body)
			}
		})
	}
}

const buildBase = `version: 1
name: b
target: https://shop.test:8443/vuln/api
scope: {allow_hosts: [shop.test:8443, other.test]}
identities:
  alice: {headers: {Authorization: "Bearer ${env:PF_TEST_ALICE}", X-Trace: "{{trace}}"}}
vars: {trace: t0}
race: {request: {request: GET /}}
check: {invariant: "true"}
`

func TestBuildRequest(t *testing.T) {
	t.Setenv("PF_TEST_ALICE", "alice-token")
	t.Setenv("PF_TEST_BODY", "body-secret")
	s := mustParse(t, buildBase, "b.yaml")
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	vars := Vars{"id": "c1", "trace": "t-1", "q": "a b", "nl": "x\r\nInjected: 1", "code": `W"10`}
	cases := []struct {
		name    string
		st      Step
		method  string
		url     string
		headers map[string]string // expected header values ("" = must be absent)
		body    string
		secrets []string
		err     string
	}{
		{name: "relative path joined", st: Step{Request: "POST /carts"}, method: "POST", url: "https://shop.test:8443/vuln/api/carts"},
		{name: "query and template", st: Step{ID: "s1", Request: "GET /carts/{{id}}?full=1"}, method: "GET", url: "https://shop.test:8443/vuln/api/carts/c1?full=1"},
		{name: "escaped path kept", st: Step{Request: "GET /a%2Fb/x"}, method: "GET", url: "https://shop.test:8443/vuln/api/a%2Fb/x"},
		{name: "double slash stays on target host", st: Step{Request: "GET //evil.test/x"}, method: "GET", url: "https://shop.test:8443/vuln/api//evil.test/x"},
		{name: "absolute in scope", st: Step{Request: "GET https://other.test/z?y=1"}, method: "GET", url: "https://other.test/z?y=1"},
		{name: "absolute without path", st: Step{Request: "GET https://other.test"}, method: "GET", url: "https://other.test/"},
		{name: "absolute out of scope", st: Step{Request: "GET https://evil.test/"}, err: "request URL host evil.test is not in scope.allow_hosts"},
		{name: "absolute via variable out of scope", st: Step{Request: "GET https://{{id}}.evil/"}, err: "not in scope.allow_hosts"},
		{name: "relative without slash", st: Step{Request: "GET carts"}, err: `request target "carts" must start with /`},
		{name: "space from variable", st: Step{Request: "GET /s?q={{q}}"}, err: "contains spaces or control characters"},
		{name: "fragment", st: Step{Request: "GET /a#b"}, err: "cannot contain a fragment"},
		{
			name: "raw with headers and body",
			st: Step{Raw: "POST /carts/{{id}}/coupons HTTP/2\nHost: ignored.test\nContent-Length: 999\nConnection: keep-alive\n" +
				":authority: x\nContent-Type: application/json\nX-Multi: 1\nX-Multi: 2\n\n{\"code\":\"{{code}}\"}\n"},
			method:  "POST",
			url:     "https://shop.test:8443/vuln/api/carts/c1/coupons",
			headers: map[string]string{"Host": "", "Content-Length": "", "Connection": "", ":authority": "", "Content-Type": "application/json", "X-Multi": "1,2"},
			body:    `{"code":"W"10"}`,
		},
		{
			name:    "identity overrides raw and is secret",
			st:      Step{As: "alice", Raw: "GET /me\nAuthorization: Bearer stale\nAccept: */*\n"},
			method:  "GET",
			url:     "https://shop.test:8443/vuln/api/me",
			headers: map[string]string{"Authorization": "Bearer alice-token", "X-Trace": "t-1", "Accept": "*/*"},
			secrets: []string{"alice-token", "Bearer alice-token", "t-1"},
		},
		{
			name:    "json body escaped and typed",
			st:      jsonStep(t, "{code: '{{code}}', n: 3, list: [x, '${env:PF_TEST_BODY}']}", "POST /c"),
			method:  "POST",
			url:     "https://shop.test:8443/vuln/api/c",
			headers: map[string]string{"Content-Type": "application/json"},
			body:    `{"code":"W\"10","n":3,"list":["x","body-secret"]}`,
			secrets: []string{"body-secret"},
		},
		{
			name:    "json keeps explicit content type",
			st:      jsonStep(t, "{}", "POST /c\nContent-Type: application/vnd.api+json\n"),
			method:  "POST",
			url:     "https://shop.test:8443/vuln/api/c",
			headers: map[string]string{"Content-Type": "application/vnd.api+json"},
			body:    `{}`,
		},
		{name: "env secret in raw body", st: Step{Raw: "POST /\n\npw=${env:PF_TEST_BODY}\n"}, method: "POST", url: "https://shop.test:8443/vuln/api/", body: "pw=body-secret", secrets: []string{"body-secret"}},
		{name: "json and raw body", st: jsonStep(t, "{}", "POST /\n\nraw\n"), err: "json and a raw body cannot both be set"},
		{name: "header injection", st: Step{Raw: "GET /\nX-A: {{nl}}\n"}, err: "header X-A: the value contains a line break"},
		{name: "transfer encoding", st: Step{Raw: "POST /\nTransfer-Encoding: chunked\n\n0\n"}, err: "request line 2: Transfer-Encoding is not supported"},
		{name: "unknown variable", st: Step{Request: "GET /{{nope}}"}, err: "request target: unknown variable {{nope}}"},
		{name: "unknown identity", st: Step{As: "bob", Request: "GET /"}, err: `unknown identity "bob"`},
		{name: "request and raw", st: Step{Request: "GET /", Raw: "GET /"}, err: "set either request or raw, not both"},
		{name: "empty", st: Step{}, err: "the request is empty"},
		{name: "bad method from variable", st: Step{Request: "{{q}} /"}, err: `invalid method "a b"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req, secrets, err := s.BuildRequest(c.st, vars)
			if c.err != "" {
				if err == nil || !strings.Contains(err.Error(), c.err) {
					t.Fatalf("err = %v, want %q", err, c.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if req.Method != c.method || req.URL.String() != c.url {
				t.Errorf("got %s %s, want %s %s", req.Method, req.URL, c.method, c.url)
			}
			if req.Label != c.st.ID {
				t.Errorf("Label = %q", req.Label)
			}
			for k, want := range c.headers {
				if got := strings.Join(req.Header.Values(k), ","); got != want {
					t.Errorf("header %s = %q, want %q", k, got, want)
				}
				if want == "" && len(req.Header[k]) > 0 {
					t.Errorf("header %s present", k)
				}
			}
			if string(req.Body) != c.body {
				t.Errorf("body = %q, want %q", req.Body, c.body)
			}
			slices.Sort(secrets)
			slices.Sort(c.secrets)
			if !slices.Equal(secrets, c.secrets) {
				t.Errorf("secrets = %q, want %q", secrets, c.secrets)
			}
		})
	}
}

func jsonStep(t *testing.T, json, request string) Step {
	t.Helper()
	src := "setup:\n  - json: " + json + "\n    raw: " + strconv.Quote(request) + "\n"
	s := mustParse(t, src, "j.yaml")
	return s.Setup[0]
}

func TestBuildRequestTargetRoot(t *testing.T) {
	for _, c := range []struct{ target, req, want string }{
		{"https://h", "/x", "https://h/x"},
		{"https://h/", "/x", "https://h/x"},
		{"https://h/api/", "/x", "https://h/api/x"},
		{"https://h/api", "/", "https://h/api/"},
		{"http://h:8080/a%20b", "/c", "http://h:8080/a%20b/c"},
	} {
		s := &Scenario{Target: c.target, Scope: Scope{AllowHosts: []string{"h"}}}
		req, _, err := s.BuildRequest(Step{Request: "GET " + c.req}, nil)
		if err != nil {
			t.Errorf("%s + %s: %v", c.target, c.req, err)
			continue
		}
		if req.URL.String() != c.want {
			t.Errorf("%s + %s = %s, want %s", c.target, c.req, req.URL, c.want)
		}
	}
	s := &Scenario{Target: "https://h?x=1", Scope: Scope{AllowHosts: []string{"h"}}}
	if _, _, err := s.BuildRequest(Step{Request: "GET /"}, nil); err == nil || !strings.Contains(err.Error(), "target: the base URL cannot have a query") {
		t.Errorf("err = %v", err)
	}
}

func TestBuildRequestErrorKeepsSecrets(t *testing.T) {
	// The error quotes the expanded target, so the env value it contains
	// must still be returned for masking.
	t.Setenv("PF_TEST_SPACE", "my secret value")
	s := &Scenario{Target: "https://h/api", Scope: Scope{AllowHosts: []string{"h"}}}
	for _, req := range []string{"GET /c?x=1&q=${env:PF_TEST_SPACE}", "${env:PF_TEST_SPACE} /c"} {
		_, secrets, err := s.BuildRequest(Step{Request: req}, nil)
		if err == nil || !strings.Contains(err.Error(), "my secret value") {
			t.Fatalf("%s: err = %v", req, err)
		}
		if !slices.Contains(secrets, "my secret value") {
			t.Errorf("%s: secrets = %q", req, secrets)
		}
	}
}
