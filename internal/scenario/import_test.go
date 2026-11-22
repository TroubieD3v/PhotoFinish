package scenario

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

const burpRequest = "POST /vuln/api/carts/c-1/coupons HTTP/2\r\n" +
	"Host: 127.0.0.1:8443\r\n" +
	"Authorization: Bearer demo-alice\r\n" +
	"Accept-Encoding: gzip, deflate, br\r\n" +
	"Content-Type: application/json\r\n" +
	"Content-Length: 20\r\n" +
	"Connection: keep-alive\r\n" +
	"\r\n" +
	`{"code":"WELCOME10"}`

// checkSkeleton verifies the properties every imported scenario shares: the
// only validation error is the TODO invariant, and the race request matches
// the imported one.
func checkSkeleton(t *testing.T, s *Scenario, method, url, body string, headers map[string]string) {
	t.Helper()
	err := s.Validate()
	if err == nil {
		t.Fatal("an imported skeleton must not validate before the invariant is written")
	}
	var fe *FieldError
	if !errors.As(err, &fe) || fe.Field != "check.invariant" || strings.Contains(err.Error(), "\n") {
		t.Fatalf("Validate error must be only check.invariant, got:\n%v", err)
	}
	if !strings.Contains(err.Error(), "TODO placeholder") {
		t.Errorf("error does not explain the placeholder: %v", err)
	}
	req, _, err := s.BuildRequest(s.Race.Request.Step, nil)
	if err != nil {
		t.Fatalf("BuildRequest: %v", err)
	}
	if req.Method != method || req.URL.String() != url || string(req.Body) != body {
		t.Errorf("request = %s %s %q, want %s %s %q", req.Method, req.URL, req.Body, method, url, body)
	}
	for k, want := range headers {
		if got := req.Header.Get(k); got != want {
			t.Errorf("header %s = %q, want %q", k, got, want)
		}
	}
	// Writing the invariant is all it takes to get a valid scenario.
	s.Check.Invariant = "size(race.filter(r, r.status == 200)) <= 1"
	if err := s.Validate(); err != nil {
		t.Errorf("Validate after writing the invariant: %v", err)
	}
}

func TestImportBurpRaw(t *testing.T) {
	s, err := ImportBurp([]byte(burpRequest))
	if err != nil {
		t.Fatal(err)
	}
	out, err := Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "import-burp.golden.yaml", out)
	if strings.Contains(string(out), "Accept-Encoding") || strings.Contains(string(out), "Content-Length") || strings.Contains(string(out), "Host:") {
		t.Errorf("dropped headers are in the output:\n%s", out)
	}
	re, err := Parse(out, "import.yaml")
	if err != nil {
		t.Fatalf("Parse(Marshal(import)): %v", err)
	}
	checkSkeleton(t, re, "POST", "https://127.0.0.1:8443/vuln/api/carts/c-1/coupons", `{"code":"WELCOME10"}`,
		map[string]string{"Authorization": "Bearer demo-alice", "Content-Type": "application/json", "Accept-Encoding": "", "Connection": ""})
}

func TestImportBurpVariants(t *testing.T) {
	cases := []struct {
		name, in      string
		target, host  string
		url, body, nm string
		err           string
	}{
		{name: "lf line endings, no body", in: "GET /api/me HTTP/1.1\nHost: Shop.Test\n\n", target: "https://Shop.Test", host: "Shop.Test", url: "https://Shop.Test/api/me", nm: "get-api-me"},
		{name: "body keeps trailing newline", in: "POST /x HTTP/1.1\r\nHost: h\r\n\r\na=1\n", target: "https://h", host: "h", url: "https://h/x", body: "a=1\n", nm: "post-x"},
		{name: "absolute form", in: "GET http://h:8080/a?b=1 HTTP/1.1\r\nHost: ignored\r\n\r\n", target: "http://h:8080", host: "h:8080", url: "http://h:8080/a?b=1", nm: "get-a"},
		{name: "chunked body decoded", in: "POST /c HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n", target: "https://h", host: "h", url: "https://h/c", body: "abc", nm: "post-c"},
		{name: "root path", in: "GET / HTTP/1.1\nHost: h\n", target: "https://h", host: "h", url: "https://h/", nm: "get-request"},
		{name: "bom and leading blank lines", in: "\xef\xbb\xbf\r\n\r\nGET /a HTTP/1.1\r\nHost: h\r\n\r\n", target: "https://h", host: "h", url: "https://h/a", nm: "get-a"},
		{name: "http2 pseudo headers", in: "POST /api/redeem HTTP/2\n:method: POST\n:authority: shop.example.com\n:scheme: https\n:path: /api/redeem\ncontent-type: application/json\n\n{}",
			target: "https://shop.example.com", host: "shop.example.com", url: "https://shop.example.com/api/redeem", body: "{}", nm: "post-api-redeem"},
		{name: "http2 pseudo headers, http", in: "GET /a HTTP/2\n:authority: h:8080\n:scheme: http\n\n",
			target: "http://h:8080", host: "h:8080", url: "http://h:8080/a", nm: "get-a"},
		{name: "template syntax kept literal", in: "POST /t HTTP/1.1\nHost: h\nX-Tpl: {{x}}\n\n{\"tpl\":\"{{7*7}}\",\"n\":\"{{name}}\",\"e\":\"${env:HOME}\"}",
			target: "https://h", host: "h", url: "https://h/t", body: `{"tpl":"{{7*7}}","n":"{{name}}","e":"${env:HOME}"}`, nm: "post-t"},
		{name: "no host", in: "GET / HTTP/1.1\r\nAccept: */*\r\n\r\n", err: "no Host header"},
		{name: "empty", in: "\r\n", err: "the file is empty"},
		{name: "not http", in: "hello\n", err: "not a raw HTTP request"},
		{name: "binary body", in: "POST / HTTP/1.1\r\nHost: h\r\n\r\n\x00\xff", err: "the request body is binary"},
		{name: "bad chunked", in: "POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n", err: "the chunked body is malformed"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, err := ImportBurp([]byte(c.in))
			if c.err != "" {
				if err == nil || !strings.Contains(err.Error(), c.err) {
					t.Fatalf("err = %v, want %q", err, c.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if s.Target != c.target || len(s.Scope.AllowHosts) != 1 || s.Scope.AllowHosts[0] != c.host || s.Name != c.nm {
				t.Errorf("target %q scope %v name %q", s.Target, s.Scope.AllowHosts, s.Name)
			}
			method, _, _ := strings.Cut(strings.TrimLeft(c.in, "\xef\xbb\xbf\r\n"), " ")
			checkSkeleton(t, s, method, c.url, c.body, nil)
		})
	}
}

func TestImportBurpXML(t *testing.T) {
	enc := base64.StdEncoding.EncodeToString([]byte(burpRequest))
	xml := `<?xml version="1.0"?>
<!DOCTYPE items [
<!ELEMENT items (item*)>
]>
<items burpVersion="2026.1" exportTime="Sun Nov 22 10:00:00 UTC 2026">
  <item>
    <time>Sun Nov 22 10:00:00 UTC 2026</time>
    <url><![CDATA[https://127.0.0.1:8443/vuln/api/carts/c-1/coupons]]></url>
    <host ip="127.0.0.1">127.0.0.1</host>
    <port>8443</port>
    <protocol>https</protocol>
    <method><![CDATA[POST]]></method>
    <request base64="true"><![CDATA[` + enc[:20] + "\n" + enc[20:] + `]]></request>
  </item>
  <item><url>https://other.test/</url><request base64="false">GET / HTTP/1.1</request></item>
</items>`
	s, err := ImportBurp([]byte(xml))
	if err != nil {
		t.Fatal(err)
	}
	if s.Target != "https://127.0.0.1:8443" {
		t.Errorf("target %q", s.Target)
	}
	if !strings.Contains(s.Description, "Burp XML export") {
		t.Errorf("description %q", s.Description)
	}
	checkSkeleton(t, s, "POST", "https://127.0.0.1:8443/vuln/api/carts/c-1/coupons", `{"code":"WELCOME10"}`, nil)

	// Without a usable URL the protocol, host and port elements decide.
	plain := `<items><item><host>shop.test</host><port>80</port><protocol>http</protocol>` +
		`<request base64="false"><![CDATA[GET /x HTTP/1.1` + "\r\nHost: wrong.test\r\n\r\n" + `]]></request></item></items>`
	s, err = ImportBurp([]byte(plain))
	if err != nil {
		t.Fatal(err)
	}
	if s.Target != "http://shop.test" {
		t.Errorf("target %q", s.Target)
	}

	for _, bad := range []struct{ in, err string }{
		{"<items></items>", "no <item> elements"},
		{`<items><item><request base64="true">!!!</request></item></items>`, "not valid base64"},
		{"<items><item>", "burp XML"},
	} {
		if _, err := ImportBurp([]byte(bad.in)); err == nil || !strings.Contains(err.Error(), bad.err) {
			t.Errorf("%q: err = %v, want %q", bad.in, err, bad.err)
		}
	}
}

func TestImportHAR(t *testing.T) {
	data := []byte(mustRead(t, "coupon.har"))
	if !IsHAR(data) {
		t.Fatal("IsHAR = false")
	}
	if IsHAR([]byte(burpRequest)) || IsHAR([]byte(`{"log":{}}`)) || IsHAR([]byte(`[]`)) {
		t.Error("IsHAR = true for a non-HAR input")
	}
	s, err := ImportHAR(data, 1)
	if err != nil {
		t.Fatal(err)
	}
	out, err := Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "import-har.golden.yaml", out)
	re, err := Parse(out, "har.yaml")
	if err != nil {
		t.Fatal(err)
	}
	checkSkeleton(t, re, "POST", "https://127.0.0.1:8443/vuln/api/carts/c-1/coupons?src=web", `{"code":"WELCOME10"}`,
		map[string]string{"Authorization": "Bearer demo-alice", "Content-Type": "application/json"})

	s, err = ImportHAR(data, 2)
	if err != nil {
		t.Fatal(err)
	}
	if s.Target != "http://shop.test" || s.Name != "post-login" {
		t.Errorf("target %q name %q", s.Target, s.Name)
	}
	checkSkeleton(t, s, "POST", "http://shop.test/login", "code=48+29&user=alice",
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"})

	s, err = ImportHAR(data, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(s.Race.Request.Raw, "GET /vuln/api/me HTTP/2\n") || strings.Contains(s.Race.Request.Raw, ":authority") {
		t.Errorf("raw = %q", s.Race.Request.Raw)
	}

	for _, bad := range []struct {
		in    string
		entry int
		err   string
	}{
		{string(data), 3, "HAR entry 3 does not exist; the file has 3 entries (0-2)"},
		{string(data), -1, "HAR entry -1 does not exist"},
		{`{"log":{"entries":[]}}`, 0, "the HAR file has no entries"},
		{`not json`, 0, "not a HAR file"},
		{`{"log":{"entries":[{"request":{"method":"GET","url":"/relative"}}]}}`, 0, "is not an absolute http(s) URL"},
		{`{"log":{"entries":[{"request":{"method":"","url":"https://h/"}}]}}`, 0, "request.method is empty"},
	} {
		if _, err := ImportHAR([]byte(bad.in), bad.entry); err == nil || !strings.Contains(err.Error(), bad.err) {
			t.Errorf("entry %d of %.30q: err = %v, want %q", bad.entry, bad.in, err, bad.err)
		}
	}
}

func TestImportName(t *testing.T) {
	cases := []struct{ method, path, want string }{
		{"POST", "/vuln/api/carts/c-1/coupons?x=1", "post-vuln-api-carts-c-1-coupons"},
		{"GET", "/", "get-request"},
		{"GET", "", "get-request"},
		{"PUT", "/Ünïcode/ÄB", "put-n-code-b"},
		{"DELETE", "/" + strings.Repeat("abcdefghij/", 10), "delete-abcdefghij-abcdefghij-abcdefghij-abcdefgh"},
	}
	for _, c := range cases {
		got := importName(c.method, c.path)
		if got != c.want {
			t.Errorf("importName(%q, %q) = %q, want %q", c.method, c.path, got, c.want)
		}
		if !nameRE.MatchString(got) || len(got) > 48 {
			t.Errorf("importName(%q, %q) = %q is not a valid name", c.method, c.path, got)
		}
	}
}

func TestMarshalNil(t *testing.T) {
	if _, err := Marshal(nil); err == nil {
		t.Error("Marshal(nil) succeeded")
	}
}
