package scenario

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"golang.org/x/net/http/httpguts"

	"github.com/TroubieD3v/photofinish/internal/engine"
)

// TargetURL parses and checks the scenario target: an absolute http or
// https URL with a host and without user info, query, fragment or
// placeholders.
func (s *Scenario) TargetURL() (*url.URL, error) {
	if strings.TrimSpace(s.Target) == "" {
		return nil, errors.New("required: the base URL, e.g. https://127.0.0.1:8443/vuln/api")
	}
	if hasPlaceholder(s.Target) {
		return nil, errors.New("placeholders are not allowed in the target (scope is checked against it)")
	}
	u, err := url.Parse(s.Target)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %v", unwrapURLError(err))
	}
	switch {
	case u.Scheme != "http" && u.Scheme != "https":
		return nil, fmt.Errorf("must be an absolute http:// or https:// URL, got %q", s.Target)
	case u.Host == "" || u.Hostname() == "":
		return nil, fmt.Errorf("the URL %q has no host", s.Target)
	case u.User != nil:
		return nil, errors.New("user info in the URL is not supported; use an identity header")
	case u.RawQuery != "" || u.ForceQuery:
		return nil, errors.New("the base URL cannot have a query; put it in the request line")
	case u.Fragment != "":
		return nil, errors.New("the base URL cannot have a fragment")
	}
	return u, nil
}

func unwrapURLError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

// Allows reports whether host (as in URL.Host, with or without a port) is
// in scope. Names are compared case-insensitively; an entry without a port
// allows any port, an entry with a port allows only that port.
func (sc Scope) Allows(host string) bool {
	h, p := splitHost(host)
	if h == "" {
		return false
	}
	for _, e := range sc.AllowHosts {
		eh, ep := splitHost(e)
		if eh == h && (ep == "" || ep == p) {
			return true
		}
	}
	return false
}

// AllowsURL reports whether the host of u is in scope; a URL without an
// explicit port is checked with the default port of its scheme.
func (sc Scope) AllowsURL(u *url.URL) bool {
	if u == nil {
		return false
	}
	host := u.Host
	if u.Port() == "" {
		switch strings.ToLower(u.Scheme) {
		case "https":
			host = net.JoinHostPort(u.Hostname(), "443")
		case "http":
			host = net.JoinHostPort(u.Hostname(), "80")
		}
	}
	return sc.Allows(host)
}

// splitHost splits "host[:port]" into a lowercased host without brackets
// or trailing dot, and the port ("" if none).
func splitHost(s string) (host, port string) {
	s = strings.ToLower(strings.TrimSpace(s))
	if h, p, err := net.SplitHostPort(s); err == nil {
		return strings.TrimSuffix(h, "."), p
	}
	return strings.TrimSuffix(strings.TrimSuffix(strings.TrimPrefix(s, "["), "]"), "."), ""
}

// rawRequest is a parsed request template; its parts are expanded later.
type rawRequest struct {
	method  string
	target  string
	version string
	headers []rawHeader
	body    string
}

type rawHeader struct {
	name, value string
	line        int // 1-based line within the request text
}

// parseRaw parses a request text: a first line "METHOD /path[?q] [HTTP/x]"
// (the version is ignored), header lines up to a blank line, and the body.
// One trailing line break of the body ("\n" from the YAML block, or
// "\r\n") is removed.
func parseRaw(text string) (*rawRequest, error) {
	trimmed := strings.TrimLeft(text, " \t\r\n")
	lineNo := 1 + strings.Count(text[:len(text)-len(trimmed)], "\n")
	text = trimmed
	if text == "" {
		return nil, errors.New("the request is empty; want \"METHOD /path\"")
	}
	first, rest, _ := strings.Cut(text, "\n")
	first = strings.TrimSpace(first)
	fields := strings.Fields(first)
	if len(fields) < 2 || len(fields) > 3 {
		return nil, fmt.Errorf("request line %d: want \"METHOD /path [HTTP/version]\", got %q", lineNo, first)
	}
	r := &rawRequest{method: fields[0], target: fields[1]}
	if len(fields) == 3 {
		if !strings.HasPrefix(strings.ToUpper(fields[2]), "HTTP/") {
			return nil, fmt.Errorf("request line %d: the third word must be an HTTP version such as HTTP/2, got %q", lineNo, fields[2])
		}
		r.version = fields[2]
	}
	for rest != "" {
		lineNo++
		var line string
		line, rest, _ = strings.Cut(rest, "\n")
		line = strings.TrimSuffix(line, "\r")
		if strings.TrimSpace(line) == "" {
			r.body = trimLineBreak(rest)
			return r, nil
		}
		if line[0] == ' ' || line[0] == '\t' {
			return nil, fmt.Errorf("request line %d: folded (indented) header lines are not supported", lineNo)
		}
		var name, value string
		var ok bool
		if strings.HasPrefix(line, ":") {
			// An HTTP/2 pseudo header copied from browser tools, such as
			// ":authority: example.com"; it is dropped later.
			name, value, ok = strings.Cut(line[1:], ":")
			name = ":" + name
		} else {
			name, value, ok = strings.Cut(line, ":")
		}
		if !ok || strings.TrimSpace(name) == "" {
			return nil, fmt.Errorf("request line %d: want \"Name: value\" (or a blank line before the body), got %q", lineNo, line)
		}
		if name != strings.TrimSpace(name) {
			return nil, fmt.Errorf("request line %d: no spaces are allowed around the header name %q", lineNo, name)
		}
		r.headers = append(r.headers, rawHeader{name: name, value: strings.TrimSpace(value), line: lineNo})
	}
	return r, nil
}

// trimLineBreak removes one trailing "\r\n" or "\n" from s.
func trimLineBreak(s string) string {
	if t, ok := strings.CutSuffix(s, "\r\n"); ok {
		return t
	}
	return strings.TrimSuffix(s, "\n")
}

// ignoredHeaders are dropped from raw requests: the engine sets Host and
// Content-Length, and hop-by-hop headers are invalid in HTTP/2.
var ignoredHeaders = []string{"host", "content-length", "connection", "keep-alive", "proxy-connection", "upgrade", "te"}

// headerRule reports whether a raw header is dropped, or why it is invalid.
func headerRule(name string) (ignore bool, err error) {
	if strings.HasPrefix(name, ":") {
		return true, nil
	}
	lower := strings.ToLower(name)
	if lower == "transfer-encoding" {
		return false, errors.New("Transfer-Encoding is not supported; write the body unencoded (the engine sets Content-Length)")
	}
	if slices.Contains(ignoredHeaders, lower) {
		return true, nil
	}
	if !httpguts.ValidHeaderFieldName(name) {
		return false, fmt.Errorf("invalid header name %q", name)
	}
	return false, nil
}

// BuildRequest turns a step into an engine request: it expands templates
// with vars and the environment, parses the request text, joins relative
// paths to the target path, checks absolute URLs against the scope, adds the
// identity headers (they replace raw headers of the same name) and encodes
// the JSON body. It returns the values that reports must mask: identity
// header values and values that came from ${env:...}. The values are
// returned with an error too, since the error may quote an expanded value.
func (s *Scenario) BuildRequest(st Step, vars Vars) (engine.Request, []string, error) {
	var req engine.Request
	if st.Request != "" && st.Raw != "" {
		return req, nil, errors.New("set either request or raw, not both")
	}
	raw, err := parseRaw(st.Text())
	if err != nil {
		return req, nil, err
	}
	var secrets []string
	exp := func(what, s string) (string, error) {
		v, sec, err := expand(s, vars)
		if err != nil {
			return "", fmt.Errorf("%s: %w", what, err)
		}
		secrets = append(secrets, sec...)
		return v, nil
	}

	method, err := exp("method", raw.method)
	if err != nil {
		return req, dedupe(secrets), err
	}
	if !httpguts.ValidHeaderFieldName(method) {
		return req, dedupe(secrets), fmt.Errorf("invalid method %q", method)
	}
	target, err := exp("request target", raw.target)
	if err != nil {
		return req, dedupe(secrets), err
	}
	u, err := s.resolve(target)
	if err != nil {
		return req, dedupe(secrets), err
	}

	header := http.Header{}
	for _, h := range raw.headers {
		ignore, err := headerRule(h.name)
		if err != nil {
			return req, dedupe(secrets), fmt.Errorf("request line %d: %v", h.line, err)
		}
		if ignore {
			continue
		}
		v, err := exp("header "+h.name, h.value)
		if err != nil {
			return req, dedupe(secrets), err
		}
		if !httpguts.ValidHeaderFieldValue(v) {
			return req, dedupe(secrets), fmt.Errorf("header %s: the value contains a line break or control character", h.name)
		}
		header.Add(h.name, v)
	}
	if st.As != "" {
		id, ok := s.Identities[st.As]
		if !ok {
			return req, dedupe(secrets), fmt.Errorf("unknown identity %q", st.As)
		}
		names := make([]string, 0, len(id.Headers))
		for n := range id.Headers {
			names = append(names, n)
		}
		slices.Sort(names)
		for _, n := range names {
			if ignore, err := headerRule(n); err != nil || ignore {
				return req, dedupe(secrets), fmt.Errorf("identity %s: header %q cannot be set", st.As, n)
			}
			v, err := exp("identity "+st.As+" header "+n, id.Headers[n])
			if err != nil {
				return req, dedupe(secrets), err
			}
			if !httpguts.ValidHeaderFieldValue(v) {
				return req, dedupe(secrets), fmt.Errorf("identity %s: header %s: the value contains a line break or control character", st.As, n)
			}
			header.Set(n, v)
			if v != "" {
				secrets = append(secrets, v)
			}
		}
	}

	var body []byte
	if raw.body != "" {
		b, err := exp("body", raw.body)
		if err != nil {
			return req, dedupe(secrets), err
		}
		body = []byte(b)
	}
	if !st.JSON.IsZero() {
		if raw.body != "" {
			return req, dedupe(secrets), errors.New("json and a raw body cannot both be set")
		}
		b, sec, err := st.JSON.Encode(vars)
		secrets = append(secrets, sec...)
		if err != nil {
			return req, dedupe(secrets), fmt.Errorf("json: %w", err)
		}
		body = b
		if header.Get("Content-Type") == "" {
			header.Set("Content-Type", "application/json")
		}
	}

	req = engine.Request{Label: st.ID, Method: method, URL: u, Header: header, Body: body}
	return req, dedupe(secrets), nil
}

// resolve turns a request target into an absolute URL: a path is joined to
// the target's path, an absolute URL must be in scope.
func (s *Scenario) resolve(target string) (*url.URL, error) {
	if strings.ContainsAny(target, " \t\r\n") || strings.ContainsFunc(target, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return nil, fmt.Errorf("request target %q contains spaces or control characters; percent-encode them", target)
	}
	if strings.Contains(target, "#") {
		return nil, fmt.Errorf("request target %q cannot contain a fragment (#)", target)
	}
	lower := strings.ToLower(target)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		u, err := url.Parse(target)
		if err != nil {
			return nil, fmt.Errorf("request URL %q: %v", target, unwrapURLError(err))
		}
		if u.Hostname() == "" {
			return nil, fmt.Errorf("request URL %q has no host", target)
		}
		if u.User != nil {
			return nil, fmt.Errorf("request URL %q: user info is not supported", target)
		}
		if !s.Scope.AllowsURL(u) {
			return nil, fmt.Errorf("request URL host %s is not in scope.allow_hosts", u.Host)
		}
		if u.Path == "" {
			u.Path = "/"
		}
		return u, nil
	}
	if !strings.HasPrefix(target, "/") {
		return nil, fmt.Errorf("request target %q must start with / (it is joined to the target path) or be an absolute http(s) URL", target)
	}
	base, err := s.TargetURL()
	if err != nil {
		return nil, fmt.Errorf("target: %v", err)
	}
	p, q, hasQuery := strings.Cut(target, "?")
	full := base.Scheme + "://" + base.Host + strings.TrimSuffix(base.EscapedPath(), "/") + p
	if hasQuery {
		full += "?" + q
	}
	u, err := url.Parse(full)
	if err != nil {
		return nil, fmt.Errorf("request target %q: %v", target, unwrapURLError(err))
	}
	if u.Host != base.Host {
		return nil, fmt.Errorf("request target %q changes the host", target)
	}
	return u, nil
}

func dedupe(ss []string) []string {
	if len(ss) == 0 {
		return nil
	}
	out := ss[:0:0]
	seen := map[string]bool{}
	for _, s := range ss {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
