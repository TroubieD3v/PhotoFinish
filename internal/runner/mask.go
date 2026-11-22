package runner

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// masked replaces every secret in a report.
const masked = "[masked]"

// minHarvested is the shortest value collected from responses as a secret.
// Shorter values ("1", "ok") would mask unrelated text all over the report;
// they are still masked where they appear under a sensitive key or header.
const minHarvested = 3

// sensitiveKey matches JSON keys, query parameters and header names whose
// values are masked.
var sensitiveKey = regexp.MustCompile(`(?i)(pass(word)?|secret|token|api[_-]?key|authorization|session)`)

// sensitiveHeaders are always masked, in canonical form.
var sensitiveHeaders = []string{
	"Authorization", "Proxy-Authorization", "Cookie", "Set-Cookie", "X-Api-Key", "X-Auth-Token",
}

// masker collects secret values and sensitive header names during a run and
// removes them from everything stored in the report. Secrets found late
// (a session token in the third trial) still mask earlier records, because
// the report is masked once, after the run.
type masker struct {
	mu      sync.Mutex
	headers map[string]bool     // canonical header names to mask
	secrets map[string]struct{} // literal values to mask anywhere
}

// newMasker returns a masker for the built-in sensitive headers.
func newMasker() *masker {
	m := &masker{headers: map[string]bool{}, secrets: map[string]struct{}{}}
	for _, h := range sensitiveHeaders {
		m.headers[h] = true
	}
	return m
}

// addHeader marks a header name (an identity header) as sensitive.
func (m *masker) addHeader(name string) {
	m.mu.Lock()
	m.headers[http.CanonicalHeaderKey(name)] = true
	m.mu.Unlock()
}

// addSecret records a value that must not appear in the report, together
// with the forms it takes when a server echoes it back or a report quotes
// it: JSON string escaping (with and without HTML escaping), path and query
// percent-encoding, and Go/CEL string quoting.
func (m *masker) addSecret(v string) {
	v = strings.TrimSpace(v)
	if v == "" || v == masked {
		return
	}
	forms := encodedForms(v)
	m.mu.Lock()
	for _, f := range forms {
		m.secrets[f] = struct{}{}
	}
	m.mu.Unlock()
}

// encodedForms returns v and its escaped and encoded forms, without the
// surrounding quotes.
func encodedForms(v string) []string {
	forms := []string{v, url.PathEscape(v), url.QueryEscape(v)}
	if q := strconv.Quote(v); len(q) >= 2 {
		forms = append(forms, q[1:len(q)-1])
	}
	if q, err := json.Marshal(v); err == nil && len(q) >= 2 {
		forms = append(forms, string(q[1:len(q)-1]))
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err == nil {
		if q := bytes.TrimSuffix(buf.Bytes(), []byte("\n")); len(q) >= 2 {
			forms = append(forms, string(q[1:len(q)-1]))
		}
	}
	return forms
}

// addHarvested records a value found in traffic, if it is long enough.
func (m *masker) addHarvested(v string) {
	if len(strings.TrimSpace(v)) >= minHarvested {
		m.addSecret(v)
	}
}

// sensitiveHeader reports whether the values of header name are masked.
func (m *masker) sensitiveHeader(name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.headers[http.CanonicalHeaderKey(name)] || sensitiveKey.MatchString(name)
}

// cookieAttributes are the Set-Cookie attributes; their values (a path, a
// domain, a lifetime) are not secrets.
var cookieAttributes = map[string]bool{
	"path": true, "domain": true, "expires": true, "max-age": true, "samesite": true,
	"secure": true, "httponly": true, "partitioned": true, "priority": true,
}

// harvestHeader collects the values of sensitive headers in h as secrets:
// the whole value, the credential after an auth scheme, and cookie values.
// Of a Set-Cookie header only the cookie value is collected, not its
// attributes.
func (m *masker) harvestHeader(h http.Header) {
	for name, vals := range h {
		if !m.sensitiveHeader(name) {
			continue
		}
		setCookie := http.CanonicalHeaderKey(name) == "Set-Cookie"
		for _, v := range vals {
			m.addHarvested(v)
			if setCookie {
				pair, _, _ := strings.Cut(v, ";")
				if _, val, ok := strings.Cut(pair, "="); ok {
					m.addHarvested(strings.Trim(strings.TrimSpace(val), `"`))
				}
				continue
			}
			if _, cred, ok := strings.Cut(v, " "); ok {
				m.addHarvested(cred)
			}
			for _, part := range strings.Split(v, ";") {
				key, val, ok := strings.Cut(part, "=")
				if ok && !cookieAttributes[strings.ToLower(strings.TrimSpace(key))] {
					m.addHarvested(strings.Trim(strings.TrimSpace(val), `"`))
				}
			}
		}
	}
}

// harvestJSON collects the string values of sensitive keys in a JSON body.
// Numbers and booleans are not collected: masking every "3600" in a report
// would hide unrelated values, and they are masked in place under their
// key anyway. A body that is not valid JSON (for example one truncated by
// the engine) is scanned for "key": "value" pairs instead.
func (m *masker) harvestJSON(body []byte) {
	v, ok := decodeJSON(body)
	if !ok {
		for _, loc := range sensitivePairRE.FindAllSubmatchIndex(body, -1) {
			if !sensitiveKey.Match(body[loc[2]:loc[3]]) {
				continue
			}
			if val := body[loc[4]:loc[5]]; len(val) > 0 && val[0] == '"' {
				m.addHarvested(unquoteLoose(val))
			}
		}
		return
	}
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, e := range x {
				if sensitiveKey.MatchString(k) {
					collectStrings(e, m.addHarvested)
					continue
				}
				walk(e)
			}
		case []any:
			for _, e := range x {
				walk(e)
			}
		}
	}
	walk(v)
}

// collectStrings calls f for every string under v.
func collectStrings(v any, f func(string)) {
	switch x := v.(type) {
	case string:
		f(x)
	case map[string]any:
		for _, e := range x {
			collectStrings(e, f)
		}
	case []any:
		for _, e := range x {
			collectStrings(e, f)
		}
	}
}

// replacer returns a replacer for all known secrets, longest first so that
// a secret containing another is masked as a whole.
func (m *masker) replacer() *strings.Replacer {
	m.mu.Lock()
	list := make([]string, 0, len(m.secrets))
	for s := range m.secrets {
		list = append(list, s)
	}
	m.mu.Unlock()
	sort.Slice(list, func(i, j int) bool {
		if len(list[i]) != len(list[j]) {
			return len(list[i]) > len(list[j])
		}
		return list[i] < list[j]
	})
	pairs := make([]string, 0, 2*len(list))
	for _, s := range list {
		pairs = append(pairs, s, masked)
	}
	return strings.NewReplacer(pairs...)
}

// scrubber applies a masker's rules with a fixed set of secrets.
type scrubber struct {
	m   *masker
	rep *strings.Replacer
}

// scrubber freezes the current secrets for masking a report.
func (m *masker) scrubber() *scrubber {
	return &scrubber{m: m, rep: m.replacer()}
}

// str removes secrets from free text.
func (s *scrubber) str(v string) string { return s.rep.Replace(v) }

// strs removes secrets from every element of list, in place.
func (s *scrubber) strs(list []string) {
	for i, v := range list {
		list[i] = s.str(v)
	}
}

// url masks sensitive query parameters and secrets in a URL string.
func (s *scrubber) url(raw string) string {
	base, query, ok := strings.Cut(raw, "?")
	if !ok {
		return s.str(raw)
	}
	frag := ""
	if q, f, ok := strings.Cut(query, "#"); ok {
		query, frag = q, "#"+f
	}
	parts := strings.Split(query, "&")
	for i, p := range parts {
		if k, _, ok := strings.Cut(p, "="); ok && sensitiveKey.MatchString(k) {
			parts[i] = k + "=" + masked
		}
	}
	return s.str(base + "?" + strings.Join(parts, "&") + frag)
}

// header returns a copy of h with sensitive values masked and secrets removed.
func (s *scrubber) header(h http.Header) http.Header {
	if h == nil {
		return nil
	}
	out := make(http.Header, len(h))
	for name, vals := range h {
		cp := make([]string, len(vals))
		for i, v := range vals {
			if s.m.sensitiveHeader(name) {
				cp[i] = masked
			} else {
				cp[i] = s.str(v)
			}
		}
		out[name] = cp
	}
	return out
}

// body masks the values of sensitive JSON keys and removes secrets from any
// body. A valid JSON document is re-encoded compactly with sorted keys; any
// other body (a truncated document, a page with inline JSON) has its
// "key": value pairs masked by a tolerant scan.
func (s *scrubber) body(b []byte) []byte {
	if len(b) == 0 {
		return b
	}
	if v, ok := decodeJSON(b); ok {
		if maskKeys(v) {
			var buf bytes.Buffer
			enc := json.NewEncoder(&buf)
			enc.SetEscapeHTML(false)
			if err := enc.Encode(v); err == nil {
				b = bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
			}
		}
	} else {
		b = maskPairs(b)
	}
	return []byte(s.str(string(b)))
}

// sensitivePairRE matches a JSON "key": value pair in text that may not be
// valid JSON. The value is a string (its closing quote may be missing when
// the text was cut) or a bare token up to the next delimiter.
var sensitivePairRE = regexp.MustCompile(`"((?:[^"\\]|\\.)*)"\s*:\s*("(?:[^"\\]|\\.)*"?|[^,{}\[\]\s"]+)`)

// maskPairs replaces the values of sensitive keys in b with "[masked]".
func maskPairs(b []byte) []byte {
	locs := sensitivePairRE.FindAllSubmatchIndex(b, -1)
	if len(locs) == 0 {
		return b
	}
	var out []byte
	last := 0
	for _, loc := range locs {
		if !sensitiveKey.Match(b[loc[2]:loc[3]]) {
			continue
		}
		out = append(out, b[last:loc[4]]...)
		out = append(out, `"`+masked+`"`...)
		last = loc[5]
	}
	if out == nil {
		return b
	}
	return append(out, b[last:]...)
}

// unquoteLoose returns the content of a JSON string token that may lack its
// closing quote, unescaped when it is complete.
func unquoteLoose(tok []byte) string {
	var v string
	if err := json.Unmarshal(tok, &v); err == nil {
		return v
	}
	return strings.TrimPrefix(string(tok), `"`)
}

// maskKeys replaces the values of sensitive keys under v and reports
// whether it changed anything.
func maskKeys(v any) bool {
	changed := false
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			if sensitiveKey.MatchString(k) {
				x[k] = masked
				changed = true
				continue
			}
			if maskKeys(e) {
				changed = true
			}
		}
	case []any:
		for _, e := range x {
			if maskKeys(e) {
				changed = true
			}
		}
	}
	return changed
}

// decodeJSON parses one JSON document, keeping numbers exact.
func decodeJSON(b []byte) (any, bool) {
	t := bytes.TrimSpace(b)
	if len(t) == 0 || (t[0] != '{' && t[0] != '[') {
		return nil, false
	}
	dec := json.NewDecoder(bytes.NewReader(t))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, false
	}
	if dec.More() {
		return nil, false
	}
	return v, true
}
