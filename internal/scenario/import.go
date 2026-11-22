package scenario

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http/httputil"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"github.com/TroubieD3v/photofinish/internal/engine"
)

// Marshal writes a scenario as YAML. Unset (zero) values are omitted, so a
// parsed file comes back without the defaults it did not spell out.
func Marshal(s *Scenario) ([]byte, error) {
	if s == nil {
		return nil, errors.New("nil scenario")
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(s); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// importDropped are headers left out of imported requests: the engine sets
// Host and Content-Length, hop-by-hop headers are invalid in HTTP/2, and a
// compressed response would hide the body from extraction and the invariant.
var importDropped = []string{"host", "content-length", "connection", "keep-alive", "proxy-connection",
	"upgrade", "te", "transfer-encoding", "accept-encoding"}

type importedHeader struct{ name, value string }

// ImportBurp turns a raw HTTP request (as saved by Burp "Copy to file" or
// copied from any proxy) or a Burp "Save items" XML export (first item) into
// a scenario skeleton: the target is https:// plus the Host header (the XML
// export gives the protocol), the scope allows that host, and the race sends
// the request. check.invariant is left as InvariantTODO, which Validate
// rejects until it is replaced.
func ImportBurp(data []byte) (*Scenario, error) {
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	trimmed := bytes.TrimSpace(data)
	if bytes.HasPrefix(trimmed, []byte("<?xml")) || bytes.HasPrefix(trimmed, []byte("<items")) {
		return importBurpXML(trimmed)
	}
	return importRawRequest(data, "", "a raw HTTP request")
}

type burpItems struct {
	Items []struct {
		URL      string `xml:"url"`
		Host     string `xml:"host"`
		Port     string `xml:"port"`
		Protocol string `xml:"protocol"`
		Request  struct {
			Base64 string `xml:"base64,attr"`
			Data   string `xml:",chardata"`
		} `xml:"request"`
	} `xml:"item"`
}

func importBurpXML(data []byte) (*Scenario, error) {
	var items burpItems
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = false
	if err := dec.Decode(&items); err != nil {
		return nil, fmt.Errorf("burp XML: %v", err)
	}
	if len(items.Items) == 0 {
		return nil, errors.New("burp XML: no <item> elements")
	}
	it := items.Items[0]
	req := []byte(it.Request.Data)
	if it.Request.Base64 == "true" {
		b, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(it.Request.Data), ""))
		if err != nil {
			return nil, fmt.Errorf("burp XML: the request is not valid base64: %v", err)
		}
		req = b
	}
	base := ""
	if u, err := url.Parse(strings.TrimSpace(it.URL)); err == nil && u.Host != "" && (u.Scheme == "http" || u.Scheme == "https") {
		base = u.Scheme + "://" + u.Host
	} else if it.Host != "" {
		scheme := strings.ToLower(strings.TrimSpace(it.Protocol))
		if scheme != "http" {
			scheme = "https"
		}
		host := strings.TrimSpace(it.Host)
		if p := strings.TrimSpace(it.Port); p != "" && !(scheme == "https" && p == "443") && !(scheme == "http" && p == "80") {
			host += ":" + p
		}
		base = scheme + "://" + host
	}
	return importRawRequest(req, base, "a Burp XML export")
}

// importRawRequest parses a raw request. base ("scheme://host") overrides
// the target derived from the Host header.
func importRawRequest(data []byte, base, source string) (*Scenario, error) {
	text := strings.TrimLeft(string(data), " \t\r\n")
	if text == "" {
		return nil, errors.New("the file is empty; want a raw HTTP request")
	}
	head, body := text, ""
	if i := strings.Index(text, "\r\n\r\n"); i >= 0 && (strings.Index(text, "\n\n") < 0 || i < strings.Index(text, "\n\n")) {
		head, body = text[:i], text[i+4:]
	} else if i := strings.Index(text, "\n\n"); i >= 0 {
		head, body = text[:i], text[i+2:]
	}
	head = strings.ReplaceAll(head, "\r\n", "\n")
	raw, err := parseRaw(head)
	if err != nil {
		return nil, fmt.Errorf("not a raw HTTP request: %v", err)
	}
	var host, authority, scheme string
	var headers []importedHeader
	chunked := false
	for _, h := range raw.headers {
		switch strings.ToLower(h.name) {
		case "host":
			host = h.value
		case ":authority":
			// HTTP/2 requests copied from browser tools carry the host
			// only in the pseudo headers.
			authority = h.value
		case ":scheme":
			scheme = strings.ToLower(h.value)
		case "transfer-encoding":
			chunked = strings.Contains(strings.ToLower(h.value), "chunked")
		}
		headers = append(headers, importedHeader{h.name, h.value})
	}
	if chunked {
		b, err := io.ReadAll(httputil.NewChunkedReader(bufio.NewReader(strings.NewReader(body))))
		if err != nil {
			return nil, fmt.Errorf("the chunked body is malformed: %v", err)
		}
		body = string(b)
	}

	target := raw.target
	lower := strings.ToLower(target)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		u, err := url.Parse(target)
		if err != nil || u.Host == "" {
			return nil, fmt.Errorf("invalid request URL %q", target)
		}
		if base == "" {
			base = strings.ToLower(u.Scheme) + "://" + u.Host
		}
		target = u.RequestURI()
	}
	if base == "" {
		if host == "" {
			host = authority
		}
		if host == "" {
			return nil, errors.New("the request has no Host header (or :authority), so the target is unknown")
		}
		if scheme != "http" {
			scheme = "https"
		}
		base = scheme + "://" + host
	}
	if !strings.HasPrefix(target, "/") {
		return nil, fmt.Errorf("unsupported request target %q; want /path", target)
	}
	return skeleton(raw.method, base, target, raw.version, headers, body, source)
}

type harFile struct {
	Log struct {
		Entries []struct {
			Request struct {
				Method      string `json:"method"`
				URL         string `json:"url"`
				HTTPVersion string `json:"httpVersion"`
				Headers     []struct {
					Name  string `json:"name"`
					Value string `json:"value"`
				} `json:"headers"`
				PostData *struct {
					MimeType string `json:"mimeType"`
					Text     string `json:"text"`
					Params   []struct {
						Name  string `json:"name"`
						Value string `json:"value"`
					} `json:"params"`
				} `json:"postData"`
			} `json:"request"`
		} `json:"entries"`
	} `json:"log"`
}

// IsHAR reports whether data looks like a HAR file (JSON with log.entries).
func IsHAR(data []byte) bool {
	var probe struct {
		Log *struct {
			Entries json.RawMessage `json:"entries"`
		} `json:"log"`
	}
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	return json.Unmarshal(data, &probe) == nil && probe.Log != nil && len(probe.Log.Entries) > 0
}

// ImportHAR turns log.entries[entry].request of a HAR file into a scenario
// skeleton, like ImportBurp.
func ImportHAR(data []byte, entry int) (*Scenario, error) {
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	var h harFile
	if err := json.Unmarshal(data, &h); err != nil {
		return nil, fmt.Errorf("not a HAR file: %v", err)
	}
	n := len(h.Log.Entries)
	if n == 0 {
		return nil, errors.New("the HAR file has no entries (log.entries is empty)")
	}
	if entry < 0 || entry >= n {
		return nil, fmt.Errorf("HAR entry %d does not exist; the file has %d entries (0-%d)", entry, n, n-1)
	}
	r := h.Log.Entries[entry].Request
	u, err := url.Parse(r.URL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("HAR entry %d: request.url %q is not an absolute http(s) URL", entry, r.URL)
	}
	if r.Method == "" {
		return nil, fmt.Errorf("HAR entry %d: request.method is empty", entry)
	}
	var headers []importedHeader
	hasCT := false
	for _, hd := range r.Headers {
		if strings.EqualFold(hd.Name, "content-type") {
			hasCT = true
		}
		headers = append(headers, importedHeader{hd.Name, hd.Value})
	}
	body := ""
	if pd := r.PostData; pd != nil {
		body = pd.Text
		if body == "" && len(pd.Params) > 0 {
			form := url.Values{}
			for _, p := range pd.Params {
				form.Add(p.Name, p.Value)
			}
			body = form.Encode()
		}
		if !hasCT && pd.MimeType != "" {
			headers = append(headers, importedHeader{"Content-Type", pd.MimeType})
		}
	}
	version := "HTTP/1.1"
	if v := strings.ToUpper(r.HTTPVersion); v == "H2" || strings.HasPrefix(v, "HTTP/2") {
		version = "HTTP/2"
	}
	return skeleton(r.Method, u.Scheme+"://"+u.Host, u.RequestURI(), version, headers, body, fmt.Sprintf("HAR entry %d", entry))
}

var nonName = regexp.MustCompile(`[^a-z0-9]+`)

// importName derives a scenario name such as "post-carts-coupons".
func importName(method, path string) string {
	p, _, _ := strings.Cut(path, "?")
	name := strings.Trim(nonName.ReplaceAllString(strings.ToLower(method+"-"+p), "-"), "-")
	if len(name) > 48 {
		name = strings.TrimRight(name[:48], "-")
	}
	if name == strings.ToLower(method) || name == "" {
		name += "-request"
	}
	return strings.TrimLeft(name, "-")
}

func skeleton(method, base, target, version string, headers []importedHeader, body, source string) (*Scenario, error) {
	if !utf8.ValidString(body) || strings.ContainsRune(body, 0) {
		return nil, errors.New("the request body is binary; scenarios hold text bodies only")
	}
	bu, err := url.Parse(base)
	if err != nil || bu.Host == "" {
		return nil, fmt.Errorf("invalid target %q", base)
	}
	if version == "" {
		version = "HTTP/1.1"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s %s\n", method, target, version)
	for _, h := range headers {
		if strings.HasPrefix(h.name, ":") || slices.Contains(importDropped, strings.ToLower(h.name)) {
			continue
		}
		if strings.ContainsAny(h.value, "\r\n") {
			return nil, fmt.Errorf("header %s: the value contains a line break", h.name)
		}
		fmt.Fprintf(&b, "%s: %s\n", h.name, h.value)
	}
	if body != "" {
		b.WriteString("\n" + body + "\n")
	}
	// The request is sent as captured: "{{" and "${env:" in it (a template
	// injection payload, say) are literals, not placeholders.
	raw := escapeTemplate(b.String())
	s := &Scenario{
		Version:     Version,
		Name:        importName(method, target),
		Description: fmt.Sprintf("Imported from %s: %s %s. Write check.invariant and review scope.budget before running.", source, method, strings.SplitN(target, "?", 2)[0]),
		Target:      bu.Scheme + "://" + bu.Host,
		Scope: Scope{
			AllowHosts: []string{bu.Host},
			Budget:     Budget{Requests: DefaultBudgetRequests, RPS: DefaultRPS},
		},
		Race: Race{
			Engine:  engine.Auto,
			Copies:  DefaultCopies,
			Request: &RaceRequest{Step: Step{Raw: raw}},
		},
		Check: &Check{
			Invariant: InvariantTODO,
			Explain:   "TODO: state the business rule in one sentence.",
		},
		Trials: DefaultTrials,
	}
	return s, nil
}
