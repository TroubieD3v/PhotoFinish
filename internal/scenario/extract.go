package scenario

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// Response is one HTTP response as seen by extraction and the invariant.
type Response struct {
	// Status is the status code, 0 if there was no response.
	Status int
	// Header holds the response headers.
	Header http.Header
	// Body is the response body (possibly truncated by the engine).
	Body []byte
}

// extractSpec is a parsed extraction spec.
type extractSpec struct {
	kind   string // "json", "header" or "status"
	header string
	path   []pathElem
}

type pathElem struct {
	key   string
	index int // >= 0 for [index], -1 for a key
}

// parseExtract parses "$.a.b[0].c", "header:Name" or "status".
func parseExtract(spec string) (*extractSpec, error) {
	spec = strings.TrimSpace(spec)
	switch {
	case spec == "status":
		return &extractSpec{kind: "status"}, nil
	case strings.HasPrefix(spec, "header:"):
		name := strings.TrimSpace(strings.TrimPrefix(spec, "header:"))
		if name == "" || strings.ContainsAny(name, " \t:") {
			return nil, fmt.Errorf("invalid header name in %q; want header:Name", spec)
		}
		return &extractSpec{kind: "header", header: name}, nil
	case strings.HasPrefix(spec, "$"):
		p, err := parseJSONPath(spec)
		if err != nil {
			return nil, err
		}
		return &extractSpec{kind: "json", path: p}, nil
	}
	return nil, fmt.Errorf("unsupported extraction %q; want \"$.json.path\", \"header:Name\" or \"status\"", spec)
}

func parseJSONPath(spec string) ([]pathElem, error) {
	bad := func(why string) error {
		return fmt.Errorf("invalid JSON path %q: %s (supported: $.name, $.a.b, $.list[0].name)", spec, why)
	}
	var out []pathElem
	s := spec[1:]
	for s != "" {
		switch s[0] {
		case '.':
			s = s[1:]
			n := 0
			for n < len(s) && isKeyChar(s[n]) {
				n++
			}
			if n == 0 {
				return nil, bad("expected a name after '.'")
			}
			out = append(out, pathElem{key: s[:n], index: -1})
			s = s[n:]
		case '[':
			end := strings.IndexByte(s, ']')
			if end < 0 {
				return nil, bad("missing ']'")
			}
			i, err := strconv.Atoi(s[1:end])
			if err != nil || i < 0 || strings.HasPrefix(s[1:end], "+") {
				return nil, bad("[...] must hold a non-negative index")
			}
			out = append(out, pathElem{index: i})
			s = s[end+1:]
		default:
			return nil, bad(fmt.Sprintf("unexpected %q", s[0]))
		}
	}
	return out, nil
}

func isKeyChar(c byte) bool {
	return c == '_' || c == '-' || c == '$' || c == '@' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= 0x80
}

// Extract returns a value from a response. spec is one of:
//
//   - "$.a.b[0].c": a JSON path of dot names and [index] elements ("$" is
//     the whole body). Strings are returned unquoted, numbers as written,
//     booleans as true/false, objects and lists as compact JSON; a missing
//     key, an index out of range or null is an error.
//   - "header:Name": the response header (case-insensitive; several values
//     are joined with ", "); a missing header is an error.
//   - "status": the status code.
func Extract(spec string, resp *Response) (string, error) {
	sp, err := parseExtract(spec)
	if err != nil {
		return "", err
	}
	if resp == nil || resp.Status == 0 {
		return "", errors.New("no response to extract from")
	}
	switch sp.kind {
	case "status":
		return strconv.Itoa(resp.Status), nil
	case "header":
		var vals []string
		for k, v := range resp.Header {
			if strings.EqualFold(k, sp.header) {
				vals = append(vals, v...)
			}
		}
		if len(vals) == 0 {
			return "", fmt.Errorf("response has no %s header", sp.header)
		}
		return strings.Join(vals, ", "), nil
	}
	dec := json.NewDecoder(bytes.NewReader(resp.Body))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return "", fmt.Errorf("%s: the response body is not JSON (status %d): %v", spec, resp.Status, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("%s: the response body has data after the JSON value", spec)
	}
	at := "$"
	for _, el := range sp.path {
		switch {
		case el.index >= 0:
			list, ok := v.([]any)
			if !ok {
				return "", fmt.Errorf("%s: %s is %s, not a list", spec, at, jsonKind(v))
			}
			if el.index >= len(list) {
				return "", fmt.Errorf("%s: %s has %d elements, index %d is out of range", spec, at, len(list), el.index)
			}
			v = list[el.index]
			at += fmt.Sprintf("[%d]", el.index)
		default:
			obj, ok := v.(map[string]any)
			if !ok {
				return "", fmt.Errorf("%s: %s is %s, not an object", spec, at, jsonKind(v))
			}
			next, ok := obj[el.key]
			if !ok {
				return "", fmt.Errorf("%s: %s has no key %q", spec, at, el.key)
			}
			v = next
			at += "." + el.key
		}
	}
	switch x := v.(type) {
	case nil:
		return "", fmt.Errorf("%s: the value is null", spec)
	case string:
		return x, nil
	case json.Number:
		return x.String(), nil
	case bool:
		return strconv.FormatBool(x), nil
	default:
		b, err := json.Marshal(x)
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
}

func jsonKind(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case map[string]any:
		return "an object"
	case []any:
		return "a list"
	case string:
		return "a string"
	case json.Number:
		return "a number"
	case bool:
		return "a boolean"
	}
	return "a value"
}
