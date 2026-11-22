package report

import (
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"regexp"
	"strings"
)

// jsonSchema is a validator for the subset of JSON Schema draft-07 that the
// SARIF 2.1.0 schema uses: $ref to local definitions, type, enum, const,
// required, properties, additionalProperties, items, minItems, uniqueItems,
// minimum, maximum, pattern, anyOf, oneOf and allOf. Formats are not
// checked, as in most validators by default.
type jsonSchema struct {
	root     map[string]any
	patterns map[string]*regexp.Regexp
}

// newJSONSchema parses a schema document.
func newJSONSchema(data []byte) (*jsonSchema, error) {
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	return &jsonSchema{root: root, patterns: map[string]*regexp.Regexp{}}, nil
}

// Validate returns the violations of the JSON document data.
func (s *jsonSchema) Validate(data []byte) ([]string, error) {
	var doc any
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	var errs []string
	s.check(s.root, doc, "$", &errs)
	return errs, nil
}

// check validates v against schema sch at path, appending violations.
func (s *jsonSchema) check(sch any, v any, path string, errs *[]string) {
	add := func(format string, args ...any) {
		*errs = append(*errs, path+": "+fmt.Sprintf(format, args...))
	}
	switch sch := sch.(type) {
	case bool:
		if !sch {
			add("no value is allowed here")
		}
		return
	case map[string]any:
		if ref, ok := sch["$ref"].(string); ok {
			target, err := s.resolve(ref)
			if err != nil {
				add("%v", err)
				return
			}
			s.check(target, v, path, errs)
			return
		}
		if t, ok := sch["type"]; ok && !typeMatches(t, v) {
			add("type %s, want %v", jsonType(v), t)
			return
		}
		if enum, ok := sch["enum"].([]any); ok && !containsValue(enum, v) {
			add("%v is not one of %v", v, enum)
		}
		if c, ok := sch["const"]; ok && !reflect.DeepEqual(c, v) {
			add("%v is not %v", v, c)
		}
		switch v := v.(type) {
		case map[string]any:
			s.checkObject(sch, v, path, errs)
		case []any:
			s.checkArray(sch, v, path, errs)
		case string:
			if p, ok := sch["pattern"].(string); ok {
				re, err := s.pattern(p)
				if err != nil {
					add("bad pattern %q: %v", p, err)
				} else if !re.MatchString(v) {
					add("%q does not match %q", v, p)
				}
			}
		case float64:
			if m, ok := sch["minimum"].(float64); ok && v < m {
				add("%v is below the minimum %v", v, m)
			}
			if m, ok := sch["maximum"].(float64); ok && v > m {
				add("%v is above the maximum %v", v, m)
			}
		}
		if all, ok := sch["allOf"].([]any); ok {
			for _, sub := range all {
				s.check(sub, v, path, errs)
			}
		}
		if anyOf, ok := sch["anyOf"].([]any); ok && s.matching(anyOf, v, path) == 0 {
			add("matches none of anyOf")
		}
		if oneOf, ok := sch["oneOf"].([]any); ok {
			if n := s.matching(oneOf, v, path); n != 1 {
				add("matches %d of oneOf, want exactly 1", n)
			}
		}
	default:
		add("unsupported schema %T", sch)
	}
}

// checkObject validates the keywords of an object.
func (s *jsonSchema) checkObject(sch map[string]any, v map[string]any, path string, errs *[]string) {
	if req, ok := sch["required"].([]any); ok {
		for _, r := range req {
			if _, ok := v[r.(string)]; !ok {
				*errs = append(*errs, fmt.Sprintf("%s: missing required property %q", path, r))
			}
		}
	}
	props, _ := sch["properties"].(map[string]any)
	for k, val := range v {
		p := path + "." + k
		if sub, ok := props[k]; ok {
			s.check(sub, val, p, errs)
			continue
		}
		if ap, ok := sch["additionalProperties"]; ok {
			if b, isBool := ap.(bool); isBool && !b {
				*errs = append(*errs, fmt.Sprintf("%s: property is not allowed", p))
				continue
			}
			s.check(ap, val, p, errs)
		}
	}
}

// checkArray validates the keywords of an array.
func (s *jsonSchema) checkArray(sch map[string]any, v []any, path string, errs *[]string) {
	if m, ok := sch["minItems"].(float64); ok && float64(len(v)) < m {
		*errs = append(*errs, fmt.Sprintf("%s: %d items, want at least %v", path, len(v), m))
	}
	if u, ok := sch["uniqueItems"].(bool); ok && u {
		seen := map[string]bool{}
		for _, item := range v {
			b, _ := json.Marshal(item)
			if seen[string(b)] {
				*errs = append(*errs, fmt.Sprintf("%s: duplicate item %s", path, b))
			}
			seen[string(b)] = true
		}
	}
	if items, ok := sch["items"]; ok {
		for i, item := range v {
			s.check(items, item, fmt.Sprintf("%s[%d]", path, i), errs)
		}
	}
}

// matching counts the subschemas that v satisfies.
func (s *jsonSchema) matching(subs []any, v any, path string) int {
	n := 0
	for _, sub := range subs {
		var errs []string
		s.check(sub, v, path, &errs)
		if len(errs) == 0 {
			n++
		}
	}
	return n
}

// resolve follows a local reference such as "#/definitions/run".
func (s *jsonSchema) resolve(ref string) (any, error) {
	if !strings.HasPrefix(ref, "#/") {
		return nil, fmt.Errorf("unsupported $ref %q", ref)
	}
	var cur any = s.root
	for _, part := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("unresolved $ref %q", ref)
		}
		if cur, ok = m[part]; !ok {
			return nil, fmt.Errorf("unresolved $ref %q", ref)
		}
	}
	return cur, nil
}

// pattern compiles and caches a pattern.
func (s *jsonSchema) pattern(p string) (*regexp.Regexp, error) {
	if re, ok := s.patterns[p]; ok {
		return re, nil
	}
	re, err := regexp.Compile(p)
	if err != nil {
		return nil, err
	}
	s.patterns[p] = re
	return re, nil
}

// typeMatches reports whether v has the schema type t (a name or a list).
func typeMatches(t any, v any) bool {
	switch t := t.(type) {
	case string:
		return typeIs(t, v)
	case []any:
		for _, name := range t {
			if s, ok := name.(string); ok && typeIs(s, v) {
				return true
			}
		}
	}
	return false
}

// typeIs reports whether v is of the JSON type name.
func typeIs(name string, v any) bool {
	if name == "integer" {
		f, ok := v.(float64)
		return ok && f == math.Trunc(f)
	}
	return jsonType(v) == name || (name == "number" && jsonType(v) == "integer")
}

// jsonType names the JSON type of a decoded value.
func jsonType(v any) string {
	switch v := v.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case string:
		return "string"
	case float64:
		if v == math.Trunc(v) {
			return "integer"
		}
		return "number"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	}
	return fmt.Sprintf("%T", v)
}

// containsValue reports whether list holds v.
func containsValue(list []any, v any) bool {
	for _, x := range list {
		if reflect.DeepEqual(x, v) {
			return true
		}
	}
	return false
}
