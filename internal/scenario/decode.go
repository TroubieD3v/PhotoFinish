package scenario

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// maxErrors caps the number of errors reported for one file.
const maxErrors = 20

// FieldError is a problem with one field of a scenario file.
type FieldError struct {
	// File is the scenario file ("" if unknown).
	File string
	// Line is the 1-based line of the field (0 if unknown).
	Line int
	// Field is the field path, e.g. "race.copies" or "setup[0].extract.id".
	Field string
	// Msg describes the problem.
	Msg string
}

// Error formats the error as "file:line: field: message".
func (e *FieldError) Error() string {
	var b strings.Builder
	switch {
	case e.File != "" && e.Line > 0:
		fmt.Fprintf(&b, "%s:%d: ", e.File, e.Line)
	case e.File != "":
		b.WriteString(e.File + ": ")
	case e.Line > 0:
		fmt.Fprintf(&b, "line %d: ", e.Line)
	}
	if e.Field != "" {
		b.WriteString(e.Field + ": ")
	}
	b.WriteString(e.Msg)
	return b.String()
}

// Load reads a scenario file, parses it and validates it.
func Load(path string) (*Scenario, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	s, err := Parse(data, path)
	if err != nil {
		return nil, err
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return s, nil
}

// Parse decodes a scenario document. path is used in error messages and
// stored in Scenario.Path. Parse checks the YAML structure (unknown fields,
// value types, duplicates) but not the meaning of the values: call Validate
// (or use Load) before running the scenario.
func Parse(data []byte, path string) (*Scenario, error) {
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, &FieldError{File: path, Msg: "the file is empty"}
		}
		return nil, syntaxError(path, data, err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err == nil {
		return nil, &FieldError{File: path, Line: extra.Line, Msg: "only one YAML document is allowed (remove the extra ---)"}
	} else if !errors.Is(err, io.EOF) {
		return nil, syntaxError(path, data, err)
	}
	root := &doc
	if root.Kind == yaml.DocumentNode {
		if len(root.Content) == 0 {
			return nil, &FieldError{File: path, Msg: "the file is empty"}
		}
		root = root.Content[0]
	}
	if root.Kind != yaml.MappingNode {
		return nil, &FieldError{File: path, Line: root.Line, Msg: "a scenario must be a YAML mapping (version, name, target, ...), got " + kindName(root)}
	}
	s := &Scenario{Path: path}
	d := &decoder{file: path, lines: map[string]int{}}
	d.decode(root, reflect.ValueOf(s).Elem(), "", root.Line)
	if len(d.errs) > 0 {
		return nil, errors.Join(d.errs...)
	}
	s.lines = d.lines
	s.InvariantLine = d.lines["check.invariant"]
	return s, nil
}

var yamlLineRE = regexp.MustCompile(`^yaml: line (\d+): `)

// yamlParserErrors are the messages of yaml.v3 parser (not scanner)
// errors. yaml.v3 reports their line 0-based, one line too early.
var yamlParserErrors = []string{
	"did not find expected",
	"found duplicate %TAG directive",
	"found duplicate %YAML directive",
	"found incompatible YAML document",
	"found undefined tag handle",
}

// syntaxError converts a yaml.v3 parse error of data into a FieldError
// with the line of the problem.
func syntaxError(path string, data []byte, err error) error {
	msg := err.Error()
	line := 0
	if m := yamlLineRE.FindStringSubmatch(msg); m != nil {
		line, _ = strconv.Atoi(m[1])
		msg = msg[len(m[0]):]
	} else {
		msg = strings.TrimPrefix(msg, "yaml: ")
	}
	if line > 0 {
		line = problemLine(data, line, msg)
	}
	return &FieldError{File: path, Line: line, Msg: "invalid YAML: " + msg}
}

// problemLine corrects the line yaml.v3 gives for a syntax error. Parser
// errors carry a 0-based line (the start of the collection being parsed).
// A tab in the indentation is reported at the end of the line before the
// tab, so the line is moved to the first of the next lines that is indented
// with a tab.
func problemLine(data []byte, line int, msg string) int {
	lines := strings.Split(string(data), "\n")
	for _, p := range yamlParserErrors {
		if strings.HasPrefix(msg, p) {
			return min(line+1, max(len(lines), 1))
		}
	}
	if strings.Contains(msg, "tab character") {
		for n := line; n <= min(line+2, len(lines)); n++ {
			text := lines[n-1]
			indent := text[:len(text)-len(strings.TrimLeft(text, " \t"))]
			if strings.Contains(indent, "\t") {
				return n
			}
		}
	}
	return line
}

// nodeDecoder is implemented by types that decode themselves from a node.
type nodeDecoder interface {
	decodeNode(n *yaml.Node) error
}

// decoder decodes a node tree into the scenario structs by their yaml tags,
// recording the line of every field and reporting errors with field paths.
type decoder struct {
	file  string
	lines map[string]int
	errs  []error
}

func (d *decoder) fail(line int, field, format string, args ...any) {
	if len(d.errs) == maxErrors {
		d.errs = append(d.errs, &FieldError{File: d.file, Msg: "too many errors"})
	}
	if len(d.errs) > maxErrors {
		return
	}
	d.errs = append(d.errs, &FieldError{File: d.file, Line: line, Field: field, Msg: fmt.Sprintf(format, args...)})
}

func joinField(parent, key string) string {
	if parent == "" {
		return key
	}
	return parent + "." + key
}

// decode stores n into v. line is the line reported for this field (the key
// line for mapping values).
func (d *decoder) decode(n *yaml.Node, v reflect.Value, field string, line int) {
	for depth := 0; n.Kind == yaml.AliasNode; depth++ {
		if n.Alias == nil || depth > 32 {
			d.fail(line, field, "unresolved alias")
			return
		}
		n = n.Alias
	}
	if field != "" {
		d.lines[field] = line
	}
	if v.CanAddr() {
		if nd, ok := v.Addr().Interface().(nodeDecoder); ok {
			if err := nd.decodeNode(n); err != nil {
				d.fail(line, field, "%v", err)
			}
			return
		}
	}
	if n.Kind == yaml.ScalarNode && n.ShortTag() == "!!null" {
		return // keep the zero value
	}
	switch v.Kind() {
	case reflect.Pointer:
		p := reflect.New(v.Type().Elem())
		d.decode(n, p.Elem(), field, line)
		v.Set(p)
	case reflect.Struct:
		d.decodeStruct(n, v, field, line)
	case reflect.Map:
		d.decodeMap(n, v, field, line)
	case reflect.Slice:
		if n.Kind != yaml.SequenceNode {
			d.fail(line, field, "expected a list, got %s", kindName(n))
			return
		}
		s := reflect.MakeSlice(v.Type(), len(n.Content), len(n.Content))
		for i, el := range n.Content {
			d.decode(el, s.Index(i), fmt.Sprintf("%s[%d]", field, i), el.Line)
		}
		v.Set(s)
	case reflect.String:
		if n.Kind != yaml.ScalarNode {
			d.fail(line, field, "expected a string, got %s", kindName(n))
			return
		}
		v.SetString(n.Value)
	case reflect.Int:
		var i int
		if n.Kind != yaml.ScalarNode || n.ShortTag() != "!!int" || n.Decode(&i) != nil {
			d.fail(line, field, "expected an integer, got %s", kindName(n))
			return
		}
		v.SetInt(int64(i))
	case reflect.Float64:
		var f float64
		if n.Kind != yaml.ScalarNode || (n.ShortTag() != "!!int" && n.ShortTag() != "!!float") || n.Decode(&f) != nil {
			d.fail(line, field, "expected a number, got %s", kindName(n))
			return
		}
		v.SetFloat(f)
	case reflect.Bool:
		var b bool
		if n.Kind != yaml.ScalarNode || n.ShortTag() != "!!bool" || n.Decode(&b) != nil {
			d.fail(line, field, "expected true or false, got %s", kindName(n))
			return
		}
		v.SetBool(b)
	default:
		d.fail(line, field, "unsupported field type %s", v.Type())
	}
}

// structFields maps yaml names to field index paths, following inline
// embedded structs.
func structFields(t reflect.Type) (map[string][]int, []string) {
	idx := map[string][]int{}
	var names []string
	var walk func(t reflect.Type, prefix []int)
	walk = func(t reflect.Type, prefix []int) {
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			tag := f.Tag.Get("yaml")
			if tag == "-" || (!f.IsExported() && !f.Anonymous) {
				continue
			}
			name, opts, _ := strings.Cut(tag, ",")
			path := append(append([]int(nil), prefix...), i)
			if strings.Contains(opts, "inline") {
				walk(f.Type, path)
				continue
			}
			if name == "" {
				name = strings.ToLower(f.Name)
			}
			idx[name] = path
			names = append(names, name)
		}
	}
	walk(t, nil)
	return idx, names
}

func (d *decoder) decodeStruct(n *yaml.Node, v reflect.Value, field string, line int) {
	if n.Kind != yaml.MappingNode {
		d.fail(line, field, "expected a mapping, got %s", kindName(n))
		return
	}
	idx, names := structFields(v.Type())
	seen := map[string]int{}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, val := n.Content[i], n.Content[i+1]
		if k.Kind != yaml.ScalarNode {
			d.fail(k.Line, field, "keys must be plain names, got %s", kindName(k))
			continue
		}
		name := k.Value
		f := joinField(field, name)
		if first, dup := seen[name]; dup {
			d.fail(k.Line, f, "duplicate field (first set on line %d)", first)
			continue
		}
		seen[name] = k.Line
		path, ok := idx[name]
		if !ok {
			d.fail(k.Line, f, "unknown field%s", suggest(name, names))
			continue
		}
		d.decode(val, v.FieldByIndex(path), f, k.Line)
	}
}

func (d *decoder) decodeMap(n *yaml.Node, v reflect.Value, field string, line int) {
	if n.Kind != yaml.MappingNode {
		d.fail(line, field, "expected a mapping, got %s", kindName(n))
		return
	}
	m := reflect.MakeMapWithSize(v.Type(), len(n.Content)/2)
	seen := map[string]int{}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, val := n.Content[i], n.Content[i+1]
		if k.Kind != yaml.ScalarNode || k.ShortTag() == "!!null" || k.ShortTag() == "!!merge" {
			d.fail(k.Line, field, "keys must be plain names, got %s", kindName(k))
			continue
		}
		f := joinField(field, k.Value)
		if first, dup := seen[strings.ToLower(k.Value)]; dup {
			d.fail(k.Line, f, "duplicate key (first set on line %d)", first)
			continue
		}
		seen[strings.ToLower(k.Value)] = k.Line
		ev := reflect.New(v.Type().Elem()).Elem()
		d.decode(val, ev, f, k.Line)
		m.SetMapIndex(reflect.ValueOf(k.Value).Convert(v.Type().Key()), ev)
	}
	v.Set(m)
}

// suggest returns " (did you mean "x"?)" for a close known name, or the list
// of known names.
func suggest(name string, known []string) string {
	best, bestD := "", 3
	for _, k := range known {
		if dist := editDistance(strings.ToLower(name), k); dist < bestD {
			best, bestD = k, dist
		}
	}
	if best != "" {
		return fmt.Sprintf(" (did you mean %q?)", best)
	}
	sorted := append([]string(nil), known...)
	sort.Strings(sorted)
	return " (known fields: " + strings.Join(sorted, ", ") + ")"
}

func editDistance(a, b string) int {
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(b)]
}
