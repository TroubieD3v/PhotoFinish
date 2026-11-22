package scenario

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration is a time.Duration written in YAML as a Go duration string such
// as "100ms" or "1.5s".
type Duration time.Duration

// String returns the duration in Go notation.
func (d Duration) String() string { return time.Duration(d).String() }

// MarshalYAML writes the duration as a string.
func (d Duration) MarshalYAML() (any, error) { return d.String(), nil }

// UnmarshalYAML reads a duration string.
func (d *Duration) UnmarshalYAML(n *yaml.Node) error { return d.decodeNode(n) }

func (d *Duration) decodeNode(n *yaml.Node) error {
	if n.Kind != yaml.ScalarNode {
		return fmt.Errorf("expected a duration such as 100ms, got %s", kindName(n))
	}
	if n.ShortTag() == "!!null" {
		*d = 0
		return nil
	}
	v, err := time.ParseDuration(n.Value)
	if err != nil {
		return fmt.Errorf("expected a duration such as 100ms, got %q", n.Value)
	}
	*d = Duration(v)
	return nil
}

// JSONBody is a JSON request body written in YAML as any value (mapping,
// list or scalar). Key order is preserved. String values and keys may use
// {{var}} and ${env:NAME}; the expanded text is JSON-escaped.
type JSONBody struct {
	node *yaml.Node
}

// NewJSONBody returns a body that encodes v. It returns an error if v
// cannot be represented in YAML.
func NewJSONBody(v any) (JSONBody, error) {
	var n yaml.Node
	if err := n.Encode(v); err != nil {
		return JSONBody{}, err
	}
	return JSONBody{node: &n}, nil
}

// IsZero reports whether no body was set. It lets yaml omit the field.
func (b JSONBody) IsZero() bool { return b.node == nil }

// MarshalYAML writes the body as it was read.
func (b JSONBody) MarshalYAML() (any, error) {
	if b.node == nil {
		return nil, nil
	}
	return cleanNode(b.node), nil
}

// UnmarshalYAML keeps the YAML value.
func (b *JSONBody) UnmarshalYAML(n *yaml.Node) error { return b.decodeNode(n) }

func (b *JSONBody) decodeNode(n *yaml.Node) error {
	if n.Kind == yaml.DocumentNode && len(n.Content) == 1 {
		n = n.Content[0]
	}
	b.node = n
	_, _, err := b.encode(func(s string) (string, []string, error) { return s, nil, nil })
	return err
}

// Encode returns the compact JSON encoding of the body with templates
// expanded, and the secret values used by the expansion.
func (b JSONBody) Encode(vars Vars) ([]byte, []string, error) {
	return b.encode(func(s string) (string, []string, error) { return expand(s, vars) })
}

func (b JSONBody) encode(exp func(string) (string, []string, error)) ([]byte, []string, error) {
	if b.node == nil {
		return nil, nil, nil
	}
	e := &jsonEncoder{exp: exp}
	if err := e.value(b.node, 0); err != nil {
		return nil, e.secrets, err
	}
	return e.buf.Bytes(), e.secrets, nil
}

type jsonEncoder struct {
	buf     bytes.Buffer
	exp     func(string) (string, []string, error)
	secrets []string
}

const maxJSONDepth = 64

func (e *jsonEncoder) str(s string) error {
	v, sec, err := e.exp(s)
	if err != nil {
		return err
	}
	e.secrets = append(e.secrets, sec...)
	enc, err := json.Marshal(v)
	if err != nil {
		return err
	}
	e.buf.Write(enc)
	return nil
}

func (e *jsonEncoder) value(n *yaml.Node, depth int) error {
	if depth > maxJSONDepth {
		return errors.New("JSON body is nested too deeply")
	}
	switch n.Kind {
	case yaml.DocumentNode:
		if len(n.Content) != 1 {
			return errors.New("empty JSON body")
		}
		return e.value(n.Content[0], depth)
	case yaml.AliasNode:
		if n.Alias == nil {
			return errors.New("unresolved alias in JSON body")
		}
		return e.value(n.Alias, depth+1)
	case yaml.MappingNode:
		e.buf.WriteByte('{')
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			if k.Kind == yaml.AliasNode && k.Alias != nil {
				k = k.Alias
			}
			if k.Kind != yaml.ScalarNode {
				return fmt.Errorf("line %d: JSON object keys must be strings", k.Line)
			}
			if k.ShortTag() == "!!merge" {
				return fmt.Errorf("line %d: YAML merge keys (<<) are not supported in JSON bodies", k.Line)
			}
			if i > 0 {
				e.buf.WriteByte(',')
			}
			if err := e.str(k.Value); err != nil {
				return err
			}
			e.buf.WriteByte(':')
			if err := e.value(v, depth+1); err != nil {
				return err
			}
		}
		e.buf.WriteByte('}')
	case yaml.SequenceNode:
		e.buf.WriteByte('[')
		for i, v := range n.Content {
			if i > 0 {
				e.buf.WriteByte(',')
			}
			if err := e.value(v, depth+1); err != nil {
				return err
			}
		}
		e.buf.WriteByte(']')
	case yaml.ScalarNode:
		return e.scalar(n)
	default:
		return fmt.Errorf("line %d: unsupported YAML value in JSON body", n.Line)
	}
	return nil
}

func (e *jsonEncoder) scalar(n *yaml.Node) error {
	switch n.ShortTag() {
	case "!!null":
		e.buf.WriteString("null")
	case "!!bool":
		var v bool
		if err := n.Decode(&v); err != nil {
			return fmt.Errorf("line %d: %v", n.Line, err)
		}
		e.buf.WriteString(strconv.FormatBool(v))
	case "!!int":
		var v int64
		if err := n.Decode(&v); err != nil {
			var u uint64
			if err2 := n.Decode(&u); err2 != nil {
				return fmt.Errorf("line %d: integer %s does not fit in 64 bits", n.Line, n.Value)
			}
			e.buf.WriteString(strconv.FormatUint(u, 10))
			return nil
		}
		e.buf.WriteString(strconv.FormatInt(v, 10))
	case "!!float":
		var v float64
		if err := n.Decode(&v); err != nil {
			return fmt.Errorf("line %d: %v", n.Line, err)
		}
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return fmt.Errorf("line %d: %s is not a JSON number", n.Line, n.Value)
		}
		enc, _ := json.Marshal(v)
		e.buf.Write(enc)
	case "!!binary":
		return fmt.Errorf("line %d: binary values are not supported in JSON bodies", n.Line)
	default: // !!str, !!timestamp and custom tags are written as strings
		return e.str(n.Value)
	}
	return nil
}

// cleanNode returns a deep copy of n without positions and comments, with
// aliases resolved, so that Marshal output does not depend on the source.
func cleanNode(n *yaml.Node) *yaml.Node {
	if n == nil {
		return nil
	}
	if n.Kind == yaml.AliasNode && n.Alias != nil {
		return cleanNode(n.Alias)
	}
	c := &yaml.Node{Kind: n.Kind, Style: n.Style, Value: n.Value}
	const quoted = yaml.DoubleQuotedStyle | yaml.SingleQuotedStyle | yaml.LiteralStyle | yaml.FoldedStyle
	switch {
	case n.Style&yaml.TaggedStyle != 0:
		c.Tag = n.Tag
	case n.Kind == yaml.ScalarNode && n.ShortTag() == "!!str" && n.Style&quoted == 0 && isAmbiguousPlain(n.Value):
		c.Style |= yaml.DoubleQuotedStyle
	}
	for _, ch := range n.Content {
		c.Content = append(c.Content, cleanNode(ch))
	}
	return c
}

// isAmbiguousPlain reports whether a plain (unquoted) scalar with this text
// would resolve to something other than a string.
func isAmbiguousPlain(s string) bool {
	var n yaml.Node
	if err := yaml.Unmarshal([]byte(s), &n); err != nil || len(n.Content) != 1 {
		return true
	}
	c := n.Content[0]
	return c.Kind != yaml.ScalarNode || c.ShortTag() != "!!str" || c.Value != s
}

// kindName describes a node kind for error messages.
func kindName(n *yaml.Node) string {
	switch n.Kind {
	case yaml.MappingNode:
		return "a mapping"
	case yaml.SequenceNode:
		return "a list"
	case yaml.ScalarNode:
		switch n.ShortTag() {
		case "!!null":
			return "null"
		case "!!int", "!!float":
			return "a number"
		case "!!bool":
			return "a boolean"
		}
		return fmt.Sprintf("%q", n.Value)
	}
	return "an unsupported value"
}
