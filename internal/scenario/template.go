package scenario

import (
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
)

// Vars are template variables: the scenario's initial vars plus values
// extracted by earlier steps.
type Vars map[string]string

// Clone returns a copy of v (never nil).
func (v Vars) Clone() Vars {
	out := make(Vars, len(v))
	for k, val := range v {
		out[k] = val
	}
	return out
}

var (
	varNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	envNameRE = varNameRE
)

const envPrefix = "${env:"

// Expand replaces {{name}} with vars[name] and ${env:NAME} with the value of
// the environment variable NAME. Spaces inside the braces are allowed
// ({{ name }}). An unknown variable, an unset environment variable, an
// unterminated placeholder or an invalid name is an error. Substituted
// values are not expanded again. A "${" that is not followed by "env:" is
// kept as it is. A quoted literal in braces, {{"text"}}, writes text as it
// is: {{"{{"}} is a literal "{{" and {{"${env:"}} a literal "${env:".
func Expand(s string, vars Vars) (string, error) {
	out, _, err := expand(s, vars)
	return out, err
}

// expand is Expand that also returns the values that came from the
// environment, which are secrets.
func expand(s string, vars Vars) (string, []string, error) {
	return scan(s, func(kind, name string) (string, error) {
		if kind == "env" {
			v, ok := os.LookupEnv(name)
			if !ok {
				return "", fmt.Errorf("environment variable %s is not set (used as ${env:%s})", name, name)
			}
			return v, nil
		}
		v, ok := vars[name]
		if !ok {
			return "", fmt.Errorf("unknown variable {{%s}}%s", name, knownVars(vars))
		}
		return v, nil
	})
}

func knownVars(vars Vars) string {
	if len(vars) == 0 {
		return " (no variables are defined)"
	}
	names := make([]string, 0, len(vars))
	for k := range vars {
		names = append(names, k)
	}
	slices.Sort(names)
	return " (known: " + strings.Join(names, ", ") + ")"
}

// scan walks the placeholders of s and replaces each with the value
// returned by fn(kind, name), where kind is "var" or "env". It returns the
// result and the substituted env values.
func scan(s string, fn func(kind, name string) (string, error)) (string, []string, error) {
	if !strings.Contains(s, "{{") && !strings.Contains(s, envPrefix) {
		return s, nil, nil
	}
	var b strings.Builder
	var secrets []string
	for {
		iv := strings.Index(s, "{{")
		ie := strings.Index(s, envPrefix)
		if iv < 0 && ie < 0 {
			b.WriteString(s)
			return b.String(), secrets, nil
		}
		if ie >= 0 && (iv < 0 || ie < iv) {
			b.WriteString(s[:ie])
			rest := s[ie+len(envPrefix):]
			end := strings.IndexByte(rest, '}')
			if end < 0 || strings.ContainsAny(rest[:end], "\n{") {
				return "", nil, fmt.Errorf("unterminated %s...} placeholder near %q", envPrefix, envPrefix+snippet(rest))
			}
			name := strings.TrimSpace(rest[:end])
			if !envNameRE.MatchString(name) {
				return "", nil, fmt.Errorf("invalid environment variable name %q in ${env:%s}", name, rest[:end])
			}
			v, err := fn("env", name)
			if err != nil {
				return "", nil, err
			}
			if v != "" {
				secrets = append(secrets, v)
			}
			b.WriteString(v)
			s = rest[end+1:]
			continue
		}
		b.WriteString(s[:iv])
		rest := s[iv+2:]
		if lit, n, ok := literal(rest); ok {
			b.WriteString(lit)
			s = rest[n:]
			continue
		}
		end := strings.Index(rest, "}}")
		if end < 0 || strings.ContainsAny(rest[:end], "\n{") {
			return "", nil, fmt.Errorf("unterminated {{ placeholder near %q", "{{"+snippet(rest))
		}
		name := strings.TrimSpace(rest[:end])
		if !varNameRE.MatchString(name) {
			return "", nil, fmt.Errorf("invalid variable name %q in {{%s}}: use letters, digits and _", name, rest[:end])
		}
		v, err := fn("var", name)
		if err != nil {
			return "", nil, err
		}
		b.WriteString(v)
		s = rest[end+2:]
	}
}

// literal parses a quoted literal placeholder, `"text"}}` (with optional
// spaces around the quotes), at the start of rest, which follows "{{". It
// returns the text and the number of bytes of rest it spans.
func literal(rest string) (text string, n int, ok bool) {
	t := strings.TrimLeft(rest, " \t")
	if !strings.HasPrefix(t, `"`) {
		return "", 0, false
	}
	q := strings.IndexByte(t[1:], '"')
	if q < 0 || strings.Contains(t[1:1+q], "\n") {
		return "", 0, false
	}
	after := strings.TrimLeft(t[2+q:], " \t")
	if !strings.HasPrefix(after, "}}") {
		return "", 0, false
	}
	return t[1 : 1+q], len(rest) - len(after) + 2, true
}

// escaper writes "{{" and "${env:" as literal placeholders.
var escaper = strings.NewReplacer("{{", `{{"{{"}}`, envPrefix, `{{"${env:"}}`)

// escapeTemplate returns s with every "{{" and "${env:" written as a
// literal, so that Expand gives back s unchanged.
func escapeTemplate(s string) string { return escaper.Replace(s) }

// snippet returns the start of s up to the end of its line, at most 20 bytes.
func snippet(s string) string {
	s, _, _ = strings.Cut(s, "\n")
	if len(s) > 20 {
		s = s[:20] + "..."
	}
	return s
}

// references returns the variable and environment names used by s, or the
// first syntax error.
func references(s string) (vars, envs []string, err error) {
	_, _, err = scan(s, func(kind, name string) (string, error) {
		if kind == "env" {
			envs = append(envs, name)
		} else {
			vars = append(vars, name)
		}
		return "", nil
	})
	return vars, envs, err
}

// hasPlaceholder reports whether s contains a template placeholder.
func hasPlaceholder(s string) bool {
	return strings.Contains(s, "{{") || strings.Contains(s, envPrefix)
}

// InitialVars returns the scenario's vars with ${env:NAME} references in
// their values expanded ({{...}} in initial values is an error), and the
// values that came from the environment, which reports must mask.
func (s *Scenario) InitialVars() (Vars, []string, error) {
	out := make(Vars, len(s.Vars))
	var secrets []string
	for k, v := range s.Vars {
		val, sec, err := scan(v, func(kind, name string) (string, error) {
			if kind != "env" {
				return "", fmt.Errorf("vars.%s: initial values cannot use {{%s}}", k, name)
			}
			e, ok := os.LookupEnv(name)
			if !ok {
				return "", fmt.Errorf("vars.%s: environment variable %s is not set", k, name)
			}
			return e, nil
		})
		if err != nil {
			return nil, nil, err
		}
		out[k] = val
		secrets = append(secrets, sec...)
	}
	return out, secrets, nil
}
