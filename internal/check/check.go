// Package check evaluates scenario invariants written in CEL.
//
// An invariant is a boolean CEL expression over the responses of one trial:
// the race responses, the check request, the setup steps and the scenario
// variables. Besides the overall result, Eval reports every conjunct of the
// top-level && chain separately (a Term), and for comparison conjuncts it
// shows both operands with their concrete values, so a report can say
// "size(check.json.discounts) <= 1 was 3 <= 1" instead of just "false".
package check

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/ast"
	"cel.dev/cel-go/common/operators"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/common/types/traits"
	"cel.dev/cel-go/parser"

	"github.com/TroubieD3v/photofinish/internal/scenario"
)

// maxValueLen caps the rendered length of one value in a Term, so a term over
// a large response body does not flood the report.
const maxValueLen = 200

// comparisons maps CEL comparison operator functions to their source form.
var comparisons = map[string]string{
	operators.Less:          "<",
	operators.LessEquals:    "<=",
	operators.Greater:       ">",
	operators.GreaterEquals: ">=",
	operators.Equals:        "==",
	operators.NotEquals:     "!=",
}

// Program is a compiled invariant. It is safe for concurrent use.
type Program struct {
	expr  string
	prg   cel.Program
	terms []termProgram
}

// termProgram is one compiled conjunct of the invariant.
type termProgram struct {
	expr        string
	prg         cel.Program
	op          string      // comparison operator, "" if the conjunct is not a comparison
	left, right cel.Program // operands of a comparison
}

// Input is the data an invariant is evaluated against.
type Input struct {
	// Race holds the race responses in input order; Status is 0 when a
	// request got no response.
	Race []scenario.Response
	// RaceErr optionally holds the engine error of each race response, by
	// the same index as Race ("" for none). It is exposed as race[i].error.
	RaceErr []string
	// Check is the response of the check request, nil if the scenario has none.
	Check *scenario.Response
	// Setup holds the setup step responses by step id.
	Setup map[string]*scenario.Response
	// Vars holds the scenario variables after setup extraction.
	Vars scenario.Vars
	// Redact, when set, removes secrets from a rendered Term value. It is
	// applied before the value is capped, so that a secret cut by the cap
	// cannot leave a prefix behind.
	Redact func(string) string
	// Sensitive, when set, reports whether the values under a map key are
	// secret; they are rendered as "[masked]" in Term values.
	Sensitive func(key string) bool
}

// masked replaces map values under sensitive keys in Term values.
const masked = "[masked]"

// Term is one conjunct of the top-level && chain of an invariant, with its
// value in this evaluation.
type Term struct {
	// Expr is the conjunct in CEL syntax.
	Expr string `json:"expr"`
	// Value is the concrete value: "left op right" for a comparison, for
	// example "3 <= 1", otherwise the conjunct's own value; for an
	// evaluation error it starts with "error: ".
	Value string `json:"value"`
	// Pass is the boolean value of the conjunct, nil if it did not
	// evaluate to a boolean.
	Pass *bool `json:"pass"`
}

// Result is the outcome of evaluating an invariant.
type Result struct {
	// Holds is true only when the invariant evaluated to true.
	Holds bool `json:"holds"`
	// Terms are the conjuncts of the invariant with their values.
	Terms []Term `json:"terms"`
	// Err is set when the invariant could not be evaluated (a missing key,
	// a wrong type); Holds is false then and the result proves nothing.
	Err string `json:"error,omitempty"`
}

// newEnv returns the CEL environment for invariants: the four variables and
// the standard library only.
func newEnv() (*cel.Env, error) {
	dynMap := cel.MapType(cel.StringType, cel.DynType)
	return cel.NewEnv(
		cel.Variable("race", cel.ListType(dynMap)),
		cel.Variable("check", dynMap),
		cel.Variable("setup", cel.MapType(cel.StringType, dynMap)),
		cel.Variable("vars", cel.MapType(cel.StringType, cel.StringType)),
		cel.EnableMacroCallTracking(),
		cel.CrossTypeNumericComparisons(true),
	)
}

// Compile parses and type-checks an invariant. The error carries CEL's
// message with line and column.
func Compile(expr string) (*Program, error) {
	if strings.TrimSpace(expr) == "" {
		return nil, errors.New("invariant is empty")
	}
	env, err := newEnv()
	if err != nil {
		return nil, fmt.Errorf("invariant environment: %w", err)
	}
	prg, err := compile(env, expr)
	if err != nil {
		return nil, err
	}
	parsed, iss := env.Parse(expr)
	if iss.Err() != nil {
		return nil, fmt.Errorf("invariant: %w", iss.Err())
	}
	p := &Program{expr: expr, prg: prg}
	native := parsed.NativeRep()
	info := native.SourceInfo()
	for _, e := range conjuncts(native.Expr()) {
		tp, err := compileTerm(env, e, info)
		if err != nil {
			// Splitting is a reporting aid; when a conjunct cannot be
			// rendered on its own, fall back to one term for the whole
			// invariant rather than refusing a valid expression.
			p.terms = []termProgram{{expr: strings.TrimSpace(expr), prg: prg}}
			break
		}
		p.terms = append(p.terms, tp)
	}
	return p, nil
}

// String returns the source text of the invariant.
func (p *Program) String() string { return p.expr }

// compile type-checks expr and plans it; the result must be a bool.
func compile(env *cel.Env, expr string) (cel.Program, error) {
	checked, iss := env.Compile(expr)
	if iss.Err() != nil {
		return nil, fmt.Errorf("invariant: %w", iss.Err())
	}
	if t := checked.OutputType(); !t.IsExactType(cel.BoolType) && !t.IsExactType(cel.DynType) {
		return nil, fmt.Errorf("invariant must be a bool expression, got %s", t)
	}
	prg, err := env.Program(checked)
	if err != nil {
		return nil, fmt.Errorf("invariant: %w", err)
	}
	return prg, nil
}

// compileTerm renders one conjunct back to CEL text and compiles it, and for
// a comparison also its two operands.
func compileTerm(env *cel.Env, e ast.Expr, info *ast.SourceInfo) (termProgram, error) {
	text, err := parser.Unparse(e, info)
	if err != nil {
		return termProgram{}, err
	}
	tp := termProgram{expr: text}
	if tp.prg, err = planAny(env, text); err != nil {
		return termProgram{}, err
	}
	if e.Kind() != ast.CallKind {
		return tp, nil
	}
	call := e.AsCall()
	op, ok := comparisons[call.FunctionName()]
	if !ok || call.IsMemberFunction() || len(call.Args()) != 2 {
		return tp, nil
	}
	left, errL := operand(env, call.Args()[0], info)
	right, errR := operand(env, call.Args()[1], info)
	if errL == nil && errR == nil {
		tp.op, tp.left, tp.right = op, left, right
	}
	return tp, nil
}

// operand compiles one side of a comparison.
func operand(env *cel.Env, e ast.Expr, info *ast.SourceInfo) (cel.Program, error) {
	text, err := parser.Unparse(e, info)
	if err != nil {
		return nil, err
	}
	return planAny(env, text)
}

// planAny compiles expr without constraining its result type.
func planAny(env *cel.Env, expr string) (cel.Program, error) {
	checked, iss := env.Compile(expr)
	if iss.Err() != nil {
		return nil, iss.Err()
	}
	return env.Program(checked)
}

// conjuncts flattens the top-level && chain of e, left to right.
func conjuncts(e ast.Expr) []ast.Expr {
	if e.Kind() == ast.CallKind {
		call := e.AsCall()
		if call.FunctionName() == operators.LogicalAnd && !call.IsMemberFunction() {
			var out []ast.Expr
			for _, arg := range call.Args() {
				out = append(out, conjuncts(arg)...)
			}
			return out
		}
	}
	return []ast.Expr{e}
}

// Eval evaluates the invariant against in.
func (p *Program) Eval(in Input) Result {
	act := activation(in)
	rd := renderer{redact: in.Redact, sensitive: in.Sensitive}
	var res Result
	val, _, err := p.prg.Eval(act)
	switch {
	case err != nil:
		res.Err = err.Error()
	default:
		if b, ok := val.(types.Bool); ok {
			res.Holds = bool(b)
		} else {
			res.Err = fmt.Sprintf("invariant evaluated to %s, not a bool", rd.render(val))
		}
	}
	res.Terms = make([]Term, 0, len(p.terms))
	for _, tp := range p.terms {
		res.Terms = append(res.Terms, tp.eval(act, rd))
	}
	return res
}

// eval evaluates one conjunct.
func (tp termProgram) eval(act map[string]any, rd renderer) Term {
	t := Term{Expr: tp.expr}
	val, _, err := tp.prg.Eval(act)
	if err != nil {
		t.Value = "error: " + err.Error()
		return t
	}
	if b, ok := val.(types.Bool); ok {
		pass := bool(b)
		t.Pass = &pass
	}
	t.Value = rd.render(val)
	if tp.op == "" {
		return t
	}
	l, _, errL := tp.left.Eval(act)
	r, _, errR := tp.right.Eval(act)
	if errL == nil && errR == nil {
		t.Value = rd.render(l) + " " + tp.op + " " + rd.render(r)
	}
	return t
}

// activation builds the CEL variables for in.
func activation(in Input) map[string]any {
	race := make([]any, len(in.Race))
	for i := range in.Race {
		m := responseMap(&in.Race[i])
		m["index"] = int64(i)
		m["error"] = ""
		if i < len(in.RaceErr) {
			m["error"] = in.RaceErr[i]
		}
		race[i] = m
	}
	chk := map[string]any{}
	if in.Check != nil {
		chk = responseMap(in.Check)
	}
	setup := make(map[string]any, len(in.Setup))
	for id, r := range in.Setup {
		if r != nil {
			setup[id] = responseMap(r)
		}
	}
	vars := make(map[string]string, len(in.Vars))
	for k, v := range in.Vars {
		vars[k] = v
	}
	return map[string]any{"race": race, "check": chk, "setup": setup, "vars": vars}
}

// responseMap converts a response to the map the invariant sees.
func responseMap(r *scenario.Response) map[string]any {
	return map[string]any{
		"status":  int64(r.Status),
		"headers": headerMap(r.Header),
		"body":    string(r.Body),
		"json":    parseJSON(r.Body),
	}
}

// headerMap lowercases header names and joins repeated values with ", ".
func headerMap(h http.Header) map[string]any {
	out := make(map[string]any, len(h))
	for name, vals := range h {
		key := strings.ToLower(name)
		if prev, ok := out[key].(string); ok {
			out[key] = prev + ", " + strings.Join(vals, ", ")
			continue
		}
		out[key] = strings.Join(vals, ", ")
	}
	return out
}

// parseJSON decodes body as JSON, or returns nil (CEL null) when it is not
// a single JSON value. Integral numbers become int64 so that comparisons
// with integer literals render as integers.
func parseJSON(body []byte) any {
	if len(bytes.TrimSpace(body)) == 0 {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil // trailing data: not one JSON document
	}
	return normalize(v)
}

// normalize replaces json.Number with int64 or float64, recursively.
func normalize(v any) any {
	switch x := v.(type) {
	case json.Number:
		if i, err := x.Int64(); err == nil {
			return i
		}
		f, _ := x.Float64()
		return f
	case map[string]any:
		for k, e := range x {
			x[k] = normalize(e)
		}
		return x
	case []any:
		for i, e := range x {
			x[i] = normalize(e)
		}
		return x
	}
	return v
}

// renderer formats values for Terms, masking secrets.
type renderer struct {
	redact    func(string) string
	sensitive func(string) bool
}

// render formats a CEL value for a Term, CEL-literal style, with secrets
// removed, capped at maxValueLen bytes on a UTF-8 character boundary.
func (rd renderer) render(v ref.Val) string {
	var b strings.Builder
	rd.writeValue(&b, v)
	s := b.String()
	if rd.redact != nil {
		s = rd.redact(s)
	}
	if len(s) > maxValueLen {
		cut := maxValueLen
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = s[:cut] + "..."
	}
	return s
}

// writeValue appends the CEL literal form of v to b.
func (rd renderer) writeValue(b *strings.Builder, v ref.Val) {
	if b.Len() > maxValueLen {
		return
	}
	switch x := v.(type) {
	case types.Null:
		b.WriteString("null")
	case types.Bool:
		b.WriteString(strconv.FormatBool(bool(x)))
	case types.Int:
		b.WriteString(strconv.FormatInt(int64(x), 10))
	case types.Uint:
		b.WriteString(strconv.FormatUint(uint64(x), 10) + "u")
	case types.Double:
		b.WriteString(strconv.FormatFloat(float64(x), 'g', -1, 64))
	case types.String:
		b.WriteString(strconv.Quote(string(x)))
	case types.Bytes:
		b.WriteString("b" + strconv.Quote(string(x)))
	case traits.Mapper:
		rd.writeMap(b, x)
	case traits.Lister:
		b.WriteByte('[')
		n := int64(x.Size().(types.Int))
		for i := int64(0); i < n; i++ {
			if i > 0 {
				b.WriteString(", ")
			}
			rd.writeValue(b, x.Get(types.Int(i)))
			if b.Len() > maxValueLen {
				return
			}
		}
		b.WriteByte(']')
	default:
		fmt.Fprintf(b, "%v", v.Value())
	}
}

// writeMap appends a map with its keys sorted, so the rendering is stable.
// Values under sensitive keys are written as "[masked]".
func (rd renderer) writeMap(b *strings.Builder, m traits.Mapper) {
	type entry struct {
		key    string
		val    ref.Val
		secret bool
	}
	var entries []entry
	it := m.Iterator()
	for it.HasNext() == types.True {
		k := it.Next()
		var kb strings.Builder
		rd.writeValue(&kb, k)
		ks, isString := k.(types.String)
		secret := isString && rd.sensitive != nil && rd.sensitive(string(ks))
		entries = append(entries, entry{kb.String(), m.Get(k), secret})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].key < entries[j].key })
	b.WriteByte('{')
	for i, e := range entries {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(e.key + ": ")
		if e.secret {
			b.WriteString(strconv.Quote(masked))
		} else {
			rd.writeValue(b, e.val)
		}
		if b.Len() > maxValueLen {
			return
		}
	}
	b.WriteByte('}')
}
