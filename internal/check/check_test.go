package check

import (
	"net/http"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"

	"github.com/TroubieD3v/photofinish/internal/scenario"
)

// couponInput is a trial in which the coupon was applied three times.
func couponInput() Input {
	return Input{
		Race: []scenario.Response{
			{Status: 200, Body: []byte(`{"applied":true}`)},
			{Status: 200, Body: []byte(`{"applied":true}`)},
			{Status: 409, Body: []byte(`{"error":"coupon already used"}`)},
			{Status: 200, Body: []byte(`{"applied":true}`)},
		},
		Check: &scenario.Response{
			Status: 200,
			Header: http.Header{"Content-Type": {"application/json"}, "X-Multi": {"a", "b"}},
			Body:   []byte(`{"id":"c1","discounts":["WELCOME10","WELCOME10","WELCOME10"],"total":90.5,"balance":-10}`),
		},
		Setup: map[string]*scenario.Response{
			"cart": {Status: 201, Body: []byte(`{"id":"c1"}`)},
		},
		Vars: scenario.Vars{"code": "WELCOME10", "cart_id": "c1"},
	}
}

func TestEval(t *testing.T) {
	tests := []struct {
		name  string
		expr  string
		in    Input
		holds bool
		err   string // substring of Result.Err, "" for none
	}{
		{name: "violated", expr: `size(check.json.discounts) <= 1`, in: couponInput(), holds: false},
		{name: "held", expr: `size(check.json.discounts) >= 1`, in: couponInput(), holds: true},
		{name: "filter on race", expr: `size(race.filter(r, r.status == 200)) == 3`, in: couponInput(), holds: true},
		{name: "exists", expr: `race.exists(r, r.status == 409)`, in: couponInput(), holds: true},
		{name: "all", expr: `race.all(r, r.status == 200)`, in: couponInput(), holds: false},
		{name: "map", expr: `race.map(r, r.status).exists(s, s == 409)`, in: couponInput(), holds: true},
		{name: "index", expr: `race[2].index == 2 && race[2].error == ""`, in: couponInput(), holds: true},
		{name: "race json", expr: `race[2].json.error == "coupon already used"`, in: couponInput(), holds: true},
		{name: "headers lowercased", expr: `check.headers["content-type"] == "application/json"`, in: couponInput(), holds: true},
		{name: "headers joined", expr: `check.headers["x-multi"] == "a, b"`, in: couponInput(), holds: true},
		{name: "body string", expr: `check.body.contains("WELCOME10")`, in: couponInput(), holds: true},
		{name: "setup", expr: `setup.cart.status == 201 && setup.cart.json.id == vars.cart_id`, in: couponInput(), holds: true},
		{name: "vars", expr: `vars.code == "WELCOME10"`, in: couponInput(), holds: true},
		{name: "int and double", expr: `check.json.total > 90 && check.json.balance < 0`, in: couponInput(), holds: true},
		{name: "json null for non-json body", expr: `race.all(r, r.json != null)`,
			in: Input{Race: []scenario.Response{{Status: 200, Body: []byte("ok")}}}, holds: false},
		{name: "no response", expr: `race[0].status == 0 && race[0].error == "timeout"`,
			in: Input{Race: []scenario.Response{{}}, RaceErr: []string{"timeout"}}, holds: true},
		{name: "missing key", expr: `check.json.nope == 1`, in: couponInput(), err: "no such key"},
		{name: "no check request", expr: `check.status == 200`, in: Input{}, err: "no such key"},
		{name: "wrong type", expr: `check.json.discounts > 1`, in: couponInput(), err: "no such overload"},
		{name: "index out of range", expr: `race[10].status == 200`, in: couponInput(), err: "index"},
		{name: "false short-circuits an error", expr: `false && check.json.nope == 1`, in: couponInput(), holds: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := Compile(tt.expr)
			if err != nil {
				t.Fatalf("Compile: %v", err)
			}
			got := p.Eval(tt.in)
			if tt.err != "" {
				if got.Holds || !strings.Contains(got.Err, tt.err) {
					t.Fatalf("got Holds=%v Err=%q, want error containing %q", got.Holds, got.Err, tt.err)
				}
				return
			}
			if got.Err != "" {
				t.Fatalf("unexpected Err %q", got.Err)
			}
			if got.Holds != tt.holds {
				t.Fatalf("Holds = %v, want %v (terms %+v)", got.Holds, tt.holds, got.Terms)
			}
		})
	}
}

func TestCompileErrors(t *testing.T) {
	tests := []struct {
		name string
		expr string
		want []string
	}{
		{name: "empty", expr: "  ", want: []string{"empty"}},
		{name: "syntax error has column", expr: "size(race) <= ", want: []string{"Syntax error", "1:15"}},
		{name: "undeclared variable", expr: "response.status == 200", want: []string{"undeclared reference", "response"}},
		{name: "custom function", expr: "count(race) == 1", want: []string{"undeclared reference", "count"}},
		{name: "not a bool", expr: "size(race)", want: []string{"bool", "int"}},
		{name: "vars are strings", expr: "vars.code == 1", want: []string{"no matching overload"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Compile(tt.expr)
			if err == nil {
				t.Fatal("Compile succeeded, want error")
			}
			for _, w := range tt.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error %q does not contain %q", err, w)
				}
			}
		})
	}
}

func TestTerms(t *testing.T) {
	p, err := Compile(`size(check.json.discounts) <= 1 &&
		size(race.filter(r, r.status == 200)) <= 1 &&
		(vars.code == "WELCOME10" && check.json.total != 90.5) &&
		race.exists(r, r.status == 409) &&
		check.json.id == vars.cart_id || false`)
	if err != nil {
		t.Fatal(err)
	}
	got := p.Eval(couponInput())
	if got.Holds || got.Err != "" {
		t.Fatalf("Holds=%v Err=%q", got.Holds, got.Err)
	}
	// The top level is an || here, so there is exactly one term.
	if len(got.Terms) != 1 {
		t.Fatalf("got %d terms for an || invariant, want 1: %+v", len(got.Terms), got.Terms)
	}

	p, err = Compile(`size(check.json.discounts) <= 1 &&
		size(race.filter(r, r.status == 200)) <= 1 &&
		(vars.code == "WELCOME10" && check.json.total != 90.5) &&
		race.exists(r, r.status == 409) &&
		check.json.id == vars.cart_id &&
		!(check.status == 500)`)
	if err != nil {
		t.Fatal(err)
	}
	got = p.Eval(couponInput())
	want := []struct {
		expr, value string
		pass        bool
	}{
		{`size(check.json.discounts) <= 1`, `3 <= 1`, false},
		{`size(race.filter(r, r.status == 200)) <= 1`, `3 <= 1`, false},
		{`vars.code == "WELCOME10"`, `"WELCOME10" == "WELCOME10"`, true},
		{`check.json.total != 90.5`, `90.5 != 90.5`, false},
		{`race.exists(r, r.status == 409)`, `true`, true},
		{`check.json.id == vars.cart_id`, `"c1" == "c1"`, true},
		{`!(check.status == 500)`, `true`, true},
	}
	if len(got.Terms) != len(want) {
		t.Fatalf("got %d terms, want %d: %+v", len(got.Terms), len(want), got.Terms)
	}
	for i, w := range want {
		g := got.Terms[i]
		if g.Expr != w.expr || g.Value != w.value || g.Pass == nil || *g.Pass != w.pass {
			pass := "nil"
			if g.Pass != nil {
				pass = map[bool]string{true: "true", false: "false"}[*g.Pass]
			}
			t.Errorf("term %d = {%q %q %s}, want {%q %q %v}", i, g.Expr, g.Value, pass, w.expr, w.value, w.pass)
		}
	}
}

func TestTermErrorAndRendering(t *testing.T) {
	p, err := Compile(`check.json.nope == 1 && check.json.discounts == ["A"] && check.json != {"id": "x"} && setup.cart.json == null`)
	if err != nil {
		t.Fatal(err)
	}
	got := p.Eval(couponInput())
	// CEL's && is commutative over errors: a false conjunct decides the
	// result even though another conjunct failed to evaluate.
	if got.Holds || got.Err != "" {
		t.Fatalf("Holds=%v Err=%q, want false without Err", got.Holds, got.Err)
	}
	if len(got.Terms) != 4 {
		t.Fatalf("got %d terms: %+v", len(got.Terms), got.Terms)
	}
	if t0 := got.Terms[0]; t0.Pass != nil || !strings.HasPrefix(t0.Value, "error: ") {
		t.Errorf("term 0 = %+v, want an error value and nil Pass", t0)
	}
	if v := got.Terms[1].Value; v != `["WELCOME10", "WELCOME10", "WELCOME10"] == ["A"]` {
		t.Errorf("list rendering = %q", v)
	}
	if v := got.Terms[2].Value; v != `{"balance": -10, "discounts": ["WELCOME10", "WELCOME10", "WELCOME10"], "id": "c1", "total": 90.5} != {"id": "x"}` {
		t.Errorf("map rendering = %q", v)
	}
	if v := got.Terms[3].Value; v != `{"id": "c1"} == null` {
		t.Errorf("null rendering = %q", v)
	}
}

func TestLongValuesAreCapped(t *testing.T) {
	p, err := Compile(`check.body == "x"`)
	if err != nil {
		t.Fatal(err)
	}
	long := strings.Repeat("a", 10*maxValueLen)
	got := p.Eval(Input{Check: &scenario.Response{Status: 200, Body: []byte(long)}})
	if v := got.Terms[0].Value; len(v) > 2*maxValueLen+20 || !strings.Contains(v, "...") {
		t.Errorf("value of %d bytes not capped: %d bytes", len(long), len(v))
	}
}

func TestEvalIsConcurrencySafe(t *testing.T) {
	p, err := Compile(`size(race.filter(r, r.status == 200)) <= 1`)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r := p.Eval(couponInput()); r.Holds || r.Err != "" {
				t.Errorf("Holds=%v Err=%q", r.Holds, r.Err)
			}
		}()
	}
	wg.Wait()
}

func TestString(t *testing.T) {
	const expr = `size(race) > 0`
	p, err := Compile(expr)
	if err != nil {
		t.Fatal(err)
	}
	if p.String() != expr {
		t.Errorf("String() = %q", p.String())
	}
}

func TestLongValuesAreCutOnACharacterBoundary(t *testing.T) {
	p, err := Compile(`check.json.s == ''`)
	if err != nil {
		t.Fatal(err)
	}
	body := `{"s":"` + strings.Repeat("é", 110) + `"}`
	got := p.Eval(Input{Check: &scenario.Response{Status: 200, Body: []byte(body)}})
	if v := got.Terms[0].Value; !utf8.ValidString(v) || !strings.Contains(v, "...") {
		t.Errorf("value %q is not valid UTF-8 or not capped", v)
	}
}

func TestTermValuesAreMasked(t *testing.T) {
	p, err := Compile(`check.json.profile == null`)
	if err != nil {
		t.Fatal(err)
	}
	body := `{"profile":{"a":"` + strings.Repeat("x", 148) + `","api_key":"fake-key-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789","note":"SECRETVALUE-123456789"}}`
	in := Input{
		Check:     &scenario.Response{Status: 200, Body: []byte(body)},
		Sensitive: func(k string) bool { return strings.Contains(k, "key") },
		Redact:    func(s string) string { return strings.ReplaceAll(s, "SECRETVALUE-123456789", "[masked]") },
	}
	got := p.Eval(in)
	v := got.Terms[0].Value
	if strings.Contains(v, "fake-key-") || !strings.Contains(v, `"api_key": "[masked]"`) {
		t.Errorf("sensitive key not masked: %q", v)
	}
	// The redacted secret sits across the cap: no prefix of it may remain.
	if strings.Contains(v, "SECRETV") {
		t.Errorf("redaction ran after the cap: %q", v)
	}
}

func TestJSONWithTrailingData(t *testing.T) {
	p, err := Compile(`race[0].json == null && race[1].json == null && race[2].json != null`)
	if err != nil {
		t.Fatal(err)
	}
	got := p.Eval(Input{Race: []scenario.Response{
		{Status: 200, Body: []byte(`{"a":1} trailing`)},
		{Status: 200, Body: []byte(`{"a":1} {"b":2}`)},
		{Status: 200, Body: []byte(" {\"a\":1}\n")},
	}})
	if !got.Holds || got.Err != "" {
		t.Errorf("result %+v", got)
	}
}
