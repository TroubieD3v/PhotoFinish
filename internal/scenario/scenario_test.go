package scenario

import (
	"bytes"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/TroubieD3v/photofinish/internal/engine"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata")

// golden compares got with testdata/name, or rewrites it with -update.
func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test -update to create it)", err)
	}
	want = bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n"))
	if !bytes.Equal(got, want) {
		t.Errorf("%s differs (run go test -update after checking the change)\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
	}
}

func mustParse(t *testing.T, src, path string) *Scenario {
	t.Helper()
	s, err := Parse([]byte(src), path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return s
}

func TestParseFull(t *testing.T) {
	s, err := Load(filepath.Join("testdata", "full.yaml"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	checks := []struct {
		name      string
		got, want any
	}{
		{"Path", s.Path, filepath.Join("testdata", "full.yaml")},
		{"Version", s.Version, 1},
		{"Name", s.Name, "coupon-applied-twice"},
		{"Target", s.Target, "https://127.0.0.1:8443/vuln/api"},
		{"TLS.Insecure", s.TLS.Insecure, true},
		{"AllowHosts", strings.Join(s.Scope.AllowHosts, ","), "127.0.0.1:8443"},
		{"Budget.Requests", s.Scope.Budget.RequestLimit(), 600},
		{"Budget.RPS", s.Scope.Budget.RateLimit(), 50.0},
		{"identity header", s.Identities["alice"].Headers["Authorization"], "Bearer ${env:PF_TEST_ALICE_TOKEN}"},
		{"vars.code", s.Vars["code"], "WELCOME10"},
		{"vars.amount (int in YAML)", s.Vars["amount"], "10"},
		{"setup count", len(s.Setup), 2},
		{"setup[1].ID", s.Setup[1].ID, "cart"},
		{"setup[1].ExpectStatus", len(s.Setup[1].ExpectStatus), 1},
		{"setup[1].Extract", s.Setup[1].Extract["cart_id"], "$.id"},
		{"setup[1].JSON set", s.Setup[1].JSON.IsZero(), false},
		{"setup[0].JSON unset", s.Setup[0].JSON.IsZero(), true},
		{"Race.Engine", s.Race.EngineKind(), engine.H2},
		{"Race.Copies", s.Race.TotalCopies(), 20},
		{"Race.Warmup", s.Race.Warmup, 2},
		{"Race.Gate", s.Race.GateDuration(), 150 * time.Millisecond},
		{"Race.Request.As", s.Race.Request.As, "alice"},
		{"Race.Request.Raw", s.Race.Request.Raw, "POST /carts/{{cart_id}}/coupons HTTP/2\nContent-Type: application/json\n\n{\"code\":\"{{code}}\"}\n"},
		{"Check.Request", s.Check.Request, "GET /carts/{{cart_id}}"},
		{"Check.Invariant", s.Check.Invariant, "size(check.json.discounts) <= 1 && size(race.filter(r, r.status == 200)) <= 1\n"},
		{"InvariantLine", s.InvariantLine, 36},
		{"Line(race.copies)", s.Line("race.copies"), 23},
		{"Line(setup[1].extract.cart_id)", s.Line("setup[1].extract.cart_id"), 20},
		{"Line(unknown child falls back)", s.Line("race.request.raw.nothing"), 28},
		{"Reset", s.Reset[0].Request, "POST /reset"},
		{"Trials", s.TrialCount(), 10},
		{"ArrivalHeader", s.Evidence.Header(), "X-Arrival-Ns"},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %#v, want %#v", c.name, c.got, c.want)
		}
	}
}

func TestDefaults(t *testing.T) {
	s := mustParse(t, `
version: 1
name: d
target: https://h
scope: {allow_hosts: [h]}
race: {request: {request: GET /}}
check: {invariant: "true"}
`, "d.yaml")
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := s.TrialCount(); got != DefaultTrials {
		t.Errorf("TrialCount = %d", got)
	}
	if got := s.Race.TotalCopies(); got != DefaultCopies {
		t.Errorf("TotalCopies = %d", got)
	}
	if got := s.Race.EngineKind(); got != engine.Auto {
		t.Errorf("EngineKind = %q", got)
	}
	if got := s.Race.GateDuration(); got != DefaultGate {
		t.Errorf("GateDuration = %v", got)
	}
	if got := s.Scope.Budget.RequestLimit(); got != DefaultBudgetRequests {
		t.Errorf("RequestLimit = %d", got)
	}
	if got := s.Scope.Budget.RateLimit(); got != DefaultRPS {
		t.Errorf("RateLimit = %v", got)
	}
	if got := s.Evidence.Header(); got != DefaultArrivalHeader {
		t.Errorf("Header = %q", got)
	}
	if s.Check.HasRequest() {
		t.Error("HasRequest = true for a check without a request")
	}
	out, err := Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, unwanted := range []string{"trials", "copies", "engine", "gate", "budget", "evidence", "tls"} {
		if bytes.Contains(out, []byte(unwanted)) {
			t.Errorf("Marshal wrote the unset default %q:\n%s", unwanted, out)
		}
	}
}

func TestEntries(t *testing.T) {
	s := mustParse(t, mustRead(t, "multi.yaml"), "multi.yaml")
	e := s.Race.Entries()
	if len(e) != 2 || e[0].Copies != 3 || e[1].Copies != 1 {
		t.Fatalf("Entries = %+v", e)
	}
	if got := s.Race.TotalCopies(); got != 4 {
		t.Errorf("TotalCopies = %d, want 4", got)
	}
	// Entries must not modify the scenario.
	if s.Race.Requests[1].Copies != 0 {
		t.Error("Entries changed race.requests[1].copies")
	}
}

func mustRead(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestGoldenRoundTrip parses each scenario, writes it back and compares the
// output with a golden file; parsing the output again must give the same
// bytes (Marshal is a fixed point after one pass).
func TestGoldenRoundTrip(t *testing.T) {
	for _, name := range []string{"full", "multi"} {
		t.Run(name, func(t *testing.T) {
			s := mustParse(t, mustRead(t, name+".yaml"), name+".yaml")
			if err := s.Validate(); err != nil {
				t.Fatalf("Validate: %v", err)
			}
			out, err := Marshal(s)
			if err != nil {
				t.Fatal(err)
			}
			golden(t, name+".golden.yaml", out)

			s2 := mustParse(t, string(out), "out.yaml")
			if err := s2.Validate(); err != nil {
				t.Fatalf("Validate after round trip: %v", err)
			}
			out2, err := Marshal(s2)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(out, out2) {
				t.Errorf("second round trip differs:\n%s\n---\n%s", out, out2)
			}
			// The requests built from both must be identical.
			t.Setenv("PF_TEST_ALICE_TOKEN", "t0ken")
			vars := Vars{"cart_id": "c1", "code": "WELCOME10", "before": "100", "note": "n"}
			for i, e := range s.Race.Entries() {
				r1, _, err1 := s.BuildRequest(e.Step, vars)
				r2, _, err2 := s2.BuildRequest(s2.Race.Entries()[i].Step, vars)
				if err1 != nil || err2 != nil {
					t.Fatalf("BuildRequest: %v / %v", err1, err2)
				}
				if r1.URL.String() != r2.URL.String() || string(r1.Body) != string(r2.Body) || r1.Method != r2.Method {
					t.Errorf("entry %d differs after round trip: %v %q vs %v %q", i, r1.URL, r1.Body, r2.URL, r2.Body)
				}
			}
		})
	}
}

func TestParseErrors(t *testing.T) {
	cases := []struct {
		name, src string
		want      []string
	}{
		{"empty", "", []string{"x.yaml: the file is empty"}},
		{"comment only", "# nothing\n", []string{"x.yaml: the file is empty"}},
		{"not a mapping", "- a\n- b\n", []string{"x.yaml:1: a scenario must be a YAML mapping"}},
		{"syntax", "version: 1\nname: [a\n", []string{"x.yaml:", "invalid YAML"}},
		{"two documents", "version: 1\n---\nversion: 1\n", []string{"x.yaml:2: only one YAML document"}},
		{"unknown top field", "version: 1\ntrails: 3\n", []string{`x.yaml:2: trails: unknown field (did you mean "trials"?)`}},
		{"unknown nested field", "race:\n  copis: 3\n", []string{`x.yaml:2: race.copis: unknown field (did you mean "copies"?)`}},
		{"unknown field lists known", "scope:\n  zzzzzzzz: 1\n", []string{"scope.zzzzzzzz: unknown field (known fields: allow_hosts, budget)"}},
		{"unknown step field", "setup:\n  - request: GET /\n    extrakt: {}\n", []string{`x.yaml:3: setup[0].extrakt: unknown field (did you mean "extract"?)`}},
		{"int expected", "race:\n  copies: many\n", []string{`x.yaml:2: race.copies: expected an integer, got "many"`}},
		{"quoted int rejected", "trials: \"5\"\n", []string{`x.yaml:1: trials: expected an integer, got "5"`}},
		{"bool expected", "tls:\n  insecure: maybe\n", []string{`x.yaml:2: tls.insecure: expected true or false, got "maybe"`}},
		{"number expected", "scope:\n  budget: {rps: fast}\n", []string{`scope.budget.rps: expected a number, got "fast"`}},
		{"list expected", "scope:\n  allow_hosts: 127.0.0.1\n", []string{`x.yaml:2: scope.allow_hosts: expected a list, got "127.0.0.1"`}},
		{"string expected", "name: {a: b}\n", []string{"x.yaml:1: name: expected a string, got a mapping"}},
		{"mapping expected", "race: fast\n", []string{`x.yaml:1: race: expected a mapping, got "fast"`}},
		{"duration", "race:\n  gate: 100\n", []string{`x.yaml:2: race.gate: expected a duration such as 100ms, got "100"`}},
		{"duplicate field", "name: a\nname: b\n", []string{"x.yaml:2: name: duplicate field (first set on line 1)"}},
		{"duplicate map key", "vars:\n  a: 1\n  a: 2\n", []string{"x.yaml:3: vars.a: duplicate key (first set on line 2)"}},
		{"duplicate header any case", "identities:\n  u:\n    headers:\n      Cookie: a\n      cookie: b\n", []string{"x.yaml:5: identities.u.headers.cookie: duplicate key"}},
		{"expect_status element", "setup:\n  - request: GET /\n    expect_status: [200, ok]\n", []string{`x.yaml:3: setup[0].expect_status[1]: expected an integer, got "ok"`}},
		{"several errors", "trails: 1\nrace: {copies: x}\n", []string{"trails: unknown field", "race.copies: expected an integer"}},
		{"bad json body", "setup:\n  - request: POST /\n    json: {a: .nan}\n", []string{"x.yaml:3: setup[0].json:", "not a JSON number"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Parse([]byte(c.src), "x.yaml")
			if err == nil {
				t.Fatal("Parse succeeded")
			}
			for _, w := range c.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error %q does not contain %q", err, w)
				}
			}
			var fe *FieldError
			if !errors.As(err, &fe) {
				t.Errorf("error %T is not a *FieldError", err)
			}
		})
	}
}

// validBase is a minimal valid scenario; validation cases replace parts of it.
const validBase = `version: 1
name: base
target: https://shop.test:8443/api
scope:
  allow_hosts: [shop.test:8443]
identities:
  alice: {headers: {Authorization: Bearer x}}
vars: {code: WELCOME10}
setup:
  - id: cart
    as: alice
    request: POST /carts
    extract: {cart_id: $.id}
race:
  copies: 20
  request:
    as: alice
    raw: |
      POST /carts/{{cart_id}}/coupons
      Content-Type: application/json

      {"code":"{{code}}"}
check:
  as: alice
  request: GET /carts/{{cart_id}}
  invariant: size(check.json.discounts) <= 1
reset:
  - request: POST /reset
`

func TestValidBase(t *testing.T) {
	s := mustParse(t, validBase, "v.yaml")
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestValidateErrors(t *testing.T) {
	cases := []struct {
		name     string
		old, new string // replace old with new in validBase
		want     string // substring of the error
	}{
		{"version missing", "version: 1\n", "", "v.yaml: version: required: set version: 1"},
		{"version 2", "version: 1", "version: 2", "v.yaml:1: version: unsupported version 2"},
		{"name missing", "name: base\n", "", "v.yaml: name: required"},
		{"name pattern", "name: base", "name: Base_1", `v.yaml:2: name: "Base_1" must use only lowercase letters`},
		{"target missing", "target: https://shop.test:8443/api\n", "", "target: required"},
		{"target scheme", "target: https://", "target: ftp://", "v.yaml:3: target: must be an absolute http:// or https:// URL"},
		{"target relative", "target: https://shop.test:8443/api", "target: /api", "target: must be an absolute"},
		{"target query", "/api\n", "/api?x=1\n", "v.yaml:3: target: the base URL cannot have a query"},
		{"target placeholder", "target: https://shop.test:8443/api", "target: https://{{h}}/api", "target: placeholders are not allowed"},
		{"target out of scope", "allow_hosts: [shop.test:8443]", "allow_hosts: [other.test]", "v.yaml:3: target: host shop.test:8443 is not in scope.allow_hosts [other.test]"},
		{"target wrong port", "allow_hosts: [shop.test:8443]", "allow_hosts: [shop.test:443]", "target: host shop.test:8443 is not in scope.allow_hosts"},
		{"scope missing", "scope:\n  allow_hosts: [shop.test:8443]\n", "", "scope.allow_hosts: required"},
		{"scope empty", "allow_hosts: [shop.test:8443]", "allow_hosts: []", "v.yaml:5: scope.allow_hosts: required"},
		{"scope url", "allow_hosts: [shop.test:8443]", "allow_hosts: [shop.test:8443, 'https://shop.test']", `v.yaml:5: scope.allow_hosts[1]: "https://shop.test": want host or host:port, not a URL`},
		{"scope wildcard", "allow_hosts: [shop.test:8443]", "allow_hosts: [shop.test:8443, '*.shop.test']", "scope.allow_hosts[1]: \"*.shop.test\": wildcards are not supported"},
		{"budget negative", "allow_hosts: [shop.test:8443]", "allow_hosts: [shop.test:8443]\n  budget: {requests: -1}", "v.yaml:6: scope.budget.requests: must be positive"},
		{"rps negative", "allow_hosts: [shop.test:8443]", "allow_hosts: [shop.test:8443]\n  budget: {rps: -2}", "scope.budget.rps: must be positive"},
		{"identity host header", "{Authorization: Bearer x}", "{Host: evil}", "v.yaml:7: identities.alice.headers.Host: the engine sets Host"},
		{"identity bad header", "{Authorization: Bearer x}", "{'Bad Name': x}", `identities.alice.headers.Bad Name: invalid header name "Bad Name"`},
		{"identity empty", "{headers: {Authorization: Bearer x}}", "{}", "identities.alice.headers: an identity needs at least one header"},
		{"identity unknown var", "{Authorization: Bearer x}", "{Authorization: 'Bearer {{tok}}'}", "identities.alice.headers.Authorization: unknown variable {{tok}}"},
		{"var name", "vars: {code: WELCOME10}", "vars: {1code: WELCOME10}", "vars.1code: variable names use letters"},
		{"var template", "vars: {code: WELCOME10}", "vars: {code: '{{x}}'}", "vars.code: initial values cannot use {{x}}"},
		{"step id pattern", "id: cart", "id: Cart", `v.yaml:10: setup[0].id: "Cart" must use only lowercase`},
		{"step id duplicate", "reset:\n  - request: POST /reset", "reset:\n  - id: cart\n    request: POST /reset", "reset[0].id: duplicate id \"cart\" (also setup[0])"},
		{"unknown identity", "    as: alice\n    request: POST /carts", "    as: carol\n    request: POST /carts", `v.yaml:11: setup[0].as: unknown identity "carol" (defined: alice)`},
		{"request missing", "    request: POST /carts\n", "", "setup[0].request: required"},
		{"request and raw", "    request: POST /carts\n", "    request: POST /carts\n    raw: GET /\n", "setup[0]: set either request or raw, not both"},
		{"bad request line", "request: POST /carts", "request: POST", `v.yaml:12: setup[0].request: request line 1: want "METHOD /path [HTTP/version]", got "POST"`},
		{"relative target", "request: POST /carts", "request: POST carts", `setup[0].request: request target "carts" must start with /`},
		{"bad version word", "request: POST /carts", "request: POST /carts HTPP/1.1", "the third word must be an HTTP version"},
		{"bad method", "request: POST /carts", "request: 'P(ST /carts'", `invalid method "P(ST"`},
		{"absolute out of scope", "request: POST /carts", "request: POST https://evil.test/carts", "v.yaml:12: setup[0].request: request URL host evil.test is not in scope.allow_hosts"},
		{"absolute placeholder host", "request: POST /carts", "request: POST https://{{h}}/carts", "the host of an absolute request URL cannot use placeholders"},
		{"bad header line", "      Content-Type: application/json\n", "      Content-Type application/json\n", `v.yaml:18: race.request.raw: request line 2: want "Name: value"`},
		{"transfer encoding", "      Content-Type: application/json\n", "      Transfer-Encoding: chunked\n", "race.request.raw: request line 2: Transfer-Encoding is not supported"},
		{"json and raw body", "    as: alice\n    raw: |", "    as: alice\n    json: {a: 1}\n    raw: |", "race.request.json: json and a raw body cannot both be set"},
		{"json unknown var", "    request: POST /carts\n", "    request: POST /carts\n    json: {x: '{{nope}}'}\n", "setup[0].json: unknown variable {{nope}}"},
		{"expect_status range", "    request: POST /carts\n", "    request: POST /carts\n    expect_status: [20]\n", "setup[0].expect_status: 20 is not an HTTP status code"},
		{"extract spec", "extract: {cart_id: $.id}", "extract: {cart_id: '$.id[x]'}", `v.yaml:13: setup[0].extract.cart_id: invalid JSON path "$.id[x]"`},
		{"extract kind", "extract: {cart_id: $.id}", "extract: {cart_id: body}", `setup[0].extract.cart_id: unsupported extraction "body"`},
		{"extract name", "extract: {cart_id: $.id}", "extract: {cart-id: $.id}", "setup[0].extract.cart-id: variable names use letters"},
		{"unknown var in race", "{{cart_id}}/coupons", "{{cart}}/coupons", "v.yaml:18: race.request.raw: unknown variable {{cart}}: define it in vars or extract it in an earlier setup step (known: cart_id, code)"},
		{"var used before extract", "    request: POST /carts\n", "    request: POST /carts/{{cart_id}}\n", "setup[0].request: unknown variable {{cart_id}}"},
		{"unterminated placeholder", "{{cart_id}}/coupons", "{{cart_id/coupons", "race.request.raw: unterminated {{ placeholder"},
		{"bad env name", "{{cart_id}}/coupons", "${env:1X}/coupons", `invalid environment variable name "1X"`},
		{"engine", "race:\n  copies: 20", "race:\n  engine: h3\n  copies: 20", `v.yaml:15: race.engine: unknown engine "h3"`},
		{"copies too many", "copies: 20", "copies: 1001", "v.yaml:15: race.copies: must be between 1 and 1000, got 1001"},
		{"copies negative", "copies: 20", "copies: -1", "race.copies: must be between 1 and 1000"},
		{"warmup negative", "copies: 20", "copies: 20\n  warmup: -1", "race.warmup: must be between 0 and 1000"},
		{"gate too long", "copies: 20", "copies: 20\n  gate: 1m", "race.gate: must be between 0 and 10s, got 1m0s"},
		{"race request missing", "race:\n  copies: 20\n  request:\n    as: alice\n", "race:\n  copies: 20\n  xrequest:\n    as: alice\n", ""},
		{"race request copies", "  request:\n    as: alice\n    raw", "  request:\n    copies: 3\n    as: alice\n    raw", "race.request.copies: use race.copies with race.request"},
		{"race request extract", "  request:\n    as: alice\n    raw", "  request:\n    extract: {a: status}\n    as: alice\n    raw", "race.request.extract: not supported in race requests"},
		{"race request id", "  request:\n    as: alice\n    raw", "  request:\n    id: x\n    as: alice\n    raw", "race.request.id: race requests have no id"},
		{"race request expect", "  request:\n    as: alice\n    raw", "  request:\n    expect_status: [200]\n    as: alice\n    raw", "race.request.expect_status: not supported in race requests"},
		{"check missing", "check:\n  as: alice\n  request: GET /carts/{{cart_id}}\n  invariant: size(check.json.discounts) <= 1\n", "", "v.yaml: check: required"},
		{"invariant missing", "  invariant: size(check.json.discounts) <= 1\n", "", "v.yaml:23: check.invariant: required"},
		{"invariant todo", "invariant: size(check.json.discounts) <= 1", "invariant: 'TODO: later'", "v.yaml:26: check.invariant: still the TODO placeholder from import"},
		{"check id", "check:\n  as: alice", "check:\n  id: c\n  as: alice", "check.id: the check has no id"},
		{"check extract", "check:\n  as: alice", "check:\n  extract: {a: status}\n  as: alice", "check.extract: not supported in the check"},
		{"check as without request", "  request: GET /carts/{{cart_id}}\n", "", "check.request: required when as, json or expect_status is set"},
		{"check expect status", "check:\n  as: alice", "check:\n  expect_status: [999]\n  as: alice", "check.expect_status: 999 is not an HTTP status code"},
		{"reset unknown var", "  - request: POST /reset", "  - request: POST /reset/{{zzz}}", "reset[0].request: unknown variable {{zzz}}"},
		{"trials negative", "reset:\n", "trials: -1\nreset:\n", "v.yaml:27: trials: must be at least 1"},
		{"trials too many", "reset:\n", "trials: 100000\nreset:\n", "trials: at most 10000"},
		{"arrival header", "reset:\n", "evidence: {arrival_header: 'X Bad'}\nreset:\n", `evidence.arrival_header: invalid header name "X Bad"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if !strings.Contains(validBase, c.old) {
				t.Fatalf("validBase does not contain %q", c.old)
			}
			src := strings.Replace(validBase, c.old, c.new, 1)
			s, err := Parse([]byte(src), "v.yaml")
			if c.want == "" { // the case only has to fail somewhere
				if err == nil {
					err = s.Validate()
				}
				if err == nil {
					t.Fatal("no error")
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			err = s.Validate()
			if err == nil {
				t.Fatalf("Validate succeeded, want %q", c.want)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error:\n%v\nwant substring:\n%s", err, c.want)
			}
		})
	}
}

func TestValidateRaceRequests(t *testing.T) {
	src := strings.Replace(validBase, "race:\n  copies: 20\n  request:\n    as: alice\n", "race:\n  requests:\n  - as: alice\n    copies: 600\n    request: GET /a\n  - copies: 401\n    request: GET /b\n  - as: alice\n", 1)
	src = strings.Replace(src, "    raw: |\n      POST /carts", "    raw: |\n      POST /carts", 1)
	s := mustParse(t, src, "v.yaml")
	err := s.Validate()
	if err == nil || !strings.Contains(err.Error(), "race.requests: 1002 requests in one race; at most 1000") {
		t.Fatalf("err = %v", err)
	}

	both := strings.Replace(validBase, "race:\n  copies: 20\n", "race:\n  copies: 20\n  requests: [{request: GET /}]\n", 1)
	err = mustParse(t, both, "v.yaml").Validate()
	if err == nil || !strings.Contains(err.Error(), "v.yaml:14: race: set exactly one of race.request and race.requests") {
		t.Fatalf("err = %v", err)
	}

	copiesWithRequests := strings.Replace(validBase, "  copies: 20\n  request:\n    as: alice\n", "  copies: 20\n  requests:\n  - as: alice\n", 1)
	err = mustParse(t, copiesWithRequests, "v.yaml").Validate()
	if err == nil || !strings.Contains(err.Error(), "race.copies: with race.requests, set copies on each entry instead") {
		t.Fatalf("err = %v", err)
	}
}

func TestValidateInCode(t *testing.T) {
	// A scenario built in code has no file or lines; errors still name fields.
	s := &Scenario{Version: 1, Name: "x", Target: "https://h", Scope: Scope{AllowHosts: []string{"h"}}}
	err := s.Validate()
	if err == nil {
		t.Fatal("no error")
	}
	if got := err.Error(); !strings.HasPrefix(got, "race: set race.request") || !strings.Contains(got, "\ncheck: required") {
		t.Errorf("err = %q", got)
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(p, []byte(strings.Replace(validBase, "copies: 20", "copies: 0x7fffffff", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(p)
	if err == nil || !strings.Contains(err.Error(), p+":15: race.copies: must be between 1 and 1000") {
		t.Fatalf("err = %v", err)
	}
	if _, err := Load(filepath.Join(dir, "missing.yaml")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing file: %v", err)
	}
	bom := filepath.Join(dir, "bom.yaml")
	if err := os.WriteFile(bom, append([]byte("\xef\xbb\xbf"), validBase...), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(bom); err != nil {
		t.Fatalf("BOM: %v", err)
	}
}

func TestFieldErrorFormat(t *testing.T) {
	cases := []struct {
		e    FieldError
		want string
	}{
		{FieldError{File: "a.yaml", Line: 3, Field: "race", Msg: "m"}, "a.yaml:3: race: m"},
		{FieldError{File: "a.yaml", Field: "race", Msg: "m"}, "a.yaml: race: m"},
		{FieldError{Line: 3, Field: "race", Msg: "m"}, "line 3: race: m"},
		{FieldError{Msg: "m"}, "m"},
	}
	for _, c := range cases {
		if got := c.e.Error(); got != c.want {
			t.Errorf("%+v: %q, want %q", c.e, got, c.want)
		}
	}
}

func TestTooManyErrors(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 30; i++ {
		b.WriteString("bad" + strings.Repeat("x", i) + ": 1\n")
	}
	_, err := Parse([]byte(b.String()), "x.yaml")
	if err == nil {
		t.Fatal("no error")
	}
	if n := strings.Count(err.Error(), "\n") + 1; n != maxErrors+1 {
		t.Errorf("%d error lines, want %d", n, maxErrors+1)
	}
	if !strings.HasSuffix(err.Error(), "too many errors") {
		t.Errorf("err does not end with too many errors: %v", err)
	}
}

func TestJSONBodyEncoding(t *testing.T) {
	s := mustParse(t, mustRead(t, "multi.yaml"), "multi.yaml")
	body, sec, err := s.Race.Requests[0].JSON.Encode(Vars{"note": `say "hi"`, "before": "10000"})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"to":"bob","amount_cents":7000,"memo":"say \"hi\" 10000","tags":["a","1",true,null,1.5]}`
	if string(body) != want {
		t.Errorf("body = %s\nwant   %s", body, want)
	}
	if len(sec) != 0 {
		t.Errorf("secrets = %v", sec)
	}
	b, err := NewJSONBody(map[string]any{"a": []int{1, 2}})
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := b.Encode(nil)
	if err != nil || string(got) != `{"a":[1,2]}` {
		t.Errorf("NewJSONBody: %s %v", got, err)
	}
	// Strings that look like numbers stay strings through Marshal.
	b, _ = NewJSONBody(map[string]any{"n": "123", "t": "true"})
	sc := &Scenario{Setup: []Step{{JSON: b}}}
	out, err := Marshal(sc)
	if err != nil {
		t.Fatal(err)
	}
	re := mustParse(t, string(out), "x")
	got, _, _ = re.Setup[0].JSON.Encode(nil)
	if string(got) != `{"n":"123","t":"true"}` {
		t.Errorf("after round trip: %s\n%s", got, out)
	}
	// Anchors and aliases are resolved.
	re = mustParse(t, "setup:\n  - request: POST /\n    json: {a: &x [1, 2], b: *x}\n", "x")
	got, _, err = re.Setup[0].JSON.Encode(nil)
	if err != nil || string(got) != `{"a":[1,2],"b":[1,2]}` {
		t.Errorf("aliases: %s %v", got, err)
	}
	// Explicit null is a body; an absent field is not.
	re = mustParse(t, "setup:\n  - request: POST /\n    json: null\n", "x")
	got, _, err = re.Setup[0].JSON.Encode(nil)
	if err != nil || string(got) != "null" || re.Setup[0].JSON.IsZero() {
		t.Errorf("null: %q %v", got, err)
	}
}

func TestJSONBodyValues(t *testing.T) {
	cases := []struct {
		yaml, want, err string
	}{
		{yaml: "{a: 0x1F, b: 1_000, c: -3, d: 18446744073709551615}", want: `{"a":31,"b":1000,"c":-3,"d":18446744073709551615}`},
		{yaml: "[1.0, 2.5e3, -0.5, .5]", want: `[1,2500,-0.5,0.5]`},
		{yaml: "[yes, no, true, ~, 2026-11-22, 'x']", want: `["yes","no",true,null,"2026-11-22","x"]`},
		{yaml: "'{{v}}'", want: `"a\"b\n"`},
		{yaml: "{'{{v}}': 1}", want: `{"a\"b\n":1}`},
		{yaml: "\"plain\"", want: `"plain"`},
		{yaml: "{a: 99999999999999999999999}", want: `{"a":1e+23}`}, // YAML resolves it as a float
		{yaml: "{a: .inf}", err: "is not a JSON number"},
		{yaml: "{a: !!binary aGk=}", err: "binary values are not supported"},
		{yaml: "{[1, 2]: x}", err: "JSON object keys must be strings"},
		{yaml: "{<<: {a: 1}}", err: "merge keys"},
		{yaml: "{a: '{{missing}}'}", err: "unknown variable {{missing}}"},
	}
	for _, c := range cases {
		s, err := Parse([]byte("setup:\n  - request: POST /\n    json: "+c.yaml+"\n"), "j.yaml")
		if err == nil {
			var body []byte
			body, _, err = s.Setup[0].JSON.Encode(Vars{"v": "a\"b\n"})
			if err == nil && string(body) != c.want {
				t.Errorf("%s: body %s, want %s", c.yaml, body, c.want)
			}
		}
		switch {
		case c.err == "" && err != nil:
			t.Errorf("%s: %v", c.yaml, err)
		case c.err != "" && (err == nil || !strings.Contains(err.Error(), c.err)):
			t.Errorf("%s: err = %v, want %q", c.yaml, err, c.err)
		}
	}
}

// TestPlainYAMLUnmarshal makes sure the custom types also work with plain
// yaml.Unmarshal, for callers that do not go through Parse.
func TestPlainYAMLUnmarshal(t *testing.T) {
	var s Scenario
	if err := yaml.Unmarshal([]byte(mustRead(t, "full.yaml")), &s); err != nil {
		t.Fatal(err)
	}
	if s.Race.GateDuration() != 150*time.Millisecond || s.Setup[1].JSON.IsZero() {
		t.Errorf("gate %v json zero %v", s.Race.GateDuration(), s.Setup[1].JSON.IsZero())
	}
	if err := yaml.Unmarshal([]byte("race: {gate: [1]}"), &s); err == nil || !strings.Contains(err.Error(), "expected a duration") {
		t.Errorf("err = %v", err)
	}
}
