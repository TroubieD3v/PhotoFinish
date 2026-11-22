// Package scenario reads, validates and writes PhotoFinish scenario files.
//
// A scenario is a YAML document that names a target, the hosts the run may
// touch, the identities and variables it uses, the setup steps run before
// every trial, the race itself, the check request and the invariant that must
// hold afterwards, and optional reset steps. The package also turns scenario
// steps into engine requests (templating, raw request parsing, URL joining and
// scope checks), extracts values from responses and imports raw requests from
// Burp and HAR files.
//
// Zero values in a Scenario mean "use the default"; the accessor methods
// (TrialCount, Race.EngineKind, Budget.RequestLimit, ...) return the effective
// values so that Marshal never has to write defaults the user did not set.
package scenario

import (
	"strings"
	"time"

	"github.com/TroubieD3v/photofinish/internal/engine"
)

// Defaults applied when a scenario leaves a value unset (zero).
const (
	// DefaultTrials is the number of trials when trials is unset.
	DefaultTrials = 10
	// DefaultCopies is the number of race copies when race.copies is unset.
	DefaultCopies = 20
	// MaxCopies is the largest total number of requests in one race.
	MaxCopies = 1000
	// MaxTrials is the largest accepted trials value.
	MaxTrials = 10000
	// DefaultBudgetRequests is scope.budget.requests when unset.
	DefaultBudgetRequests = 1000
	// DefaultRPS is scope.budget.rps when unset.
	DefaultRPS = 20
	// DefaultGate is race.gate when unset.
	DefaultGate = 100 * time.Millisecond
	// MaxGate is the largest accepted race.gate.
	MaxGate = 10 * time.Second
	// DefaultArrivalHeader is evidence.arrival_header when unset.
	DefaultArrivalHeader = "X-Arrival-Ns"
	// Version is the only supported scenario format version.
	Version = 1
)

// InvariantTODO is the placeholder invariant written by the importers. It
// deliberately fails Validate until the user replaces it.
const InvariantTODO = "TODO: write the rule that must hold after the race as a CEL expression"

// Scenario is one parsed scenario file. Its fields mirror the YAML format.
type Scenario struct {
	// Version is the format version; it must be 1.
	Version int `yaml:"version"`
	// Name identifies the scenario in reports; it matches [a-z0-9-]+.
	Name string `yaml:"name"`
	// Description is free text.
	Description string `yaml:"description,omitempty"`
	// Target is the base URL; request paths are appended to its path.
	Target string `yaml:"target"`
	// TLS configures certificate verification.
	TLS TLS `yaml:"tls,omitempty"`
	// Scope lists the hosts the run may contact and the request budget.
	Scope Scope `yaml:"scope"`
	// Identities are named sets of headers that steps select with "as".
	Identities map[string]Identity `yaml:"identities,omitempty"`
	// Vars are the initial template variables.
	Vars Vars `yaml:"vars,omitempty"`
	// Setup steps run before every trial.
	Setup []Step `yaml:"setup,omitempty"`
	// Race describes the synchronized requests.
	Race Race `yaml:"race"`
	// Check holds the check request and the invariant.
	Check *Check `yaml:"check,omitempty"`
	// Reset steps run after every trial.
	Reset []Step `yaml:"reset,omitempty"`
	// Trials is the number of trials; 0 means DefaultTrials.
	Trials int `yaml:"trials,omitempty"`
	// Evidence configures what the engines record.
	Evidence Evidence `yaml:"evidence,omitempty"`

	// Path is the file the scenario came from ("" if it was built in code).
	Path string `yaml:"-"`
	// InvariantLine is the 1-based line of check.invariant in the file, or 0.
	InvariantLine int `yaml:"-"`

	// lines maps field paths such as "race.copies" to 1-based lines.
	lines map[string]int
}

// TLS configures TLS for every request of the scenario.
type TLS struct {
	// Insecure skips certificate verification (the demo shop needs it).
	Insecure bool `yaml:"insecure,omitempty"`
}

// Scope limits where and how much the scenario may send.
type Scope struct {
	// AllowHosts is required and non-empty. Entries are compared to URL.Host
	// case-insensitively; an entry without a port allows any port.
	AllowHosts []string `yaml:"allow_hosts,flow"`
	// Budget caps the number and rate of requests.
	Budget Budget `yaml:"budget,flow,omitempty"`
}

// Budget caps the requests of a run.
type Budget struct {
	// Requests is the total cap for the whole run; 0 means DefaultBudgetRequests.
	Requests int `yaml:"requests,omitempty"`
	// RPS limits setup, check and reset steps (not the race); 0 means DefaultRPS.
	RPS float64 `yaml:"rps,omitempty"`
}

// Identity is a named set of headers added to the steps that use it.
type Identity struct {
	// Headers are added to every request of a step with "as" set to this
	// identity. Values may use {{var}} and ${env:NAME}; they are masked in
	// reports.
	Headers map[string]string `yaml:"headers,omitempty"`
}

// Step is one setup, reset or check request.
type Step struct {
	// ID names the step; setup step responses are available to the invariant
	// as setup.<id>. It matches [a-z0-9_]+ and is unique.
	ID string `yaml:"id,omitempty"`
	// As selects an identity.
	As string `yaml:"as,omitempty"`
	// Request is "METHOD /path" or a full raw request.
	Request string `yaml:"request,omitempty"`
	// Raw is a full raw request; exactly one of Request and Raw is set.
	Raw string `yaml:"raw,omitempty"`
	// JSON is an optional JSON body; it sets Content-Type: application/json.
	JSON JSONBody `yaml:"json,omitempty"`
	// ExpectStatus lists the acceptable status codes; a mismatch makes the
	// trial INCONCLUSIVE.
	ExpectStatus []int `yaml:"expect_status,flow,omitempty"`
	// Extract maps variable names to extraction specs (see Extract).
	Extract map[string]string `yaml:"extract,omitempty"`
}

// Text returns the request text of the step: Request if set, else Raw.
func (st Step) Text() string {
	if st.Request != "" {
		return st.Request
	}
	return st.Raw
}

// RaceRequest is one request of the race. ID, ExpectStatus and Extract are
// not allowed in race requests.
type RaceRequest struct {
	Step `yaml:",inline"`
	// Copies is the number of copies of this entry in race.requests; 0
	// means 1. It is not allowed in race.request (use race.copies).
	Copies int `yaml:"copies,omitempty"`
}

// Race describes the synchronized part of a trial.
type Race struct {
	// Engine is h2, h1, burst or auto; "" means auto.
	Engine engine.Kind `yaml:"engine,omitempty"`
	// Copies is the number of copies of Request; 0 means DefaultCopies.
	// It is not allowed together with Requests.
	Copies int `yaml:"copies,omitempty"`
	// Warmup is the number of warm-up requests sent on the race connections.
	Warmup int `yaml:"warmup,omitempty"`
	// Gate is the pause between pre-send and release; 0 means DefaultGate.
	Gate Duration `yaml:"gate,omitempty"`
	// Request is the request sent Copies times. Exactly one of Request and
	// Requests is set.
	Request *RaceRequest `yaml:"request,omitempty"`
	// Requests is a multi-endpoint race; each entry has its own Copies.
	Requests []RaceRequest `yaml:"requests,omitempty"`
	// Expect429 declares that a 429 without Retry-After or RateLimit
	// headers is the application's own answer (for example a lockout that
	// is the defence under test), not rate limiting. By default any 429 in
	// the race makes a trial INCONCLUSIVE.
	Expect429 bool `yaml:"expect_429,omitempty"`
}

// EngineKind returns the engine, defaulting to auto.
func (r Race) EngineKind() engine.Kind {
	if r.Engine == "" {
		return engine.Auto
	}
	return r.Engine
}

// GateDuration returns the gate, defaulting to DefaultGate.
func (r Race) GateDuration() time.Duration {
	if r.Gate <= 0 {
		return DefaultGate
	}
	return time.Duration(r.Gate)
}

// Entries returns the race requests with their effective copy counts: the
// single Request with Copies (or DefaultCopies), or every entry of Requests
// with its own Copies (or 1).
func (r Race) Entries() []RaceRequest {
	if r.Request != nil {
		e := *r.Request
		e.Copies = r.Copies
		if e.Copies <= 0 {
			e.Copies = DefaultCopies
		}
		return []RaceRequest{e}
	}
	out := make([]RaceRequest, len(r.Requests))
	for i, e := range r.Requests {
		if e.Copies <= 0 {
			e.Copies = 1
		}
		out[i] = e
	}
	return out
}

// TotalCopies returns the number of requests in one race (without warm-up).
func (r Race) TotalCopies() int {
	n := 0
	for _, e := range r.Entries() {
		n += e.Copies
	}
	return n
}

// Check is the request made after the race and the rule that must hold.
type Check struct {
	// Step is the optional check request (Request or Raw empty: no request).
	// ID and Extract are not allowed.
	Step `yaml:",inline"`
	// Invariant is a CEL expression over race, check, setup and vars.
	Invariant string `yaml:"invariant"`
	// Explain states the rule in words for reports.
	Explain string `yaml:"explain,omitempty"`
}

// HasRequest reports whether the check makes a request.
func (c *Check) HasRequest() bool {
	return c != nil && c.Text() != ""
}

// Evidence configures recorded evidence.
type Evidence struct {
	// ArrivalHeader is the response header with the server arrival time;
	// "" means DefaultArrivalHeader and "-" disables it.
	ArrivalHeader string `yaml:"arrival_header,omitempty"`
}

// Header returns the effective arrival header name ("-" when disabled).
func (e Evidence) Header() string {
	if e.ArrivalHeader == "" {
		return DefaultArrivalHeader
	}
	return e.ArrivalHeader
}

// RequestLimit returns the total request cap, defaulting to DefaultBudgetRequests.
func (b Budget) RequestLimit() int {
	if b.Requests <= 0 {
		return DefaultBudgetRequests
	}
	return b.Requests
}

// RateLimit returns the setup/check/reset rate limit in requests per second,
// defaulting to DefaultRPS.
func (b Budget) RateLimit() float64 {
	if b.RPS <= 0 {
		return DefaultRPS
	}
	return b.RPS
}

// TrialCount returns the number of trials, defaulting to DefaultTrials.
func (s *Scenario) TrialCount() int {
	if s.Trials <= 0 {
		return DefaultTrials
	}
	return s.Trials
}

// Line returns the 1-based line of a field path such as "race.copies" or
// "setup[0].request" in the source file, falling back to the nearest parent
// that has a line; it returns 0 for scenarios built in code.
func (s *Scenario) Line(field string) int {
	for field != "" {
		if l, ok := s.lines[field]; ok {
			return l
		}
		i := strings.LastIndexAny(field, ".[")
		if i < 0 {
			break
		}
		field = field[:i]
	}
	return 0
}
