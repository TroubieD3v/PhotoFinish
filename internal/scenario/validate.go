package scenario

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"golang.org/x/net/http/httpguts"

	"github.com/TroubieD3v/photofinish/internal/engine"
)

var (
	nameRE     = regexp.MustCompile(`^[a-z0-9-]+$`)
	stepIDRE   = regexp.MustCompile(`^[a-z0-9_]+$`)
	identityRE = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
)

// validator collects FieldErrors with the lines recorded by Parse.
type validator struct {
	s    *Scenario
	errs []error
}

func (v *validator) add(field, format string, args ...any) {
	if len(v.errs) > maxErrors {
		return
	}
	if len(v.errs) == maxErrors {
		v.errs = append(v.errs, &FieldError{File: v.s.Path, Msg: "too many errors"})
		return
	}
	v.errs = append(v.errs, &FieldError{File: v.s.Path, Line: v.s.Line(field), Field: field, Msg: fmt.Sprintf(format, args...)})
}

// Validate checks the meaning of every field: required fields, names,
// ranges, scope, identities, request syntax, extraction specs and that every
// {{variable}} is defined before it is used. Errors are *FieldError values
// (joined with errors.Join) that name the field and, for parsed files, the
// line. The invariant is not compiled here (see package check).
func (s *Scenario) Validate() error {
	v := &validator{s: s}

	switch s.Version {
	case Version:
	case 0:
		v.add("version", "required: set version: 1")
	default:
		v.add("version", "unsupported version %d; this build reads version 1", s.Version)
	}
	switch {
	case s.Name == "":
		v.add("name", "required: a short id such as coupon-applied-twice ([a-z0-9-]+)")
	case !nameRE.MatchString(s.Name):
		v.add("name", "%q must use only lowercase letters, digits and - ([a-z0-9-]+)", s.Name)
	}

	v.scope()
	target, err := s.TargetURL()
	if err != nil {
		v.add("target", "%v", err)
	} else if len(s.Scope.AllowHosts) > 0 && !s.Scope.AllowsURL(target) {
		v.add("target", "host %s is not in scope.allow_hosts %v", target.Host, s.Scope.AllowHosts)
	}

	for name, id := range sortedMap(s.Identities) {
		f := "identities." + name
		if !identityRE.MatchString(name) {
			v.add(f, "identity names use letters, digits, _ and -")
		}
		if len(id.Headers) == 0 {
			v.add(f+".headers", "an identity needs at least one header")
		}
		for h, val := range sortedMap(id.Headers) {
			hf := f + ".headers." + h
			if ignore, err := headerRule(h); err != nil {
				v.add(hf, "%v", err)
			} else if ignore {
				v.add(hf, "the engine sets %s; it cannot be an identity header", h)
			}
			if _, _, err := references(val); err != nil {
				v.add(hf, "%v", err)
			}
		}
	}

	known := map[string]bool{}
	for name, val := range sortedMap(s.Vars) {
		f := "vars." + name
		if !varNameRE.MatchString(name) {
			v.add(f, "variable names use letters, digits and _ and do not start with a digit")
		}
		vars, _, err := references(val)
		switch {
		case err != nil:
			v.add(f, "%v", err)
		case len(vars) > 0:
			v.add(f, "initial values cannot use {{%s}}; only ${env:NAME} is expanded here", vars[0])
		}
		known[name] = true
	}

	// Identity headers are expanded in every step that uses them, so their
	// variables must be known from the start.
	for name, id := range sortedMap(s.Identities) {
		for h, val := range sortedMap(id.Headers) {
			v.refs("identities."+name+".headers."+h, val, known)
		}
	}

	ids := map[string]string{}
	for i, st := range s.Setup {
		v.step(fmt.Sprintf("setup[%d]", i), st, stepSetup, known, ids)
	}
	afterSetup := clone(known)
	v.race(afterSetup)
	v.check(afterSetup)
	resetKnown := clone(afterSetup)
	for i, st := range s.Reset {
		v.step(fmt.Sprintf("reset[%d]", i), st, stepReset, resetKnown, ids)
	}

	switch {
	case s.Trials < 0:
		v.add("trials", "must be at least 1 (default %d), got %d", DefaultTrials, s.Trials)
	case s.Trials > MaxTrials:
		v.add("trials", "at most %d, got %d", MaxTrials, s.Trials)
	}
	if h := s.Evidence.ArrivalHeader; h != "" && h != "-" && !httpguts.ValidHeaderFieldName(h) {
		v.add("evidence.arrival_header", "invalid header name %q (use - to disable)", h)
	}
	return errors.Join(v.errs...)
}

func (v *validator) scope() {
	sc := v.s.Scope
	if len(sc.AllowHosts) == 0 {
		v.add("scope.allow_hosts", "required: list the hosts this scenario may contact, e.g. [127.0.0.1:8443]")
	}
	for i, h := range sc.AllowHosts {
		f := fmt.Sprintf("scope.allow_hosts[%d]", i)
		switch {
		case strings.TrimSpace(h) == "":
			v.add(f, "empty host")
		case strings.Contains(h, "://") || strings.ContainsAny(h, "/?#@"):
			v.add(f, "%q: want host or host:port, not a URL", h)
		case strings.Contains(h, "*"):
			v.add(f, "%q: wildcards are not supported; list every host", h)
		case hasPlaceholder(h) || strings.ContainsAny(h, " \t"):
			v.add(f, "%q: want host or host:port", h)
		default:
			if host, _ := splitHost(h); host == "" {
				v.add(f, "%q: want host or host:port", h)
			} else if _, err := url.Parse("https://" + h + "/"); err != nil {
				v.add(f, "%q: want host or host:port", h)
			}
		}
	}
	if sc.Budget.Requests < 0 {
		v.add("scope.budget.requests", "must be positive (default %d), got %d", DefaultBudgetRequests, sc.Budget.Requests)
	}
	if sc.Budget.RPS < 0 {
		v.add("scope.budget.rps", "must be positive (default %d), got %g", DefaultRPS, sc.Budget.RPS)
	}
}

type stepKind int

const (
	stepSetup stepKind = iota
	stepReset
	stepRace
	stepCheck
)

// step validates a setup/reset step and adds its extracted names to known.
func (v *validator) step(f string, st Step, kind stepKind, known map[string]bool, ids map[string]string) {
	if st.ID != "" {
		switch {
		case !stepIDRE.MatchString(st.ID):
			v.add(f+".id", "%q must use only lowercase letters, digits and _ ([a-z0-9_]+)", st.ID)
		case ids[st.ID] != "":
			v.add(f+".id", "duplicate id %q (also %s)", st.ID, ids[st.ID])
		default:
			ids[st.ID] = f
		}
	}
	v.request(f, st, kind, known)
	for _, code := range st.ExpectStatus {
		if code < 100 || code > 599 {
			v.add(f+".expect_status", "%d is not an HTTP status code (100-599)", code)
		}
	}
	for name, spec := range sortedMap(st.Extract) {
		ef := f + ".extract." + name
		if !varNameRE.MatchString(name) {
			v.add(ef, "variable names use letters, digits and _ and do not start with a digit")
		}
		if _, err := parseExtract(spec); err != nil {
			v.add(ef, "%v", err)
		}
	}
	for name := range st.Extract {
		known[name] = true
	}
}

// request validates the request part of any step against the variables
// known at that point.
func (v *validator) request(f string, st Step, kind stepKind, known map[string]bool) {
	if st.As != "" {
		if _, ok := v.s.Identities[st.As]; !ok {
			v.add(f+".as", "unknown identity %q%s", st.As, listKeys(" (defined: ", v.s.Identities, ")"))
		}
	}
	field := f + ".request"
	switch {
	case st.Request != "" && st.Raw != "":
		v.add(f, "set either request or raw, not both")
		return
	case st.Raw != "":
		field = f + ".raw"
	case st.Request == "":
		if kind == stepCheck {
			if !st.JSON.IsZero() || st.As != "" || len(st.ExpectStatus) > 0 {
				v.add(f+".request", "required when as, json or expect_status is set")
			}
			return
		}
		v.add(f+".request", "required: \"METHOD /path\" or a raw request (raw: |)")
		return
	}
	text := st.Text()
	v.refs(field, text, known)
	raw, err := parseRaw(text)
	if err != nil {
		v.add(field, "%v", err)
		return
	}
	if !hasPlaceholder(raw.method) && !httpguts.ValidHeaderFieldName(raw.method) {
		v.add(field, "invalid method %q", raw.method)
	}
	v.target(field, raw.target)
	for _, h := range raw.headers {
		if _, err := headerRule(h.name); err != nil {
			v.add(field, "request line %d: %v", h.line, err)
		}
	}
	if !st.JSON.IsZero() {
		if raw.body != "" {
			v.add(f+".json", "json and a raw body cannot both be set")
		}
		if _, _, err := st.JSON.encode(func(s string) (string, []string, error) {
			vars, _, err := references(s)
			if err == nil {
				for _, n := range vars {
					if !known[n] {
						err = fmt.Errorf("unknown variable {{%s}}%s", n, listKeys(" (known: ", known, ")"))
						break
					}
				}
			}
			return s, nil, err
		}); err != nil {
			v.add(f+".json", "%v", err)
		}
	}
}

// target checks the request target of a template: a path, or an absolute
// URL whose host is fixed and in scope.
func (v *validator) target(field, t string) {
	lower := strings.ToLower(t)
	if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
		if !strings.HasPrefix(t, "/") {
			v.add(field, "request target %q must start with / (it is joined to the target path) or be an absolute http(s) URL", t)
		}
		return
	}
	rest := t[strings.Index(t, "://")+3:]
	authority, _, _ := strings.Cut(rest, "/")
	authority, _, _ = strings.Cut(authority, "?")
	if hasPlaceholder(authority) {
		v.add(field, "the host of an absolute request URL cannot use placeholders (scope is checked before the run)")
		return
	}
	u, err := url.Parse(t[:strings.Index(t, "://")+3] + authority + "/")
	if err != nil || u.Hostname() == "" {
		v.add(field, "invalid request URL %q", t)
		return
	}
	if !v.s.Scope.AllowsURL(u) {
		v.add(field, "request URL host %s is not in scope.allow_hosts", u.Host)
	}
}

// refs reports {{variables}} in s that are not known and placeholder
// syntax errors.
func (v *validator) refs(field, s string, known map[string]bool) {
	vars, _, err := references(s)
	if err != nil {
		v.add(field, "%v", err)
		return
	}
	for _, n := range vars {
		if !known[n] {
			v.add(field, "unknown variable {{%s}}: define it in vars or extract it in an earlier setup step%s", n, listKeys(" (known: ", known, ")"))
			return
		}
	}
}

func (v *validator) race(known map[string]bool) {
	r := v.s.Race
	switch r.Engine {
	case "", engine.H2, engine.H1, engine.Burst, engine.Auto:
	default:
		v.add("race.engine", "unknown engine %q; want h2, h1, burst or auto", r.Engine)
	}
	if r.Warmup < 0 || r.Warmup > MaxCopies {
		v.add("race.warmup", "must be between 0 and %d, got %d", MaxCopies, r.Warmup)
	}
	if r.Gate < 0 || time.Duration(r.Gate) > MaxGate {
		v.add("race.gate", "must be between 0 and %s, got %s", MaxGate, r.Gate)
	}
	switch {
	case r.Request == nil && len(r.Requests) == 0:
		v.add("race", "set race.request (one request sent copies times) or race.requests (several endpoints)")
		return
	case r.Request != nil && len(r.Requests) > 0:
		v.add("race", "set exactly one of race.request and race.requests")
		return
	}
	if r.Request != nil {
		if r.Copies < 0 || r.Copies > MaxCopies {
			v.add("race.copies", "must be between 1 and %d, got %d", MaxCopies, r.Copies)
		}
		if r.Request.Copies != 0 {
			v.add("race.request.copies", "use race.copies with race.request (copies per entry is for race.requests)")
		}
		v.raceRequest("race.request", *r.Request, known)
		return
	}
	if r.Copies != 0 {
		v.add("race.copies", "with race.requests, set copies on each entry instead")
	}
	total := 0
	for i, e := range r.Requests {
		f := fmt.Sprintf("race.requests[%d]", i)
		if e.Copies < 0 || e.Copies > MaxCopies {
			v.add(f+".copies", "must be between 1 and %d, got %d", MaxCopies, e.Copies)
		}
		total += max(e.Copies, 1)
		v.raceRequest(f, e, known)
	}
	if total > MaxCopies {
		v.add("race.requests", "%d requests in one race; at most %d", total, MaxCopies)
	}
}

func (v *validator) raceRequest(f string, e RaceRequest, known map[string]bool) {
	if e.ID != "" {
		v.add(f+".id", "race requests have no id (their responses are race[0], race[1], ...)")
	}
	if len(e.ExpectStatus) > 0 {
		v.add(f+".expect_status", "not supported in race requests; check statuses in the invariant, e.g. race.all(r, r.status == 200)")
	}
	if len(e.Extract) > 0 {
		v.add(f+".extract", "not supported in race requests; extract in setup steps")
	}
	v.request(f, e.Step, stepRace, known)
}

func (v *validator) check(known map[string]bool) {
	c := v.s.Check
	if c == nil {
		v.add("check", "required: at least check.invariant, the rule that must hold after the race")
		return
	}
	inv := strings.TrimSpace(c.Invariant)
	switch {
	case inv == "":
		v.add("check.invariant", "required: a CEL expression that must hold after the race, e.g. size(race.filter(r, r.status == 200)) <= 1")
	case strings.HasPrefix(strings.ToUpper(inv), "TODO"):
		v.add("check.invariant", "still the TODO placeholder from import: write the rule as a CEL expression over race, check, setup and vars, e.g. size(race.filter(r, r.status == 200)) <= 1")
	}
	if c.ID != "" {
		v.add("check.id", "the check has no id (its response is check)")
	}
	if len(c.Extract) > 0 {
		v.add("check.extract", "not supported in the check; use check.json in the invariant")
	}
	v.request("check", c.Step, stepCheck, known)
	for _, code := range c.ExpectStatus {
		if code < 100 || code > 599 {
			v.add("check.expect_status", "%d is not an HTTP status code (100-599)", code)
		}
	}
}

func clone(m map[string]bool) map[string]bool {
	out := make(map[string]bool, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// sortedMap iterates a string-keyed map in key order.
func sortedMap[V any](m map[string]V) func(func(string, V) bool) {
	return func(yield func(string, V) bool) {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			if !yield(k, m[k]) {
				return
			}
		}
	}
}

func listKeys[V any](prefix string, m map[string]V, suffix string) string {
	if len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return prefix + strings.Join(keys, ", ") + suffix
}
