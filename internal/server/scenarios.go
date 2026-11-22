package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/TroubieD3v/photofinish/internal/check"
	"github.com/TroubieD3v/photofinish/internal/engine"
	"github.com/TroubieD3v/photofinish/internal/runner"
	"github.com/TroubieD3v/photofinish/internal/scenario"
)

// lastRun is the most recent finished run of a scenario file.
type lastRun struct {
	ID         string         `json:"id"`
	Verdict    runner.Verdict `json:"verdict"`
	FinishedAt time.Time      `json:"finishedAt"`
}

// scenarioEntry describes one workspace scenario file or one example.
type scenarioEntry struct {
	// Path is relative to the workspace, with forward slashes. For an
	// example it is where "copy" puts it: examples/<name>.yaml.
	Path        string      `json:"path"`
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Target      string      `json:"target"`
	Engine      engine.Kind `json:"engine"`
	Valid       bool        `json:"valid"`
	Error       string      `json:"error,omitempty"`
	LastRun     *lastRun    `json:"lastRun,omitempty"`
	// InWorkspace is set on examples that already exist at Path.
	InWorkspace bool `json:"inWorkspace,omitempty"`
}

// scenariosResponse is the body of GET /api/scenarios.
type scenariosResponse struct {
	Scenarios []scenarioEntry `json:"scenarios"`
	Examples  []scenarioEntry `json:"examples"`
	// Truncated reports that the workspace has more scenario files than
	// the listing returns.
	Truncated bool `json:"truncated"`
}

// scenarioKeys are top-level keys of which a YAML file needs at least one to
// be listed as a scenario; other YAML files (compose files, manifests) are
// left out.
var scenarioKeys = []string{"race", "check", "target", "scope", "trials", "setup"}

// looksLikeScenario reports whether data should be listed as a scenario: a
// YAML mapping with one of scenarioKeys, or a document that does not parse
// (a scenario in the middle of an edit).
func looksLikeScenario(data []byte) bool {
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		var top any
		if yaml.Unmarshal(data, &top) == nil {
			return false // valid YAML, but not a mapping
		}
		return true
	}
	for _, k := range scenarioKeys {
		if _, ok := doc[k]; ok {
			return true
		}
	}
	return false
}

// describe parses and validates data and fills an entry.
func describe(p string, data []byte) scenarioEntry {
	e := scenarioEntry{Path: p}
	s, err := scenario.Parse(data, p)
	if err != nil {
		e.Error = firstError(err)
		e.Name = strings.TrimSuffix(path.Base(p), path.Ext(p))
		return e
	}
	e.Name, e.Description, e.Target = s.Name, strings.TrimSpace(s.Description), s.Target
	e.Engine = s.Race.EngineKind()
	if e.Name == "" {
		e.Name = strings.TrimSuffix(path.Base(p), path.Ext(p))
	}
	if problems := validateScenario(s); len(problems) > 0 {
		e.Error = problems[0].String()
		return e
	}
	e.Valid = true
	return e
}

// firstError returns the first error of a joined error, as one line.
func firstError(err error) string {
	if errs := unjoin(err); len(errs) > 0 {
		err = errs[0]
	}
	var fe *scenario.FieldError
	if errors.As(err, &fe) {
		return problemOf(fe).String()
	}
	return err.Error()
}

// unjoin returns the errors joined in err, or err itself.
func unjoin(err error) []error {
	if j, ok := err.(interface{ Unwrap() []error }); ok {
		var out []error
		for _, e := range j.Unwrap() {
			out = append(out, unjoin(e)...)
		}
		return out
	}
	return []error{err}
}

func (s *Server) listScenarios(w http.ResponseWriter, r *http.Request) {
	files, truncated, err := s.listFiles()
	if err != nil {
		fail(w, http.StatusInternalServerError, fmt.Errorf("list the workspace: %v", unwrapPathError(err)))
		return
	}
	last := map[string]*lastRun{}
	if latest, err := s.store.LatestByFile(); err == nil {
		for file, run := range latest {
			last[file] = &lastRun{ID: run.ID, Verdict: run.Verdict, FinishedAt: run.FinishedAt}
		}
	} else {
		s.logger.Printf("list runs: %v", err)
	}
	resp := scenariosResponse{Scenarios: []scenarioEntry{}, Examples: []scenarioEntry{}, Truncated: truncated}
	for _, f := range files {
		if f.err != nil {
			resp.Scenarios = append(resp.Scenarios, scenarioEntry{
				Path:  f.path,
				Name:  strings.TrimSuffix(path.Base(f.path), path.Ext(f.path)),
				Error: f.err.Error(),
			})
			continue
		}
		if !looksLikeScenario(f.data) {
			continue
		}
		e := describe(f.path, f.data)
		e.LastRun = last[f.path]
		resp.Scenarios = append(resp.Scenarios, e)
	}
	names, err := s.exampleNames()
	if err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	for _, name := range names {
		data, err := fs.ReadFile(s.examples, name+".yaml")
		if err != nil {
			continue
		}
		e := describe(exampleDest(name), data)
		e.Name = name
		if _, err := s.root.Lstat(exampleDest(name)); err == nil {
			e.InWorkspace = true
		}
		resp.Examples = append(resp.Examples, e)
	}
	writeJSON(w, http.StatusOK, resp)
}

// exampleNames returns the names of the embedded examples (file names
// without .yaml), sorted.
func (s *Server) exampleNames() ([]string, error) {
	matches, err := fs.Glob(s.examples, "*.yaml")
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(matches))
	for _, m := range matches {
		names = append(names, strings.TrimSuffix(m, ".yaml"))
	}
	slices.Sort(names)
	return names, nil
}

// exampleDest is where an example is copied in the workspace.
func exampleDest(name string) string { return "examples/" + name + ".yaml" }

// exampleNameRE matches the names of embedded examples.
var exampleNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

func (s *Server) copyExample(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !exampleNameRE.MatchString(name) {
		fail(w, http.StatusNotFound, fmt.Errorf("no example named %q", name))
		return
	}
	data, err := fs.ReadFile(s.examples, name+".yaml")
	if err != nil {
		fail(w, http.StatusNotFound, fmt.Errorf("no example named %q", name))
		return
	}
	dest := exampleDest(name)
	if err := s.writeFile(dest, data, true); err != nil {
		fail(w, statusOf(err), err)
		return
	}
	writeJSON(w, http.StatusCreated, fileResponse{Path: dest, Hash: hashContent(data)})
}

// fileResponse is the body of GET and PUT /api/scenarios/file.
type fileResponse struct {
	Path    string `json:"path"`
	Content string `json:"content,omitempty"`
	Hash    string `json:"hash"`
}

func (s *Server) getFile(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Query().Get("path")
	data, err := s.readFile(p)
	if err != nil {
		fail(w, statusOf(err), err)
		return
	}
	writeJSON(w, http.StatusOK, fileResponse{Path: p, Content: string(data), Hash: hashContent(data)})
}

// putRequest is the body of PUT /api/scenarios/file.
type putRequest struct {
	Content *string `json:"content"`
	// BaseHash is the hash the client loaded; when set, the write fails
	// with 409 if the file changed (or disappeared) since.
	BaseHash string `json:"baseHash"`
}

func (s *Server) putFile(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Query().Get("path")
	if _, err := s.checkPath(p); err != nil {
		fail(w, statusOf(err), err)
		return
	}
	var req putRequest
	if !readJSON(w, r, &req) {
		return
	}
	if req.Content == nil {
		fail(w, http.StatusBadRequest, errors.New(`the body needs "content"`))
		return
	}
	content := []byte(*req.Content)
	if len(content) > MaxFileBytes {
		fail(w, http.StatusRequestEntityTooLarge, fmt.Errorf("the content is larger than %d KiB", MaxFileBytes>>10))
		return
	}
	// The check and the write are not atomic; the hash guards against an
	// editor tab that is out of date, not against concurrent writers.
	s.fileMu.Lock()
	defer s.fileMu.Unlock()
	if req.BaseHash != "" {
		cur, err := s.readFile(p)
		switch {
		case statusOf(err) == http.StatusNotFound:
			writeJSON(w, http.StatusConflict, errorBody{Error: fmt.Sprintf("%s was deleted since it was loaded", p)})
			return
		case err != nil:
			fail(w, statusOf(err), err)
			return
		case hashContent(cur) != req.BaseHash:
			writeJSON(w, http.StatusConflict, errorBody{
				Error: fmt.Sprintf("%s changed since it was loaded; reload it or save under another name", p),
				Hash:  hashContent(cur),
			})
			return
		}
	}
	if err := s.writeFile(p, content, false); err != nil {
		fail(w, statusOf(err), err)
		return
	}
	writeJSON(w, http.StatusOK, fileResponse{Path: p, Hash: hashContent(content)})
}

func (s *Server) deleteFile(w http.ResponseWriter, r *http.Request) {
	if err := s.removeFile(r.URL.Query().Get("path")); err != nil {
		fail(w, statusOf(err), err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// problem is one validation error for the editor.
type problem struct {
	Line    int    `json:"line"`
	Column  int    `json:"column,omitempty"`
	Field   string `json:"field,omitempty"`
	Message string `json:"message"`
}

// String formats the problem as "line N: field: message".
func (p problem) String() string {
	var b strings.Builder
	if p.Line > 0 {
		fmt.Fprintf(&b, "line %d: ", p.Line)
	}
	if p.Field != "" {
		b.WriteString(p.Field + ": ")
	}
	b.WriteString(p.Message)
	return b.String()
}

// problemOf converts a FieldError.
func problemOf(fe *scenario.FieldError) problem {
	return problem{Line: fe.Line, Field: fe.Field, Message: fe.Msg}
}

// problemsOf converts the joined errors of Parse or Validate.
func problemsOf(err error) []problem {
	var out []problem
	for _, e := range unjoin(err) {
		var fe *scenario.FieldError
		if errors.As(e, &fe) {
			out = append(out, problemOf(fe))
			continue
		}
		out = append(out, problem{Message: e.Error()})
	}
	return out
}

// celPosRE finds the position in a CEL error: "<input>:1:5: ...".
var celPosRE = regexp.MustCompile(`<input>:(\d+):(\d+):`)

// validateScenario runs Validate and compiles the invariant, the checks the
// runner makes before the first request.
func validateScenario(s *scenario.Scenario) []problem {
	var out []problem
	if err := s.Validate(); err != nil {
		out = problemsOf(err)
	}
	invLine := s.InvariantLine
	if invLine == 0 {
		invLine = s.Line("check")
	}
	switch {
	case s.Check == nil || strings.TrimSpace(s.Check.Invariant) == "":
		if !slices.ContainsFunc(out, func(p problem) bool { return p.Field == "check.invariant" || p.Field == "check" }) {
			out = append(out, problem{Line: invLine, Field: "check.invariant", Message: "required: the rule that must hold after the race, as a CEL expression"})
		}
	case slices.ContainsFunc(out, func(p problem) bool { return p.Field == "check.invariant" }):
		// Validate already rejected it (the importer placeholder).
	default:
		if _, err := check.Compile(s.Check.Invariant); err != nil {
			out = append(out, problem{Line: invLine, Field: "check.invariant", Message: err.Error()})
		}
	}
	return out
}

// summary is the parsed overview of a scenario shown next to the editor.
type summary struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Target      string      `json:"target"`
	Engine      engine.Kind `json:"engine"`
	Copies      int         `json:"copies"`
	Trials      int         `json:"trials"`
	Invariant   string      `json:"invariant"`
	Explain     string      `json:"explain,omitempty"`
	Scope       scopeJSON   `json:"scope"`
	// Insecure is tls.insecure of the scenario.
	Insecure bool `json:"insecure"`
}

// scopeJSON is the scope of a summary.
type scopeJSON struct {
	AllowHosts []string `json:"allowHosts"`
	Requests   int      `json:"requests"`
	RPS        float64  `json:"rps"`
}

// summarize returns the overview of a parsed scenario.
func summarize(s *scenario.Scenario) *summary {
	sum := &summary{
		Name:        s.Name,
		Description: strings.TrimSpace(s.Description),
		Target:      s.Target,
		Engine:      s.Race.EngineKind(),
		Copies:      s.Race.TotalCopies(),
		Trials:      s.TrialCount(),
		Insecure:    s.TLS.Insecure,
		Scope: scopeJSON{
			AllowHosts: append([]string{}, s.Scope.AllowHosts...),
			Requests:   s.Scope.Budget.RequestLimit(),
			RPS:        s.Scope.Budget.RateLimit(),
		},
	}
	if s.Check != nil {
		sum.Invariant = strings.TrimSpace(s.Check.Invariant)
		sum.Explain = strings.TrimSpace(s.Check.Explain)
	}
	return sum
}

// validateRequest is the body of POST /api/scenarios/validate.
type validateRequest struct {
	Content string `json:"content"`
	Path    string `json:"path"`
}

// validateResponse is the answer of POST /api/scenarios/validate.
type validateResponse struct {
	Valid    bool      `json:"valid"`
	Errors   []problem `json:"errors"`
	Scenario *summary  `json:"scenario,omitempty"`
}

func (s *Server) validate(w http.ResponseWriter, r *http.Request) {
	var req validateRequest
	if !readJSON(w, r, &req) {
		return
	}
	if len(req.Content) > MaxFileBytes {
		fail(w, http.StatusRequestEntityTooLarge, fmt.Errorf("the content is larger than %d KiB", MaxFileBytes>>10))
		return
	}
	if req.Path != "" {
		if _, err := cleanPath(req.Path); err != nil {
			fail(w, statusOf(err), err)
			return
		}
	}
	writeJSON(w, http.StatusOK, validateContent([]byte(req.Content), req.Path))
}

// validateContent parses, validates and compiles a scenario document.
func validateContent(data []byte, p string) validateResponse {
	resp := validateResponse{Errors: []problem{}}
	sc, err := scenario.Parse(data, p)
	if err != nil {
		resp.Errors = problemsOf(err)
		return resp
	}
	resp.Scenario = summarize(sc)
	problems := validateScenario(sc)
	for i := range problems {
		if problems[i].Field == "check.invariant" && problems[i].Column == 0 {
			problems[i].Column = invariantErrorColumn(data, sc, problems[i].Message)
		}
	}
	resp.Errors = append(resp.Errors, problems...)
	resp.Valid = len(resp.Errors) == 0
	return resp
}

// invariantErrorColumn returns the 1-based column of a CEL error in a
// one-line invariant written on the same line as its key, or 0 when it
// cannot be placed exactly (block scalars, quoted strings with escapes).
func invariantErrorColumn(data []byte, sc *scenario.Scenario, msg string) int {
	m := celPosRE.FindStringSubmatch(msg)
	if m == nil || sc.Check == nil || sc.InvariantLine == 0 || strings.Contains(sc.Check.Invariant, "\n") {
		return 0
	}
	if m[1] != "1" {
		return 0
	}
	col, _ := strconv.Atoi(m[2]) // 1-based in CEL messages
	lines := bytes.Split(data, []byte("\n"))
	if sc.InvariantLine > len(lines) {
		return 0
	}
	line := string(lines[sc.InvariantLine-1])
	i := strings.Index(line, sc.Check.Invariant)
	if i < 0 {
		return 0
	}
	return i + col
}

// importRequest is the body of POST /api/import.
type importBody struct {
	Kind     string `json:"kind"`
	Content  string `json:"content"`
	HAREntry int    `json:"harEntry"`
}

// harEntry describes one request of a HAR file, for choosing the entry.
type harEntry struct {
	Index  int    `json:"index"`
	Method string `json:"method"`
	URL    string `json:"url"`
}

// importResponse is the answer of POST /api/import.
type importResponse struct {
	// Content is the generated scenario YAML.
	Content string `json:"content"`
	// Todo lists what the skeleton still needs before it runs.
	Todo []string `json:"todo"`
	// Kind is the detected input: "burp" (a raw HTTP request) or "har".
	Kind string `json:"kind"`
	// Entries lists the requests of a HAR file.
	Entries []harEntry `json:"entries,omitempty"`
	// Name is the scenario name, a suggestion for the file name.
	Name string `json:"name"`
}

func (s *Server) importRequest(w http.ResponseWriter, r *http.Request) {
	var req importBody
	if !readJSON(w, r, &req) {
		return
	}
	data := []byte(req.Content)
	if len(bytes.TrimSpace(data)) == 0 {
		fail(w, http.StatusBadRequest, errors.New("paste a raw HTTP request or a HAR file"))
		return
	}
	if req.HAREntry < 0 {
		fail(w, http.StatusBadRequest, fmt.Errorf("harEntry must not be negative, got %d", req.HAREntry))
		return
	}
	kind := req.Kind
	switch kind {
	case "", "auto":
		kind = "burp"
		if _, ok := harEntryList(data); ok {
			kind = "har"
		}
	case "burp", "har":
	default:
		fail(w, http.StatusBadRequest, fmt.Errorf(`kind must be "burp", "har" or "auto", got %q`, req.Kind))
		return
	}
	resp := importResponse{Kind: kind}
	var sc *scenario.Scenario
	var err error
	if kind == "har" {
		entries, ok := harEntryList(data)
		if !ok {
			fail(w, http.StatusUnprocessableEntity, errors.New("not a HAR file: expected JSON with log.entries"))
			return
		}
		resp.Entries = entries
		sc, err = scenario.ImportHAR(data, req.HAREntry)
	} else {
		sc, err = scenario.ImportBurp(data)
	}
	if err != nil {
		fail(w, http.StatusUnprocessableEntity, fmt.Errorf("import: %w", err))
		return
	}
	out, err := scenario.Marshal(sc)
	if err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	resp.Content, resp.Name, resp.Todo = string(out), sc.Name, importTodo(out)
	writeJSON(w, http.StatusOK, resp)
}

// harEntryList returns the requests of a HAR document, and false when data
// is not one.
func harEntryList(data []byte) ([]harEntry, bool) {
	trimmed := bytes.TrimSpace(bytes.TrimPrefix(data, []byte("\xef\xbb\xbf")))
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, false
	}
	var doc struct {
		Log *struct {
			Entries []struct {
				Request struct {
					Method string `json:"method"`
					URL    string `json:"url"`
				} `json:"request"`
			} `json:"entries"`
		} `json:"log"`
	}
	if err := json.Unmarshal(trimmed, &doc); err != nil || doc.Log == nil || doc.Log.Entries == nil {
		return nil, false
	}
	out := make([]harEntry, len(doc.Log.Entries))
	for i, e := range doc.Log.Entries {
		out[i] = harEntry{Index: i, Method: e.Request.Method, URL: e.Request.URL}
	}
	return out, true
}

// credentialHeader matches YAML lines that carry a header which usually holds
// a credential.
var credentialHeader = regexp.MustCompile(`(?im)^[\s"'-]*(authorization|proxy-authorization|cookie|x-api-key|x-auth-token)\s*["']?\s*:`)

// importTodo lists what an imported skeleton still needs, as the import
// command prints it.
func importTodo(out []byte) []string {
	todo := []string{
		"write the check: a check request and check.invariant (the placeholder fails validation on purpose)",
		"review scope.allow_hosts and set scope.budget (defaults: 1000 requests per run, 20 rps outside the race)",
		"add setup steps that create fresh state for every trial, and reset steps if needed",
	}
	var found []string
	for _, m := range credentialHeader.FindAllSubmatch(out, -1) {
		h := strings.ToLower(string(m[1]))
		if !slices.Contains(found, h) {
			found = append(found, h)
		}
	}
	if len(found) > 0 {
		todo = append(todo, fmt.Sprintf("the request carries %s: move the values to identities with ${env:NAME} before sharing the file",
			strings.Join(found, ", ")))
	}
	if bytes.Contains(out, []byte(`{{"{{"}}`)) || bytes.Contains(out, []byte(`{{"${env:"}}`)) {
		todo = append(todo, `the request contains "{{" or "${env:"; they are written as the literals {{"{{"}} and {{"${env:"}} so that they are sent as captured`)
	}
	return todo
}
