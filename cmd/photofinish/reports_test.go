package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TroubieD3v/photofinish/internal/check"
	"github.com/TroubieD3v/photofinish/internal/engine"
	"github.com/TroubieD3v/photofinish/internal/runner"
)

// fixtureVerdicts maps the first word of a fixture file name to its verdict:
// "violated-2.yaml" is a VIOLATED scenario named violated-2.
var fixtureVerdicts = map[string]runner.Verdict{
	"held":         runner.Held,
	"violated":     runner.Violated,
	"inconclusive": runner.Inconclusive,
	"error":        runner.Errored,
}

// fixtureReport returns a fixed report for file, whose verdict comes from
// the file name (see fixtureVerdicts).
func fixtureReport(file string) *runner.Report {
	name := strings.TrimSuffix(filepath.Base(file), filepath.Ext(file))
	word, _, _ := strings.Cut(name, "-")
	v, ok := fixtureVerdicts[word]
	if !ok {
		panic("fixture file name must start with a verdict: " + file)
	}
	start := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
	rep := &runner.Report{
		Schema:     runner.Schema,
		Tool:       "photofinish 0.0.0-test",
		Scenario:   name,
		File:       file,
		Target:     "https://127.0.0.1:8443/vuln/api",
		Engine:     engine.H2,
		Copies:     2,
		Invariant:  "size(check.json.discounts) <= 1",
		Verdict:    v,
		StartedAt:  start,
		FinishedAt: start.Add(2 * time.Second),
		Reproduce:  "photofinish run " + file + " --engine h2 --trials 2 --copies 2",
	}
	pass, fail := true, false
	race := func() *engine.Race {
		return &engine.Race{
			Kind: engine.H2, Target: "https://127.0.0.1:8443", ALPN: "h2", Connections: 1,
			Release: engine.Release{Writes: 1, Bytes: 18},
			Results: []engine.Result{
				{Index: 0, Stream: 1, Proto: "HTTP/2.0", Status: 200, PreSentNs: 1000, ReleasedNs: 5000, FirstByteNs: 400000, DoneNs: 410000},
				{Index: 1, Stream: 3, Proto: "HTTP/2.0", Status: 200, PreSentNs: 1200, ReleasedNs: 5000, FirstByteNs: 520000, DoneNs: 530000},
			},
			StartedNs: 0, FinishedNs: 600000,
		}
	}
	checkStep := &runner.StepRecord{Method: "GET", URL: "https://127.0.0.1:8443/vuln/api/carts/1", Status: 200, Body: `{"discounts":[1,2]}`}
	held := runner.Trial{Verdict: runner.Held, Race: race(), Check: checkStep,
		Terms: []check.Term{{Expr: "size(check.json.discounts) <= 1", Value: "1 <= 1", Pass: &pass}}}
	switch v {
	case runner.Held:
		rep.Summary = "the rule held in 2 of 2 trials"
		rep.Trials = []runner.Trial{held, held}
		rep.Stats = runner.Stats{Planned: 2, Ran: 2, Held: 2, RequestsSpent: 8}
	case runner.Violated:
		rep.Summary = "1 of 2 trials broke the rule"
		rep.Trials = []runner.Trial{{Verdict: runner.Violated, Race: race(), Check: checkStep,
			Reasons: []string{"size(check.json.discounts) <= 1 was 2 <= 1"},
			Terms:   []check.Term{{Expr: "size(check.json.discounts) <= 1", Value: "2 <= 1", Pass: &fail}}}, held}
		rep.Stats = runner.Stats{Planned: 2, Ran: 2, Violated: 1, Held: 1, RequestsSpent: 8}
	case runner.Inconclusive:
		rep.Summary = "2 of 2 trials could not be judged"
		t := runner.Trial{Verdict: runner.Inconclusive, Race: race(), Reasons: []string{"the race was rate limited (429)"}}
		rep.Trials = []runner.Trial{t, t}
		rep.Stats = runner.Stats{Planned: 2, Ran: 2, Inconclusive: 2, RequestsSpent: 6}
	case runner.Errored:
		rep.Summary = "scope: host 127.0.0.2 is not in scope.allow_hosts"
		rep.Trials = []runner.Trial{}
	}
	for i := range rep.Trials {
		rep.Trials[i].Number = i + 1
	}
	return rep
}

// fakeRunner makes the run command use fixtureReport instead of running
// scenarios and returns the files it was asked to run.
func fakeRunner(t *testing.T) *[]string {
	t.Helper()
	var calls []string
	prev := runScenario
	runScenario = func(_ context.Context, file string, _ runOptions, _, _ io.Writer) *runner.Report {
		calls = append(calls, file)
		return fixtureReport(file)
	}
	t.Cleanup(func() { runScenario = prev })
	return &calls
}

// runCLI runs the CLI and returns the exit code and both streams.
func runCLI(args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestFailOnExitCode(t *testing.T) {
	const (
		h = runner.Held
		v = runner.Violated
		i = runner.Inconclusive
		e = runner.Errored
	)
	cases := []struct {
		verdicts                      []runner.Verdict
		violated, inconclusive, never int
	}{
		{[]runner.Verdict{h}, 0, 0, 0},
		{[]runner.Verdict{h, h}, 0, 0, 0},
		{[]runner.Verdict{v}, 1, 1, 0},
		{[]runner.Verdict{i}, 2, 2, 0},
		{[]runner.Verdict{h, i}, 2, 2, 0},
		{[]runner.Verdict{i, v, h}, 1, 1, 0},
		{[]runner.Verdict{e}, 3, 3, 3},
		{[]runner.Verdict{v, e}, 3, 3, 3},
		{[]runner.Verdict{h, i, e}, 3, 3, 3},
	}
	for _, c := range cases {
		for failOn, want := range map[string]int{"violated": c.violated, "inconclusive": c.inconclusive, "never": c.never} {
			if got := failOnExitCode(c.verdicts, failOn); got != want {
				t.Errorf("failOnExitCode(%v, %s) = %d, want %d", c.verdicts, failOn, got, want)
			}
		}
		// The default keeps the exit codes of earlier versions.
		if got, want := failOnExitCode(c.verdicts, failOnViolated), combinedExitCode(c.verdicts); got != want {
			t.Errorf("default fail-on for %v: %d, combinedExitCode %d", c.verdicts, got, want)
		}
	}
}

// TestRunFailOn checks the exit code of the run command for every --fail-on
// value and verdict mix, in text mode and with a document format.
func TestRunFailOn(t *testing.T) {
	fakeRunner(t)
	cases := []struct {
		files []string
		// want is the exit code without --fail-on, then for violated,
		// inconclusive and never.
		want [4]int
	}{
		{[]string{"held.yaml"}, [4]int{0, 0, 0, 0}},
		{[]string{"held.yaml", "held-2.yaml"}, [4]int{0, 0, 0, 0}},
		{[]string{"violated.yaml"}, [4]int{1, 1, 1, 0}},
		{[]string{"inconclusive.yaml"}, [4]int{2, 2, 2, 0}},
		{[]string{"held.yaml", "inconclusive.yaml"}, [4]int{2, 2, 2, 0}},
		{[]string{"inconclusive.yaml", "violated.yaml", "held.yaml"}, [4]int{1, 1, 1, 0}},
		{[]string{"error.yaml"}, [4]int{3, 3, 3, 3}},
		{[]string{"violated.yaml", "error.yaml"}, [4]int{3, 3, 3, 3}},
		{[]string{"held.yaml", "inconclusive.yaml", "error.yaml"}, [4]int{3, 3, 3, 3}},
	}
	flags := [4][]string{nil, {"--fail-on", "violated"}, {"--fail-on", "inconclusive"}, {"--fail-on=never"}}
	for _, c := range cases {
		for k, f := range flags {
			for _, format := range []string{"text", "json"} {
				args := append([]string{"run"}, c.files...)
				args = append(args, f...)
				args = append(args, "--format", format, "--quiet")
				code, stdout, stderr := runCLI(args...)
				if code != c.want[k] {
					t.Errorf("%q: exit code %d, want %d\nstdout: %s\nstderr: %s", args[1:], code, c.want[k], stdout, stderr)
				}
			}
		}
	}
}

// TestRunFailOnTextOutputUnchanged checks that --fail-on only changes the
// exit code, not what is printed.
func TestRunFailOnTextOutputUnchanged(t *testing.T) {
	fakeRunner(t)
	_, want, _ := runCLI("run", "violated.yaml", "inconclusive.yaml")
	for _, failOn := range []string{"violated", "inconclusive", "never"} {
		_, got, _ := runCLI("run", "violated.yaml", "inconclusive.yaml", "--fail-on", failOn)
		if got != want {
			t.Errorf("--fail-on %s changed stdout:\n%s\nwant:\n%s", failOn, got, want)
		}
	}
	if !strings.Contains(want, "violated: VIOLATED") || !strings.Contains(want, "inconclusive: INCONCLUSIVE") {
		t.Errorf("stdout:\n%s", want)
	}
}

// sarifLog holds the parts of a SARIF log the CLI is responsible for.
type sarifLog struct {
	Version string `json:"version"`
	Runs    []struct {
		OriginalURIBaseIDs map[string]struct {
			URI string `json:"uri"`
		} `json:"originalUriBaseIds"`
		Results []struct {
			RuleID    string `json:"ruleId"`
			Level     string `json:"level"`
			Locations []struct {
				PhysicalLocation struct {
					ArtifactLocation struct {
						URI       string `json:"uri"`
						URIBaseID string `json:"uriBaseId"`
					} `json:"artifactLocation"`
				} `json:"physicalLocation"`
			} `json:"locations"`
		} `json:"results"`
	} `json:"runs"`
}

func parseSARIF(t *testing.T, data []byte) sarifLog {
	t.Helper()
	var l sarifLog
	if err := json.Unmarshal(data, &l); err != nil {
		t.Fatalf("not a SARIF document: %v\n%s", err, data)
	}
	if l.Version != "2.1.0" || len(l.Runs) != 1 {
		t.Fatalf("SARIF version %q with %d runs", l.Version, len(l.Runs))
	}
	return l
}

// junitDoc holds the parts of a JUnit document the CLI is responsible for.
type junitDoc struct {
	XMLName xml.Name `xml:"testsuites"`
	Suites  []struct {
		Name string `xml:"name,attr"`
	} `xml:"testsuite"`
}

func parseJUnit(t *testing.T, data []byte) []string {
	t.Helper()
	var d junitDoc
	if err := xml.Unmarshal(data, &d); err != nil {
		t.Fatalf("not a JUnit document: %v\n%s", err, data)
	}
	var names []string
	for _, s := range d.Suites {
		names = append(names, s.Name)
	}
	return names
}

// sarifBaseDir returns the local path of the %SRCROOT% base URI.
func sarifBaseDir(t *testing.T, l sarifLog) string {
	t.Helper()
	base, ok := l.Runs[0].OriginalURIBaseIDs["%SRCROOT%"]
	if !ok {
		t.Fatal("SARIF run has no %SRCROOT% base")
	}
	p := strings.TrimPrefix(base.URI, "file://")
	if u, err := url.Parse(base.URI); err == nil {
		p = u.Path
	}
	if runtime.GOOS == "windows" {
		p = strings.TrimPrefix(p, "/") // /C:/dir -> C:/dir
	}
	return p
}

// equalPath compares two slash-separated directory paths, ignoring case on
// Windows and a trailing slash.
func equalPath(a, b string) bool {
	a, b = strings.TrimSuffix(a, "/"), strings.TrimSuffix(b, "/")
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// TestRunDocumentFormats checks every --format other than text: stdout holds
// exactly one document covering all scenarios in file order, and the text
// summary is not printed.
func TestRunDocumentFormats(t *testing.T) {
	calls := fakeRunner(t)
	dir := t.TempDir()
	t.Chdir(dir)
	files := []string{"scenarios/violated.yaml", "scenarios/held.yaml", "scenarios/inconclusive.yaml", "scenarios/error.yaml"}
	names := []string{"violated", "held", "inconclusive", "error"}

	for _, format := range []string{"json", "sarif", "junit", "html"} {
		t.Run(format, func(t *testing.T) {
			*calls = nil
			args := append([]string{"run"}, files...)
			code, stdout, stderr := runCLI(append(args, "--format", format, "--quiet")...)
			if code != 3 {
				t.Errorf("exit code %d, want 3 (one scenario ERROR)", code)
			}
			if stderr != "" {
				t.Errorf("unexpected stderr:\n%s", stderr)
			}
			if !slices.Equal(*calls, files) {
				t.Errorf("ran %q, want %q", *calls, files)
			}
			if strings.Contains(stdout, "violated: VIOLATED") {
				t.Errorf("the text summary is printed with --format %s:\n%s", format, stdout)
			}
			switch format {
			case "json":
				var reps []runner.Report
				dec := json.NewDecoder(strings.NewReader(stdout))
				if err := dec.Decode(&reps); err != nil {
					t.Fatalf("stdout is not a JSON array of reports: %v\n%s", err, stdout)
				}
				if dec.More() {
					t.Error("stdout holds more than one JSON document")
				}
				var got []string
				for _, r := range reps {
					got = append(got, r.Scenario)
				}
				if !slices.Equal(got, names) {
					t.Errorf("reports %q, want %q", got, names)
				}
			case "sarif":
				l := parseSARIF(t, []byte(stdout))
				var rules, uris []string
				for _, r := range l.Runs[0].Results {
					rules = append(rules, r.RuleID+"/"+r.Level)
					for _, loc := range r.Locations {
						uris = append(uris, loc.PhysicalLocation.ArtifactLocation.URI)
					}
				}
				if want := []string{"PF001/error", "PF002/warning"}; !slices.Equal(rules, want) {
					t.Errorf("results %q, want %q", rules, want)
				}
				// The base directory is the current directory, so the
				// locations are the paths given on the command line.
				if want := []string{"scenarios/violated.yaml", "scenarios/inconclusive.yaml"}; !slices.Equal(uris, want) {
					t.Errorf("locations %q, want %q", uris, want)
				}
				cwd, err := os.Getwd()
				if err != nil {
					t.Fatal(err)
				}
				if got := sarifBaseDir(t, l); !equalPath(got, filepath.ToSlash(cwd)) {
					t.Errorf("SARIF base directory %q, want the current directory %q", got, filepath.ToSlash(cwd))
				}
			case "junit":
				if got := parseJUnit(t, []byte(stdout)); !slices.Equal(got, names) {
					t.Errorf("test suites %q, want %q", got, names)
				}
			case "html":
				if !strings.Contains(strings.ToLower(stdout), "<html") {
					t.Errorf("stdout is not an HTML page:\n%.300s", stdout)
				}
				last := -1
				for _, n := range names {
					i := strings.Index(stdout, n)
					if i < 0 {
						t.Errorf("the page does not mention %s", n)
					}
					if i < last {
						t.Errorf("%s is not in file order", n)
					}
					last = i
				}
			}
		})
	}
}

// TestRunDocumentFormatProgressOnStderr checks that without --quiet the
// progress goes to stderr, so that stdout stays one document.
func TestRunDocumentFormatProgressOnStderr(t *testing.T) {
	addr := startShop(t, 0)
	fixed := writeExample(t, t.TempDir(), "coupon-fixed.yaml", addr)
	code, stdout, stderr := runCLI("run", fixed, "--trials", "2", "--format", "junit")
	if code != 0 {
		t.Errorf("exit code %d, want 0\nstderr: %s", code, stderr)
	}
	if got := parseJUnit(t, []byte(stdout)); !slices.Equal(got, []string{"coupon-fixed"}) {
		t.Errorf("test suites %q", got)
	}
	for _, want := range []string{"run " + fixed + "\n", "trial 1/2: HELD", fixed + ": HELD\n"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr does not contain %q:\n%s", want, stderr)
		}
	}
}

// TestRunDocumentFormatErrorOnStderr checks that a scenario that cannot be
// loaded is named on stderr with its error, not only inside the document.
func TestRunDocumentFormatErrorOnStderr(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.yaml")
	code, stdout, stderr := runCLI("run", missing, "--format", "sarif")
	if code != 3 {
		t.Errorf("exit code %d, want 3\nstderr: %s", code, stderr)
	}
	if !strings.Contains(stdout, `"toolExecutionNotifications"`) {
		t.Errorf("stdout has no notification:\n%s", stdout)
	}
	if !strings.Contains(stderr, missing+": ERROR\n  open ") {
		t.Errorf("stderr does not name the error:\n%s", stderr)
	}
}

// TestRunOutputFile checks that --output FILE receives the document that
// stdout would get, replacing any previous content, and stdout stays empty.
func TestRunOutputFile(t *testing.T) {
	fakeRunner(t)
	dir := t.TempDir()
	t.Chdir(dir)
	for _, format := range []string{"json", "sarif", "junit", "html"} {
		t.Run(format, func(t *testing.T) {
			_, want, _ := runCLI("run", "violated.yaml", "held.yaml", "--format", format)
			output := filepath.Join(dir, "result."+format)
			if err := os.WriteFile(output, bytes.Repeat([]byte("stale "), 50000), 0o644); err != nil {
				t.Fatal(err)
			}
			code, stdout, stderr := runCLI("run", "violated.yaml", "held.yaml", "--format", format, "--output", output)
			if code != 1 {
				t.Errorf("exit code %d, want 1\nstderr: %s", code, stderr)
			}
			if stdout != "" || stderr != "" {
				t.Errorf("unexpected output\nstdout: %s\nstderr: %s", stdout, stderr)
			}
			got, err := os.ReadFile(output)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != want {
				t.Errorf("--output differs from stdout:\n%.500s\nwant:\n%.500s", got, want)
			}
		})
	}
}

// TestRunOutputSingleFileJSON checks that one scenario file gives one JSON
// object, in --output as on stdout.
func TestRunOutputSingleFileJSON(t *testing.T) {
	fakeRunner(t)
	output := filepath.Join(t.TempDir(), "r.json")
	if code, _, stderr := runCLI("run", "violated.yaml", "--format", "json", "--output", output, "--fail-on", "never"); code != 0 {
		t.Errorf("exit code %d, want 0\nstderr: %s", code, stderr)
	}
	rep := readReport(t, output)
	if rep.Scenario != "violated" || rep.Verdict != runner.Violated {
		t.Errorf("report: scenario %q, verdict %s", rep.Scenario, rep.Verdict)
	}
}

func TestRenderJSONKeepsArrayForSeveralFiles(t *testing.T) {
	reps := []*runner.Report{fixtureReport("held.yaml")}
	var b bytes.Buffer
	if err := renderReports(&b, formatJSON, reps, 2); err != nil {
		t.Fatal(err)
	}
	var arr []runner.Report
	if err := json.Unmarshal(b.Bytes(), &arr); err != nil || len(arr) != 1 {
		t.Errorf("an interrupted run of two files must still print an array: %v\n%s", err, b.String())
	}
	b.Reset()
	if err := renderReports(&b, formatJSON, reps, 1); err != nil {
		t.Fatal(err)
	}
	var obj runner.Report
	if err := json.Unmarshal(b.Bytes(), &obj); err != nil || obj.Scenario != "held" {
		t.Errorf("one file must print one object: %v\n%s", err, b.String())
	}
}

// checkOutDir checks the reports that --out wrote for the given scenarios.
func checkOutDir(t *testing.T, dir string, names ...string) {
	t.Helper()
	for _, n := range names {
		if rep := readReport(t, filepath.Join(dir, n+".json")); rep.Scenario != n {
			t.Errorf("%s.json: scenario %q", n, rep.Scenario)
		}
	}
	data, err := os.ReadFile(filepath.Join(dir, "results.sarif"))
	if err != nil {
		t.Fatal(err)
	}
	parseSARIF(t, data)
	if data, err = os.ReadFile(filepath.Join(dir, "junit.xml")); err != nil {
		t.Fatal(err)
	}
	if got := parseJUnit(t, data); !slices.Equal(got, names) {
		t.Errorf("junit.xml: test suites %q, want %q", got, names)
	}
	if data, err = os.ReadFile(filepath.Join(dir, "report.html")); err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		if !strings.Contains(string(data), n) {
			t.Errorf("report.html does not mention %s", n)
		}
	}
}

// TestRunOutDir checks that --out writes the JSON report of every scenario
// and the HTML, SARIF and JUnit reports of all of them, in every format.
func TestRunOutDir(t *testing.T) {
	fakeRunner(t)
	t.Run("text", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "reports")
		code, stdout, stderr := runCLI("run", "violated.yaml", "held.yaml", "--out", out)
		if code != 1 {
			t.Errorf("exit code %d, want 1\nstderr: %s", code, stderr)
		}
		for _, want := range []string{
			"report     " + filepath.Join(out, "violated.json") + "\n",
			"report     " + filepath.Join(out, "held.json") + "\n",
			"\nreports    " + filepath.Join(out, "report.html") + ", " + filepath.Join(out, "results.sarif") + ", " + filepath.Join(out, "junit.xml") + "\n",
		} {
			if !strings.Contains(stdout, want) {
				t.Errorf("stdout does not contain %q:\n%s", want, stdout)
			}
		}
		checkOutDir(t, out, "violated", "held")
	})
	t.Run("json to stdout", func(t *testing.T) {
		out := t.TempDir()
		code, stdout, _ := runCLI("run", "held.yaml", "inconclusive.yaml", "--out", out, "--format", "json")
		if code != 2 {
			t.Errorf("exit code %d, want 2", code)
		}
		var reps []runner.Report
		if err := json.Unmarshal([]byte(stdout), &reps); err != nil || len(reps) != 2 {
			t.Errorf("stdout is not the JSON array of both reports: %v\n%s", err, stdout)
		}
		checkOutDir(t, out, "held", "inconclusive")
	})
	t.Run("sarif to the same file", func(t *testing.T) {
		out := t.TempDir()
		output := filepath.Join(out, "results.sarif")
		code, stdout, stderr := runCLI("run", "violated.yaml", "--out", out, "--format", "sarif", "--output", output)
		if code != 1 || stdout != "" {
			t.Errorf("exit code %d, want 1\nstdout: %s\nstderr: %s", code, stdout, stderr)
		}
		checkOutDir(t, out, "violated")
	})
}

// TestRunReportWriteErrors checks that a report that cannot be written makes
// the run exit 3, whatever --fail-on says.
func TestRunReportWriteErrors(t *testing.T) {
	calls := fakeRunner(t)

	t.Run("out file is a directory", func(t *testing.T) {
		out := t.TempDir()
		if err := os.Mkdir(filepath.Join(out, "report.html"), 0o755); err != nil {
			t.Fatal(err)
		}
		code, _, stderr := runCLI("run", "held.yaml", "--out", out, "--fail-on", "never", "--quiet")
		if code != 3 {
			t.Errorf("exit code %d, want 3", code)
		}
		if !strings.Contains(stderr, "report.html") {
			t.Errorf("stderr does not name the file:\n%s", stderr)
		}
		// The other reports are still written.
		for _, name := range []string{"held.json", "results.sarif", "junit.xml"} {
			if _, err := os.Stat(filepath.Join(out, name)); err != nil {
				t.Error(err)
			}
		}
	})

	t.Run("output directory missing", func(t *testing.T) {
		*calls = nil
		output := filepath.Join(t.TempDir(), "missing", "r.sarif")
		code, stdout, stderr := runCLI("run", "held.yaml", "--format", "sarif", "--output", output, "--fail-on", "never")
		if code != 3 {
			t.Errorf("exit code %d, want 3", code)
		}
		if !strings.HasPrefix(stderr, "error: ") || stdout != "" {
			t.Errorf("stdout: %s\nstderr: %s", stdout, stderr)
		}
		if len(*calls) != 0 {
			t.Errorf("scenarios ran although --output cannot be written: %q", *calls)
		}
	})
}

// TestRunOutputCollisions checks the usage errors for an --output FILE that
// would overwrite a scenario or another report of --out DIR.
func TestRunOutputCollisions(t *testing.T) {
	calls := fakeRunner(t)
	dir := t.TempDir()
	scenarioFile := filepath.Join(dir, "held.yaml")
	if err := os.WriteFile(scenarioFile, []byte("version: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		args   []string
		stderr string
	}{
		{"scenario file", []string{"run", scenarioFile, "--format", "json", "--output", scenarioFile}, "would overwrite the scenario file"},
		{"scenario file, another spelling", []string{"run", scenarioFile, "--format", "json", "--output", filepath.Join(dir, ".", "held.yaml")}, "would overwrite the scenario file"},
		{"html report of --out", []string{"run", scenarioFile, "--out", dir, "--format", "sarif", "--output", filepath.Join(dir, "report.html")}, "is the html report that --out"},
		{"junit report of --out", []string{"run", scenarioFile, "--out", dir, "--format", "json", "--output", filepath.Join(dir, "junit.xml")}, "is the junit report that --out"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			*calls = nil
			code, stdout, stderr := runCLI(c.args...)
			if code != exitUsage {
				t.Errorf("exit code %d, want %d", code, exitUsage)
			}
			if !strings.Contains(stderr, c.stderr) || stdout != "" {
				t.Errorf("stdout: %s\nstderr does not contain %q: %s", stdout, c.stderr, stderr)
			}
			if len(*calls) != 0 {
				t.Errorf("scenarios ran: %q", *calls)
			}
		})
	}
	data, err := os.ReadFile(scenarioFile)
	if err != nil || string(data) != "version: 1\n" {
		t.Errorf("the scenario file changed: %q, %v", data, err)
	}
}

func TestRunHelpDocumentsReports(t *testing.T) {
	code, _, stderr := runCLI("run", "-h")
	if code != exitOK {
		t.Errorf("exit code %d", code)
	}
	for _, want := range []string{
		"--format text|json|sarif|junit|html", "--output FILE", "--fail-on violated|inconclusive|never",
		"DIR/report.html, DIR/results.sarif and DIR/junit.xml", "PF001", "PF002",
		"never         0 whatever the verdicts, unless a scenario is ERROR (3)", "Usage errors exit 64",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("run -h does not contain %q:\n%s", want, stderr)
		}
	}
	code, stdout, _ := runCLI("help")
	if code != exitOK || !strings.Contains(stdout, "[--fail-on violated|inconclusive|never]") || !strings.Contains(stdout, "--format text|json|sarif|junit|html") {
		t.Errorf("help does not list the report flags:\n%s", stdout)
	}
}

// TestRunCommandReports runs the coupon examples against the demo shop with
// every report written: SARIF to --output, everything else to --out.
func TestRunCommandReports(t *testing.T) {
	addr := startShop(t, 2*time.Millisecond)
	dir := t.TempDir()
	writeExample(t, dir, "coupon-vuln.yaml", addr)
	writeExample(t, dir, "coupon-fixed.yaml", addr)
	t.Chdir(dir) // after writeExample, which reads ../../examples

	code, stdout, stderr := runCLI("run", "coupon-vuln.yaml", "coupon-fixed.yaml", "--engine", "h2", "--trials", "5",
		"--format", "sarif", "--output", "vuln.sarif", "--out", "reports")
	if code != 1 {
		t.Fatalf("exit code %d, want 1\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}
	if stdout != "" {
		t.Errorf("stdout is not empty with --output:\n%s", stdout)
	}
	data, err := os.ReadFile("vuln.sarif")
	if err != nil {
		t.Fatal(err)
	}
	l := parseSARIF(t, data)
	if res := l.Runs[0].Results; len(res) != 1 || res[0].RuleID != "PF001" || res[0].Level != "error" ||
		len(res[0].Locations) != 1 || res[0].Locations[0].PhysicalLocation.ArtifactLocation.URI != "coupon-vuln.yaml" {
		t.Errorf("SARIF results: %+v", res)
	}
	checkOutDir(t, "reports", "coupon-vuln", "coupon-fixed")
	html, err := os.ReadFile(filepath.Join("reports", "report.html"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(html, []byte("demo-alice")) || bytes.Contains(data, []byte("demo-alice")) {
		t.Error("a report contains the unmasked token demo-alice")
	}

	// --fail-on never reports the violation but exits 0.
	if code, _, stderr := runCLI("run", "coupon-vuln.yaml", "--engine", "h2", "--trials", "2", "--fail-on", "never", "--quiet"); code != 0 {
		t.Errorf("--fail-on never: exit code %d, want 0\nstderr: %s", code, stderr)
	}
}
