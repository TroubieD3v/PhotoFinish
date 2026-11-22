package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/TroubieD3v/photofinish/internal/check"
	"github.com/TroubieD3v/photofinish/internal/engine"
	"github.com/TroubieD3v/photofinish/internal/report"
	"github.com/TroubieD3v/photofinish/internal/runner"
	"github.com/TroubieD3v/photofinish/internal/scenario"
)

const runUsage = `Usage: photofinish run <scenario.yaml>... [--engine auto|h2|h1|burst] [--trials N] [--copies N]
                                          [--insecure] [--format text|json|sarif|junit|html] [--output FILE]
                                          [--out DIR] [--fail-on violated|inconclusive|never] [--quiet]

Runs every scenario: for each trial the setup steps, the synchronized race and
the check, then evaluates the invariant. Only hosts listed in scope.allow_hosts
are contacted, within scope.budget.

Output formats. With --format text (the default) stdout gets progress lines
and a summary of every scenario. Any other format writes one document that
covers all scenarios, in file order, to stdout or to --output FILE, and
progress goes to stderr:
  json   the full report: one JSON object for one scenario file, a JSON array
         of reports for several
  sarif  SARIF 2.1.0 for code scanning: a PF001 error per VIOLATED scenario, a
         PF002 warning per INCONCLUSIVE one; scenario paths are relative to the
         current directory
  junit  JUnit XML for CI: a test suite per scenario, a test case per trial
  html   one self-contained HTML page with the evidence of every scenario

--out DIR writes DIR/<scenario-name>.json for every scenario and, covering all
of them, DIR/report.html, DIR/results.sarif and DIR/junit.xml, whatever the
format. With --out, sarif or junit the scenarios of one run need distinct
names: report files, SARIF fingerprints and JUnit suites are keyed by name.
Scenarios that an interruption (Ctrl+C) leaves unrun appear in the documents
as ERROR.

Exit code over all scenarios, depending on --fail-on:
  violated      (default) 3 if any ERROR, else 1 if any VIOLATED, else 2 if
                any INCONCLUSIVE, else 0 (every scenario HELD)
  inconclusive  the same codes: an INCONCLUSIVE scenario already exits 2
  never         0 whatever the verdicts, unless a scenario is ERROR (3)
A report that cannot be written counts as ERROR. Usage errors exit 64.

Flags:
`

// Values of --format.
const (
	formatText  = "text"
	formatJSON  = "json"
	formatSARIF = "sarif"
	formatJUnit = "junit"
	formatHTML  = "html"
)

// formats lists the values of --format.
var formats = []string{formatText, formatJSON, formatSARIF, formatJUnit, formatHTML}

// Values of --fail-on.
const (
	failOnViolated     = "violated"
	failOnInconclusive = "inconclusive"
	failOnNever        = "never"
)

// outFiles are the reports that --out DIR writes for all scenarios together,
// besides the JSON report of every scenario.
var outFiles = []struct{ name, format string }{
	{"report.html", formatHTML},
	{"results.sarif", formatSARIF},
	{"junit.xml", formatJUnit},
}

// runOptions holds the parsed flags of the run command.
type runOptions struct {
	files    []string
	engine   engine.Kind
	trials   int
	copies   int
	insecure bool
	out      string
	format   string
	output   string
	failOn   string
	quiet    bool
}

// parseRun parses and validates the run flags. Problems are reported on stderr.
func parseRun(args []string, stderr io.Writer) (runOptions, error) {
	var o runOptions
	var eng string
	fs := newFlagSet("run", runUsage, stderr)
	fs.StringVar(&eng, "engine", "", "override the scenario engine: auto, h2, h1 or burst")
	fs.IntVar(&o.trials, "trials", 0, "override the number of trials (0: the scenario's trials)")
	fs.IntVar(&o.copies, "copies", 0, "override the number of race copies, 1 to 1000 (0: the scenario's copies)")
	fs.BoolVar(&o.insecure, "insecure", false, "skip TLS certificate verification (like tls.insecure in the scenario)")
	fs.StringVar(&o.out, "out", "", "write the JSON report of every scenario to `DIR`/<scenario-name>.json, plus DIR/report.html, DIR/results.sarif and DIR/junit.xml")
	fs.StringVar(&o.format, "format", formatText, "output format: text, json, sarif, junit or html")
	fs.StringVar(&o.output, "output", "", "write the json, sarif, junit or html document to `FILE` instead of stdout")
	fs.StringVar(&o.failOn, "fail-on", failOnViolated, "verdicts that give a non-zero exit code: violated, inconclusive or never")
	fs.BoolVar(&o.quiet, "quiet", false, "no progress lines; print only the summary of every scenario")
	files, err := parseFlags(fs, args)
	if err != nil {
		return o, err
	}
	o.files = files
	switch engine.Kind(eng) {
	case "", engine.Auto, engine.H2, engine.H1, engine.Burst:
		o.engine = engine.Kind(eng)
	default:
		return o, fmt.Errorf("--engine must be auto, h2, h1 or burst, got %q", eng)
	}
	switch {
	case len(o.files) == 0:
		return o, errors.New("run needs at least one scenario file\n\n" + firstLine(runUsage))
	case o.trials < 0 || o.trials > scenario.MaxTrials:
		return o, fmt.Errorf("--trials must be between 1 and %d (0 keeps the scenario's value), got %d", scenario.MaxTrials, o.trials)
	case o.copies < 0 || o.copies > scenario.MaxCopies:
		return o, fmt.Errorf("--copies must be between 1 and %d (0 keeps the scenario's value), got %d", scenario.MaxCopies, o.copies)
	case !slices.Contains(formats, o.format):
		return o, fmt.Errorf("--format must be text, json, sarif, junit or html, got %q", o.format)
	case o.failOn != failOnViolated && o.failOn != failOnInconclusive && o.failOn != failOnNever:
		return o, fmt.Errorf("--fail-on must be violated, inconclusive or never, got %q", o.failOn)
	case o.output != "" && o.format == formatText:
		return o, errors.New("--output needs --format json, sarif, junit or html; the text summary always goes to stdout")
	}
	if o.output != "" {
		if err := checkOutput(o); err != nil {
			return o, err
		}
	}
	return o, nil
}

// checkOutput rejects an --output FILE that would overwrite a scenario file,
// or one of the --out DIR reports with a document of another format.
func checkOutput(o runOptions) error {
	for _, f := range o.files {
		if samePath(o.output, f) {
			return fmt.Errorf("--output %s would overwrite the scenario file %s", o.output, f)
		}
	}
	if o.out == "" {
		return nil
	}
	for _, of := range outFiles {
		p := filepath.Join(o.out, of.name)
		if of.format != o.format && samePath(o.output, p) {
			return fmt.Errorf("--output %s is the %s report that --out %s writes; choose another file", o.output, of.format, o.out)
		}
	}
	return nil
}

// samePath reports whether a and b name the same file: the same existing
// file, or the same absolute path (ignoring case on Windows).
func samePath(a, b string) bool {
	if fa, err := os.Stat(a); err == nil {
		if fb, err := os.Stat(b); err == nil {
			return os.SameFile(fa, fb)
		}
	}
	aa, err1 := filepath.Abs(a)
	ab, err2 := filepath.Abs(b)
	if err1 != nil || err2 != nil {
		return false
	}
	if runtime.GOOS == "windows" {
		return strings.EqualFold(aa, ab)
	}
	return aa == ab
}

// firstLine returns the first line of s.
func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}

func cmdRun(args []string, stdout, stderr io.Writer) int {
	o, err := parseRun(args, stderr)
	if code, done := flagExit(err, stderr); done {
		return code
	}
	if code, done := flagExit(checkNames(o), stderr); done {
		return code
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runScenarios(ctx, o, stdout, stderr)
}

// loadName returns the name of the scenario in file, or "" when the file
// cannot be loaded (its report is then named after the file). Tests replace
// it together with runScenario.
var loadName = func(file string) string {
	s, err := scenario.Load(file)
	if err != nil {
		return ""
	}
	return s.Name
}

// checkNames rejects, before any request, a run whose reports would collide:
// two scenarios with the same name when the run writes --out DIR (one JSON
// file per name), SARIF (fingerprints include the name) or JUnit (one suite
// per name), and an --output FILE that is the JSON report of a scenario in
// --out DIR.
func checkNames(o runOptions) error {
	if o.out == "" && o.format != formatSARIF && o.format != formatJUnit {
		return nil
	}
	seen := map[string]string{} // report file name -> scenario file
	for _, file := range o.files {
		name := reportName(&runner.Report{Scenario: loadName(file)}, file)
		key := name
		if runtime.GOOS == "windows" {
			key = strings.ToLower(name) // the file system ignores case
		}
		if prev, ok := seen[key]; ok {
			return fmt.Errorf("%s and %s are both named %s; give the scenarios distinct names "+
				"(report files, SARIF fingerprints and JUnit suites are keyed by name)",
				prev, file, strings.TrimSuffix(name, ".json"))
		}
		seen[key] = file
		if o.out != "" && o.output != "" && samePath(o.output, filepath.Join(o.out, name)) {
			return fmt.Errorf("--output %s is the JSON report of %s that --out %s writes; choose another file", o.output, file, o.out)
		}
	}
	return nil
}

// runScenario runs one scenario file; tests replace it to inject reports.
var runScenario = runOne

// runScenarios runs every scenario file in order, prints the results, writes
// the requested reports and returns the exit code for o.failOn.
func runScenarios(ctx context.Context, o runOptions, stdout, stderr io.Writer) int {
	fail := func(err error) int {
		fmt.Fprintln(stderr, "error:", err)
		return runner.ExitCode(runner.Errored)
	}
	if o.out != "" {
		if err := os.MkdirAll(o.out, 0o755); err != nil {
			return fail(err)
		}
	}
	// Open --output before the first request, so that a bad path does not
	// cost a run.
	var output *os.File
	if o.output != "" {
		f, err := os.OpenFile(o.output, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return fail(err)
		}
		defer f.Close()
		output = f
	}
	text := o.format == formatText

	var verdicts []runner.Verdict
	var reports []*runner.Report
	written := map[string]string{} // report file -> scenario file
	for i, file := range o.files {
		if ctx.Err() != nil {
			// The documents list the scenarios that did not run as ERROR,
			// so that SARIF and JUnit consumers see a failed run.
			fmt.Fprintf(stderr, "interrupted; %d of %d scenarios not run\n", len(o.files)-i, len(o.files))
			for _, f := range o.files[i:] {
				reports = append(reports, errorReport(f, errors.New("not run: the run was interrupted"), time.Now()))
				verdicts = append(verdicts, runner.Errored)
			}
			break
		}
		if text && i > 0 {
			fmt.Fprintln(stdout)
		}
		rep := runScenario(ctx, file, o, stdout, stderr)
		verdict := rep.Verdict

		var reportPath string
		if o.out != "" {
			p, err := writeReport(o.out, rep, file, written)
			if err != nil {
				fmt.Fprintf(stderr, "error: %s: %v\n", file, err)
				failReport(rep, err)
				verdict = rep.Verdict
			}
			reportPath = p
		}
		if text {
			writeSummary(stdout, rep)
			if reportPath != "" {
				fmt.Fprintf(stdout, "  report     %s\n", reportPath)
			}
		}
		reports = append(reports, rep)
		verdicts = append(verdicts, verdict)
	}

	if o.out != "" && len(reports) > 0 {
		paths, err := writeOutFiles(o.out, reports, len(o.files))
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			verdicts = append(verdicts, runner.Errored)
		}
		if text && len(paths) > 0 {
			fmt.Fprintf(stdout, "\nreports    %s\n", strings.Join(paths, ", "))
		}
	}
	if !text && len(reports) > 0 {
		var w io.Writer = stdout
		if output != nil {
			w = output
		}
		err := renderReports(w, o.format, reports, len(o.files))
		if output != nil {
			if cerr := output.Close(); err == nil {
				err = cerr
			}
		}
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			verdicts = append(verdicts, runner.Errored)
		}
	}
	return failOnExitCode(verdicts, o.failOn)
}

// failReport turns rep into an ERROR report because its JSON report could
// not be written: the run cannot keep its evidence, and the documents of the
// run (SARIF, JUnit, HTML) must say so, as the exit code does. The verdict
// the trials reached stays in the summary.
func failReport(rep *runner.Report, err error) {
	msg := "the JSON report could not be written: " + err.Error()
	switch {
	case rep.Summary == "":
	case rep.Verdict != runner.Errored:
		msg += fmt.Sprintf("; the trials gave %s: %s", rep.Verdict, rep.Summary)
	default:
		msg += "; " + rep.Summary
	}
	rep.Verdict = runner.Errored
	rep.Summary = msg
}

// renderReports writes reps as one document in format (json, sarif, junit or
// html). files is the number of scenario files of the run: for several
// files the JSON document is always an array, even if an interruption left
// a single report.
func renderReports(w io.Writer, format string, reps []*runner.Report, files int) error {
	switch format {
	case formatJSON:
		if files > 1 && len(reps) == 1 {
			return encodeJSON(w, reps)
		}
		return report.JSON(w, reps)
	case formatSARIF:
		base, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("SARIF base directory: %w", err)
		}
		return report.SARIF(w, reps, report.SARIFOptions{BaseDir: base})
	case formatJUnit:
		return report.JUnit(w, reps)
	case formatHTML:
		return report.HTML(w, reps)
	default:
		return fmt.Errorf("unknown report format %q", format)
	}
}

// writeOutFiles writes the reports of outFiles to dir and returns the paths
// written. Every file is rendered completely before it is written, so a
// failing renderer does not leave half a report behind.
func writeOutFiles(dir string, reps []*runner.Report, files int) ([]string, error) {
	var paths []string
	var errs []error
	for _, of := range outFiles {
		p := filepath.Join(dir, of.name)
		var b bytes.Buffer
		if err := renderReports(&b, of.format, reps, files); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", p, err))
			continue
		}
		if err := os.WriteFile(p, b.Bytes(), 0o600); err != nil {
			errs = append(errs, err)
			continue
		}
		paths = append(paths, p)
	}
	return paths, errors.Join(errs...)
}

// failOnExitCode returns the exit code over all verdicts for the --fail-on
// value: ERROR always gives 3; never turns every other verdict into 0;
// violated and inconclusive both keep combinedExitCode, under which an
// INCONCLUSIVE scenario already exits 2.
func failOnExitCode(verdicts []runner.Verdict, failOn string) int {
	if slices.Contains(verdicts, runner.Errored) {
		return runner.ExitCode(runner.Errored)
	}
	if failOn == failOnNever {
		return runner.ExitCode(runner.Held)
	}
	return combinedExitCode(verdicts)
}

// runOne loads and runs one scenario. It always returns a report: a scenario
// that cannot be loaded or run yields a report with verdict ERROR and the
// error in the summary. With a format other than text the progress lines go
// to stderr, framed by the scenario file and its verdict, so that stdout
// stays a single document.
func runOne(ctx context.Context, file string, o runOptions, stdout, stderr io.Writer) *runner.Report {
	var progress io.Writer
	switch {
	case o.quiet:
	case o.format != formatText:
		progress = stderr
	default:
		progress = stdout
	}
	if progress == nil {
		return loadAndRun(ctx, file, o, nil)
	}
	fmt.Fprintf(progress, "run %s\n", file)
	rep := loadAndRun(ctx, file, o, progress)
	if o.format != formatText {
		fmt.Fprintf(progress, "%s: %s\n", file, rep.Verdict)
		if rep.Verdict == runner.Errored && rep.Summary != "" {
			fmt.Fprintf(progress, "  %s\n", strings.ReplaceAll(strings.TrimRight(rep.Summary, "\n"), "\n", "\n  "))
		}
	}
	return rep
}

// loadAndRun loads and runs one scenario, writing progress lines to progress
// (nil disables them). It always returns a report, as runOne does.
func loadAndRun(ctx context.Context, file string, o runOptions, progress io.Writer) *runner.Report {
	started := time.Now()
	s, err := scenario.Load(file)
	if err != nil {
		return errorReport(file, err, started)
	}
	rep, err := runner.Run(ctx, s, runner.Options{
		Engine:   o.engine,
		Trials:   o.trials,
		Copies:   o.copies,
		Insecure: o.insecure,
		Stdout:   progress,
		Version:  version,
	})
	if rep == nil {
		if err == nil {
			err = errors.New("the runner returned no report")
		}
		return errorReport(file, err, started)
	}
	if err != nil {
		// The run ended early (Ctrl+C): the report covers the trials that
		// ran, and a violation found before the interruption still counts.
		if rep.Summary == "" {
			rep.Verdict = runner.Errored
			rep.Summary = err.Error()
		} else {
			rep.Summary += fmt.Sprintf(" (stopped early: %v)", err)
		}
	}
	if rep.File == "" {
		rep.File = file
	}
	return rep
}

// errorReport is the report of a scenario that failed before it could run.
func errorReport(file string, err error, started time.Time) *runner.Report {
	return &runner.Report{
		Schema:     runner.Schema,
		Tool:       "photofinish " + version,
		File:       file,
		Verdict:    runner.Errored,
		Summary:    err.Error(),
		StartedAt:  started,
		FinishedAt: time.Now(),
	}
}

// combinedExitCode returns the exit code over several scenarios: 3 if any
// ERROR, else 1 if any VIOLATED, else 2 if any INCONCLUSIVE, else 0.
func combinedExitCode(verdicts []runner.Verdict) int {
	for _, v := range []runner.Verdict{runner.Errored, runner.Violated, runner.Inconclusive} {
		if slices.Contains(verdicts, v) {
			return runner.ExitCode(v)
		}
	}
	return runner.ExitCode(runner.Held)
}

// reportName returns the file name of the report: the scenario name, or the
// base name of the scenario file when the scenario could not be loaded.
func reportName(rep *runner.Report, file string) string {
	if rep.Scenario != "" {
		return rep.Scenario + ".json"
	}
	base := filepath.Base(file)
	return strings.TrimSuffix(base, filepath.Ext(base)) + ".json"
}

// writeReport writes rep to dir and returns the path. written maps the report
// files of this run to their scenario files, so that two scenarios with the
// same name do not silently overwrite each other's evidence.
func writeReport(dir string, rep *runner.Report, file string, written map[string]string) (string, error) {
	p := filepath.Join(dir, reportName(rep, file))
	if prev, ok := written[p]; ok {
		return "", fmt.Errorf("%s was already written for %s in this run; give the scenarios distinct names", p, prev)
	}
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return "", err
	}
	if err := encodeJSON(f, rep); err != nil {
		f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	written[p] = file
	return p, nil
}

// encodeJSON writes v as indented JSON. HTML escaping is off so that
// invariants such as "a <= 1" stay readable.
func encodeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

// writeSummary prints the text summary of one report: verdict and summary
// sentence, what was tested, trial counts, the failing terms of the first
// violated trial (or the reasons of the first inconclusive one) and the
// command that reproduces the run.
func writeSummary(w io.Writer, rep *runner.Report) {
	name := rep.Scenario
	if name == "" {
		name = rep.File
	}
	fmt.Fprintf(w, "%s: %s\n", name, rep.Verdict)
	if rep.Summary != "" {
		// A summary may hold several validation errors, one per line.
		fmt.Fprintf(w, "  %s\n", strings.ReplaceAll(strings.TrimRight(rep.Summary, "\n"), "\n", "\n  "))
	}
	if rep.Explain != "" {
		fmt.Fprintf(w, "  rule       %s\n", oneLine(rep.Explain))
	}
	if rep.Invariant != "" {
		fmt.Fprintf(w, "  invariant  %s\n", oneLine(rep.Invariant))
	}
	if rep.Target != "" {
		fmt.Fprintf(w, "  target     %s (engine %s, %d copies)\n", rep.Target, rep.Engine, rep.Copies)
	}
	if len(rep.Trials) > 0 {
		fmt.Fprintf(w, "  trials     %s\n", trialCounts(rep.Trials))
		if spread, ok := medianSpread(rep.Trials, responseSpread); ok {
			line := "median response spread " + formatMs(spread)
			if server, ok := medianSpread(rep.Trials, serverSpread); ok {
				line += ", server arrival spread " + formatMs(server)
			}
			fmt.Fprintf(w, "  timing     %s\n", line)
		}
	}
	if t := firstTrial(rep.Trials, runner.Violated); t != nil {
		fmt.Fprintf(w, "  failing terms in trial %d:\n", t.Number)
		for _, term := range t.Terms {
			if term.Pass != nil && *term.Pass {
				continue
			}
			writeTerm(w, term)
		}
		for _, r := range t.Reasons {
			if !termReason(r, t.Terms) {
				fmt.Fprintf(w, "    %s\n", r)
			}
		}
	} else if t := firstTrial(rep.Trials, runner.Inconclusive); t != nil && rep.Verdict == runner.Inconclusive {
		fmt.Fprintf(w, "  inconclusive because (trial %d):\n", t.Number)
		for _, r := range t.Reasons {
			fmt.Fprintf(w, "    %s\n", r)
		}
	}
	for _, n := range reportNotes(rep) {
		fmt.Fprintf(w, "  note       %s\n", n)
	}
	if rep.Reproduce != "" {
		fmt.Fprintf(w, "  reproduce  %s\n", rep.Reproduce)
	}
}

// reportNotes returns the run notes of rep (skipped trials, for example)
// followed by the distinct notes of its races (split release writes).
func reportNotes(rep *runner.Report) []string {
	notes := slices.Clone(rep.Notes)
	for _, t := range rep.Trials {
		if t.Race == nil {
			continue
		}
		for _, n := range t.Race.Notes {
			if !slices.Contains(notes, n) {
				notes = append(notes, n)
			}
		}
	}
	return notes
}

// writeTerm prints one failed (or unevaluated) conjunct of the invariant with
// its concrete value.
func writeTerm(w io.Writer, term check.Term) {
	status := "FAIL"
	if term.Pass == nil {
		status = "ERROR"
	}
	if term.Value != "" {
		fmt.Fprintf(w, "    %-5s %s    (%s)\n", status, term.Expr, term.Value)
		return
	}
	fmt.Fprintf(w, "    %-5s %s\n", status, term.Expr)
}

// termReason reports whether reason only repeats one of the terms (the runner
// lists failing terms as reasons of a violated trial).
func termReason(reason string, terms []check.Term) bool {
	for _, t := range terms {
		if strings.Contains(reason, t.Expr) {
			return true
		}
	}
	return false
}

// oneLine collapses the whitespace of a possibly multi-line YAML value.
func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// firstTrial returns the first trial with verdict v, or nil.
func firstTrial(trials []runner.Trial, v runner.Verdict) *runner.Trial {
	for i := range trials {
		if trials[i].Verdict == v {
			return &trials[i]
		}
	}
	return nil
}

// trialCounts summarizes the trial verdicts, e.g. "7 violated, 3 held".
func trialCounts(trials []runner.Trial) string {
	counts := map[runner.Verdict]int{}
	for _, t := range trials {
		counts[t.Verdict]++
	}
	var parts []string
	for _, v := range []runner.Verdict{runner.Violated, runner.Held, runner.Inconclusive, runner.Errored} {
		if n := counts[v]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, strings.ToLower(string(v))))
		}
	}
	return fmt.Sprintf("%d run: %s", len(trials), strings.Join(parts, ", "))
}

// responseSpread is the client-side response spread of a trial's race.
func responseSpread(r *engine.Race) (time.Duration, bool) {
	n := 0
	for _, res := range r.Results {
		if res.FirstByteNs != 0 {
			n++
		}
	}
	return r.ResponseSpread(), n >= 2
}

// serverSpread is the server arrival spread of a trial's race, if the target
// reported arrival times.
func serverSpread(r *engine.Race) (time.Duration, bool) {
	return r.ServerArrivalSpread()
}

// medianSpread returns the median of spread over the trials that raced.
func medianSpread(trials []runner.Trial, spread func(*engine.Race) (time.Duration, bool)) (time.Duration, bool) {
	var ds []time.Duration
	for _, t := range trials {
		if t.Race == nil {
			continue
		}
		if d, ok := spread(t.Race); ok {
			ds = append(ds, d)
		}
	}
	if len(ds) == 0 {
		return 0, false
	}
	return medianDuration(ds), true
}

// formatMs formats d in milliseconds with two decimals, e.g. "0.41 ms".
func formatMs(d time.Duration) string {
	return fmt.Sprintf("%.2f ms", float64(d)/float64(time.Millisecond))
}
