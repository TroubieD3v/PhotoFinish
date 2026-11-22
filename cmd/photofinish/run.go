package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/TroubieD3v/photofinish/internal/check"
	"github.com/TroubieD3v/photofinish/internal/engine"
	"github.com/TroubieD3v/photofinish/internal/runner"
	"github.com/TroubieD3v/photofinish/internal/scenario"
)

const runUsage = `Usage: photofinish run <scenario.yaml>... [--engine auto|h2|h1|burst] [--trials N] [--copies N]
                                          [--insecure] [--out DIR] [--format text|json] [--quiet]

Runs every scenario: for each trial the setup steps, the synchronized race and
the check, then evaluates the invariant. Only hosts listed in scope.allow_hosts
are contacted, within scope.budget.

With --format json, stdout is one JSON report for one scenario file, or a JSON
array of reports, in file order, for several.

Exit code over all scenarios: 3 if any ERROR, else 1 if any VIOLATED, else 2 if
any INCONCLUSIVE, else 0 (every scenario HELD). Usage errors exit 64.

Flags:
`

// runOptions holds the parsed flags of the run command.
type runOptions struct {
	files    []string
	engine   engine.Kind
	trials   int
	copies   int
	insecure bool
	out      string
	format   string
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
	fs.StringVar(&o.out, "out", "", "write the JSON report of every scenario to `DIR`/<scenario-name>.json")
	fs.StringVar(&o.format, "format", "text", "stdout format: text or json (the full report; an array of reports for several files)")
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
	case o.format != "text" && o.format != "json":
		return o, fmt.Errorf("--format must be text or json, got %q", o.format)
	}
	return o, nil
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
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runScenarios(ctx, o, stdout, stderr)
}

// runScenarios runs every scenario file in order, prints the results and
// returns the combined exit code.
func runScenarios(ctx context.Context, o runOptions, stdout, stderr io.Writer) int {
	if o.out != "" {
		if err := os.MkdirAll(o.out, 0o755); err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return runner.ExitCode(runner.Errored)
		}
	}
	var verdicts []runner.Verdict
	var reports []*runner.Report   // for --format json
	written := map[string]string{} // report file -> scenario file
	for i, file := range o.files {
		if ctx.Err() != nil {
			fmt.Fprintf(stderr, "interrupted; %d of %d scenarios not run\n", len(o.files)-i, len(o.files))
			verdicts = append(verdicts, runner.Errored)
			break
		}
		if o.format == "text" && i > 0 {
			fmt.Fprintln(stdout)
		}
		rep := runOne(ctx, file, o, stdout, stderr)
		verdict := rep.Verdict

		var reportPath string
		if o.out != "" {
			p, err := writeReport(o.out, rep, file, written)
			if err != nil {
				fmt.Fprintf(stderr, "error: %s: %v\n", file, err)
				verdict = runner.Errored
			}
			reportPath = p
		}

		switch o.format {
		case "json":
			reports = append(reports, rep)
		default:
			writeSummary(stdout, rep)
			if reportPath != "" {
				fmt.Fprintf(stdout, "  report     %s\n", reportPath)
			}
		}
		verdicts = append(verdicts, verdict)
	}
	if o.format == "json" && len(reports) > 0 {
		// One document on stdout: the report itself for one file, an
		// array for several, so that any JSON parser reads the output.
		var doc any = reports
		if len(o.files) == 1 {
			doc = reports[0]
		}
		if err := encodeJSON(stdout, doc); err != nil {
			fmt.Fprintln(stderr, "error:", err)
			verdicts = append(verdicts, runner.Errored)
		}
	}
	return combinedExitCode(verdicts)
}

// runOne loads and runs one scenario. It always returns a report: a scenario
// that cannot be loaded or run yields a report with verdict ERROR and the
// error in the summary.
func runOne(ctx context.Context, file string, o runOptions, stdout, stderr io.Writer) *runner.Report {
	var progress io.Writer
	switch {
	case o.quiet:
	case o.format == "json":
		progress = stderr // keep stdout valid JSON
	default:
		progress = stdout
		fmt.Fprintf(stdout, "run %s\n", file)
	}

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
