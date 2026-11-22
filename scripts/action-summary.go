//go:build ignore

// Command action-summary is a helper of the PhotoFinish GitHub Action
// (action.yml). It reads the JSON reports that "photofinish run --out DIR"
// wrote, prints the worst verdict on stdout and appends a markdown table
// (scenario, verdict, summary) to the job summary file.
//
// The exit code of the run has the last word: a run that exited 3 (a report
// that could not be written, an interruption) or 64 is ERROR even if every
// report it left says otherwise, and a scenario file without a report gets
// an ERROR row of its own.
//
// It uses the standard library only and runs with "go run", so it works
// wherever the action has installed Go:
//
//	go run scripts/action-summary.go -out DIR -summary "$GITHUB_STEP_SUMMARY" \
//	    -exit-code 1 -fail-on violated [scenario files in run order...]
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf8"
)

// report holds the fields of a runner report that the summary needs.
type report struct {
	Scenario string `json:"scenario"`
	File     string `json:"file"`
	Verdict  string `json:"verdict"`
	Summary  string `json:"summary"`
}

// severity orders the verdicts like the exit code of "photofinish run":
// ERROR before VIOLATED before INCONCLUSIVE before HELD.
var severity = map[string]int{"HELD": 0, "INCONCLUSIVE": 1, "VIOLATED": 2, "ERROR": 3}

// maxSummary caps the summary column, in runes.
const maxSummary = 300

func main() {
	out := flag.String("out", "", "directory with the JSON reports of the run")
	summary := flag.String("summary", "", "markdown file to append the table to (usually $GITHUB_STEP_SUMMARY); empty: none")
	exitCode := flag.Int("exit-code", 0, "exit code of photofinish run")
	failOn := flag.String("fail-on", "violated", "the fail-on setting of the run, shown in the summary")
	var files []string
	flag.Func("report", "a report file to list under the table (repeatable)", func(s string) error {
		files = append(files, s)
		return nil
	})
	flag.Parse()
	if *out == "" {
		fmt.Fprintln(os.Stderr, "action-summary: -out is required")
		os.Exit(64)
	}

	reps, err := readReports(*out, flag.Args())
	if err != nil {
		fmt.Fprintln(os.Stderr, "action-summary:", err)
		os.Exit(1)
	}
	reps = addMissing(reps, flag.Args())
	worst := worstVerdict(reps, *exitCode)
	fmt.Println(worst)

	if *summary == "" {
		return
	}
	f, err := os.OpenFile(*summary, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		fmt.Fprintln(os.Stderr, "action-summary:", err)
		os.Exit(1)
	}
	writeMarkdown(f, reps, worst, *exitCode, *failOn, files)
	if err := f.Close(); err != nil {
		fmt.Fprintln(os.Stderr, "action-summary:", err)
		os.Exit(1)
	}
}

// readReports reads every *.json report in dir, ordered like the scenario
// files in order (reports of other files last, by name).
func readReports(dir string, order []string) ([]report, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, err
	}
	slices.Sort(paths)
	var reps []report
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		var r report
		if err := json.Unmarshal(data, &r); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		if r.Verdict == "" {
			continue // not a run report
		}
		reps = append(reps, r)
	}
	rank := func(r report) int {
		if i := slices.Index(order, r.File); i >= 0 {
			return i
		}
		return len(order)
	}
	slices.SortStableFunc(reps, func(a, b report) int { return rank(a) - rank(b) })
	return reps, nil
}

// missingSummary is the summary of a scenario file without a report.
const missingSummary = "no report was written for this scenario file (the run was interrupted or the report could not be written); see the log of the run step"

// addMissing appends an ERROR row for every scenario file in files that no
// report names, in file order.
func addMissing(reps []report, files []string) []report {
	for _, f := range files {
		if !slices.ContainsFunc(reps, func(r report) bool { return r.File == f }) {
			reps = append(reps, report{File: f, Verdict: "ERROR", Summary: missingSummary})
		}
	}
	return reps
}

// worstVerdict returns the most severe verdict of reps, or ERROR when there
// are no reports at all (the run failed before it wrote any) or when the
// exit code of the run is not a verdict code below ERROR: a run that exits
// 3 or 64 failed whatever its reports say.
func worstVerdict(reps []report, exitCode int) string {
	if len(reps) == 0 || exitCode < 0 || exitCode > 2 {
		return "ERROR"
	}
	worst := "HELD"
	for _, r := range reps {
		s, ok := severity[r.Verdict]
		if !ok {
			return "ERROR"
		}
		if s > severity[worst] {
			worst = r.Verdict
		}
	}
	return worst
}

// writeMarkdown writes the job summary: a table with one row per scenario,
// the worst verdict with the exit code, and the report files.
func writeMarkdown(w io.Writer, reps []report, worst string, exitCode int, failOn string, files []string) {
	fmt.Fprint(w, "### PhotoFinish\n\n")
	if len(reps) == 0 {
		fmt.Fprintf(w, "No report was written (exit code %d); see the log of the run step.\n\n", exitCode)
		return
	}
	if worst == "ERROR" && !slices.ContainsFunc(reps, func(r report) bool { return r.Verdict == "ERROR" }) {
		fmt.Fprintf(w, "The run failed (exit code %d) after the reports below were written; see the log of the run step.\n\n", exitCode)
	}
	fmt.Fprint(w, "| Scenario | Verdict | Summary |\n|---|---|---|\n")
	for _, r := range reps {
		name := r.Scenario
		if name == "" {
			name = r.File
		}
		fmt.Fprintf(w, "| %s | %s | %s |\n", escape(name), escape(r.Verdict), escape(truncate(r.Summary, maxSummary)))
	}
	fmt.Fprintf(w, "\nWorst verdict: **%s**, exit code %d (fail-on: %s).\n", escape(worst), exitCode, escape(failOn))
	var listed []string
	for _, f := range files {
		if _, err := os.Stat(f); err == nil {
			listed = append(listed, "`"+strings.ReplaceAll(f, "`", "'")+"`")
		}
	}
	if len(listed) > 0 {
		fmt.Fprintf(w, "Reports: %s.\n", strings.Join(listed, ", "))
	}
	fmt.Fprintln(w)
}

// mdEscaper makes untrusted text inert in a markdown table cell: no column
// breaks, no line breaks, no links or autolinks, emphasis, code spans or HTML.
var mdEscaper = strings.NewReplacer(
	`\`, `\\`, "|", `\|`, "`", "\\`", "*", `\*`, "_", `\_`, "[", `\[`, "]", `\]`,
	"#", `\#`, "~", `\~`, "!", `\!`, "://", `:\/\/`,
	"&", "&amp;", "<", "&lt;", ">", "&gt;",
	"\r\n", " ", "\r", " ", "\n", " ", "\t", " ",
)

// escape returns s safe for a markdown table cell.
func escape(s string) string {
	return mdEscaper.Replace(strings.TrimSpace(s))
}

// truncate shortens s to at most n runes, marking the cut with "...".
func truncate(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return strings.TrimSpace(string(r[:n-3])) + "..."
}
