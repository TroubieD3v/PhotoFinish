// Package report renders runner reports for people and for other tools:
// indented JSON (the report itself), SARIF 2.1.0 for code scanning, JUnit
// XML for CI test views and a self-contained HTML page.
//
// Every renderer takes the reports of one run in scenario order. Reports are
// already masked by the runner; the renderers add no secrets and escape all
// content for their format.
package report

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/TroubieD3v/photofinish/internal/check"
	"github.com/TroubieD3v/photofinish/internal/engine"
	"github.com/TroubieD3v/photofinish/internal/runner"
)

// notePrefix marks trial reasons that add context without changing the
// verdict.
const notePrefix = "note: "

// checkReports returns an error if reps holds a nil report.
func checkReports(reps []*runner.Report) error {
	for i, rep := range reps {
		if rep == nil {
			return fmt.Errorf("report: report %d is nil", i)
		}
	}
	return nil
}

// errNoReports is returned by renderers that need at least one report.
var errNoReports = errors.New("report: no reports to render")

// scenarioName returns the scenario name, or the base name of the scenario
// file without its extension when the scenario could not be loaded.
func scenarioName(rep *runner.Report) string {
	if rep.Scenario != "" {
		return rep.Scenario
	}
	if rep.File != "" {
		base := filepath.Base(filepath.FromSlash(rep.File))
		if name := strings.TrimSuffix(base, filepath.Ext(base)); name != "" {
			return name
		}
	}
	return "scenario"
}

// toolVersion returns the version part of rep.Tool ("photofinish 0.1.0").
func toolVersion(rep *runner.Report) string {
	v := strings.TrimSpace(strings.TrimPrefix(rep.Tool, "photofinish"))
	if v == "" {
		return "dev"
	}
	return v
}

// firstTrial returns the first trial with verdict v, or nil.
func firstTrial(rep *runner.Report, v runner.Verdict) *runner.Trial {
	for i := range rep.Trials {
		if rep.Trials[i].Verdict == v {
			return &rep.Trials[i]
		}
	}
	return nil
}

// failingTerms returns the failing terms of a violated trial as the runner
// lists them ("size(check.json.discounts) <= 1 was 3 <= 1"): its reasons
// without notes, or the terms that did not pass when it has no reasons.
func failingTerms(t *runner.Trial) []string {
	var out []string
	for _, r := range t.Reasons {
		if !strings.HasPrefix(r, notePrefix) {
			out = append(out, r)
		}
	}
	if len(out) > 0 {
		return out
	}
	for _, tm := range t.Terms {
		if tm.Pass == nil || !*tm.Pass {
			out = append(out, termText(tm))
		}
	}
	return out
}

// termText renders a term as "expr was value", or the expression alone when
// it has no value.
func termText(tm check.Term) string {
	if tm.Value == "" {
		return tm.Expr
	}
	return tm.Expr + " was " + tm.Value
}

// statusSummary counts the race responses by status, in ascending status
// order with "no response" last: "3 x 200, 17 x 409".
func statusSummary(race *engine.Race) string {
	if race == nil || len(race.Results) == 0 {
		return ""
	}
	counts := map[int]int{}
	var codes []int
	for _, res := range race.Results {
		if counts[res.Status] == 0 {
			codes = append(codes, res.Status)
		}
		counts[res.Status]++
	}
	slices.SortFunc(codes, func(a, b int) int {
		switch {
		case a == b:
			return 0
		case a == 0:
			return 1
		case b == 0:
			return -1
		}
		return a - b
	})
	parts := make([]string, len(codes))
	for i, c := range codes {
		label := strconv.Itoa(c)
		if c == 0 {
			label = "no response"
		}
		parts[i] = fmt.Sprintf("%d x %s", counts[c], label)
	}
	return strings.Join(parts, ", ")
}

// trialDuration returns the time spent in a trial: its steps and its race.
func trialDuration(t *runner.Trial) time.Duration {
	var ns int64
	for _, s := range t.Setup {
		ns += s.DurationNs
	}
	for _, s := range t.Reset {
		ns += s.DurationNs
	}
	if t.Check != nil {
		ns += t.Check.DurationNs
	}
	if t.Race != nil && t.Race.FinishedNs > t.Race.StartedNs {
		ns += t.Race.FinishedNs - t.Race.StartedNs
	}
	return time.Duration(ns)
}

// runDuration returns FinishedAt - StartedAt, or 0 when unknown.
func runDuration(rep *runner.Report) time.Duration {
	if rep.StartedAt.IsZero() || rep.FinishedAt.Before(rep.StartedAt) {
		return 0
	}
	return rep.FinishedAt.Sub(rep.StartedAt)
}

// oneLine collapses the whitespace of a possibly multi-line YAML value.
func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// formatDuration formats d for people with a unit that suits its size:
// "38 µs", "0.41 ms", "1.20 s".
func formatDuration(d time.Duration) string {
	switch {
	case d < time.Millisecond:
		return fmt.Sprintf("%d µs", d.Microseconds())
	case d < time.Second:
		return fmt.Sprintf("%.2f ms", float64(d)/float64(time.Millisecond))
	default:
		return fmt.Sprintf("%.2f s", d.Seconds())
	}
}

// formatMs formats d in milliseconds with two decimals, as the text output
// of the run command does: "0.41 ms".
func formatMs(d time.Duration) string {
	return fmt.Sprintf("%.2f ms", float64(d)/float64(time.Millisecond))
}
