package report

import (
	"encoding/xml"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/TroubieD3v/photofinish/internal/runner"
)

// JUnit writes the reports as JUnit XML in the form Jenkins and the common
// GitHub test report actions read: a <testsuites> root named "photofinish",
// one <testsuite> per scenario and one <testcase> "trial N" per trial. A
// VIOLATED trial is a <failure> (the failing terms and the response
// statuses), an INCONCLUSIVE trial is <skipped> with its reasons, and a
// scenario with verdict ERROR adds a testcase "scenario" with an <error>.
func JUnit(w io.Writer, reps []*runner.Report) error {
	if err := checkReports(reps); err != nil {
		return err
	}
	root := junitSuites{Name: "photofinish", Suites: []junitSuite{}}
	var total time.Duration
	for _, rep := range reps {
		s := junitSuiteFor(rep)
		root.Tests += s.Tests
		root.Failures += s.Failures
		root.Errors += s.Errors
		root.Skipped += s.Skipped
		total += runDuration(rep)
		root.Suites = append(root.Suites, s)
	}
	root.Time = seconds(total)
	if _, err := io.WriteString(w, xml.Header); err != nil {
		return err
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(root); err != nil {
		return err
	}
	_, err := io.WriteString(w, "\n")
	return err
}

// junitSuiteFor builds the test suite of one report.
func junitSuiteFor(rep *runner.Report) junitSuite {
	name := scenarioName(rep)
	s := junitSuite{
		Name: name,
		Time: seconds(runDuration(rep)),
		Properties: &junitProperties{Props: []junitProperty{
			{"verdict", string(rep.Verdict)},
		}},
		Cases: []junitCase{},
	}
	if !rep.StartedAt.IsZero() {
		s.Timestamp = rep.StartedAt.UTC().Format("2006-01-02T15:04:05")
	}
	props := &s.Properties.Props
	for _, p := range [][2]string{
		{"file", rep.File},
		{"target", rep.Target},
		{"engine", string(rep.Engine)},
		{"copies", copiesText(rep.Copies)},
		{"invariant", oneLine(rep.Invariant)},
		{"explain", oneLine(rep.Explain)},
		{"tool", rep.Tool},
		{"reproduce", rep.Reproduce},
	} {
		if p[1] != "" {
			*props = append(*props, junitProperty{p[0], p[1]})
		}
	}

	class := "photofinish." + name
	for i := range rep.Trials {
		t := &rep.Trials[i]
		if rep.Verdict == runner.Errored && t.Verdict == runner.Errored {
			continue // folded into the scenario error below
		}
		c := junitCase{
			ClassName: class,
			Name:      "trial " + strconv.Itoa(t.Number),
			Time:      seconds(trialDuration(t)),
		}
		switch t.Verdict {
		case runner.Violated:
			c.Failure = &junitProblem{Type: "InvariantViolated", Message: rep.Summary, Text: failureText(t)}
			s.Failures++
		case runner.Inconclusive:
			c.Skipped = &junitProblem{Message: strings.Join(t.Reasons, "; ")}
			s.Skipped++
		case runner.Errored:
			c.Error = &junitProblem{Type: "TrialError", Message: strings.Join(t.Reasons, "; "), Text: failureText(t)}
			s.Errors++
		}
		s.Cases = append(s.Cases, c)
	}
	if rep.Verdict == runner.Errored {
		text := rep.Summary
		for _, t := range rep.Trials {
			if t.Verdict == runner.Errored && len(t.Reasons) > 0 {
				text += fmt.Sprintf("\ntrial %d: %s", t.Number, strings.Join(t.Reasons, "; "))
			}
		}
		s.Cases = append(s.Cases, junitCase{
			ClassName: class,
			Name:      "scenario",
			Time:      seconds(runDuration(rep)),
			Error:     &junitProblem{Type: "ScenarioError", Message: rep.Summary, Text: text},
		})
		s.Errors++
	}
	s.Tests = len(s.Cases)

	var out []string
	if rep.Summary != "" {
		out = append(out, string(rep.Verdict)+": "+rep.Summary)
	}
	for _, n := range rep.Notes {
		out = append(out, "note: "+n)
	}
	if rep.Reproduce != "" {
		out = append(out, "reproduce: "+rep.Reproduce)
	}
	if len(out) > 0 {
		s.SystemOut = strings.Join(out, "\n")
	}
	return s
}

// failureText is the body of a failure: the failing terms, the response
// statuses of the race and the notes of the trial.
func failureText(t *runner.Trial) string {
	var b strings.Builder
	if terms := failingTerms(t); len(terms) > 0 && t.Verdict == runner.Violated {
		b.WriteString("failing terms:\n")
		for _, term := range terms {
			b.WriteString("  " + term + "\n")
		}
	}
	if st := statusSummary(t.Race); st != "" {
		b.WriteString("responses: " + st + "\n")
	}
	for _, r := range t.Reasons {
		if strings.HasPrefix(r, notePrefix) || t.Verdict != runner.Violated {
			b.WriteString(r + "\n")
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

// copiesText formats a copy count, "" for 0.
func copiesText(n int) string {
	if n == 0 {
		return ""
	}
	return strconv.Itoa(n)
}

// seconds formats d in seconds with millisecond precision.
func seconds(d time.Duration) string {
	return strconv.FormatFloat(d.Seconds(), 'f', 3, 64)
}

// The JUnit XML model.

type junitSuites struct {
	XMLName  xml.Name     `xml:"testsuites"`
	Name     string       `xml:"name,attr"`
	Tests    int          `xml:"tests,attr"`
	Failures int          `xml:"failures,attr"`
	Errors   int          `xml:"errors,attr"`
	Skipped  int          `xml:"skipped,attr"`
	Time     string       `xml:"time,attr"`
	Suites   []junitSuite `xml:"testsuite"`
}

type junitSuite struct {
	Name       string           `xml:"name,attr"`
	Tests      int              `xml:"tests,attr"`
	Failures   int              `xml:"failures,attr"`
	Errors     int              `xml:"errors,attr"`
	Skipped    int              `xml:"skipped,attr"`
	Time       string           `xml:"time,attr"`
	Timestamp  string           `xml:"timestamp,attr,omitempty"`
	Properties *junitProperties `xml:"properties,omitempty"`
	Cases      []junitCase      `xml:"testcase"`
	SystemOut  string           `xml:"system-out,omitempty"`
}

type junitProperties struct {
	Props []junitProperty `xml:"property"`
}

type junitProperty struct {
	Name  string `xml:"name,attr"`
	Value string `xml:"value,attr"`
}

type junitCase struct {
	ClassName string        `xml:"classname,attr"`
	Name      string        `xml:"name,attr"`
	Time      string        `xml:"time,attr"`
	Failure   *junitProblem `xml:"failure,omitempty"`
	Error     *junitProblem `xml:"error,omitempty"`
	Skipped   *junitProblem `xml:"skipped,omitempty"`
}

type junitProblem struct {
	Type    string `xml:"type,attr,omitempty"`
	Message string `xml:"message,attr"`
	Text    string `xml:",chardata"`
}
