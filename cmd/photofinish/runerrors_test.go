package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TroubieD3v/photofinish/internal/runner"
)

// sarifInvocations holds the invocation part of a SARIF log.
type sarifInvocations struct {
	Runs []struct {
		Invocations []struct {
			ExecutionSuccessful bool `json:"executionSuccessful"`
			Notifications       []struct {
				Level   string `json:"level"`
				Message struct {
					Text string `json:"text"`
				} `json:"message"`
			} `json:"toolExecutionNotifications"`
		} `json:"invocations"`
		Results []struct {
			RuleID string `json:"ruleId"`
		} `json:"results"`
	} `json:"runs"`
}

func readInvocation(t *testing.T, path string) sarifInvocations {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var l sarifInvocations
	if err := json.Unmarshal(data, &l); err != nil {
		t.Fatalf("%s is not a SARIF document: %v\n%s", path, err, data)
	}
	if len(l.Runs) != 1 || len(l.Runs[0].Invocations) != 1 {
		t.Fatalf("%s: want one run with one invocation:\n%s", path, data)
	}
	return l
}

// TestRunDuplicateNames checks that scenarios sharing a name are rejected
// before any request when the run writes reports keyed by name, and still
// run when it does not.
func TestRunDuplicateNames(t *testing.T) {
	calls := fakeRunner(t)
	a, b := filepath.Join("a", "violated.yaml"), filepath.Join("b", "violated.yaml")
	for _, args := range [][]string{
		{"--format", "sarif"},
		{"--format", "junit"},
		{"--out", t.TempDir()},
	} {
		t.Run(args[0]+" "+filepath.Base(args[1]), func(t *testing.T) {
			*calls = nil
			code, stdout, stderr := runCLI(append([]string{"run", a, b}, args...)...)
			if code != exitUsage {
				t.Errorf("exit code %d, want %d", code, exitUsage)
			}
			if !strings.Contains(stderr, "both named violated") || stdout != "" {
				t.Errorf("stdout: %s\nstderr: %s", stdout, stderr)
			}
			if len(*calls) != 0 {
				t.Errorf("scenarios ran: %q", *calls)
			}
		})
	}
	for _, args := range [][]string{nil, {"--format", "json"}, {"--format", "html"}} {
		t.Run("allowed "+strings.Join(args, " "), func(t *testing.T) {
			*calls = nil
			code, _, stderr := runCLI(append([]string{"run", a, b, "--quiet"}, args...)...)
			if code != 1 || len(*calls) != 2 {
				t.Errorf("exit code %d, calls %q\nstderr: %s", code, *calls, stderr)
			}
		})
	}
}

// TestRunOutputIsScenarioReport checks that --output cannot name the JSON
// report of a scenario that --out DIR writes: the two writes would interleave
// in one file.
func TestRunOutputIsScenarioReport(t *testing.T) {
	calls := fakeRunner(t)
	for _, format := range []string{formatSARIF, formatJSON, formatHTML} {
		t.Run(format, func(t *testing.T) {
			*calls = nil
			out := t.TempDir()
			output := filepath.Join(out, "violated.json")
			code, stdout, stderr := runCLI("run", "held.yaml", "violated.yaml", "--quiet",
				"--format", format, "--output", output, "--out", out)
			if code != exitUsage {
				t.Errorf("exit code %d, want %d", code, exitUsage)
			}
			if !strings.Contains(stderr, "is the JSON report of violated.yaml") || stdout != "" {
				t.Errorf("stdout: %s\nstderr: %s", stdout, stderr)
			}
			if len(*calls) != 0 {
				t.Errorf("scenarios ran: %q", *calls)
			}
			if _, err := os.Stat(output); err == nil {
				t.Errorf("%s was created", output)
			}
		})
	}
}

// TestRunReportWriteErrorInDocuments checks that a scenario whose JSON report
// cannot be written is ERROR in the SARIF and JUnit documents of the run,
// as it is in the exit code.
func TestRunReportWriteErrorInDocuments(t *testing.T) {
	fakeRunner(t)
	out := t.TempDir()
	if err := os.Mkdir(filepath.Join(out, "violated.json"), 0o755); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "r.sarif")
	code, _, stderr := runCLI("run", "held.yaml", "violated.yaml", "--quiet", "--out", out,
		"--format", "sarif", "--output", output)
	if code != 3 {
		t.Errorf("exit code %d, want 3\nstderr: %s", code, stderr)
	}
	for _, p := range []string{output, filepath.Join(out, "results.sarif")} {
		l := readInvocation(t, p)
		inv := l.Runs[0].Invocations[0]
		if inv.ExecutionSuccessful || len(inv.Notifications) != 1 {
			t.Fatalf("%s: executionSuccessful %v, notifications %+v", p, inv.ExecutionSuccessful, inv.Notifications)
		}
		msg := inv.Notifications[0].Message.Text
		if !strings.Contains(msg, "the JSON report could not be written") || !strings.Contains(msg, "the trials gave VIOLATED") {
			t.Errorf("%s: notification %q", p, msg)
		}
		if n := len(l.Runs[0].Results); n != 0 {
			t.Errorf("%s: %d results, want none", p, n)
		}
	}
	data, err := os.ReadFile(filepath.Join(out, "junit.xml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `name="scenario"`) || !strings.Contains(string(data), `type="ScenarioError"`) {
		t.Errorf("junit.xml has no scenario error:\n%s", data)
	}
}

// junitErrors holds the error counts of a JUnit document.
type junitErrors struct {
	XMLName xml.Name `xml:"testsuites"`
	Errors  int      `xml:"errors,attr"`
	Suites  []struct {
		Name string `xml:"name,attr"`
	} `xml:"testsuite"`
}

// TestRunInterruptedInDocuments checks that scenarios an interruption left
// unrun appear as ERROR in the documents, and that an interruption before
// the first scenario still leaves a valid document in --output.
func TestRunInterruptedInDocuments(t *testing.T) {
	fakeRunner(t)
	o := runOptions{files: []string{"held.yaml", "violated.yaml"}, format: formatSARIF, failOn: failOnViolated, quiet: true}

	t.Run("before the first scenario", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		o := o
		o.output = filepath.Join(t.TempDir(), "r.sarif")
		var stderr bytes.Buffer
		if code := runScenarios(ctx, o, io.Discard, &stderr); code != 3 {
			t.Errorf("exit code %d, want 3", code)
		}
		if !strings.Contains(stderr.String(), "2 of 2 scenarios not run") {
			t.Errorf("stderr: %s", stderr.String())
		}
		inv := readInvocation(t, o.output).Runs[0].Invocations[0]
		if inv.ExecutionSuccessful || len(inv.Notifications) != 2 {
			t.Fatalf("executionSuccessful %v, notifications %+v", inv.ExecutionSuccessful, inv.Notifications)
		}
		if msg := inv.Notifications[1].Message.Text; msg != "violated: not run: the run was interrupted" {
			t.Errorf("notification %q", msg)
		}
	})

	t.Run("after the first scenario", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		prev := runScenario
		runScenario = func(ctx context.Context, file string, o runOptions, stdout, stderr io.Writer) *runner.Report {
			defer cancel()
			return prev(ctx, file, o, stdout, stderr)
		}
		t.Cleanup(func() { runScenario = prev })
		o := o
		o.format = formatJUnit
		var stdout bytes.Buffer
		if code := runScenarios(ctx, o, &stdout, io.Discard); code != 3 {
			t.Errorf("exit code %d, want 3", code)
		}
		var d junitErrors
		if err := xml.Unmarshal(stdout.Bytes(), &d); err != nil {
			t.Fatalf("not a JUnit document: %v\n%s", err, stdout.String())
		}
		if len(d.Suites) != 2 || d.Suites[1].Name != "violated" || d.Errors != 1 {
			t.Errorf("suites %+v, errors %d\n%s", d.Suites, d.Errors, stdout.String())
		}
	})
}
