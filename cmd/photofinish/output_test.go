package main

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TroubieD3v/photofinish/internal/engine"
	"github.com/TroubieD3v/photofinish/internal/runner"
)

// TestRunFormatJSONSeveralFiles checks that several scenarios give one JSON
// document, an array of reports in file order.
func TestRunFormatJSONSeveralFiles(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(bad, []byte("version: 1\nname: Bad_Name\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "missing.yaml")
	var stdout, stderr bytes.Buffer
	if got := run([]string{"run", missing, bad, "--format", "json"}, &stdout, &stderr); got != 3 {
		t.Errorf("exit code %d, want 3", got)
	}
	var reps []runner.Report
	if err := json.Unmarshal(stdout.Bytes(), &reps); err != nil {
		t.Fatalf("stdout is not one JSON document: %v\n%s", err, stdout.String())
	}
	if len(reps) != 2 || reps[0].File != missing || reps[1].File != bad {
		t.Errorf("reports %+v", reps)
	}
}

// TestRunMultiLineSummaryIsIndented checks that every validation error of
// an invalid scenario stays under its heading.
func TestRunMultiLineSummaryIsIndented(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(bad, []byte("version: 1\nname: Bad_Name\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	run([]string{"run", bad}, &stdout, &bytes.Buffer{})
	errs := 0
	for _, line := range strings.Split(strings.TrimSpace(stdout.String()), "\n") {
		if strings.HasPrefix(line, bad) && line != bad+": ERROR" {
			t.Errorf("unindented line %q", line)
		}
		if strings.HasPrefix(line, "  "+bad) {
			errs++
		}
	}
	if errs < 2 {
		t.Errorf("want several indented errors:\n%s", stdout.String())
	}
}

// TestRunSetupFailureBeforeFirstRace checks the text and JSON output of a
// run whose first setup step cannot reach the target: the aborted trial is
// counted as an error, never as a trial without a verdict.
func TestRunSetupFailureBeforeFirstRace(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close() // nothing listens there now
	file := writeExample(t, t.TempDir(), "coupon-vuln.yaml", addr)

	var stdout bytes.Buffer
	if got := run([]string{"run", file, "--trials", "2", "--quiet"}, &stdout, &bytes.Buffer{}); got != 3 {
		t.Errorf("exit code %d, want 3", got)
	}
	if !strings.Contains(stdout.String(), "  trials     1 run: 1 error\n") {
		t.Errorf("stdout:\n%s", stdout.String())
	}

	stdout.Reset()
	run([]string{"run", file, "--trials", "2", "--format", "json"}, &stdout, &bytes.Buffer{})
	var rep runner.Report
	if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if len(rep.Trials) != 1 || rep.Trials[0].Verdict != runner.Errored || rep.Stats.Errored != 1 {
		t.Errorf("trials %+v stats %+v", rep.Trials, rep.Stats)
	}
}

func TestWriteSummaryNotes(t *testing.T) {
	split := "split into 2 writes: 200 streams exceed one segment"
	rep := &runner.Report{
		Scenario: "s",
		Verdict:  runner.Violated,
		Summary:  "2 of 2 trials broke the rule; 3 of 5 planned trials skipped",
		Notes:    []string{"request budget exhausted: 3 of 5 trials skipped"},
		Trials: []runner.Trial{
			{Number: 1, Verdict: runner.Violated, Race: &engine.Race{Notes: []string{split}}},
			{Number: 2, Verdict: runner.Violated, Race: &engine.Race{Notes: []string{split}}},
		},
	}
	var b bytes.Buffer
	writeSummary(&b, rep)
	got := b.String()
	for _, want := range []string{
		"  note       request budget exhausted: 3 of 5 trials skipped\n",
		"  note       " + split + "\n",
	} {
		if strings.Count(got, want) != 1 {
			t.Errorf("summary must contain %q once:\n%s", want, got)
		}
	}
}

func TestImportEmptyHAR(t *testing.T) {
	file := filepath.Join(t.TempDir(), "e.har")
	if err := os.WriteFile(file, []byte(`{"log":{"entries":[]}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	if got := run([]string{"import", file}, &bytes.Buffer{}, &stderr); got != exitFailure {
		t.Errorf("exit code %d, want %d", got, exitFailure)
	}
	if !strings.Contains(stderr.String(), "has no HAR entries") || strings.Contains(stderr.String(), "-1") {
		t.Errorf("stderr: %s", stderr.String())
	}
}
