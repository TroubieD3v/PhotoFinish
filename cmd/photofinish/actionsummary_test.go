package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// runActionSummary runs scripts/action-summary.go, the job summary helper of
// the GitHub Action, and returns its stdout and the markdown it appended.
func runActionSummary(t *testing.T, out string, args ...string) (string, string) {
	t.Helper()
	if testing.Short() {
		t.Skip("builds scripts/action-summary.go")
	}
	gobin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go command:", err)
	}
	md := filepath.Join(t.TempDir(), "summary.md")
	cmd := exec.Command(gobin, append([]string{"run", filepath.Join("..", "..", "scripts", "action-summary.go"),
		"-out", out, "-summary", md}, args...)...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("action-summary: %v\n%s", err, stderr.String())
	}
	data, err := os.ReadFile(md)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(stdout.String()), string(data)
}

// TestActionSummaryExitCode checks that the action reports ERROR, with a row
// for the scenario file that has no report, when the run exited 3 although
// the reports it left are HELD.
func TestActionSummaryExitCode(t *testing.T) {
	fakeRunner(t)
	out := t.TempDir()
	if code, _, stderr := runCLI("run", "held.yaml", "--out", out, "--quiet"); code != 0 {
		t.Fatalf("exit code %d\n%s", code, stderr)
	}

	verdict, md := runActionSummary(t, out, "-exit-code", "3", "--", "held.yaml", "missing.yaml")
	if verdict != "ERROR" {
		t.Errorf("verdict %q, want ERROR", verdict)
	}
	for _, want := range []string{"| held | HELD |", "| missing.yaml | ERROR | no report was written", "Worst verdict: **ERROR**, exit code 3"} {
		if !strings.Contains(md, want) {
			t.Errorf("the summary lacks %q:\n%s", want, md)
		}
	}

	verdict, md = runActionSummary(t, out, "-exit-code", "3", "--", "held.yaml")
	if verdict != "ERROR" || !strings.Contains(md, "The run failed (exit code 3)") {
		t.Errorf("verdict %q\n%s", verdict, md)
	}

	verdict, md = runActionSummary(t, out, "-exit-code", "0", "--", "held.yaml")
	if verdict != "HELD" || strings.Contains(md, "ERROR") {
		t.Errorf("verdict %q\n%s", verdict, md)
	}
}
