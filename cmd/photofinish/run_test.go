package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TroubieD3v/photofinish/internal/check"
	"github.com/TroubieD3v/photofinish/internal/engine"
	"github.com/TroubieD3v/photofinish/internal/runner"
	"github.com/TroubieD3v/photofinish/internal/scenario"
)

func TestParseFlagsInterleaved(t *testing.T) {
	cases := []struct {
		args   []string
		pos    []string
		trials int
		quiet  bool
	}{
		{args: []string{"a.yaml"}, pos: []string{"a.yaml"}},
		{args: []string{"--trials", "5", "a.yaml", "b.yaml"}, pos: []string{"a.yaml", "b.yaml"}, trials: 5},
		{args: []string{"a.yaml", "--trials", "5", "b.yaml", "--quiet"}, pos: []string{"a.yaml", "b.yaml"}, trials: 5, quiet: true},
		{args: []string{"a.yaml", "--", "--quiet", "-x.yaml"}, pos: []string{"a.yaml", "--quiet", "-x.yaml"}},
		{args: nil, pos: nil},
	}
	for _, c := range cases {
		fs := flag.NewFlagSet("t", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		trials := fs.Int("trials", 0, "")
		quiet := fs.Bool("quiet", false, "")
		pos, err := parseFlags(fs, c.args)
		if err != nil {
			t.Errorf("%q: %v", c.args, err)
			continue
		}
		if !slices.Equal(pos, c.pos) || *trials != c.trials || *quiet != c.quiet {
			t.Errorf("%q: positional %q trials %d quiet %v, want %q %d %v", c.args, pos, *trials, *quiet, c.pos, c.trials, c.quiet)
		}
	}
}

func TestCommandUsageErrors(t *testing.T) {
	cases := []struct {
		name   string
		args   []string
		stderr string
	}{
		{"run without files", []string{"run"}, "at least one scenario file"},
		{"run unknown flag", []string{"run", "a.yaml", "--fast"}, "flag provided but not defined: -fast"},
		{"run bad engine", []string{"run", "a.yaml", "--engine", "h3"}, "--engine must be auto, h2, h1 or burst"},
		{"run bad format", []string{"run", "a.yaml", "--format", "xml"}, "--format must be text, json, sarif, junit or html"},
		{"run empty format", []string{"run", "a.yaml", "--format", ""}, "--format must be text, json, sarif, junit or html"},
		{"run upper-case format", []string{"run", "a.yaml", "--format", "SARIF"}, `got "SARIF"`},
		{"run bad fail-on", []string{"run", "a.yaml", "--fail-on", "always"}, "--fail-on must be violated, inconclusive or never"},
		{"run empty fail-on", []string{"run", "a.yaml", "--fail-on="}, "--fail-on must be violated, inconclusive or never"},
		{"run fail-on without value", []string{"run", "a.yaml", "--fail-on"}, "flag needs an argument: -fail-on"},
		{"run output with the default format", []string{"run", "a.yaml", "--output", "r.json"}, "--output needs --format json, sarif, junit or html"},
		{"run output with text", []string{"run", "a.yaml", "--format", "text", "--output", "r.txt"}, "--output needs --format"},
		{"run output without value", []string{"run", "a.yaml", "--format", "json", "--output"}, "flag needs an argument: -output"},
		{"run negative trials", []string{"run", "a.yaml", "--trials", "-1"}, "--trials must be between 1 and 10000"},
		{"run too many trials", []string{"run", "a.yaml", "--trials", "10001"}, "--trials must be between 1 and 10000"},
		{"run too many copies", []string{"run", "a.yaml", "--copies", "1001"}, "--copies must be between 1 and 1000"},
		{"run non-numeric copies", []string{"run", "a.yaml", "--copies", "many"}, "--copies"},
		{"probe without URL", []string{"probe"}, "probe needs a URL"},
		{"probe two URLs", []string{"probe", "https://a.test/", "https://b.test/"}, "one URL"},
		{"probe bad scheme", []string{"probe", "ftp://a.test/"}, "https:// or http://"},
		{"probe no host", []string{"probe", "https:///path"}, "no host"},
		{"import without file", []string{"import"}, "import needs a file"},
		{"import two files", []string{"import", "a.txt", "b.txt"}, "one file"},
		{"import negative entry", []string{"import", "a.har", "--har-entry", "-1"}, "--har-entry must not be negative"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if got := run(c.args, &stdout, &stderr); got != exitUsage {
				t.Errorf("exit code %d, want %d\nstderr: %s", got, exitUsage, stderr.String())
			}
			if !strings.Contains(stderr.String(), c.stderr) {
				t.Errorf("stderr does not contain %q:\n%s", c.stderr, stderr.String())
			}
			if stdout.Len() > 0 {
				t.Errorf("unexpected stdout:\n%s", stdout.String())
			}
		})
	}
}

func TestCommandHelp(t *testing.T) {
	for _, cmd := range []string{"run", "probe", "import"} {
		var stdout, stderr bytes.Buffer
		if got := run([]string{cmd, "-h"}, &stdout, &stderr); got != exitOK {
			t.Errorf("%s -h: exit code %d", cmd, got)
		}
		if !strings.Contains(stderr.String(), "Usage: photofinish "+cmd) {
			t.Errorf("%s -h does not print its usage:\n%s", cmd, stderr.String())
		}
	}
}

func TestCombinedExitCode(t *testing.T) {
	cases := []struct {
		verdicts []runner.Verdict
		want     int
	}{
		{[]runner.Verdict{runner.Held}, 0},
		{[]runner.Verdict{runner.Held, runner.Held}, 0},
		{[]runner.Verdict{runner.Held, runner.Inconclusive}, 2},
		{[]runner.Verdict{runner.Inconclusive, runner.Violated, runner.Held}, 1},
		{[]runner.Verdict{runner.Violated, runner.Errored}, 3},
		{[]runner.Verdict{runner.Errored, runner.Held}, 3},
	}
	for _, c := range cases {
		if got := combinedExitCode(c.verdicts); got != c.want {
			t.Errorf("combinedExitCode(%v) = %d, want %d", c.verdicts, got, c.want)
		}
	}
}

func TestRunScenarioErrors(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(bad, []byte("version: 1\nname: Not A Valid Name\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "missing.yaml")
	out := filepath.Join(dir, "out")

	var stdout, stderr bytes.Buffer
	if got := run([]string{"run", missing, bad, "--out", out}, &stdout, &stderr); got != 3 {
		t.Errorf("exit code %d, want 3\nstdout: %s\nstderr: %s", got, stdout.String(), stderr.String())
	}
	for _, want := range []string{missing + ": ERROR", bad + ": ERROR"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("stdout does not contain %q:\n%s", want, stdout.String())
		}
	}
	for _, name := range []string{"missing.json", "bad.json"} {
		rep := readReport(t, filepath.Join(out, name))
		if rep.Verdict != runner.Errored || rep.Summary == "" || rep.Schema != runner.Schema {
			t.Errorf("%s: verdict %s, summary %q, schema %q", name, rep.Verdict, rep.Summary, rep.Schema)
		}
	}
}

// writeExample copies an example into dir with its target and scope pointed
// at addr and returns the new path.
func writeExample(t *testing.T, dir, name, addr string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(examplesDir, name))
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, bytes.ReplaceAll(data, []byte(exampleAddr), []byte(addr)), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func readReport(t *testing.T, path string) *runner.Report {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var rep runner.Report
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return &rep
}

// TestRunCommand drives "photofinish run" end to end against an in-process
// demo shop (Window = 2ms, see TestExamples): text output, --out and the
// combined exit code.
func TestRunCommand(t *testing.T) {
	addr := startShop(t, 2*time.Millisecond)
	dir := t.TempDir()
	vuln := writeExample(t, dir, "coupon-vuln.yaml", addr)
	fixed := writeExample(t, dir, "coupon-fixed.yaml", addr)
	out := filepath.Join(dir, "reports")

	var stdout, stderr bytes.Buffer
	got := run([]string{"run", vuln, fixed, "--engine", "h2", "--trials", "5", "--out", out}, &stdout, &stderr)
	if got != 1 {
		t.Errorf("exit code %d, want 1 (one scenario VIOLATED)\nstdout: %s\nstderr: %s", got, stdout.String(), stderr.String())
	}
	text := stdout.String()
	for _, want := range []string{
		"run " + vuln,
		"coupon-vuln: VIOLATED",
		"coupon-fixed: HELD",
		"failing terms in trial",
		"invariant  size(check.json.discounts) <= 1 && size(race.filter(r, r.status == 200)) <= 1",
		"reproduce  photofinish run",
		"report     " + filepath.Join(out, "coupon-vuln.json"),
	} {
		if !strings.Contains(text, want) {
			t.Errorf("stdout does not contain %q:\n%s", want, text)
		}
	}

	for name, want := range map[string]runner.Verdict{"coupon-vuln": runner.Violated, "coupon-fixed": runner.Held} {
		rep := readReport(t, filepath.Join(out, name+".json"))
		if rep.Verdict != want || rep.Scenario != name || len(rep.Trials) != 5 {
			t.Errorf("%s.json: verdict %s, scenario %q, %d trials", name, rep.Verdict, rep.Scenario, len(rep.Trials))
		}
		if rep.Tool != "photofinish "+version {
			t.Errorf("%s.json: tool %q", name, rep.Tool)
		}
	}
	// The demo token must not appear in the evidence.
	data, err := os.ReadFile(filepath.Join(out, "coupon-vuln.json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("demo-alice")) {
		t.Error("the report contains the unmasked token demo-alice")
	}
}

// TestRunCommandJSON checks that --format json prints exactly the report on
// stdout and that --quiet keeps progress off both streams.
func TestRunCommandJSON(t *testing.T) {
	addr := startShop(t, 0)
	fixed := writeExample(t, t.TempDir(), "coupon-fixed.yaml", addr)

	var stdout, stderr bytes.Buffer
	if got := run([]string{"run", fixed, "--trials", "2", "--format", "json", "--quiet"}, &stdout, &stderr); got != 0 {
		t.Errorf("exit code %d, want 0\nstdout: %s\nstderr: %s", got, stdout.String(), stderr.String())
	}
	var rep runner.Report
	dec := json.NewDecoder(&stdout)
	if err := dec.Decode(&rep); err != nil {
		t.Fatalf("stdout is not a JSON report: %v", err)
	}
	if dec.More() {
		t.Error("stdout has more than one JSON value for one scenario")
	}
	if rep.Verdict != runner.Held || rep.Scenario != "coupon-fixed" || rep.Schema != runner.Schema {
		t.Errorf("report: verdict %s, scenario %q, schema %q", rep.Verdict, rep.Scenario, rep.Schema)
	}
	if stderr.Len() > 0 {
		t.Errorf("--quiet still wrote to stderr:\n%s", stderr.String())
	}
}

func TestProbeCommand(t *testing.T) {
	addr := startShop(t, 0)
	var stdout, stderr bytes.Buffer
	if got := run([]string{"probe", "https://" + addr + "/healthz", "--insecure"}, &stdout, &stderr); got != exitOK {
		t.Fatalf("exit code %d\nstdout: %s\nstderr: %s", got, stdout.String(), stderr.String())
	}
	for _, want := range []string{"HTTP/2       yes", "ALPN h2", "Arrival      present", "Recommended  --engine h2", "Round trips"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("stdout does not contain %q:\n%s", want, stdout.String())
		}
	}

	// Without --insecure the self-signed certificate is rejected.
	stdout.Reset()
	stderr.Reset()
	if got := run([]string{"probe", "https://" + addr + "/healthz"}, &stdout, &stderr); got != exitFailure {
		t.Errorf("probe of a self-signed target without --insecure: exit code %d, want %d\nstdout: %s", got, exitFailure, stdout.String())
	}
}

const rawRequest = "POST /api/carts/42/coupons HTTP/1.1\r\n" +
	"Host: shop.example.test\r\n" +
	"Authorization: Bearer secret-token\r\n" +
	"Content-Type: application/json\r\n" +
	"\r\n" +
	`{"code":"WELCOME10"}`

func TestImportRaw(t *testing.T) {
	file := filepath.Join(t.TempDir(), "request.txt")
	if err := os.WriteFile(file, []byte(rawRequest), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if got := run([]string{"import", file}, &stdout, &stderr); got != exitOK {
		t.Fatalf("exit code %d\nstderr: %s", got, stderr.String())
	}
	if !strings.Contains(stdout.String(), "/api/carts/42/coupons") {
		t.Errorf("the skeleton does not contain the request:\n%s", stdout.String())
	}
	s, err := scenario.Parse(stdout.Bytes(), "imported.yaml")
	if err != nil {
		t.Fatalf("the skeleton is not a scenario document: %v", err)
	}
	if err := s.Validate(); err == nil || !strings.Contains(err.Error(), "check.invariant") {
		t.Errorf("validation of the skeleton: %v; its invariant placeholder must fail until it is written", err)
	}
	for _, want := range []string{"check.invariant", "scope.budget", "authorization", "${env:NAME}"} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("stderr does not contain %q:\n%s", want, stderr.String())
		}
	}
	if got := run([]string{"import", file, "--har-entry", "1"}, io.Discard, &stderr); got != exitUsage {
		t.Errorf("--har-entry on a raw request: exit code %d, want %d", got, exitUsage)
	}
}

const harDocument = `{"log": {"version": "1.2", "entries": [
  {"request": {"method": "GET", "url": "https://shop.example.test/api/me", "httpVersion": "HTTP/2",
    "headers": [], "queryString": [], "cookies": [], "headersSize": -1, "bodySize": 0}},
  {"request": {"method": "POST", "url": "https://shop.example.test/api/giftcards/GIFT-1/redeem", "httpVersion": "HTTP/2",
    "headers": [{"name": "Content-Type", "value": "application/json"}], "queryString": [], "cookies": [],
    "headersSize": -1, "bodySize": 2, "postData": {"mimeType": "application/json", "text": "{}"}}}
]}}`

func TestImportHAR(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "capture.har")
	if err := os.WriteFile(file, []byte(harDocument), 0o644); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(dir, "scenario.yaml")
	var stdout, stderr bytes.Buffer
	if got := run([]string{"import", file, "--har-entry", "1", "--output", output}, &stdout, &stderr); got != exitOK {
		t.Fatalf("exit code %d\nstderr: %s", got, stderr.String())
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "/api/giftcards/GIFT-1/redeem") {
		t.Errorf("the skeleton does not contain entry 1:\n%s", data)
	}
	if !strings.Contains(stdout.String(), "wrote "+output) || !strings.Contains(stdout.String(), "check.invariant") {
		t.Errorf("stdout:\n%s", stdout.String())
	}

	// An existing file is never overwritten.
	stderr.Reset()
	if got := run([]string{"import", file, "--output", output}, io.Discard, &stderr); got != exitFailure {
		t.Errorf("import over an existing file: exit code %d, want %d", got, exitFailure)
	}
	if !strings.Contains(stderr.String(), "already exists") {
		t.Errorf("stderr: %s", stderr.String())
	}

	stderr.Reset()
	if got := run([]string{"import", file, "--har-entry", "2"}, io.Discard, &stderr); got != exitUsage {
		t.Errorf("--har-entry out of range: exit code %d, want %d", got, exitUsage)
	}
	if !strings.Contains(stderr.String(), "has 2 entries") {
		t.Errorf("stderr: %s", stderr.String())
	}
}

func TestHarEntries(t *testing.T) {
	cases := []struct {
		data string
		n    int
		ok   bool
	}{
		{harDocument, 2, true},
		{"\xef\xbb\xbf" + `{"log":{"entries":[]}}`, 0, true},
		{`{"log":{}}`, 0, false},
		{`{"entries":[]}`, 0, false},
		{`[1,2]`, 0, false},
		{rawRequest, 0, false},
		{"", 0, false},
	}
	for _, c := range cases {
		if n, ok := harEntries([]byte(c.data)); n != c.n || ok != c.ok {
			t.Errorf("harEntries(%.30q) = %d, %v, want %d, %v", c.data, n, ok, c.n, c.ok)
		}
	}
}

func TestWriteSummary(t *testing.T) {
	pass, fail := true, false
	rep := &runner.Report{
		Scenario:  "coupon-vuln",
		File:      "examples/coupon-vuln.yaml",
		Target:    "https://127.0.0.1:8443/vuln/api",
		Engine:    engine.H2,
		Copies:    20,
		Invariant: "size(check.json.discounts) <= 1 &&\n  size(race.filter(r, r.status == 200)) <= 1\n",
		Explain:   "A single-use coupon must apply at most once per cart.",
		Verdict:   runner.Violated,
		Summary:   "1 of 2 trials broke the rule",
		Reproduce: "photofinish run examples/coupon-vuln.yaml --engine h2 --trials 2 --copies 20",
		Trials: []runner.Trial{
			{Number: 1, Verdict: runner.Held, Terms: []check.Term{{Expr: "size(check.json.discounts) <= 1", Value: "1 <= 1", Pass: &pass}}},
			{Number: 2, Verdict: runner.Violated, Terms: []check.Term{
				{Expr: "size(check.json.discounts) <= 1", Value: "3 <= 1", Pass: &fail},
				{Expr: "size(race.filter(r, r.status == 200)) <= 1", Value: "1 <= 1", Pass: &pass},
			}},
		},
	}
	var b bytes.Buffer
	writeSummary(&b, rep)
	got := b.String()
	for _, want := range []string{
		"coupon-vuln: VIOLATED\n",
		"  1 of 2 trials broke the rule\n",
		"  invariant  size(check.json.discounts) <= 1 && size(race.filter(r, r.status == 200)) <= 1\n",
		"  target     https://127.0.0.1:8443/vuln/api (engine h2, 20 copies)\n",
		"  trials     2 run: 1 violated, 1 held\n",
		"  failing terms in trial 2:\n    FAIL  size(check.json.discounts) <= 1    (3 <= 1)\n",
		"  reproduce  photofinish run examples/coupon-vuln.yaml",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("summary does not contain %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "1 <= 1") {
		t.Errorf("summary lists a passing term:\n%s", got)
	}
}
