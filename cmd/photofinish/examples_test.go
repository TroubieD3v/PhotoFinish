package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TroubieD3v/photofinish/internal/demo"
	"github.com/TroubieD3v/photofinish/internal/engine"
	"github.com/TroubieD3v/photofinish/internal/runner"
	"github.com/TroubieD3v/photofinish/internal/scenario"
)

// examplesDir holds the scenarios for the demo shop, relative to this package.
const examplesDir = "../../examples"

// exampleAddr is the demo address the example files are written for. The
// tests replace it with the address of an in-process shop.
const exampleAddr = "127.0.0.1:8443"

// exampleTrials is the number of trials per example in the integration tests.
const exampleTrials = 15

// wantExamples lists the example files; every scenario exists for both variants.
var wantExamples = []string{
	"coupon-fixed.yaml", "coupon-vuln.yaml",
	"giftcard-fixed.yaml", "giftcard-vuln.yaml",
	"transfer-fixed.yaml", "transfer-vuln.yaml",
	"twofa-fixed.yaml", "twofa-vuln.yaml",
}

// exampleFiles returns the paths of the example scenarios and checks that the
// set is complete.
func exampleFiles(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(examplesDir, "*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, f := range files {
		names = append(names, filepath.Base(f))
	}
	slices.Sort(names)
	if !slices.Equal(names, wantExamples) {
		t.Fatalf("examples %v, want %v", names, wantExamples)
	}
	return files
}

// startShop serves a fresh demo shop with the given /vuln window on a free
// loopback port until the test ends and returns its address.
func startShop(t *testing.T, window time.Duration) string {
	t.Helper()
	shop, err := demo.New(demo.Config{Window: window})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	addrc := make(chan string, 1)
	errc := make(chan error, 1)
	go func() {
		errc <- demo.Serve(ctx, "127.0.0.1:0", shop, func(addr, _ string) { addrc <- addr })
	}()
	t.Cleanup(func() {
		cancel()
		if err := <-errc; err != nil {
			t.Errorf("demo shop: %v", err)
		}
		shop.Close()
	})
	select {
	case addr := <-addrc:
		return addr
	case err := <-errc:
		errc <- err // let the cleanup see it too
		t.Fatalf("demo shop did not start: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("demo shop was not ready within 10s")
	}
	return ""
}

// loadExample parses an example with its target and scope pointed at addr.
func loadExample(t *testing.T, file, addr string) *scenario.Scenario {
	t.Helper()
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte(exampleAddr)) {
		t.Fatalf("%s does not mention %s", file, exampleAddr)
	}
	data = bytes.ReplaceAll(data, []byte(exampleAddr), []byte(addr))
	s, err := scenario.Parse(data, file)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	return s
}

// runExample runs one example against the shop at addr with the h2 engine.
func runExample(t *testing.T, file, addr string) *runner.Report {
	t.Helper()
	s := loadExample(t, file, addr)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	rep, err := runner.Run(ctx, s, runner.Options{Engine: engine.H2, Trials: exampleTrials})
	if err != nil {
		t.Fatalf("run %s: %v", file, err)
	}
	if rep == nil {
		t.Fatalf("run %s: no report", file)
	}
	return rep
}

// countTrials returns how many trials of rep ended with verdict v.
func countTrials(rep *runner.Report, v runner.Verdict) int {
	n := 0
	for _, tr := range rep.Trials {
		if tr.Verdict == v {
			n++
		}
	}
	return n
}

// TestExamples runs every example against an in-process demo shop with the h2
// engine: every *-vuln scenario must be VIOLATED and every *-fixed one HELD.
//
// The shop runs with Window = 2ms, an artificial pause between check and write
// in the /vuln handlers. Without it the race is real but only a few
// microseconds wide, and on a slow or loaded CI machine (the race detector
// slows everything down) a vuln example could miss it in all 15 trials. The
// pause changes nothing for /fixed, whose handlers are atomic, so HELD there
// is still a meaningful result. TestExamplesNoWindow measures the real,
// narrow race without asserting anything.
func TestExamples(t *testing.T) {
	for _, file := range exampleFiles(t) {
		name := strings.TrimSuffix(filepath.Base(file), ".yaml")
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			// Each example gets its own shop: the scenarios reset the state of
			// their variant before every trial and must not interfere.
			addr := startShop(t, 2*time.Millisecond)
			rep := runExample(t, file, addr)

			want := runner.Held
			if strings.HasSuffix(name, "-vuln") {
				want = runner.Violated
			}
			if rep.Verdict != want {
				t.Errorf("verdict %s, want %s: %s", rep.Verdict, want, rep.Summary)
				for _, tr := range rep.Trials {
					t.Logf("trial %d: %s %v", tr.Number, tr.Verdict, tr.Reasons)
				}
			}
			if len(rep.Trials) != exampleTrials {
				t.Errorf("%d trials ran, want %d", len(rep.Trials), exampleTrials)
			}
			if rep.Engine != engine.H2 {
				t.Errorf("engine %q, want h2", rep.Engine)
			}
			if want == runner.Held && countTrials(rep, runner.Violated) > 0 {
				t.Errorf("a /fixed example broke its invariant in %d trials", countTrials(rep, runner.Violated))
			}
			t.Logf("%s: %s, %d of %d trials violated", name, rep.Verdict, countTrials(rep, runner.Violated), len(rep.Trials))
		})
	}
}

// TestExamplesNoWindow runs every example against a shop without the
// artificial pause and only logs how often each one broke its invariant: the
// rate depends on the machine, so there is nothing stable to assert.
func TestExamplesNoWindow(t *testing.T) {
	if testing.Short() {
		t.Skip("measurement only; skipped with -short")
	}
	files := exampleFiles(t)
	// One shop for all examples, run one after the other, so that the rates
	// are not distorted by concurrent load.
	addr := startShop(t, 0)
	for _, file := range files {
		name := strings.TrimSuffix(filepath.Base(file), ".yaml")
		rep := runExample(t, file, addr)
		t.Logf("window 0: %-15s %-12s violated %2d, held %2d, inconclusive %2d of %d trials",
			name, rep.Verdict, countTrials(rep, runner.Violated), countTrials(rep, runner.Held),
			countTrials(rep, runner.Inconclusive), len(rep.Trials))
	}
}
