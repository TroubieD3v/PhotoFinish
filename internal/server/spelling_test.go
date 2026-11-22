package server

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TroubieD3v/photofinish/internal/runner"
	"github.com/TroubieD3v/photofinish/internal/store"
)

// refusedSpelling sends every file request for p and fails the test when
// one of them succeeds.
func refusedSpelling(t *testing.T, e *env, p string) {
	t.Helper()
	q := "?path=" + url.QueryEscape(p)
	for _, req := range []request{
		{path: "/api/scenarios/file" + q},
		{method: "PUT", path: "/api/scenarios/file" + q, body: `{"content":"name: pwned\n"}`},
		{method: "DELETE", path: "/api/scenarios/file" + q},
		{method: "POST", path: "/api/runs", body: map[string]string{"path": p}},
		{method: "POST", path: "/api/runs", body: map[string]any{"path": p, "content": "version: 1\n"}},
	} {
		if r := e.do(req); r.code < 400 {
			t.Errorf("%s %s: status %d: %s", valueOr(req.method, "GET"), p, r.code, r.body)
		}
	}
}

func TestOtherLetterCaseIsRefused(t *testing.T) {
	e := newEnv(t)
	e.write("sub/ok.yaml", minimal)
	if _, err := os.Stat(filepath.Join(e.workspace, "SUB", "OK.YAML")); err != nil {
		t.Skip("the file system is case-sensitive: SUB/OK.YAML is another file")
	}
	for _, p := range []string{"SUB/OK.YAML", "sub/OK.yaml", "Sub/ok.yaml"} {
		refusedSpelling(t, e, p)
	}
	data, err := os.ReadFile(filepath.Join(e.workspace, "sub", "ok.yaml"))
	if err != nil || string(data) != minimal {
		t.Errorf("sub/ok.yaml changed: %q %v", data, err)
	}
	// The real spelling still works.
	want(t, e.get("/api/scenarios/file?path=sub/ok.yaml"), http.StatusOK)
}

func TestShortNamesDoNotReachDotDirectories(t *testing.T) {
	e := newEnv(t)
	e.write(".github/workflows/ci.yml", "name: ci\n")
	e.write(".hidden/h.yaml", "name: hidden\n")
	short := shortName(filepath.Join(e.workspace, ".hidden"))
	if short == "" || short == ".hidden" {
		t.Skip("no 8.3 short names on this file system")
	}
	refusedSpelling(t, e, short+"/h.yaml")
	refusedSpelling(t, e, short+"/w.yaml")
	if gh := shortName(filepath.Join(e.workspace, ".github")); gh != "" {
		if wf := shortName(filepath.Join(e.workspace, ".github", "workflows")); wf != "" {
			refusedSpelling(t, e, gh+"/"+wf+"/ci.yml")
		}
	}
	if data, err := os.ReadFile(filepath.Join(e.workspace, ".github", "workflows", "ci.yml")); err != nil || string(data) != "name: ci\n" {
		t.Errorf("the workflow changed: %q %v", data, err)
	}
	if _, err := os.Stat(filepath.Join(e.workspace, ".hidden", "w.yaml")); !os.IsNotExist(err) {
		t.Errorf("a file was written into .hidden: %v", err)
	}
	if data, _ := os.ReadFile(filepath.Join(e.workspace, ".hidden", "h.yaml")); string(data) != "name: hidden\n" {
		t.Errorf(".hidden/h.yaml changed: %q", data)
	}
}

// violatedReport stores a finished VIOLATED run of file and returns its id.
func violatedReport(t *testing.T, e *env, file string) string {
	t.Helper()
	rep := runner.Report{
		Schema: runner.Schema, Tool: "photofinish test", Scenario: "secret", File: file,
		Verdict: runner.Violated, Summary: "The invariant was violated.", Trials: []runner.Trial{},
		StartedAt: time.Now(), FinishedAt: time.Now(),
	}
	data, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	rec := &store.Run{Scenario: "secret", File: file, Verdict: runner.Violated, StartedAt: rep.StartedAt, FinishedAt: rep.FinishedAt, Report: data}
	if err := e.store.Save(rec); err != nil {
		t.Fatal(err)
	}
	return rec.ID
}

// sarifStartLine downloads the SARIF report of a run and returns the start
// line of its first result.
func sarifStartLine(t *testing.T, e *env, id string) int {
	t.Helper()
	r := e.get("/api/runs/" + id + "/report.sarif")
	want(t, r, http.StatusOK)
	var log struct {
		Runs []struct {
			Results []struct {
				Locations []struct {
					Physical struct {
						Region struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(r.body, &log); err != nil {
		t.Fatal(err)
	}
	if len(log.Runs) != 1 || len(log.Runs[0].Results) != 1 || len(log.Runs[0].Results[0].Locations) != 1 {
		t.Fatalf("sarif %s", r.body)
	}
	return log.Runs[0].Results[0].Locations[0].Physical.Region.StartLine
}

// invariantAt is a scenario whose check.invariant is on the given line.
func invariantAt(line int) string {
	return strings.Repeat("# padding\n", line-2) + "check:\n  invariant: size(race) == 1\n"
}

func TestSARIFReadsTheScenarioInsideTheWorkspaceOnly(t *testing.T) {
	e := newEnv(t)
	e.write("inside.yaml", invariantAt(12))
	if got := sarifStartLine(t, e, violatedReport(t, e, "inside.yaml")); got != 12 {
		t.Errorf("inside the workspace: start line %d, want 12", got)
	}

	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.yaml"), []byte(invariantAt(30)), 0o644); err != nil {
		t.Fatal(err)
	}
	// The run names a file that a link, made after the run, points out of
	// the workspace: the report must not read it.
	id := violatedReport(t, e, "junc/secret.yaml")
	linkDir(t, outside, filepath.Join(e.workspace, "junc"))
	if got := sarifStartLine(t, e, id); got != 1 {
		t.Errorf("through a link out of the workspace: start line %d, want 1", got)
	}
	// A run cannot name such a file in the first place.
	r := e.post("/api/runs", map[string]any{"path": "junc/secret.yaml", "content": invariantAt(5)})
	if r.code != http.StatusForbidden {
		t.Errorf("run naming a file outside: %d %s", r.code, r.body)
	}
}

func TestHistoryWhileRunningAndFilters(t *testing.T) {
	e := newEnv(t)
	g := newGate(t)
	content := strings.Replace(g.scenario("auto-gated", 5), "engine: h1", "engine: auto", 1)
	id := e.startRun(map[string]any{"content": content})
	g.waitEntered(t)
	var list []runJSON
	e.get("/api/runs").json(t, &list)
	if len(list) != 1 || list[0].Engine != "auto" {
		t.Errorf("before the first race: %+v", list)
	}
	// After the first race the history shows the engine auto resolved to,
	// as the stored run will.
	g.release <- struct{}{}
	g.waitEntered(t)
	e.get("/api/runs").json(t, &list)
	if len(list) != 1 || list[0].Status != statusRunning || list[0].Engine != "h1" {
		t.Errorf("after the first race: %+v", list)
	}
	var names []string
	e.get("/api/runs/scenarios").json(t, &names)
	if strings.Join(names, ",") != "auto-gated" {
		t.Errorf("scenario names while running: %v", names)
	}
	want(t, e.post("/api/runs/"+id+"/cancel", nil), http.StatusAccepted)
	d := e.waitRun(id)

	// Older runs of other scenarios are found by the filters however many
	// newer runs there are.
	old := violatedReport(t, e, "old.yaml")
	for range 5 {
		if err := e.store.Save(&store.Run{Scenario: "busy", File: "busy.yaml", Verdict: runner.Held, StartedAt: time.Now(), FinishedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	e.get("/api/runs?limit=3&scenario=secret").json(t, &list)
	if len(list) != 1 || list[0].ID != old {
		t.Errorf("scenario filter: %+v", list)
	}
	e.get("/api/runs?limit=3&verdict=VIOLATED").json(t, &list)
	if len(list) != 1 || list[0].ID != old {
		t.Errorf("verdict filter: %+v", list)
	}
	e.get("/api/runs?verdict="+string(d.Run.Verdict)+"&scenario=auto-gated").json(t, &list)
	if len(list) != 1 || list[0].ID != id {
		t.Errorf("both filters: %+v", list)
	}
	want(t, e.get("/api/runs?verdict=violated"), http.StatusBadRequest)
	e.get("/api/runs/scenarios").json(t, &names)
	if strings.Join(names, ",") != "auto-gated,busy,secret" {
		t.Errorf("scenario names: %v", names)
	}
}
