package runner

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/TroubieD3v/photofinish/internal/engine"
	"github.com/TroubieD3v/photofinish/internal/scenario"
)

func TestMaskingEncodedSecrets(t *testing.T) {
	const pw = `hu"nt&er<2>\x`
	const name = "Grüße-secret"
	m := newMasker()
	m.addSecret(pw)
	m.addSecret(name)
	sc := m.scrubber()

	escaped, _ := json.Marshal(map[string]any{"got": map[string]string{"pw": pw}})
	if got := string(sc.body(escaped)); strings.Contains(got, "nt") {
		t.Errorf("HTML-escaped JSON echo not masked: %s", got)
	}
	var plain strings.Builder
	enc := json.NewEncoder(&plain)
	enc.SetEscapeHTML(false)
	enc.Encode(map[string]string{"pw": pw})
	if got := sc.str(plain.String()); strings.Contains(got, "nt") {
		t.Errorf("JSON echo not masked: %s", got)
	}
	if got := sc.str("value " + strconv.Quote(pw)); strings.Contains(got, "nt") {
		t.Errorf("quoted form not masked: %s", got)
	}
	for _, s := range []string{url.PathEscape(name), url.QueryEscape(name), url.QueryEscape(pw), url.PathEscape(pw)} {
		if got := sc.url("https://h/api/state/" + s + "?q=" + s); strings.Contains(got, "secret") || strings.Contains(got, "nt") {
			t.Errorf("percent-encoded form %q not masked: %s", s, got)
		}
	}
}

func TestMaskingSetCookieAttributes(t *testing.T) {
	m := newMasker()
	m.harvestHeader(http.Header{"Set-Cookie": {"sid=abcdefsecret; Domain=127.0.0.1; Path=/api; Max-Age=3600; SameSite=Lax"}})
	m.harvestHeader(http.Header{"Cookie": {"a=cookieone; b=cookietwo"}})
	m.harvestJSON([]byte(`{"session":{"tokens":100,"id":"sess-string-1"},"balance":100,"flag":true}`))
	sc := m.scrubber()
	for in, want := range map[string]string{
		"https://127.0.0.1:49372/api/state": "https://127.0.0.1:49372/api/state",
		"check.json.balance == 3600":        "check.json.balance == 3600",
		"100 <= 99":                         "100 <= 99",
		"Lax true":                          "Lax true",
		"abcdefsecret cookieone cookietwo sess-string-1 x": "[masked] [masked] [masked] [masked] x",
	} {
		if got := sc.str(in); got != want {
			t.Errorf("str(%q) = %q, want %q", in, got, want)
		}
	}
	if got := string(sc.body([]byte(`{"session":{"tokens":100},"balance":100}`))); got != `{"balance":100,"session":"[masked]"}` {
		t.Errorf("body %s", got)
	}
}

func TestMaskingTruncatedBody(t *testing.T) {
	cut := []byte(`{"token":"SECRETBIG1234567","n":{"api_key":12345,"x":"ok"},"Password": "half-a-sec`)
	m := newMasker()
	m.harvestJSON(cut)
	sc := m.scrubber()
	got := string(sc.body(cut))
	for _, s := range []string{"SECRETBIG1234567", "12345", "half-a-sec"} {
		if strings.Contains(got, s) {
			t.Errorf("truncated body keeps %q: %s", s, got)
		}
	}
	if !strings.Contains(got, `"x":"ok"`) {
		t.Errorf("truncated body lost a plain value: %s", got)
	}
	// The value harvested from the cut body is masked elsewhere too.
	if got := sc.str("echo SECRETBIG1234567"); got != "echo [masked]" {
		t.Errorf("str %q", got)
	}
}

func TestMaskingLargeRaceBody(t *testing.T) {
	// The engine cuts the body at MaxBody, so it no longer parses as JSON.
	t.Setenv("PF_RUNNER_TEST_TOKEN", envToken)
	sh := newShop(t)
	body := `{"token":"SECRETBIG1234567","pad":"` + strings.Repeat("x", 70000) + `"}`
	installEngine(t, sh, always(trialPlan{ok: 1, body: body[:engine.DefaultMaxBody]}))
	rep := mustRun(t, testScenario(sh, 1), Options{})
	data, _ := json.Marshal(rep)
	if strings.Contains(string(data), "SECRETBIG1234567") || strings.Contains(string(rep.Trials[0].Race.Results[0].Body), "SECRETBIG") {
		t.Error("the truncated race body keeps the token")
	}
}

func TestMaskingLargeStepBody(t *testing.T) {
	// A short value under a sensitive key is not harvested as a secret; it
	// must be masked by key before the body is cut for the report.
	t.Setenv("PF_RUNNER_TEST_TOKEN", envToken)
	sh := newShop(t)
	sh.checkBody.Store(`{"discounts":[],"token":"q1","pad":"` + strings.Repeat("x", maxRecordBody+10) + `"}`)
	installEngine(t, sh, always(trialPlan{ok: 1}))
	rep := mustRun(t, testScenario(sh, 1), Options{})
	b := rep.Trials[0].Check.Body
	if len(b) > maxRecordBody || !strings.HasPrefix(b, `{"discounts":[]`) {
		t.Fatalf("check body of %d bytes starts %q", len(b), b[:min(len(b), 60)])
	}
	if strings.Contains(b, `"q1"`) {
		t.Error("the cut check body keeps the token")
	}
}

func TestMaskingEnvValueInBuildError(t *testing.T) {
	t.Setenv("PF_RUNNER_TEST_TOKEN", envToken)
	t.Setenv("PF_RUNNER_TEST_P", "my secret value")
	sh := newShop(t)
	installEngine(t, sh, always(trialPlan{ok: 1}))
	s := testScenario(sh, 1)
	s.Setup[0] = scenario.Step{ID: "e", Request: "GET /cookie?x=1&q=${env:PF_RUNNER_TEST_P}"}
	rep := mustRun(t, s, Options{})
	if rep.Verdict != Errored {
		t.Fatalf("verdict %s summary %q", rep.Verdict, rep.Summary)
	}
	data, _ := json.Marshal(rep)
	if strings.Contains(string(data), "my secret value") || !strings.Contains(rep.Summary, "contains spaces") {
		t.Errorf("summary %q", rep.Summary)
	}
}

func TestMaskingSensitiveQueryInErrors(t *testing.T) {
	t.Setenv("PF_RUNNER_TEST_TOKEN", envToken)
	sh := newShop(t)
	installEngine(t, sh, always(trialPlan{ok: 1}))
	s := testScenario(sh, 1)
	s.Setup[0] = scenario.Step{Request: "POST /reset?api_key=LITERALKEY99"}
	sh.srv.Close() // the step fails with an error that quotes the URL
	rep := mustRun(t, s, Options{})
	if rep.Verdict != Errored {
		t.Fatalf("verdict %s summary %q", rep.Verdict, rep.Summary)
	}
	data, _ := json.Marshal(rep)
	if strings.Contains(string(data), "LITERALKEY99") {
		t.Errorf("report keeps the query secret: summary %q, step %+v", rep.Summary, rep.Trials[0].Setup[0])
	}
	if !strings.Contains(rep.Trials[0].Setup[0].URL, "api_key=[masked]") {
		t.Errorf("step URL %q", rep.Trials[0].Setup[0].URL)
	}
}

func TestTermValueCapDoesNotLeakSecrets(t *testing.T) {
	t.Setenv("PF_RUNNER_TEST_TOKEN", envToken)
	sh := newShop(t)
	sh.checkBody.Store(`{"discounts":[],"profile":{"a":"` + strings.Repeat("x", 160) +
		`","api_key":"fake-key-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"}}`)
	installEngine(t, sh, always(trialPlan{ok: 1}))
	s := testScenario(sh, 1)
	s.Check.Invariant = "check.json.profile == null"
	rep := mustRun(t, s, Options{})
	data, _ := json.Marshal(rep)
	if strings.Contains(string(data), "fake-key-ABC") {
		t.Errorf("terms %+v", rep.Trials[0].Terms)
	}
}
