package report

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"flag"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/TroubieD3v/photofinish/internal/runner"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata/golden")

// golden compares got with testdata/golden/name, or rewrites the file with
// -update. Line endings are normalized so that a checkout with CRLF still
// compares equal.
func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", "golden", name)
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test ./internal/report -update to create it)", err)
	}
	want = bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n"))
	if !bytes.Equal(got, want) {
		t.Errorf("%s differs from the golden file; run go test ./internal/report -update and review the diff\n%s",
			name, firstDiff(string(got), string(want)))
	}
}

// firstDiff shows the first differing line.
func firstDiff(got, want string) string {
	g, w := strings.Split(got, "\n"), strings.Split(want, "\n")
	for i := 0; i < len(g) || i < len(w); i++ {
		var gl, wl string
		if i < len(g) {
			gl = g[i]
		}
		if i < len(w) {
			wl = w[i]
		}
		if gl != wl {
			return "line " + strconv.Itoa(i+1) + ":\n got:  " + gl + "\n want: " + wl
		}
	}
	return ""
}

// render runs one renderer over the fixture.
func render(t *testing.T, f func(io.Writer, []*runner.Report) error, reps []*runner.Report) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := f(&buf, reps); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// sarifFixture renders the fixture as SARIF with testdata as the base and
// replaces the machine-specific base URI with a placeholder.
func sarifFixture(t *testing.T, reps []*runner.Report) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := SARIF(&buf, reps, SARIFOptions{BaseDir: "testdata"}); err != nil {
		t.Fatal(err)
	}
	abs, err := filepath.Abs("testdata")
	if err != nil {
		t.Fatal(err)
	}
	return bytes.ReplaceAll(buf.Bytes(), []byte(baseURI(abs)), []byte("file:///BASE/"))
}

func TestGoldenJSON(t *testing.T) {
	golden(t, "report.json", render(t, JSON, fixture()))
}

func TestGoldenSARIF(t *testing.T) {
	golden(t, "report.sarif", sarifFixture(t, fixture()))
}

func TestGoldenJUnit(t *testing.T) {
	golden(t, "report.junit.xml", render(t, JUnit, fixture()))
}

func TestGoldenHTML(t *testing.T) {
	golden(t, "report.html", render(t, HTML, fixture()))
}

func TestJSONShape(t *testing.T) {
	reps := fixture()
	one := render(t, JSON, reps[:1])
	var obj map[string]any
	if err := json.Unmarshal(one, &obj); err != nil {
		t.Fatalf("one report is not a JSON object: %v", err)
	}
	if obj["scenario"] != "coupon-vuln" || obj["schema"] != runner.Schema {
		t.Errorf("object = scenario %v schema %v", obj["scenario"], obj["schema"])
	}
	if !bytes.Contains(one, []byte(`size(check.json.discounts) <= 1`)) {
		t.Error("HTML escaping is on: invariants are not readable")
	}
	var arr []map[string]any
	if err := json.Unmarshal(render(t, JSON, reps), &arr); err != nil || len(arr) != 4 {
		t.Fatalf("several reports: %d elements, err %v", len(arr), err)
	}
	if got := string(render(t, JSON, nil)); got != "[]\n" {
		t.Errorf("no reports = %q, want []", got)
	}
}

func TestNilReport(t *testing.T) {
	reps := []*runner.Report{fixture()[0], nil}
	for name, f := range map[string]func(io.Writer, []*runner.Report) error{
		"json":  JSON,
		"junit": JUnit,
		"html":  HTML,
		"sarif": func(w io.Writer, r []*runner.Report) error { return SARIF(w, r, SARIFOptions{}) },
	} {
		if err := f(io.Discard, reps); err == nil {
			t.Errorf("%s accepted a nil report", name)
		}
	}
	if err := HTML(io.Discard, nil); err == nil {
		t.Error("HTML rendered no reports")
	}
}

func TestSARIFSchema(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "sarif-2.1.0.json"))
	if err != nil {
		t.Fatal(err)
	}
	schema, err := newJSONSchema(data)
	if err != nil {
		t.Fatal(err)
	}
	for name, reps := range map[string][]*runner.Report{
		"fixture":   fixture(),
		"held only": fixture()[1:2],
		"none":      nil,
	} {
		var buf bytes.Buffer
		if err := SARIF(&buf, reps, SARIFOptions{BaseDir: "testdata"}); err != nil {
			t.Fatal(err)
		}
		errs, err := schema.Validate(buf.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range errs {
			t.Errorf("%s: %s", name, e)
		}
	}

	// The validator itself must catch a broken log.
	broken := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x","rules":[{"id":"PF001",` +
		`"defaultConfiguration":{"level":"fatal"}}]}},"results":[{"message":{"text":"m"},"level":"error",` +
		`"locations":[{"physicalLocation":{"region":{"startLine":0}}}]}],"bogus":1}]}`
	errs, err := schema.Validate([]byte(broken))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"level", "startLine", "bogus"} {
		found := false
		for _, e := range errs {
			found = found || strings.Contains(e, want)
		}
		if !found {
			t.Errorf("the validator missed the bad %s in %v", want, errs)
		}
	}
}

// sarifDoc is the part of a SARIF log the tests inspect.
type sarifDoc struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []struct {
		Tool struct {
			Driver struct {
				Name           string `json:"name"`
				Version        string `json:"version"`
				InformationURI string `json:"informationUri"`
				Rules          []struct {
					ID                   string `json:"id"`
					Name                 string `json:"name"`
					DefaultConfiguration struct {
						Level string `json:"level"`
					} `json:"defaultConfiguration"`
					Properties map[string]any `json:"properties"`
				} `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Invocations []struct {
			ExecutionSuccessful bool `json:"executionSuccessful"`
			Notifications       []struct {
				Level   string `json:"level"`
				Message struct {
					Text string `json:"text"`
				} `json:"message"`
			} `json:"toolExecutionNotifications"`
		} `json:"invocations"`
		OriginalURIBaseIDs map[string]struct {
			URI string `json:"uri"`
		} `json:"originalUriBaseIds"`
		Results []struct {
			RuleID    string `json:"ruleId"`
			RuleIndex int    `json:"ruleIndex"`
			Level     string `json:"level"`
			Message   struct {
				Text string `json:"text"`
			} `json:"message"`
			Locations []struct {
				PhysicalLocation struct {
					ArtifactLocation struct {
						URI       string `json:"uri"`
						URIBaseID string `json:"uriBaseId"`
					} `json:"artifactLocation"`
					Region struct {
						StartLine int `json:"startLine"`
					} `json:"region"`
				} `json:"physicalLocation"`
			} `json:"locations"`
			PartialFingerprints map[string]string `json:"partialFingerprints"`
			Properties          map[string]any    `json:"properties"`
		} `json:"results"`
	} `json:"runs"`
}

func decodeSARIF(t *testing.T, reps []*runner.Report, opts SARIFOptions) sarifDoc {
	t.Helper()
	var buf bytes.Buffer
	if err := SARIF(&buf, reps, opts); err != nil {
		t.Fatal(err)
	}
	var doc sarifDoc
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Runs) != 1 || len(doc.Runs[0].Invocations) != 1 {
		t.Fatalf("want one run with one invocation, got %+v", doc)
	}
	return doc
}

func TestSARIFContent(t *testing.T) {
	doc := decodeSARIF(t, fixture(), SARIFOptions{BaseDir: "testdata"})
	if doc.Version != "2.1.0" || doc.Schema == "" {
		t.Errorf("version %q schema %q", doc.Version, doc.Schema)
	}
	run := doc.Runs[0]
	d := run.Tool.Driver
	if d.Name != "PhotoFinish" || d.Version != "0.3.0-test" || d.InformationURI != "https://github.com/TroubieD3v/PhotoFinish" {
		t.Errorf("driver = %q %q %q", d.Name, d.Version, d.InformationURI)
	}
	if len(d.Rules) != 2 || d.Rules[0].ID != "PF001" || d.Rules[1].ID != "PF002" {
		t.Fatalf("rules = %+v", d.Rules)
	}
	r0 := d.Rules[0]
	if r0.Name != "InvariantViolatedUnderConcurrency" || r0.DefaultConfiguration.Level != "error" ||
		r0.Properties["security-severity"] != "7.5" {
		t.Errorf("PF001 = %+v", r0)
	}
	if tags, _ := json.Marshal(r0.Properties["tags"]); string(tags) != `["security","race-condition"]` {
		t.Errorf("PF001 tags = %s", tags)
	}
	if d.Rules[1].Name != "RaceTestInconclusive" || d.Rules[1].DefaultConfiguration.Level != "warning" {
		t.Errorf("PF002 = %+v", d.Rules[1])
	}

	base := run.OriginalURIBaseIDs["%SRCROOT%"].URI
	if !strings.HasPrefix(base, "file:///") || !strings.HasSuffix(base, "/internal/report/testdata/") || strings.Contains(base, `\`) {
		t.Errorf("%%SRCROOT%% = %q", base)
	}

	inv := run.Invocations[0]
	if inv.ExecutionSuccessful {
		t.Error("executionSuccessful is true with an ERROR scenario")
	}
	if len(inv.Notifications) != 1 || inv.Notifications[0].Level != "error" ||
		!strings.HasPrefix(inv.Notifications[0].Message.Text, "broken: invalid scenario") {
		t.Errorf("notifications = %+v", inv.Notifications)
	}

	if len(run.Results) != 2 {
		t.Fatalf("%d results, want 2 (VIOLATED and INCONCLUSIVE)", len(run.Results))
	}
	v, i := run.Results[0], run.Results[1]
	if v.RuleID != "PF001" || v.RuleIndex != 0 || v.Level != "error" {
		t.Errorf("violated result = %s %d %s", v.RuleID, v.RuleIndex, v.Level)
	}
	if i.RuleID != "PF002" || i.RuleIndex != 1 || i.Level != "warning" {
		t.Errorf("inconclusive result = %s %d %s", i.RuleID, i.RuleIndex, i.Level)
	}
	wantMsg := "1 of 3 trials broke the rule (h2, median response spread 0.32 ms). Failing in trial 1: " +
		"size(check.json.discounts) <= 1 was 3 <= 1; size(race.filter(r, r.status == 200)) <= 1 was 3 <= 1."
	if v.Message.Text != wantMsg {
		t.Errorf("message = %q\nwant      %q", v.Message.Text, wantMsg)
	}
	loc := v.Locations[0].PhysicalLocation
	if loc.ArtifactLocation.URI != "scenarios/coupon-vuln.yaml" || loc.ArtifactLocation.URIBaseID != "%SRCROOT%" || loc.Region.StartLine != 39 {
		t.Errorf("location = %+v", loc)
	}
	if il := i.Locations[0].PhysicalLocation; il.Region.StartLine != 33 {
		t.Errorf("inconclusive startLine = %d, want 33", il.Region.StartLine)
	}
	if fp := v.PartialFingerprints["photofinish/v1"]; !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(fp) {
		t.Errorf("fingerprint = %q", fp)
	}
	for _, k := range []string{"target", "engine", "trials", "violated", "inconclusive", "medianResponseSpreadNs", "medianServerArrivalSpreadNs"} {
		if _, ok := v.Properties[k]; !ok {
			t.Errorf("result property %s is missing", k)
		}
	}
	if _, ok := i.Properties["medianServerArrivalSpreadNs"]; ok {
		t.Error("medianServerArrivalSpreadNs is set although the target reported no arrival times")
	}

	ok := decodeSARIF(t, fixture()[1:2], SARIFOptions{BaseDir: "testdata"})
	if !ok.Runs[0].Invocations[0].ExecutionSuccessful || len(ok.Runs[0].Results) != 0 {
		t.Errorf("HELD only: successful %v, %d results", ok.Runs[0].Invocations[0].ExecutionSuccessful, len(ok.Runs[0].Results))
	}
}

func TestSARIFFingerprintIgnoresHostAndLayout(t *testing.T) {
	a, b := fixture()[0], fixture()[0]
	b.Target = "https://staging.example.test:9443/vuln/api"
	b.Invariant = "size(check.json.discounts) <= 1 && size(race.filter(r, r.status == 200)) <= 1"
	if fingerprint(a) != fingerprint(b) {
		t.Error("the fingerprint changed with the host or the invariant's line breaks")
	}
	b.Target = "https://127.0.0.1:8443/fixed/api"
	if fingerprint(a) == fingerprint(b) {
		t.Error("the fingerprint ignores the target path")
	}
}

func TestSARIFLocationOutsideBase(t *testing.T) {
	rep := fixture()[0]
	doc := decodeSARIF(t, []*runner.Report{rep}, SARIFOptions{BaseDir: filepath.Join("testdata", "scenarios", "nested")})
	loc := doc.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation
	if !strings.HasPrefix(loc.URI, "file:///") || !strings.HasSuffix(loc.URI, "/testdata/scenarios/coupon-vuln.yaml") || loc.URIBaseID != "" {
		t.Errorf("outside the base: %+v", loc)
	}
	rep.File = "testdata/scenarios/missing file.yaml"
	doc = decodeSARIF(t, []*runner.Report{rep}, SARIFOptions{BaseDir: "testdata"})
	pl := doc.Runs[0].Results[0].Locations[0].PhysicalLocation
	if pl.ArtifactLocation.URI != "scenarios/missing%20file.yaml" || pl.Region.StartLine != 1 {
		t.Errorf("unreadable file: %+v", pl)
	}
}

// junitDoc is the JUnit model the tests decode.
type junitDoc struct {
	XMLName  xml.Name `xml:"testsuites"`
	Name     string   `xml:"name,attr"`
	Tests    int      `xml:"tests,attr"`
	Failures int      `xml:"failures,attr"`
	Errors   int      `xml:"errors,attr"`
	Skipped  int      `xml:"skipped,attr"`
	Suites   []struct {
		Name     string `xml:"name,attr"`
		Tests    int    `xml:"tests,attr"`
		Failures int    `xml:"failures,attr"`
		Errors   int    `xml:"errors,attr"`
		Skipped  int    `xml:"skipped,attr"`
		Cases    []struct {
			ClassName string `xml:"classname,attr"`
			Name      string `xml:"name,attr"`
			Failure   *struct {
				Type    string `xml:"type,attr"`
				Message string `xml:"message,attr"`
				Text    string `xml:",chardata"`
			} `xml:"failure"`
			Error *struct {
				Message string `xml:"message,attr"`
			} `xml:"error"`
			Skipped *struct {
				Message string `xml:"message,attr"`
			} `xml:"skipped"`
		} `xml:"testcase"`
	} `xml:"testsuite"`
}

func TestJUnitContent(t *testing.T) {
	reps := fixture()
	data := render(t, JUnit, reps)
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = true
	var doc junitDoc
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("JUnit output is not well-formed XML: %v", err)
	}
	if doc.Name != "photofinish" || doc.Tests != 8 || doc.Failures != 1 || doc.Errors != 1 || doc.Skipped != 3 {
		t.Errorf("testsuites = %q tests %d failures %d errors %d skipped %d", doc.Name, doc.Tests, doc.Failures, doc.Errors, doc.Skipped)
	}
	if len(doc.Suites) != 4 {
		t.Fatalf("%d suites, want 4", len(doc.Suites))
	}
	vs := doc.Suites[0]
	if vs.Name != "coupon-vuln" || len(vs.Cases) != 3 || vs.Cases[0].ClassName != "photofinish.coupon-vuln" || vs.Cases[0].Name != "trial 1" {
		t.Fatalf("violated suite = %+v", vs)
	}
	f := vs.Cases[0].Failure
	if f == nil || f.Type != "InvariantViolated" || f.Message != reps[0].Summary ||
		!strings.Contains(f.Text, "size(check.json.discounts) <= 1 was 3 <= 1") || !strings.Contains(f.Text, "responses: 3 x 200, 2 x 409, 1 x 429") {
		t.Errorf("failure = %+v", f)
	}
	if vs.Cases[1].Failure != nil || vs.Cases[1].Skipped != nil || vs.Cases[2].Skipped == nil {
		t.Errorf("held or inconclusive trial mapped wrongly: %+v", vs.Cases[1:])
	}
	es := doc.Suites[3]
	if es.Name != "broken" || len(es.Cases) != 1 || es.Cases[0].Name != "scenario" || es.Cases[0].Error == nil ||
		es.Cases[0].Error.Message != reps[3].Summary {
		t.Errorf("error suite = %+v", es)
	}
	// Markup in values is escaped, not interpreted.
	if bytes.Contains(data, []byte("<for every scenario>")) {
		t.Error("unescaped markup in the JUnit output")
	}
}

// externalRef finds URL-valued attributes and CSS url() references that leave
// the page.
var externalRef = regexp.MustCompile(`(?i)(?:url\(\s*['"]?|@import\s+['"]?)(?:https?:)?//`)

func TestHTMLSelfContained(t *testing.T) {
	data := render(t, HTML, fixture())

	// Well-formed: the page is written as polyglot markup that a strict
	// XML parser accepts.
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = true
	dec.Entity = xml.HTMLEntity
	elements := map[string]int{}
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("HTML is not well-formed: %v", err)
		}
		el, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		elements[el.Name.Local]++
		for _, a := range el.Attr {
			switch strings.ToLower(a.Name.Local) {
			case "src", "srcset", "action", "formaction", "poster", "data":
				t.Errorf("<%s %s=%q> loads a resource", el.Name.Local, a.Name.Local, a.Value)
			case "href":
				if el.Name.Local != "a" {
					t.Errorf("<%s href=%q> loads a resource", el.Name.Local, a.Value)
				}
			case "style":
				if externalRef.MatchString(a.Value) {
					t.Errorf("style attribute references a URL: %q", a.Value)
				}
			}
		}
	}
	for _, el := range []string{"script", "link", "img", "iframe", "object", "embed", "base"} {
		if elements[el] > 0 {
			t.Errorf("the page has %d <%s> elements", elements[el], el)
		}
	}
	if elements["svg"] < 3 || elements["section"] != 5 {
		t.Errorf("elements = %v", elements)
	}
	if externalRef.Match(data) || bytes.Contains(data, []byte("@font-face")) {
		t.Error("the page references an external resource from CSS")
	}

	// Untrusted content is escaped.
	if bytes.Contains(data, []byte("<script>alert(1)</script>")) || bytes.Contains(data, []byte("<for every scenario>")) {
		t.Error("unescaped markup from the report")
	}
	if !bytes.Contains(data, []byte("&lt;script&gt;alert(1)&lt;/script&gt;")) {
		t.Error("the escaped check body is missing")
	}

	// The page carries the palette, its light variant and no gradients.
	for _, want := range []string{"#191b1e", "#3e6489", "prefers-color-scheme: light", "#eef0f2", `"IBM Plex Sans"`, `"Cascadia Mono"`} {
		if !bytes.Contains(data, []byte(want)) {
			t.Errorf("the page lacks %s", want)
		}
	}
	if bytes.Contains(data, []byte("gradient")) || bytes.Contains(data, []byte("text-transform")) {
		t.Error("the page uses gradients or transformed text")
	}
}

func TestHTMLTimelineAndBody(t *testing.T) {
	rep := fixture()[0]
	big := `{"items":[` + strings.Repeat(`"0123456789",`, 600) + `"end"]}`
	rep.Trials[0].Check.Body = big
	html := string(render(t, HTML, []*runner.Report{rep}))
	for _, want := range []string{
		"Trial 1 · 6 streams over 1 connection",
		">s11<",                         // stream labels
		`class="release"`,               // dashed release line
		`fill="url(#hatch-scenario-1)"`, // hatched pre-send segment
		"Server arrival",
		"6 requests within 38 µs",
		"Cut to the first 4 KB.",
		"Evaluated on trial 1",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("the page lacks %q", want)
		}
	}
	// The reproduce command keeps its exact text; every word is a span so
	// that a line never breaks inside a flag.
	_, cmd, _ := strings.Cut(html, `<pre class="code reproduce">`)
	cmd, _, _ = strings.Cut(cmd, "</pre>")
	cmd = strings.NewReplacer("<span>", "", "</span>", "").Replace(cmd)
	if want := "photofinish run testdata/scenarios/coupon-vuln.yaml --engine h2 --trials 3"; cmd != want {
		t.Errorf("reproduce block %q, want %q", cmd, want)
	}
	if strings.Contains(html, `&#34;end&#34;`) || !strings.Contains(html, `&#34;0123456789&#34;`) {
		t.Error("the check body was not cut to 4 KB")
	}
	if strings.Contains(html, `class="panel overview"`) {
		t.Error("a single report has an overview table")
	}
}

func TestTicks(t *testing.T) {
	for _, tc := range []struct {
		v, step float64
		signed  bool
		want    string
	}{
		{0, 200e3, true, "0 ms"},
		{-200e3, 200e3, true, "-0.2 ms"},
		{40e3, 20e3, true, "+40 µs"},
		{1e6, 1e6, true, "+1 ms"},
		{1.5e6, 0.5e6, true, "+1.5 ms"},
		{20e3, 10e3, false, "20 µs"},
		{0.5e3, 0.5e3, false, "0.5 µs"},
	} {
		if got := tickLabel(tc.v, tc.step, tc.signed); got != tc.want {
			t.Errorf("tickLabel(%v, %v) = %q, want %q", tc.v, tc.step, got, tc.want)
		}
	}
	for raw, want := range map[float64]float64{0.7: 1, 1.3: 2, 3: 5, 7: 10, 120: 200} {
		if got := niceStep(raw); got != want {
			t.Errorf("niceStep(%v) = %v, want %v", raw, got, want)
		}
	}
}

func TestSARIFReadFileOption(t *testing.T) {
	rep := fixture()[0]
	var asked []string
	doc := decodeSARIF(t, []*runner.Report{rep}, SARIFOptions{BaseDir: "testdata", ReadFile: func(name string) ([]byte, error) {
		asked = append(asked, name)
		return []byte("version: 1\n\n\ncheck:\n  invariant: size(race) == 1\n"), nil
	}})
	if got := doc.Runs[0].Results[0].Locations[0].PhysicalLocation.Region.StartLine; got != 5 || len(asked) != 1 {
		t.Errorf("start line %d from the reader (asked %v), want 5", got, asked)
	}
	doc = decodeSARIF(t, []*runner.Report{rep}, SARIFOptions{BaseDir: "testdata", ReadFile: func(string) ([]byte, error) {
		return nil, fs.ErrPermission
	}})
	if got := doc.Runs[0].Results[0].Locations[0].PhysicalLocation.Region.StartLine; got != 1 {
		t.Errorf("start line %d when the reader refuses, want 1", got)
	}
}
