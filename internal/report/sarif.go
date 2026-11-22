package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/TroubieD3v/photofinish/internal/runner"
	"github.com/TroubieD3v/photofinish/internal/scenario"
)

// SARIF constants.
const (
	sarifVersion = "2.1.0"
	sarifSchema  = "https://json.schemastore.org/sarif-2.1.0.json"
	// InformationURI is the project page written as the tool's
	// informationUri.
	InformationURI = "https://github.com/TroubieD3v/PhotoFinish"
	// srcRoot is the uriBaseId of scenario files.
	srcRoot = "%SRCROOT%"
	// fingerprintKey names the partial fingerprint of a result.
	fingerprintKey = "photofinish/v1"
)

// Rule ids.
const (
	// RuleViolated is reported for every VIOLATED scenario.
	RuleViolated = "PF001"
	// RuleInconclusive is reported for every INCONCLUSIVE scenario.
	RuleInconclusive = "PF002"
)

// SARIFOptions configures the SARIF output.
type SARIFOptions struct {
	// BaseDir is the directory scenario paths are made relative to (with
	// forward slashes); it is written as the %SRCROOT% base URI. "" means
	// the current directory. Scenario files outside BaseDir get absolute
	// file URIs instead.
	BaseDir string
	// ReadFile reads a scenario file named in a report, to find the line of
	// its invariant. nil means os.ReadFile; a server passes a reader that
	// stays inside its workspace. An error makes the line 1.
	ReadFile func(name string) ([]byte, error)
}

// SARIF writes the reports as one SARIF 2.1.0 log with one run: a PF001
// error result for every VIOLATED scenario, a PF002 warning result for every
// INCONCLUSIVE one, nothing for HELD ones, and a tool execution
// notification for every ERROR scenario (the invocation is then not
// successful).
//
// The region of a result is the line of check.invariant, read from the
// scenario file named in the report; it is 1 when the file cannot be read.
func SARIF(w io.Writer, reps []*runner.Report, opts SARIFOptions) error {
	if err := checkReports(reps); err != nil {
		return err
	}
	read := opts.ReadFile
	if read == nil {
		read = os.ReadFile
	}
	base, err := filepath.Abs(valueOr(opts.BaseDir, "."))
	if err != nil {
		return err
	}
	run := sarifRun{
		Tool: sarifTool{Driver: sarifDriver{
			Name:           "PhotoFinish",
			Version:        "dev",
			InformationURI: InformationURI,
			Rules:          sarifRules(),
		}},
		OriginalURIBaseIDs: map[string]sarifArtifactLocation{
			srcRoot: {URI: baseURI(base)},
		},
		Results: []sarifResult{},
	}
	inv := sarifInvocation{ExecutionSuccessful: true}
	for _, rep := range reps {
		if rep.Tool != "" && run.Tool.Driver.Version == "dev" {
			run.Tool.Driver.Version = toolVersion(rep)
		}
		inv.addTimes(rep.StartedAt, rep.FinishedAt)
		switch rep.Verdict {
		case runner.Violated, runner.Inconclusive:
			run.Results = append(run.Results, sarifResultFor(rep, base, read))
		case runner.Errored:
			inv.ExecutionSuccessful = false
			n := sarifNotification{
				Level:   "error",
				Message: sarifMessage{Text: scenarioName(rep) + ": " + rep.Summary},
			}
			if loc, ok := artifactLocation(rep.File, base); ok {
				n.Locations = []sarifLocation{{PhysicalLocation: sarifPhysicalLocation{ArtifactLocation: loc}}}
			}
			inv.Notifications = append(inv.Notifications, n)
		}
	}
	run.Invocations = []sarifInvocation{inv}
	log := sarifLog{Schema: sarifSchema, Version: sarifVersion, Runs: []sarifRun{run}}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(log)
}

// sarifRules returns the reporting descriptors of PF001 and PF002, in rule
// index order.
func sarifRules() []sarifRule {
	help := InformationURI + "#reports"
	return []sarifRule{
		{
			ID:   RuleViolated,
			Name: "InvariantViolatedUnderConcurrency",
			ShortDescription: sarifMessage{
				Text: "A business rule broke when requests ran concurrently",
			},
			FullDescription: sarifMessage{
				Text: "PhotoFinish sent the same request several times in one synchronized race and the scenario's invariant " +
					"evaluated to false afterwards in at least one trial. This is a proven race condition: the server let " +
					"concurrent requests pass a check that each of them passes alone (a coupon applied twice, a balance " +
					"spent twice, a one-time code accepted twice).",
			},
			HelpURI:              help,
			DefaultConfiguration: sarifConfiguration{Level: "error"},
			Properties: &sarifRuleProperties{
				Tags:             []string{"security", "race-condition"},
				Precision:        "high",
				SecuritySeverity: "7.5",
			},
		},
		{
			ID:   RuleInconclusive,
			Name: "RaceTestInconclusive",
			ShortDescription: sarifMessage{
				Text: "A race test could not decide whether the business rule holds",
			},
			FullDescription: sarifMessage{
				Text: "At least half of the trials of the scenario could not be judged: race requests failed or got no " +
					"response, responses arrived before the release (the endpoint did not wait for the request), the " +
					"server rate limited the race, a setup step returned an unexpected status or the invariant could not " +
					"be evaluated. Neither a violation nor a holding rule was shown.",
			},
			HelpURI:              help,
			DefaultConfiguration: sarifConfiguration{Level: "warning"},
			Properties: &sarifRuleProperties{
				Tags: []string{"race-condition"},
			},
		},
	}
}

// sarifResultFor builds the result of a VIOLATED or INCONCLUSIVE report.
func sarifResultFor(rep *runner.Report, base string, read func(string) ([]byte, error)) sarifResult {
	res := sarifResult{
		RuleID:    RuleViolated,
		RuleIndex: 0,
		Level:     "error",
		Message:   sarifMessage{Text: resultMessage(rep)},
		PartialFingerprints: map[string]string{
			fingerprintKey: fingerprint(rep),
		},
		Properties: sarifResultProperties{
			Scenario:                    scenarioName(rep),
			Target:                      rep.Target,
			Engine:                      string(rep.Engine),
			Copies:                      rep.Copies,
			Trials:                      rep.Stats.Ran,
			Violated:                    rep.Stats.Violated,
			Held:                        rep.Stats.Held,
			Inconclusive:                rep.Stats.Inconclusive,
			MedianResponseSpreadNs:      rep.Stats.MedianResponseSpreadNs,
			MedianServerArrivalSpreadNs: rep.Stats.MedianServerArrivalSpreadNs,
			Explain:                     oneLine(rep.Explain),
		},
	}
	if rep.Verdict == runner.Inconclusive {
		res.RuleID, res.RuleIndex, res.Level = RuleInconclusive, 1, "warning"
	}
	if loc, ok := artifactLocation(rep.File, base); ok {
		res.Locations = []sarifLocation{{PhysicalLocation: sarifPhysicalLocation{
			ArtifactLocation: loc,
			Region:           &sarifRegion{StartLine: invariantLine(rep.File, read)},
		}}}
	}
	return res
}

// resultMessage is the summary of the report followed, for a violation, by
// the failing terms of the first violated trial.
func resultMessage(rep *runner.Report) string {
	msg := strings.TrimRight(rep.Summary, ". \n")
	if msg == "" {
		msg = scenarioName(rep) + " is " + strings.ToLower(string(rep.Verdict))
	}
	msg += "."
	if t := firstTrial(rep, runner.Violated); t != nil && rep.Verdict == runner.Violated {
		if terms := failingTerms(t); len(terms) > 0 {
			msg += " Failing in trial " + strconv.Itoa(t.Number) + ": " + strings.Join(terms, "; ") + "."
		}
	}
	return msg
}

// fingerprint identifies a finding across runs, hosts and line moves: the
// SHA-256 of the scenario name, the target path and the invariant with its
// whitespace collapsed, separated by newlines.
func fingerprint(rep *runner.Report) string {
	path := rep.Target
	if u, err := url.Parse(rep.Target); err == nil && u.Host != "" {
		path = u.EscapedPath()
	}
	sum := sha256.Sum256([]byte(rep.Scenario + "\n" + path + "\n" + oneLine(rep.Invariant)))
	return hex.EncodeToString(sum[:])
}

// artifactLocation returns the location of the scenario file: relative to
// base under %SRCROOT%, or an absolute file URI when it lies outside base.
func artifactLocation(file, base string) (sarifArtifactLocation, bool) {
	if file == "" {
		return sarifArtifactLocation{}, false
	}
	abs, err := filepath.Abs(filepath.FromSlash(file))
	if err != nil {
		return sarifArtifactLocation{}, false
	}
	rel, err := filepath.Rel(base, abs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return sarifArtifactLocation{URI: fileURI(abs)}, true
	}
	segs := strings.Split(filepath.ToSlash(rel), "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return sarifArtifactLocation{URI: strings.Join(segs, "/"), URIBaseID: srcRoot}, true
}

// baseURI returns the file URI of the directory dir with a trailing slash:
// "file:///C:/work/" or "file:///home/me/work/".
func baseURI(dir string) string {
	u := fileURI(dir)
	if !strings.HasSuffix(u, "/") {
		u += "/"
	}
	return u
}

// fileURI returns the file URI of the absolute path p.
func fileURI(p string) string {
	p = filepath.ToSlash(p)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return (&url.URL{Scheme: "file", Path: p}).String()
}

// invariantLine returns the 1-based line of check.invariant in the scenario
// file, or 1 when the file cannot be read or parsed.
func invariantLine(file string, read func(string) ([]byte, error)) int {
	data, err := read(filepath.FromSlash(file))
	if err != nil {
		return 1
	}
	s, err := scenario.Parse(data, file)
	if err != nil || s.InvariantLine < 1 {
		return 1
	}
	return s.InvariantLine
}

// addTimes widens the invocation's time span to include [start, end].
func (inv *sarifInvocation) addTimes(start, end time.Time) {
	if !start.IsZero() {
		s := start.UTC().Format(time.RFC3339Nano)
		if inv.StartTimeUTC == "" || start.Before(inv.start) {
			inv.StartTimeUTC, inv.start = s, start
		}
	}
	if !end.IsZero() {
		e := end.UTC().Format(time.RFC3339Nano)
		if inv.EndTimeUTC == "" || end.After(inv.end) {
			inv.EndTimeUTC, inv.end = e, end
		}
	}
}

// valueOr returns v, or def when v is empty.
func valueOr(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// The SARIF object model, limited to what PhotoFinish writes.

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool               sarifTool                        `json:"tool"`
	Invocations        []sarifInvocation                `json:"invocations"`
	OriginalURIBaseIDs map[string]sarifArtifactLocation `json:"originalUriBaseIds"`
	Results            []sarifResult                    `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string               `json:"id"`
	Name                 string               `json:"name"`
	ShortDescription     sarifMessage         `json:"shortDescription"`
	FullDescription      sarifMessage         `json:"fullDescription"`
	HelpURI              string               `json:"helpUri"`
	DefaultConfiguration sarifConfiguration   `json:"defaultConfiguration"`
	Properties           *sarifRuleProperties `json:"properties,omitempty"`
}

type sarifConfiguration struct {
	Level string `json:"level"`
}

type sarifRuleProperties struct {
	Tags             []string `json:"tags"`
	Precision        string   `json:"precision,omitempty"`
	SecuritySeverity string   `json:"security-severity,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifInvocation struct {
	ExecutionSuccessful bool                `json:"executionSuccessful"`
	StartTimeUTC        string              `json:"startTimeUtc,omitempty"`
	EndTimeUTC          string              `json:"endTimeUtc,omitempty"`
	Notifications       []sarifNotification `json:"toolExecutionNotifications,omitempty"`

	start, end time.Time
}

type sarifNotification struct {
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

type sarifResult struct {
	RuleID              string                `json:"ruleId"`
	RuleIndex           int                   `json:"ruleIndex"`
	Level               string                `json:"level"`
	Message             sarifMessage          `json:"message"`
	Locations           []sarifLocation       `json:"locations,omitempty"`
	PartialFingerprints map[string]string     `json:"partialFingerprints"`
	Properties          sarifResultProperties `json:"properties"`
}

type sarifResultProperties struct {
	Scenario                    string `json:"scenario"`
	Target                      string `json:"target"`
	Engine                      string `json:"engine"`
	Copies                      int    `json:"copies"`
	Trials                      int    `json:"trials"`
	Violated                    int    `json:"violated"`
	Held                        int    `json:"held"`
	Inconclusive                int    `json:"inconclusive"`
	MedianResponseSpreadNs      int64  `json:"medianResponseSpreadNs"`
	MedianServerArrivalSpreadNs *int64 `json:"medianServerArrivalSpreadNs,omitempty"`
	Explain                     string `json:"explain,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId,omitempty"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}
