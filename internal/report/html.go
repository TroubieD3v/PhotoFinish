package report

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/TroubieD3v/photofinish/internal/check"
	"github.com/TroubieD3v/photofinish/internal/engine"
	"github.com/TroubieD3v/photofinish/internal/runner"
)

//go:embed html.tmpl
var htmlSource string

var htmlTemplate = template.Must(template.New("report").Parse(htmlSource))

// HTML limits.
const (
	// maxBodyBytes caps the check response body shown in the report.
	maxBodyBytes = 4 << 10
	// maxTimelineRows caps the rows of a timeline.
	maxTimelineRows = 120
)

// Timeline geometry, in SVG user units.
const (
	tlWidth   = 760.0
	tlLabelX  = 8.0
	tlStatusX = 104.0
	tlStatusW = 40.0
	tlPlotX0  = 160.0
	tlPlotX1  = tlWidth - 14
	tlAxisH   = 24.0
	tlRowH    = 22.0
)

// Server arrival strip geometry.
const (
	arWidth  = 760.0
	arPlotX0 = 24.0
	arPlotX1 = arWidth - 40
	arHeight = 52.0
)

// HTML writes one self-contained HTML page for the reports: a header strip,
// the trials, a timeline of one race, the invariant with its evaluated terms,
// the check response and the reproduce command for every scenario. The page
// loads nothing: styles and graphics are inline and fonts come from the
// system. Every value from the reports is escaped by html/template.
func HTML(w io.Writer, reps []*runner.Report) error {
	if err := checkReports(reps); err != nil {
		return err
	}
	if len(reps) == 0 {
		return errNoReports
	}
	page := htmlPage{Tool: reps[0].Tool, Overview: len(reps) > 1, ProjectURL: InformationURI}
	if page.Tool == "" {
		page.Tool = "photofinish dev"
	}
	for i, rep := range reps {
		page.Scenarios = append(page.Scenarios, htmlScenarioFor(i+1, rep))
	}
	if len(reps) == 1 {
		page.Title = scenarioName(reps[0]) + ": " + string(reps[0].Verdict)
	} else {
		page.Title = fmt.Sprintf("%d scenarios", len(reps))
	}
	page.Counts = verdictCounts(reps)
	if !reps[0].StartedAt.IsZero() {
		page.Started = reps[0].StartedAt.UTC().Format("2006-01-02 15:04:05 UTC")
	}
	var buf bytes.Buffer
	if err := htmlTemplate.Execute(&buf, page); err != nil {
		return err
	}
	_, err := w.Write(buf.Bytes())
	return err
}

// htmlPage is the view model of the whole page.
type htmlPage struct {
	Title      string
	Tool       string
	ProjectURL string
	Started    string
	Counts     string
	Overview   bool
	Scenarios  []htmlScenario
}

// htmlScenario is the view model of one report.
type htmlScenario struct {
	ID        string
	Name      string
	File      string
	Target    string
	Verdict   string
	Class     string
	Summary   string
	Explain   string
	Invariant string
	// Reproduce holds the words of the reproduce command, rendered so that
	// a line never breaks inside a flag such as --engine.
	Reproduce []string
	Metrics   []htmlMetric
	Trials    []htmlTrialRow
	Shown     *htmlTrial
	Notes     []string
	Footer    []string
}

// htmlMetric is one cell of the header strip.
type htmlMetric struct {
	Label, Value string
}

// htmlTrialRow is one row of the trials table.
type htmlTrialRow struct {
	Number   int
	Verdict  string
	Class    string
	Statuses string
	Spread   string
	Shown    bool
}

// htmlTrial is the detail view of the trial shown in the timeline.
type htmlTrial struct {
	Number    int
	Caption   string
	Reasons   []string
	Timeline  *timeline
	Arrival   *arrivalStrip
	Terms     []htmlTerm
	CheckLine string
	CheckBody string
	Truncated bool
}

// htmlTerm is one conjunct of the invariant with its value. Long values
// (a rendered list, say) get a row of their own under the expression, where
// they wrap, instead of squeezing the expression.
type htmlTerm struct {
	Expr, Value, State, Class string
	Long                      bool
}

// maxInlineValue is the longest term value, in runes, shown beside its
// expression.
const maxInlineValue = 24

// htmlScenarioFor builds the view model of the n-th report.
func htmlScenarioFor(n int, rep *runner.Report) htmlScenario {
	s := htmlScenario{
		ID:        "scenario-" + strconv.Itoa(n),
		Name:      scenarioName(rep),
		File:      rep.File,
		Target:    rep.Target,
		Verdict:   string(rep.Verdict),
		Class:     verdictClass(rep.Verdict),
		Summary:   strings.TrimRight(rep.Summary, "\n"),
		Explain:   oneLine(rep.Explain),
		Invariant: strings.TrimSpace(rep.Invariant),
		Notes:     reportNotes(rep),
	}
	if rep.Reproduce != "" {
		s.Reproduce = strings.Split(rep.Reproduce, " ")
	}
	shown := firstTrial(rep, runner.Violated)
	if shown == nil && rep.Verdict == runner.Inconclusive {
		shown = firstTrial(rep, runner.Inconclusive)
	}
	if shown == nil && len(rep.Trials) > 0 {
		shown = &rep.Trials[0]
	}
	s.Metrics = metrics(rep, shown)
	for i := range rep.Trials {
		t := &rep.Trials[i]
		row := htmlTrialRow{
			Number:   t.Number,
			Verdict:  string(t.Verdict),
			Class:    verdictClass(t.Verdict),
			Statuses: compactStatuses(t.Race),
			Shown:    t == shown,
		}
		if t.Race != nil {
			row.Spread = formatMs(t.Race.ResponseSpread())
		}
		s.Trials = append(s.Trials, row)
	}
	if shown != nil {
		s.Shown = htmlTrialFor(shown)
		if r := shown.Race; r != nil {
			if r.TLSVersion != "" {
				s.Footer = append(s.Footer, r.TLSVersion)
			}
			if r.ALPN != "" {
				s.Footer = append(s.Footer, "ALPN "+r.ALPN)
			}
			s.Footer = append(s.Footer, plural(r.Connections, "connection"), "warm-up "+plural(r.Warmup, "request"))
		}
	}
	if rep.Tool != "" {
		s.Footer = append(s.Footer, rep.Tool)
	}
	if !rep.StartedAt.IsZero() {
		s.Footer = append(s.Footer, "started "+rep.StartedAt.UTC().Format("2006-01-02 15:04:05 UTC"))
	}
	return s
}

// metrics returns the header strip cells of a report.
func metrics(rep *runner.Report, shown *runner.Trial) []htmlMetric {
	var m []htmlMetric
	add := func(label, value string) {
		if value != "" {
			m = append(m, htmlMetric{label, value})
		}
	}
	add("Copies per trial", copiesText(rep.Copies))
	add("Engine", string(rep.Engine))
	if shown != nil && shown.Race != nil {
		rel := shown.Race.Release
		switch {
		case rel.Writes > 0:
			add("Final writes", fmt.Sprintf("%s · %d B", plural(rel.Writes, "write"), rel.Bytes))
		case rel.Bytes > 0:
			add("Final writes", fmt.Sprintf("%d B", rel.Bytes))
		}
	}
	st := rep.Stats
	if st.Ran > 0 {
		add("Trials", fmt.Sprintf("%d of %d", st.Ran, st.Planned))
	}
	// Spreads exist only for trials that raced: a run that failed before
	// its first race has no spread, not a spread of 0.
	if raced(rep) {
		add("Response spread, median", formatMs(time.Duration(st.MedianResponseSpreadNs)))
		if st.MedianServerArrivalSpreadNs != nil {
			add("Server arrival spread, median", formatDuration(time.Duration(*st.MedianServerArrivalSpreadNs)))
		} else {
			add("Server arrival spread, median", "not reported")
		}
	}
	if st.RequestsSpent > 0 {
		add("Requests spent", strconv.Itoa(st.RequestsSpent))
	}
	return m
}

// raced reports whether any trial of rep sent a race.
func raced(rep *runner.Report) bool {
	for _, t := range rep.Trials {
		if t.Race != nil {
			return true
		}
	}
	return false
}

// htmlTrialFor builds the detail view of a trial.
func htmlTrialFor(t *runner.Trial) *htmlTrial {
	v := &htmlTrial{Number: t.Number, Caption: fmt.Sprintf("Trial %d", t.Number)}
	for _, r := range t.Reasons {
		if t.Verdict != runner.Violated || strings.HasPrefix(r, notePrefix) {
			v.Reasons = append(v.Reasons, r)
		}
	}
	if r := t.Race; r != nil {
		v.Caption += " · " + raceCaption(r)
		v.Timeline = newTimeline(r, t.Verdict == runner.Violated)
		v.Arrival = newArrivalStrip(r)
	}
	for _, tm := range t.Terms {
		v.Terms = append(v.Terms, htmlTermFor(tm))
	}
	if c := t.Check; c != nil {
		line := strings.TrimSpace(c.Method + " " + c.URL)
		switch {
		case c.Err != "":
			line += " → " + c.Err
		case c.Status != 0:
			line += " → " + strconv.Itoa(c.Status)
		}
		v.CheckLine = line
		v.CheckBody, v.Truncated = prettyBody(c.Body)
	}
	return v
}

// raceCaption describes a race: "6 streams over 1 connection".
func raceCaption(r *engine.Race) string {
	n := len(r.Results)
	switch r.Kind {
	case engine.H2:
		return plural(n, "stream") + " over " + plural(max(r.Connections, 1), "connection")
	case engine.H1:
		return plural(n, "request") + " over " + plural(max(r.Connections, n), "connection")
	default:
		return plural(n, "request") + " (" + string(r.Kind) + ")"
	}
}

// htmlTermFor renders one term.
func htmlTermFor(tm check.Term) htmlTerm {
	t := htmlTerm{Expr: tm.Expr, Value: tm.Value, Long: utf8.RuneCountInString(tm.Value) > maxInlineValue}
	switch {
	case tm.Pass == nil:
		t.State, t.Class = "error", "warn"
	case *tm.Pass:
		t.State, t.Class = "pass", "ok"
	default:
		t.State, t.Class = "fail", "bad"
	}
	return t
}

// prettyBody indents a JSON body and cuts any body to maxBodyBytes.
func prettyBody(body string) (string, bool) {
	if body == "" {
		return "", false
	}
	if json.Valid([]byte(body)) {
		var b bytes.Buffer
		if err := json.Indent(&b, []byte(body), "", "  "); err == nil {
			body = b.String()
		}
	}
	if len(body) <= maxBodyBytes {
		return body, false
	}
	cut := maxBodyBytes
	for cut > 0 && !utf8.RuneStart(body[cut]) {
		cut--
	}
	return body[:cut], true
}

// reportNotes returns the run notes followed by the distinct race notes.
func reportNotes(rep *runner.Report) []string {
	notes := append([]string(nil), rep.Notes...)
	seen := map[string]bool{}
	for _, n := range notes {
		seen[n] = true
	}
	for _, t := range rep.Trials {
		if t.Race == nil {
			continue
		}
		for _, n := range t.Race.Notes {
			if !seen[n] {
				seen[n] = true
				notes = append(notes, n)
			}
		}
	}
	return notes
}

// verdictClass maps a verdict to its color class.
func verdictClass(v runner.Verdict) string {
	switch v {
	case runner.Violated:
		return "bad"
	case runner.Held:
		return "ok"
	case runner.Inconclusive:
		return "warn"
	default:
		return "err"
	}
}

// verdictCounts summarizes the verdicts of the reports: "1 violated, 2 held".
func verdictCounts(reps []*runner.Report) string {
	counts := map[runner.Verdict]int{}
	for _, r := range reps {
		counts[r.Verdict]++
	}
	var parts []string
	for _, v := range []runner.Verdict{runner.Violated, runner.Held, runner.Inconclusive, runner.Errored} {
		if n := counts[v]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, strings.ToLower(string(v))))
		}
	}
	return strings.Join(parts, ", ")
}

// compactStatuses is statusSummary in table form: "3×200 3×409".
func compactStatuses(r *engine.Race) string {
	s := statusSummary(r)
	s = strings.ReplaceAll(s, " x ", "×")
	s = strings.ReplaceAll(s, "×no response", "×none")
	return strings.ReplaceAll(s, ", ", " ")
}

// plural formats a count with a noun: "1 write", "2 writes".
func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return strconv.Itoa(n) + " " + noun + "s"
}

// timeline is the SVG view of one race: a row per request with the hatched
// pre-send segment, the bar from release to first byte and the status.
type timeline struct {
	Width, Height float64
	ReleaseX      float64
	AxisY         float64
	Bottom        float64
	Ticks         []tick
	Rows          []timelineRow
	Legend        []legendItem
	Hidden        int
	// HasPre is set when a row has a pre-send segment.
	HasPre bool
	// LineLabel names the dashed line: "release", or "first send" for
	// races without a release (burst).
	LineLabel string
}

// tick is one axis label.
type tick struct {
	X     float64
	Label string
}

// legendItem explains a bar color.
type legendItem struct {
	Class, Label string
}

// timelineRow is one request of the race.
type timelineRow struct {
	Y, TextY    float64
	Label       string
	Status      string
	Class       string
	PreX, PreW  float64
	BarX, BarW  float64
	EndX        float64
	HasBar      bool
	HasPre      bool
	Title       string
	StatusTextX float64
	StatusRectX float64
	StatusRectW float64
	StatusRectY float64
	StatusRectH float64
	BarY, BarH  float64
	TickY1      float64
	TickY2      float64
	LabelX      float64
}

// newTimeline lays out a race. violated colors successful responses as the
// ones that broke the rule.
func newTimeline(r *engine.Race, violated bool) *timeline {
	if len(r.Results) == 0 {
		return nil
	}
	var release int64
	for _, res := range r.Results {
		if res.ReleasedNs > 0 && (release == 0 || res.ReleasedNs < release) {
			release = res.ReleasedNs
		}
	}
	// A burst race has no release: every request is sent whole, and its
	// release time is its send time. The line then marks the first send.
	lineLabel := "release"
	if r.Kind == engine.Burst || release == 0 {
		lineLabel = "first send"
	}
	if release == 0 {
		// No release time at all: start at the earliest pre-send.
		for _, res := range r.Results {
			if res.PreSentNs > 0 && (release == 0 || res.PreSentNs < release) {
				release = res.PreSentNs
			}
		}
	}
	lo, hi := 0.0, 0.0
	for _, res := range r.Results {
		for _, ns := range []int64{res.ReleasedNs, res.FirstByteNs} {
			if ns > 0 {
				d := float64(ns - release)
				lo, hi = math.Min(lo, d), math.Max(hi, d)
			}
		}
	}
	if hi <= 0 {
		hi = float64(time.Millisecond)
	}
	axisMin := math.Min(-0.35*hi, 1.1*lo)
	axisMax := 1.08 * hi
	x := func(d float64) float64 {
		return round1(tlPlotX0 + (d-axisMin)/(axisMax-axisMin)*(tlPlotX1-tlPlotX0))
	}

	rows := r.Results
	tl := &timeline{Width: tlWidth, AxisY: 15, ReleaseX: x(0), LineLabel: lineLabel}
	if len(rows) > maxTimelineRows {
		tl.Hidden = len(rows) - maxTimelineRows
		rows = rows[:maxTimelineRows]
	}
	tl.Ticks = axisTicks(axisMin, axisMax, x)
	classes := map[string]bool{}
	for i, res := range rows {
		y := tlAxisH + float64(i)*tlRowH
		cy := y + tlRowH/2
		row := timelineRow{
			Y:           y,
			TextY:       cy + 4,
			LabelX:      tlLabelX,
			Label:       shortLabel(res),
			Status:      statusText(res.Status),
			Class:       statusClass(res, violated),
			StatusRectX: tlStatusX,
			StatusRectY: cy - 8,
			StatusRectW: tlStatusW,
			StatusRectH: 16,
			StatusTextX: tlStatusX + tlStatusW/2,
			BarY:        cy - 3,
			BarH:        6,
			TickY1:      cy - 7,
			TickY2:      cy + 7,
			Title:       resultTitle(res, release),
		}
		classes[row.Class] = true
		if res.PreSentNs > 0 && res.ReleasedNs > res.PreSentNs {
			x0 := x(math.Max(float64(res.PreSentNs-release), axisMin))
			x1 := x(float64(res.ReleasedNs - release))
			if x1 > x0 {
				row.HasPre, row.PreX, row.PreW = true, x0, round1(x1-x0)
				tl.HasPre = true
			}
		}
		if res.FirstByteNs > 0 {
			start := res.ReleasedNs
			if start == 0 {
				start = res.PreSentNs
			}
			// The end tick marks the first byte, which comes before the
			// start of the bar for a response that arrived early.
			end := x(float64(res.FirstByteNs - release))
			a, b := x(float64(start-release)), end
			if b < a {
				a, b = b, a
			}
			row.HasBar, row.BarX, row.BarW, row.EndX = true, a, round1(math.Max(b-a, 1)), end
		}
		tl.Rows = append(tl.Rows, row)
	}
	tl.Bottom = tlAxisH + float64(len(rows))*tlRowH + 4
	tl.Height = tl.Bottom + 4
	for _, li := range []legendItem{
		{"bad", "succeeded, broke the rule"},
		{"ok", "succeeded"},
		{"neutral", "rejected"},
		{"warn", "rate limited or early"},
		{"err", "no response"},
	} {
		if classes[li.Class] {
			tl.Legend = append(tl.Legend, li)
		}
	}
	return tl
}

// shortLabel names a timeline row: the HTTP/2 stream, else the request
// label shortened to fit the label column.
func shortLabel(res engine.Result) string {
	if res.Stream > 0 {
		return "s" + strconv.FormatUint(uint64(res.Stream), 10)
	}
	l := strings.ReplaceAll(res.Label, "request ", "req ")
	if l == "" {
		l = "#" + strconv.Itoa(res.Index+1)
	}
	if utf8.RuneCountInString(l) > 13 {
		l = string([]rune(l)[:12]) + "…"
	}
	return l
}

// statusText is the status shown in the lozenge.
func statusText(status int) string {
	if status == 0 {
		return "none"
	}
	return strconv.Itoa(status)
}

// statusClass colors a response.
func statusClass(res engine.Result, violated bool) string {
	switch {
	case res.Status == 0:
		return "err"
	case res.Status == 429 || res.EarlyResponse:
		return "warn"
	case res.Status >= 200 && res.Status < 300 && violated:
		return "bad"
	case res.Status >= 200 && res.Status < 300:
		return "ok"
	default:
		return "neutral"
	}
}

// resultTitle is the tooltip of a timeline row.
func resultTitle(res engine.Result, release int64) string {
	parts := []string{valueOr(res.Label, "request "+strconv.Itoa(res.Index+1))}
	if res.Stream > 0 {
		parts = append(parts, fmt.Sprintf("stream %d", res.Stream))
	}
	if res.Status != 0 {
		parts = append(parts, "status "+strconv.Itoa(res.Status))
	}
	if res.FirstByteNs > 0 {
		parts = append(parts, "first byte "+signedDuration(res.FirstByteNs-release)+" after release")
	}
	if res.EarlyResponse {
		parts = append(parts, "responded before release")
	}
	if res.Err != "" {
		parts = append(parts, res.Err)
	}
	return strings.Join(parts, ", ")
}

// signedDuration formats ns with a sign: "+0.41 ms", "-12 µs".
func signedDuration(ns int64) string {
	if ns < 0 {
		return "-" + formatDuration(time.Duration(-ns))
	}
	return "+" + formatDuration(time.Duration(ns))
}

// arrivalStrip is the SVG view of the server arrival times of a race.
type arrivalStrip struct {
	Width, Height float64
	Count         int
	Spread        string
	Ticks         []tick
	Marks         []float64
	AxisY         float64
	MarkY1        float64
	MarkY2        float64
}

// newArrivalStrip lays out the server arrival times, nil when fewer than two
// results carry one.
func newArrivalStrip(r *engine.Race) *arrivalStrip {
	spread, ok := r.ServerArrivalSpread()
	if !ok {
		return nil
	}
	var first int64
	var vals []int64
	for _, res := range r.Results {
		if res.ServerArrivalNs != 0 {
			vals = append(vals, res.ServerArrivalNs)
			if first == 0 || res.ServerArrivalNs < first {
				first = res.ServerArrivalNs
			}
		}
	}
	axisMax := float64(spread) * 1.05
	if axisMax < float64(time.Microsecond) {
		axisMax = float64(time.Microsecond)
	}
	x := func(d float64) float64 {
		return round1(arPlotX0 + d/axisMax*(arPlotX1-arPlotX0))
	}
	a := &arrivalStrip{
		Width: arWidth, Height: arHeight, Count: len(vals),
		Spread: microseconds(float64(spread), float64(time.Microsecond)),
		AxisY:  arHeight - 6, MarkY1: 4, MarkY2: 28,
	}
	for _, v := range vals {
		a.Marks = append(a.Marks, x(float64(v-first)))
	}
	step := niceStep(axisMax / 5)
	for v := 0.0; v <= axisMax+step/1e6; v += step {
		a.Ticks = append(a.Ticks, tick{X: x(v), Label: microseconds(v, step)})
	}
	return a
}

// microseconds formats ns in microseconds with as many decimals as step
// (in ns) needs: "0 µs", "100 µs", "2500 µs", "0.5 µs". The server arrival
// strip always uses µs, the unit of arrival spreads.
func microseconds(ns, step float64) string {
	if ns == 0 {
		return "0 µs"
	}
	decimals := 0
	if s := step / float64(time.Microsecond); s < 1 {
		decimals = int(math.Ceil(-math.Log10(s)))
	}
	return strconv.FormatFloat(ns/float64(time.Microsecond), 'f', decimals, 64) + " µs"
}

// axisTicks returns the labels of a time axis from lo to hi nanoseconds.
func axisTicks(lo, hi float64, x func(float64) float64) []tick {
	step := niceStep((hi - lo) / 8)
	var ticks []tick
	for v := math.Ceil(lo/step) * step; v <= hi; v += step {
		if math.Abs(v) < step/1e6 {
			v = 0
		}
		ticks = append(ticks, tick{X: x(v), Label: tickLabel(v, step, true)})
	}
	return ticks
}

// niceStep returns 1, 2 or 5 times a power of ten, at least raw.
func niceStep(raw float64) float64 {
	if raw <= 0 {
		return 1
	}
	p := math.Pow(10, math.Floor(math.Log10(raw)))
	for _, m := range []float64{1, 2, 5, 10} {
		if m*p >= raw {
			return m * p
		}
	}
	return 10 * p
}

// tickLabel formats an axis value in ns with the unit that suits step:
// milliseconds from a step of 100 µs up, microseconds below.
func tickLabel(v, step float64, signed bool) string {
	unit, div := "ms", float64(time.Millisecond)
	if step < 100*float64(time.Microsecond) {
		unit, div = "µs", float64(time.Microsecond)
	}
	if v == 0 {
		return "0 " + unit
	}
	decimals := 0
	if s := step / div; s < 1 {
		decimals = int(math.Ceil(-math.Log10(s)))
	}
	num := strconv.FormatFloat(math.Abs(v)/div, 'f', decimals, 64)
	switch {
	case !signed:
		return num + " " + unit
	case v < 0:
		return "-" + num + " " + unit
	default:
		return "+" + num + " " + unit
	}
}

// round1 rounds to one decimal so that the SVG stays compact and stable.
func round1(f float64) float64 {
	return math.Round(f*10) / 10
}
