package report

import (
	"strings"
	"testing"

	"github.com/TroubieD3v/photofinish/internal/check"
	"github.com/TroubieD3v/photofinish/internal/engine"
	"github.com/TroubieD3v/photofinish/internal/runner"
)

// TestHTMLLongTermValue checks that a long term value gets a wrapping row of
// its own instead of a nowrap cell beside the expression.
func TestHTMLLongTermValue(t *testing.T) {
	rep := fixture()[0]
	long := "[" + strings.Repeat(`{"amount_cents": 810, "code": "WELCOME10"}, `, 9) + "] == []"
	if len(long) < 400 {
		t.Fatalf("the long value has %d bytes", len(long))
	}
	rep.Trials[0].Terms = []check.Term{
		{Expr: "check.json.discounts == []", Value: long, Pass: ptr(false)},
		{Expr: "size(check.json.discounts) <= 1", Value: "3 <= 1", Pass: ptr(false)},
	}
	html := string(render(t, HTML, []*runner.Report{rep}))
	_, terms, _ := strings.Cut(html, `<table class="terms">`)
	terms, _, _ = strings.Cut(terms, "</table>")
	if !strings.Contains(terms, `<td class="expr mono" colspan="2">check.json.discounts == []</td>`) ||
		!strings.Contains(terms, `<tr class="long-value"><td class="val long mono" colspan="3">[{&#34;amount_cents&#34;`) {
		t.Errorf("the long value has no row of its own:\n%s", terms)
	}
	if !strings.Contains(terms, `<td class="val mono">3 &lt;= 1</td>`) {
		t.Errorf("a short value is not beside its expression:\n%s", terms)
	}
	if !strings.Contains(html, ".terms .val.long { white-space: pre-wrap; overflow-wrap: anywhere;") {
		t.Error("long values do not wrap")
	}
}

// TestHTMLVerdictLozengeDoesNotShrink checks the header lozenge keeps its
// width next to a long summary.
func TestHTMLVerdictLozengeDoesNotShrink(t *testing.T) {
	html := string(render(t, HTML, fixture()[:1]))
	if !strings.Contains(html, ".strip .verdict .loz { flex: none; }") {
		t.Error("the verdict lozenge of the header strip can shrink")
	}
}

// TestTimelineEarlyResponse checks that the end tick of a response that came
// before the release sits at its first byte, left of the release line.
func TestTimelineEarlyResponse(t *testing.T) {
	r := race(engine.H2, 0, []int{200, 429}, []int64{400, 500}, nil)
	r.Results[1].FirstByteNs = r.Results[1].ReleasedNs - us(2000)
	r.Results[1].EarlyResponse = true
	tl := newTimeline(r, false)
	early := tl.Rows[1]
	if !early.HasBar || early.EndX >= tl.ReleaseX {
		t.Fatalf("end tick at %v, release at %v", early.EndX, tl.ReleaseX)
	}
	if early.EndX != early.BarX || early.BarX+early.BarW != tl.ReleaseX {
		t.Errorf("bar %v+%v, end %v, release %v: the bar must span first byte to release", early.BarX, early.BarW, early.EndX, tl.ReleaseX)
	}
	if late := tl.Rows[0]; late.EndX != late.BarX+late.BarW {
		t.Errorf("on time: end tick %v, bar end %v", late.EndX, late.BarX+late.BarW)
	}
}

// TestArrivalStripMicroseconds checks that the server arrival axis and its
// caption are in µs whatever the spread.
func TestArrivalStripMicroseconds(t *testing.T) {
	for _, tc := range []struct {
		arrival []int64
		caption string
		ticks   []string
	}{
		{[]int64{0, 120, 361}, "361 µs", []string{"0 µs", "100 µs", "200 µs", "300 µs"}},
		{[]int64{0, 900, 2820}, "2820 µs", []string{"0 µs", "1000 µs", "2000 µs"}},
		{[]int64{0, 1, 2}, "2 µs", []string{"0 µs", "0.5 µs", "1.0 µs", "1.5 µs", "2.0 µs"}},
	} {
		r := race(engine.H2, 0, []int{200, 200, 200}, []int64{400, 410, 420}, tc.arrival)
		a := newArrivalStrip(r)
		if a.Spread != tc.caption {
			t.Errorf("caption %q, want %q", a.Spread, tc.caption)
		}
		var got []string
		for _, tk := range a.Ticks {
			got = append(got, tk.Label)
		}
		if strings.Join(got, ",") != strings.Join(tc.ticks, ",") {
			t.Errorf("spread %s: ticks %q, want %q", tc.caption, got, tc.ticks)
		}
	}
}

// TestHTMLNoRaceNoSpread checks that a run that failed before its first race
// shows no response spread in the header strip.
func TestHTMLNoRaceNoSpread(t *testing.T) {
	rep := &runner.Report{
		Scenario: "bad-target", Verdict: runner.Errored, Copies: 10, Engine: engine.H2,
		Summary: `setup step reset failed before the first race: Post "https://127.0.0.1:18499/vuln/api/reset": dial tcp: connection refused`,
		Trials:  []runner.Trial{{Number: 1, Verdict: runner.Errored, Reasons: []string{"setup step reset failed"}}},
		Stats:   runner.Stats{Planned: 10, Ran: 1, Errored: 1, RequestsSpent: 1},
	}
	for _, m := range metrics(rep, &rep.Trials[0]) {
		if strings.Contains(m.Label, "spread") {
			t.Errorf("metric %s = %s for a run without a race", m.Label, m.Value)
		}
	}
	html := string(render(t, HTML, []*runner.Report{rep}))
	if strings.Contains(html, "Response spread") || !strings.Contains(html, "1 of 10") {
		t.Error("the header strip shows a spread for a run without a race, or no trial count")
	}
	// A run with races keeps both spreads.
	var labels []string
	for _, m := range metrics(fixture()[0], nil) {
		labels = append(labels, m.Label)
	}
	if got := strings.Join(labels, ","); !strings.Contains(got, "Response spread, median,Server arrival spread, median") {
		t.Errorf("metrics of a raced run: %s", got)
	}
}

// TestTimelineLegendBurst checks that a burst race, which has neither a
// pre-send segment nor a release, does not claim them in the legend.
func TestTimelineLegendBurst(t *testing.T) {
	rep := fixture()[0]
	r := race(engine.Burst, 0, []int{200, 409}, []int64{400, 450}, nil)
	for i := range r.Results {
		// The burst engine stamps both times just before it sends.
		res := &r.Results[i]
		res.ReleasedNs += us(int64(i))
		res.PreSentNs = res.ReleasedNs
	}
	rep.Trials[0].Race = r
	tl := newTimeline(r, true)
	if tl.HasPre || tl.LineLabel != "first send" {
		t.Errorf("burst timeline: pre %v, line %q", tl.HasPre, tl.LineLabel)
	}
	html := string(render(t, HTML, []*runner.Report{rep}))
	_, legend, _ := strings.Cut(html, `<span class="legend">`)
	legend, _, _ = strings.Cut(legend, "</h3>")
	if strings.Contains(legend, "pre-sent") || !strings.Contains(legend, `<span class="rel">first send</span>`) {
		t.Errorf("burst legend:\n%s", legend)
	}

	h2 := newTimeline(fixture()[0].Trials[0].Race, true)
	if !h2.HasPre || h2.LineLabel != "release" {
		t.Errorf("h2 timeline: pre %v, line %q", h2.HasPre, h2.LineLabel)
	}
}
