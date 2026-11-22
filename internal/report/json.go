package report

import (
	"encoding/json"
	"io"

	"github.com/TroubieD3v/photofinish/internal/runner"
)

// JSON writes the reports as indented JSON: the report object itself for one
// report and an array, in the given order, for none or several. HTML
// escaping is off so that invariants such as "a <= 1" stay readable; the
// output is the same document that run --format json prints.
func JSON(w io.Writer, reps []*runner.Report) error {
	if err := checkReports(reps); err != nil {
		return err
	}
	var doc any = reps
	switch len(reps) {
	case 0:
		doc = []*runner.Report{}
	case 1:
		doc = reps[0]
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(doc)
}
