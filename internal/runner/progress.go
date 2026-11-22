package runner

import (
	"slices"

	"github.com/TroubieD3v/photofinish/internal/check"
	"github.com/TroubieD3v/photofinish/internal/engine"
)

// Progress phases.
const (
	// PhaseStart is reported once, before the first trial, with the
	// resolved plan.
	PhaseStart = "start"
	// PhaseTrial is reported after every trial that ends up in the report,
	// including a trial aborted by an error.
	PhaseTrial = "trial"
	// PhaseDone is reported once, last, with the overall verdict.
	PhaseDone = "done"
)

// Progress is one structured progress event of a run, passed to
// Options.OnProgress.
//
// A run that gets past validation reports "start", one "trial" per trial
// and "done". A run that fails validation (an ERROR verdict before any
// trial is planned) reports only "done", with Planned 0.
type Progress struct {
	// Phase is PhaseStart, PhaseTrial or PhaseDone.
	Phase string `json:"phase"`
	// Planned is the number of trials the run was asked for.
	Planned int `json:"planned"`
	// Done is the number of trials finished so far.
	Done int `json:"done"`
	// Trial is the trial just finished (PhaseTrial only), masked like the
	// trials of the Report. It is a copy owned by the receiver. Secrets are
	// masked as far as they are known when the trial ends; the Report is
	// masked again after the run, with every secret the run collected.
	Trial *Trial `json:"trial,omitempty"`
	// Verdict is the overall verdict (PhaseDone only).
	Verdict Verdict `json:"verdict,omitempty"`
}

// notify passes p to the progress callback, if there is one.
func (o Options) notify(p Progress) {
	if o.OnProgress != nil {
		o.OnProgress(p)
	}
}

// notifyTrial reports a finished trial as a masked copy.
func (r *run) notifyTrial(t Trial, done int) {
	if r.opts.OnProgress == nil {
		return
	}
	cp := cloneTrial(t)
	scrubTrial(r.mask.scrubber(), &cp)
	r.opts.notify(Progress{Phase: PhaseTrial, Planned: r.trials, Done: done, Trial: &cp})
}

// cloneTrial returns a copy of t that shares nothing scrubTrial modifies in
// place, and nothing the receiver of a progress event could change in the
// report.
func cloneTrial(t Trial) Trial {
	t.Reasons = slices.Clone(t.Reasons)
	t.Setup = cloneSteps(t.Setup)
	t.Reset = cloneSteps(t.Reset)
	if t.Check != nil {
		c := cloneStep(*t.Check)
		t.Check = &c
	}
	if t.Terms != nil {
		terms := make([]check.Term, len(t.Terms))
		for i, tm := range t.Terms {
			if tm.Pass != nil {
				p := *tm.Pass
				tm.Pass = &p
			}
			terms[i] = tm
		}
		t.Terms = terms
	}
	if t.Race != nil {
		race := *t.Race
		race.Notes = slices.Clone(race.Notes)
		if race.Results != nil {
			race.Results = make([]engine.Result, len(t.Race.Results))
			for i, res := range t.Race.Results {
				res.Header = res.Header.Clone()
				res.Body = slices.Clone(res.Body)
				race.Results[i] = res
			}
		}
		t.Race = &race
	}
	return t
}

// cloneSteps copies a list of step records.
func cloneSteps(recs []StepRecord) []StepRecord {
	if recs == nil {
		return nil
	}
	out := make([]StepRecord, len(recs))
	for i, rec := range recs {
		out[i] = cloneStep(rec)
	}
	return out
}

// cloneStep copies one step record.
func cloneStep(rec StepRecord) StepRecord {
	rec.Header = rec.Header.Clone()
	return rec
}
