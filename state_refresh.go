package main

import (
	"fmt"
	"slices"
	"time"

	"github.com/cxpsemea/Cx1ClientGo"
	"github.com/sirupsen/logrus"
)

// stateRetryDelay is how long to wait before re-reading the results once, when the platform's
// states do not match what AI Triage said (the result state may lag behind the triage job).
const stateRetryDelay = 15 * time.Second

// severityList turns the -severity set into the list the results filter takes, most severe first.
func severityList(severities map[string]bool) []string {
	list := make([]string, 0, len(severities))
	for s := range severities {
		list = append(list, s)
	}
	slices.SortFunc(list, sevcmp)
	return list
}

// resultsFetcher returns the scan's results as the platform currently has them.
type resultsFetcher func() (Cx1ClientGo.ScanResultSet, error)

// fetchResultsFor builds a resultsFetcher for one scan, limited to the -severity list. It has no
// state filter, so findings whose state changed to anything are seen.
func fetchResultsFor(cx1client *Cx1ClientGo.Cx1Client, scanID string, severities map[string]bool) resultsFetcher {
	return func() (Cx1ClientGo.ScanResultSet, error) {
		pagination := cx1client.GetPaginationSettings()
		_, fetched, err := cx1client.GetAllScanResultsFiltered(Cx1ClientGo.ScanResultsFilter{
			BaseFilter: Cx1ClientGo.BaseFilter{Limit: pagination.Results},
			ScanID:     scanID,
			Severity:   severityList(severities),
		})
		return fetched, err
	}
}

// refreshStates re-reads the scan's results from the platform after AI Triage and sets the state
// of every finding in index to what the platform reports: the platform, not the AI's label, is
// the source of truth for whether a finding is exploitable. AI Triage's own assessment is only
// used as an expectation. If a triaged finding's state is not what that assessment implies, it
// is logged, and the results are read once more after wait, in case the state lags behind the
// triage job; whatever is reported then is used, with any remaining mismatch logged again.
// If the results cannot be fetched, the states are left as they were, so nothing becomes
// eligible for remediation on a guess. The retry is skipped if the budget has less than wait left.
func refreshStates(logger *logrus.Logger, fetch resultsFetcher, index []resultIndex, aiBudget budget, wait time.Duration, sleep func(time.Duration)) error {
	fetched, err := fetch()
	if err != nil {
		return err
	}
	applyFetchedStates(logger, index, &fetched)

	mismatches := triageMismatches(index)
	if len(mismatches) == 0 {
		return nil
	}
	for _, m := range mismatches {
		logger.Warn(m)
	}
	if aiBudget.remaining() <= wait {
		logger.Warn("Not enough of the overall -timeout left to re-read the results; using the states above")
		return nil
	}

	logger.Infof("The state of %d finding(s) does not match what AI Triage said; waiting %s and re-reading the results once", len(mismatches), wait)
	sleep(wait)
	fetched, err = fetch()
	if err != nil {
		logger.Warnf("Could not re-read the results (%s); using the states above", err)
		return nil
	}
	applyFetchedStates(logger, index, &fetched)
	for _, m := range triageMismatches(index) {
		logger.Warn("Still the case after re-reading: " + m)
	}
	return nil
}

// triageMismatches describes each finding whose current state is not one AI Triage's assessment
// implies (see expectedStates). Findings without an assessment, or without an expectation from
// it, are never reported.
func triageMismatches(index []resultIndex) []string {
	var out []string
	for i := range index {
		f := &index[i]
		if f.AI == nil {
			continue
		}
		expected := expectedStates(*f.AI)
		if expected == nil || slices.Contains(expected, f.State) {
			continue
		}
		out = append(out, fmt.Sprintf("AI Triage said %s is exploitability %s, reachability %s (expected one of %v), but the platform reports its state as %s",
			f, f.AI.Exploitability, f.AI.Reachability, expected, f.State))
	}
	return out
}

// applyFetchedStates sets each finding's State from the matching result (same engine and
// alternate ID) in fetched. An empty or unrecognized state is kept as it was, with a warning
// (see resolveState). It returns how many states changed and how many findings were not found.
func applyFetchedStates(logger *logrus.Logger, index []resultIndex, fetched *Cx1ClientGo.ScanResultSet) (changed, missing int) {
	type key struct{ engine, alternateID string }
	states := map[key]string{}
	for _, r := range fetched.SAST {
		states[key{"sast", r.AlternateID}] = r.State
	}
	for _, r := range fetched.SCA {
		states[key{"sca", r.AlternateID}] = r.State
	}
	for _, r := range fetched.IAC {
		states[key{"iac", r.AlternateID}] = r.State
	}

	for i := range index {
		f := &index[i]
		raw, ok := states[key{f.Engine, f.AlternateID}]
		if !ok {
			missing++
			logger.Warnf("%s was not in the results re-read from the platform; its state stays %s", f, f.State)
			continue
		}
		state := resolveState(logger, "Platform state of "+f.String(), raw, f.State)
		if state != f.State {
			logger.Infof("State of %s is now %s (was %s)", f, state, f.State)
			f.State = state
			changed++
		}
	}
	return changed, missing
}
