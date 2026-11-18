package main

import (
	"fmt"
	"slices"
	"strings"

	"github.com/cxpsemea/Cx1ClientGo"
	"github.com/sirupsen/logrus"
)

// engineCount is the number of results of one engine that still count against the threshold.
type engineCount struct {
	Engine  string
	Count   int
	Handled bool // whether this tool can triage/remediate this engine in this run
}

// remainingByEngine counts, per engine, the results in the report that have one of the given
// severities and are not NOT_EXPLOITABLE. PROPOSED_NOT_EXPLOITABLE is still counted: AI Triage
// only proposes that state and a person has to confirm it. Engines with no such results are
// left out. Results of an engine the library does not know are reported as "Unknown".
//
// This approximates what the AST CLI's threshold counted, from the state recorded in the scan
// report; it does not change as this run triages findings or opens pull requests.
func remainingByEngine(results *Cx1ClientGo.ScanResultSet, severities map[string]bool, inScope enginesInScope) []engineCount {
	counts := []engineCount{}
	add := func(engine string, handled bool, n int) {
		if n > 0 {
			counts = append(counts, engineCount{Engine: engine, Count: n, Handled: handled})
		}
	}
	remaining := func(severity, state string) bool {
		return severities[severity] && normalizeState(state) != stateNotExploitable
	}

	n := 0
	for _, r := range results.SAST {
		if remaining(r.Severity, r.State) {
			n++
		}
	}
	add("SAST", inScope.SAST, n)
	n = 0
	for _, r := range results.SCA {
		if remaining(r.Severity, r.State) {
			n++
		}
	}
	add("SCA", inScope.SCA, n)
	n = 0
	for _, r := range results.SCAContainer {
		if remaining(r.Severity, r.State) {
			n++
		}
	}
	add("SCA Container", false, n)
	n = 0
	for _, r := range results.IAC {
		if remaining(r.Severity, r.State) {
			n++
		}
	}
	add("IaC", inScope.IAC, n)
	n = 0
	for _, r := range results.Containers {
		if remaining(r.Severity, r.State) {
			n++
		}
	}
	add("Containers", false, n)
	n = 0
	for _, r := range results.Scorecard {
		if remaining(r.Severity, r.State) {
			n++
		}
	}
	add("Scorecard", false, n)
	n = 0
	for _, r := range results.Secrets {
		if remaining(r.Severity, r.State) {
			n++
		}
	}
	add("Secret Detection", false, n)
	n = 0
	for _, r := range results.Unknown {
		if remaining(r.Severity, r.State) {
			n++
		}
	}
	add("Unknown", false, n)
	return counts
}

// formatRemaining renders the counts as one line, e.g.
// "SAST 3, SCA 12, Secret Detection 1 (not handled by this tool)".
func formatRemaining(counts []engineCount) string {
	if len(counts) == 0 {
		return "none"
	}
	parts := make([]string, 0, len(counts))
	for _, c := range counts {
		s := fmt.Sprintf("%s %d", c.Engine, c.Count)
		if !c.Handled {
			s += " (not handled by this tool)"
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, ", ")
}

// summary of the report, set once it is parsed so finish can log it on every exit path.
var (
	summaryResults    *Cx1ClientGo.ScanResultSet
	summarySeverities map[string]bool
	summaryEngines    enginesInScope
)

func logRemainingSummary(logger *logrus.Logger) {
	if summaryResults == nil {
		return
	}
	for _, line := range describeRun(summaryIndex, run) {
		logger.Info(line)
	}
	counts := remainingByEngine(summaryResults, summarySeverities, summaryEngines)
	logger.Warnf("Results from the scan report still counting against the threshold (-severity matches, state not NOT_EXPLOITABLE; PROPOSED_NOT_EXPLOITABLE still counts): %s", formatRemaining(counts))
}

// runCounters records what this run did, for the summary logged on exit.
type runCounters struct {
	Requested    map[string]bool // findings AI Remediation was requested for
	BranchExists map[string]bool // verified findings skipped because their pull request branch already exists
	PRsOpened    int
}

var (
	run          = runCounters{Requested: map[string]bool{}, BranchExists: map[string]bool{}}
	summaryIndex []resultIndex // the findings this tool handles; their states are the current ones
)

func findingKey(f *resultIndex) string { return f.Engine + "/" + f.AlternateID }

// describeRun summarizes what this run did with the findings it handles (the -engine and
// -severity selection): what AI Triage concluded, what was remediated, and what is still waiting
// for a later run. Nothing here is a priority or a gate; every in-scope finding has to be
// addressed eventually, so the order in which runs get to them does not matter.
func describeRun(index []resultIndex, c runCounters) []string {
	triaged := map[string]int{}
	nTriaged, notTriaged, verified, notRemediated := 0, 0, 0, 0
	for i := range index {
		f := &index[i]
		if f.AI != nil {
			nTriaged++
			triaged[f.State]++
		} else if f.State == stateToVerify {
			notTriaged++
		}
		if isVerified(f) {
			verified++
			if !c.Requested[findingKey(f)] && !c.BranchExists[findingKey(f)] {
				notRemediated++
			}
		}
	}

	states := make([]string, 0, len(triaged))
	for s := range triaged {
		states = append(states, s)
	}
	slices.Sort(states)
	outcome := make([]string, 0, len(states))
	for _, s := range states {
		outcome = append(outcome, fmt.Sprintf("%s %d", s, triaged[s]))
	}

	lines := []string{}
	if nTriaged == 0 {
		lines = append(lines, "AI Triage: no findings were triaged in this run")
	} else {
		lines = append(lines, fmt.Sprintf("AI Triage: %d finding(s) triaged; resulting states: %s", nTriaged, strings.Join(outcome, ", ")))
	}
	lines = append(lines, fmt.Sprintf("AI Remediation: requested for %d finding(s), %d pull request(s) opened, %d Confirmed/Urgent finding(s) skipped because their branch already exists", len(c.Requested), c.PRsOpened, len(c.BranchExists)))
	lines = append(lines, fmt.Sprintf("Still to do in later runs (in scope for this tool): %d To_Verify finding(s) not triaged yet, %d Confirmed/Urgent finding(s) not remediated yet (of %d Confirmed/Urgent in total)", notTriaged, notRemediated, verified))
	return lines
}
