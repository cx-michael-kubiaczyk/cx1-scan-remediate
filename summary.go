package main

import (
	"fmt"
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
	counts := remainingByEngine(summaryResults, summarySeverities, summaryEngines)
	logger.Warnf("Results from the scan report still counting against the threshold (-severity matches, state not NOT_EXPLOITABLE; PROPOSED_NOT_EXPLOITABLE still counts): %s", formatRemaining(counts))
}
