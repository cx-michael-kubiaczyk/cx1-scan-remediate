package main

import (
	"strings"

	"github.com/sirupsen/logrus"
)

// Result states this tool understands. AI Triage never sets NOT_EXPLOITABLE itself: it only
// proposes PROPOSED_NOT_EXPLOITABLE, which a human still has to confirm. The state of a finding
// after AI Triage is whatever the platform reports when the results are re-read (state_refresh.go).
const (
	stateToVerify               = "TO_VERIFY"
	stateNotExploitable         = "NOT_EXPLOITABLE"
	stateProposedNotExploitable = "PROPOSED_NOT_EXPLOITABLE"
	stateConfirmed              = "CONFIRMED"
	stateUrgent                 = "URGENT"
)

var knownStates = map[string]bool{
	stateToVerify:               true,
	stateNotExploitable:         true,
	stateProposedNotExploitable: true,
	stateConfirmed:              true,
	stateUrgent:                 true,
}

// normalizeState upper-cases a state and turns spaces and hyphens into underscores, so that
// "Proposed Not Exploitable" and "proposed-not-exploitable" match PROPOSED_NOT_EXPLOITABLE.
func normalizeState(raw string) string {
	s := strings.ToUpper(strings.TrimSpace(raw))
	return strings.NewReplacer(" ", "_", "-", "_").Replace(s)
}

// aiTriageState is the state a finding gets from AI Triage's own response, used while
// useRefetchedStates is off. AI Triage never sets NOT_EXPLOITABLE: a NOT_EXPLOITABLE
// exploitability or a NOT_REACHABLE reachability becomes PROPOSED_NOT_EXPLOITABLE, which a person
// still has to confirm. An EXPLOITABLE exploitability (that is not a state itself) is treated as
// CONFIRMED, so the finding is remediated in this same run. Any other unrecognized value keeps the
// finding's state, with a warning.
func aiTriageState(logger *logrus.Logger, source, exploitability, reachability, fallback string) string {
	if strings.EqualFold(strings.TrimSpace(exploitability), "EXPLOITABLE") && !strings.EqualFold(strings.TrimSpace(reachability), "NOT_REACHABLE") {
		return stateConfirmed
	}
	s := resolveState(logger, source, exploitability, fallback)
	if s == stateNotExploitable || s == stateProposedNotExploitable || strings.EqualFold(strings.TrimSpace(reachability), "NOT_REACHABLE") {
		return stateProposedNotExploitable
	}
	return s
}

// resolveState normalizes a state reported by the platform. If it is empty or not one of the
// known states it logs a warning and returns fallback, so an unexpected value can never
// silently change how a finding is treated (only CONFIRMED and URGENT are ever remediated).
func resolveState(logger *logrus.Logger, source string, raw, fallback string) string {
	s := normalizeState(raw)
	switch {
	case s == "":
		logger.Warnf("%s: empty state received; keeping %q", source, fallback)
		return fallback
	case !knownStates[s]:
		logger.Warnf("%s: unrecognized state %q (expected one of TO_VERIFY, NOT_EXPLOITABLE, PROPOSED_NOT_EXPLOITABLE, CONFIRMED, URGENT); keeping %q", source, raw, fallback)
		return fallback
	}
	return s
}

// aiAssessment is what AI Triage said about a finding. It is only an expectation of what the
// platform will then report, never the finding's state itself.
type aiAssessment struct {
	Exploitability string
	Reachability   string
}

// expectedStates returns the states the platform is expected to report for a finding after AI
// Triage gave this assessment, or nil if the assessment implies none (empty, still to verify,
// or a value this tool does not know). AI Triage never sets NOT_EXPLOITABLE itself, so a
// not-exploitable or not-reachable assessment is expected as PROPOSED_NOT_EXPLOITABLE, and an
// exploitable one as CONFIRMED or URGENT.
func expectedStates(a aiAssessment) []string {
	ex := normalizeState(a.Exploitability)
	re := normalizeState(a.Reachability)
	switch {
	case re == "NOT_REACHABLE", ex == stateNotExploitable, ex == stateProposedNotExploitable:
		return []string{stateProposedNotExploitable, stateNotExploitable}
	case ex == "EXPLOITABLE", ex == stateConfirmed, ex == stateUrgent:
		return []string{stateConfirmed, stateUrgent}
	}
	return nil
}
