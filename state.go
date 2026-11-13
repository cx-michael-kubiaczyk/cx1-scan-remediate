package main

import (
	"strings"

	"github.com/sirupsen/logrus"
)

// Result states this tool understands. AI Triage never sets NOT_EXPLOITABLE itself: it only
// proposes PROPOSED_NOT_EXPLOITABLE, which a human still has to confirm.
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

// aiTriageState turns an AI Triage result into the state this tool records for the finding.
// AI Triage never sets NOT_EXPLOITABLE: a NOT_EXPLOITABLE exploitability or a NOT_REACHABLE
// reachability becomes PROPOSED_NOT_EXPLOITABLE, which a person still has to confirm. The
// platform's own state is not fetched again, as the two APIs are not always in sync.
func aiTriageState(logger *logrus.Logger, source, exploitability, reachability, fallback string) string {
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
