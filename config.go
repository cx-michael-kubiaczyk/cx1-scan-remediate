package main

import (
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
)

// maxAIFindings is the most findings a single run will submit to AI Triage, and the most to AI
// Remediation, however high -triage or -remediate is set. Every one spends AI credits.
const maxAIFindings = 25

// supportedEngines are the engines AI Triage and AI Remediation can act on.
var supportedEngines = []string{"SAST", "SCA"}

// parseLogLevel turns the -log value into a logrus level. It accepts TRACE, DEBUG, INFO,
// WARNING (or WARN), ERROR and FATAL in any case, ignoring surrounding whitespace.
func parseLogLevel(s string) (logrus.Level, error) {
	switch v := strings.ToUpper(strings.TrimSpace(s)); v {
	case "TRACE":
		return logrus.TraceLevel, nil
	case "DEBUG":
		return logrus.DebugLevel, nil
	case "INFO":
		return logrus.InfoLevel, nil
	case "WARNING", "WARN":
		return logrus.WarnLevel, nil
	case "ERROR":
		return logrus.ErrorLevel, nil
	case "FATAL":
		return logrus.FatalLevel, nil
	default:
		return logrus.InfoLevel, fmt.Errorf("unknown log level %q, expected one of TRACE, DEBUG, INFO, WARNING, ERROR, FATAL", s)
	}
}

// enginesInScope records which engines the run will triage and remediate.
type enginesInScope struct {
	SAST bool
	IAC  bool // not supported by AI Triage/Remediation yet; always false
	SCA  bool
}

// parseEngines turns the -engine list (case-insensitive, whitespace-tolerant) into the engines
// to process. Unknown or unsupported engines are an error, so a typo can't silently drop one.
func parseEngines(list string) (enginesInScope, error) {
	var in enginesInScope
	seen := 0
	for e := range strings.SplitSeq(list, ",") {
		e = strings.ToUpper(strings.TrimSpace(e))
		switch e {
		case "":
			continue
		case "SAST":
			in.SAST = true
		case "SCA":
			in.SCA = true
		case "IAC", "KICS":
			return in, fmt.Errorf("engine %q is not supported by AI Triage/Remediation yet; supported: %s", e, strings.Join(supportedEngines, ","))
		default:
			return in, fmt.Errorf("unknown engine %q, expected any of %s", e, strings.Join(supportedEngines, ","))
		}
		seen++
	}
	if seen == 0 {
		return in, fmt.Errorf("no engines specified, expected any of %s", strings.Join(supportedEngines, ","))
	}
	return in, nil
}

// checkCount validates a -triage or -remediate value: negative is an error, and more than
// maxAIFindings is reduced to it with a warning.
func checkCount(logger *logrus.Logger, name string, n int) (int, error) {
	if n < 0 {
		return 0, fmt.Errorf("-%s must not be negative (got %d)", name, n)
	}
	if n > maxAIFindings {
		logger.Warnf("-%s capped at %d per run (requested %d) to protect AI credits", name, maxAIFindings, n)
		return maxAIFindings, nil
	}
	return n, nil
}
