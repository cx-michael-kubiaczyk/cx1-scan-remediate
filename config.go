package main

import (
	"flag"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/cxpsemea/Cx1ClientGo"
	"github.com/sirupsen/logrus"
)

// maxAIFindings is the most findings a single run will submit to AI Triage, and the most to AI
// Remediation, however high --triage-count or --remediate-count is set. Every one spends AI credits.
const maxAIFindings = 25

// supportedEngines are the engines AI Triage and AI Remediation can act on.
var supportedEngines = []string{"SAST", "SCA"}

// parseLogLevel turns the --log-level value into a logrus level. It accepts TRACE, DEBUG, INFO,
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
		return 0, fmt.Errorf("--%s must not be negative (got %d)", name, n)
	}
	if n > maxAIFindings {
		logger.Warnf("--%s capped at %d per run (requested %d) to protect AI credits", name, maxAIFindings, n)
		return maxAIFindings, nil
	}
	return n, nil
}

// flagEnv lists, for each flag, the environment variables it falls back to when the flag is not
// given (the first one that is set wins). Every flag except --access-token (short-lived) has one,
// so a pipeline can configure the tool without a command line. The Checkmarx One ones are the
// names the AST CLI reads too.
var flagEnv = map[string][]string{
	"log-level":              {"CXSR_LOG_LEVEL"},
	"report-file":            {"CXSR_REPORT_FILE"},
	"source-dir":             {"CXSR_SOURCE_DIR"},
	"engines":                {"CXSR_ENGINES"},
	"severities":             {"CXSR_SEVERITIES"},
	"triage-count":           {"CXSR_TRIAGE_COUNT"},
	"remediate-count":        {"CXSR_REMEDIATE_COUNT"},
	"triage-batch-size":      {"CXSR_TRIAGE_BATCH_SIZE"},
	"remediation-batch-size": {"CXSR_REMEDIATION_BATCH_SIZE"},
	"timeout":                {"CXSR_TIMEOUT"},
	"ai-poll-interval":         {"CXSR_AI_POLL_INTERVAL"},
	"ai-poll-timeout":          {"CXSR_AI_POLL_TIMEOUT"},
	"ai-details-poll-interval": {"CXSR_AI_DETAILS_POLL_INTERVAL"},
	"ai-details-poll-timeout":  {"CXSR_AI_DETAILS_POLL_TIMEOUT"},
	"github-token":           {"GITHUB_TOKEN"},
	"repo":                   {"CXSR_REPO"},
	"base-branch":            {"CXSR_BASE_BRANCH"},
	"pr-branch":              {"CXSR_PR_BRANCH"},
	"proxy":                  {"CXSR_PROXY"},
	"insecure":               {"CXSR_INSECURE"},
	"ca-cert":                {"CXSR_CA_CERT"},
	"no-keep-alive":          {"CXSR_NO_KEEP_ALIVE"},
	"keep-temp":              {"CXSR_KEEP_TEMP"},
	"user-agent":             {"CXSR_USER_AGENT"},
	"apikey":                 {"CX_APIKEY"},
	"client-id":              {"CX_CLIENT_ID"},
	"client-secret":          {"CX_CLIENT_SECRET"},
	"base-uri":               {"CX_BASE_URI"},
	"base-auth-uri":          {"CX_BASE_AUTH_URI"},
	"tenant":                 {"CX_TENANT"},
}

// documentEnv appends each flag's environment variables to its help text.
func documentEnv(fs *flag.FlagSet) {
	fs.VisitAll(func(f *flag.Flag) {
		if names := flagEnv[f.Name]; len(names) > 0 {
			f.Usage += " [env: " + strings.Join(names, ", ") + "]"
		}
	})
}

// applyEnvDefaults sets every flag that was not given on the command line from its environment
// variable, if that is set and not blank. A flag given on the command line always wins. It must
// run after fs.Parse.
func applyEnvDefaults(fs *flag.FlagSet) error {
	given := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { given[f.Name] = true })
	for name, envs := range flagEnv {
		if given[name] {
			continue
		}
		if v := valueOrEnv("", envs...); v != "" {
			if err := fs.Set(name, v); err != nil {
				return fmt.Errorf("invalid value %q in %s for --%s: %w", v, strings.Join(envs, "/"), name, err)
			}
		}
	}
	return nil
}

// applyPollingOverrides sets the library's AI polling settings from the --ai-* flags: how often
// the platform is asked whether an AI Triage or AI Remediation job has finished, and how long to
// wait for one finding, and the same for fetching the result details afterwards. A zero value
// keeps the library's default; a negative one is an error. Values are rounded up to whole seconds.
func applyPollingOverrides(vars *Cx1ClientGo.ClientVars, interval, timeout, detailsInterval, detailsTimeout time.Duration) error {
	for _, o := range []struct {
		name string
		d    time.Duration
		dst  *int
	}{
		{"--ai-poll-interval", interval, &vars.AIPollingDelaySeconds},
		{"--ai-poll-timeout", timeout, &vars.AIPollingMaxSeconds},
		{"--ai-details-poll-interval", detailsInterval, &vars.AIDetailsPollingDelaySeconds},
		{"--ai-details-poll-timeout", detailsTimeout, &vars.AIDetailsPollingMaxSeconds},
	} {
		if o.d < 0 {
			return fmt.Errorf("%s must not be negative (got %s)", o.name, o.d)
		}
		if o.d > 0 {
			*o.dst = int(math.Ceil(o.d.Seconds()))
		}
	}
	return nil
}
