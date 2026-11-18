package main

import (
	"bytes"
	"flag"
	"strings"
	"time"
	"testing"

	"github.com/cxpsemea/Cx1ClientGo"
	"github.com/sirupsen/logrus"
)

func TestParseLogLevel(t *testing.T) {
	for in, want := range map[string]logrus.Level{
		"INFO": logrus.InfoLevel, "info": logrus.InfoLevel, " debug  ": logrus.DebugLevel,
		"warn": logrus.WarnLevel, "Warning": logrus.WarnLevel, "TRACE": logrus.TraceLevel,
		"error": logrus.ErrorLevel, "fatal": logrus.FatalLevel,
	} {
		got, err := parseLogLevel(in)
		if err != nil || got != want {
			t.Errorf("parseLogLevel(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "information", "verbose"} {
		if _, err := parseLogLevel(bad); err == nil {
			t.Errorf("parseLogLevel(%q): expected an error", bad)
		}
	}
}

func TestParseEngines(t *testing.T) {
	in, err := parseEngines(" sast, SCA ")
	if err != nil || !in.SAST || !in.SCA || in.IAC {
		t.Errorf("got %+v, %v", in, err)
	}
	in, err = parseEngines("sca")
	if err != nil || in.SAST || !in.SCA {
		t.Errorf("got %+v, %v", in, err)
	}
	for _, bad := range []string{"", " , ", "sast,sac", "iac", "sast,kics", "containers"} {
		if _, err := parseEngines(bad); err == nil {
			t.Errorf("parseEngines(%q): expected an error", bad)
		}
	}
}

func TestCheckCount(t *testing.T) {
	logger := logrus.New()
	var buf bytes.Buffer
	logger.SetOutput(&buf)

	if n, err := checkCount(logger, "triage", 5); n != 5 || err != nil {
		t.Errorf("got %d, %v", n, err)
	}
	if n, err := checkCount(logger, "triage", 0); n != 0 || err != nil {
		t.Errorf("got %d, %v", n, err)
	}
	if _, err := checkCount(logger, "triage", -1); err == nil {
		t.Error("negative must be an error")
	}
	if buf.Len() != 0 {
		t.Errorf("unexpected log output: %s", buf.String())
	}
	if n, err := checkCount(logger, "triage", 1000); n != maxAIFindings || err != nil {
		t.Errorf("got %d, %v; want cap %d", n, err, maxAIFindings)
	}
	if buf.Len() == 0 {
		t.Error("expected a warning when capping")
	}
}

func TestApplyEnvDefaults(t *testing.T) {
	newSet := func(args ...string) (*flag.FlagSet, *int, *bool, *string) {
		fs := flag.NewFlagSet("t", flag.ContinueOnError)
		n := fs.Int("triage-count", 0, "")
		b := fs.Bool("insecure", false, "")
		s := fs.String("repo", "", "")
		if err := fs.Parse(args); err != nil {
			t.Fatal(err)
		}
		return fs, n, b, s
	}
	t.Setenv("CXSR_TRIAGE_COUNT", "7")
	t.Setenv("CXSR_INSECURE", "true")
	t.Setenv("CXSR_REPO", "  o/r  ")

	fs, n, b, s := newSet()
	if err := applyEnvDefaults(fs); err != nil {
		t.Fatal(err)
	}
	if *n != 7 || !*b || *s != "o/r" {
		t.Errorf("env not applied: %d %v %q", *n, *b, *s)
	}

	// a flag given on the command line wins over the environment
	fs, n, _, s = newSet("--triage-count", "2", "--repo=x/y")
	if err := applyEnvDefaults(fs); err != nil {
		t.Fatal(err)
	}
	if *n != 2 || *s != "x/y" {
		t.Errorf("flag should win: %d %q", *n, *s)
	}

	// a blank variable is ignored; an invalid one is an error naming the variable
	t.Setenv("CXSR_REPO", "   ")
	fs, _, _, s = newSet()
	if err := applyEnvDefaults(fs); err != nil || *s != "" {
		t.Errorf("blank env: %v %q", err, *s)
	}
	t.Setenv("CXSR_TRIAGE_COUNT", "many")
	fs, _, _, _ = newSet()
	if err := applyEnvDefaults(fs); err == nil || !strings.Contains(err.Error(), "CXSR_TRIAGE_COUNT") {
		t.Errorf("want an error naming CXSR_TRIAGE_COUNT, got %v", err)
	}
}

// flag names are kebab-case and each has at least one environment variable
func TestFlagEnvNamesAreKebabCase(t *testing.T) {
	for name, envs := range flagEnv {
		if name != strings.ToLower(name) || strings.ContainsAny(name, "_ ") {
			t.Errorf("flag %q is not kebab-case", name)
		}
		if len(envs) == 0 {
			t.Errorf("flag %q has no environment variable", name)
		}
	}
}

func TestApplyPollingOverrides(t *testing.T) {
	vars := Cx1ClientGo.ClientVars{AIPollingDelaySeconds: 30, AIPollingMaxSeconds: 600, AIDetailsPollingDelaySeconds: 15, AIDetailsPollingMaxSeconds: 60}
	if err := applyPollingOverrides(&vars, 0, 20*time.Minute, 1500*time.Millisecond, 0); err != nil {
		t.Fatal(err)
	}
	if vars.AIPollingDelaySeconds != 30 || vars.AIPollingMaxSeconds != 1200 || vars.AIDetailsPollingDelaySeconds != 2 || vars.AIDetailsPollingMaxSeconds != 60 {
		t.Errorf("unexpected %+v", vars)
	}
	if err := applyPollingOverrides(&vars, -time.Second, 0, 0, 0); err == nil {
		t.Error("a negative duration must be rejected")
	}
}
