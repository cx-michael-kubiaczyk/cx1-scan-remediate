package main

import (
	"bytes"
	"testing"

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
