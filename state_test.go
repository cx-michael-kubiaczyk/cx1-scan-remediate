package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
)

func TestNormalizeState(t *testing.T) {
	for in, want := range map[string]string{
		"TO_VERIFY":                "TO_VERIFY",
		" confirmed ":              "CONFIRMED",
		"Proposed Not Exploitable": "PROPOSED_NOT_EXPLOITABLE",
		"not-exploitable":          "NOT_EXPLOITABLE",
		"urgent":                   "URGENT",
	} {
		if got := normalizeState(in); got != want {
			t.Errorf("normalizeState(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestResolveState(t *testing.T) {
	var buf bytes.Buffer
	logger := logrus.New()
	logger.SetOutput(&buf)

	for _, s := range []string{"TO_VERIFY", "NOT_EXPLOITABLE", "PROPOSED_NOT_EXPLOITABLE", "CONFIRMED", "URGENT"} {
		if got := resolveState(logger, "t", s, "TO_VERIFY"); got != s {
			t.Errorf("resolveState(%q) = %q", s, got)
		}
	}
	if buf.Len() != 0 {
		t.Errorf("unexpected warnings for known states: %s", buf.String())
	}

	if got := resolveState(logger, "t", "Proposed Not Exploitable", "TO_VERIFY"); got != "PROPOSED_NOT_EXPLOITABLE" {
		t.Errorf("got %q", got)
	}

	// unknown and empty values keep the fallback and warn
	for _, bad := range []string{"", "EXPLOITABLE", "false_positive"} {
		buf.Reset()
		if got := resolveState(logger, "t", bad, "CONFIRMED"); got != "CONFIRMED" {
			t.Errorf("resolveState(%q) = %q, want fallback", bad, got)
		}
		if !strings.Contains(buf.String(), "level=warning") {
			t.Errorf("expected a warning for %q, got %q", bad, buf.String())
		}
	}
}

func TestIsVerifiedOnlyConfirmedOrUrgent(t *testing.T) {
	for state, want := range map[string]bool{
		"CONFIRMED": true, "URGENT": true,
		"TO_VERIFY": false, "NOT_EXPLOITABLE": false, "PROPOSED_NOT_EXPLOITABLE": false,
	} {
		if got := isVerified(&resultIndex{State: state}); got != want {
			t.Errorf("isVerified(%s) = %v, want %v", state, got, want)
		}
	}
}
