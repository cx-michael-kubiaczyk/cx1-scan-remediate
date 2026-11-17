package main

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/cxpsemea/Cx1ClientGo"
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

func TestCanTriage(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(&bytes.Buffer{})

	cases := []struct {
		name string
		f    resultIndex
		want bool
	}{
		{"sast to_verify", resultIndex{Engine: "sast", State: "TO_VERIFY", SimilarityID: "1"}, true},
		{"sast confirmed", resultIndex{Engine: "sast", State: "CONFIRMED", SimilarityID: "1"}, false},
		{"sca complete", resultIndex{Engine: "sca", State: "TO_VERIFY", SimilarityID: "1", PackageID: "Npm-x-1.0"}, true},
		{"sca no package id", resultIndex{Engine: "sca", State: "TO_VERIFY", SimilarityID: "1"}, false},
		{"sca no similarity id", resultIndex{Engine: "sca", State: "TO_VERIFY", PackageID: "Npm-x-1.0"}, false},
	}
	for _, c := range cases {
		if got := canTriage(logger, &c.f); got != c.want {
			t.Errorf("%s: canTriage = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestApplyFetchedStates(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	index := []resultIndex{
		{Engine: "sca", AlternateID: "a1", State: "TO_VERIFY"},  // becomes proposed not exploitable
		{Engine: "sca", AlternateID: "a2", State: "TO_VERIFY"},  // becomes confirmed
		{Engine: "sast", AlternateID: "a1", State: "TO_VERIFY"}, // same alternate ID, other engine: unchanged
		{Engine: "sca", AlternateID: "a3", State: "TO_VERIFY"},  // platform reports an unknown state: kept
		{Engine: "sca", AlternateID: "a4", State: "CONFIRMED"},  // not returned by the platform: kept
	}
	fetched := &Cx1ClientGo.ScanResultSet{
		SCA: []Cx1ClientGo.ScanSCAResult{
			{ScanResultBase: Cx1ClientGo.ScanResultBase{AlternateID: "a1", State: "PROPOSED_NOT_EXPLOITABLE"}},
			{ScanResultBase: Cx1ClientGo.ScanResultBase{AlternateID: "a2", State: "Confirmed"}},
			{ScanResultBase: Cx1ClientGo.ScanResultBase{AlternateID: "a3", State: "EXPLOITABLE"}},
		},
		SAST: []Cx1ClientGo.ScanSASTResult{
			{ScanResultBase: Cx1ClientGo.ScanResultBase{AlternateID: "a1", State: "TO_VERIFY"}},
		},
	}

	changed, missing := applyFetchedStates(logger, index, fetched)
	want := []string{"PROPOSED_NOT_EXPLOITABLE", "CONFIRMED", "TO_VERIFY", "TO_VERIFY", "CONFIRMED"}
	for i, w := range want {
		if index[i].State != w {
			t.Errorf("finding %d: state %q, want %q", i, index[i].State, w)
		}
	}
	if changed != 2 || missing != 1 {
		t.Errorf("changed=%d missing=%d, want 2 and 1", changed, missing)
	}
	if isVerified(&index[0]) || !isVerified(&index[1]) {
		t.Error("only the finding the platform reports as CONFIRMED may be remediated")
	}
}

func TestSeverityList(t *testing.T) {
	got := severityList(map[string]bool{"HIGH": true, "CRITICAL": true, "LOW": true})
	if len(got) != 3 || got[0] != "CRITICAL" || got[1] != "HIGH" || got[2] != "LOW" {
		t.Errorf("got %v", got)
	}
}
