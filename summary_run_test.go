package main

import (
	"strings"
	"testing"
)

func TestDescribeRun(t *testing.T) {
	index := []resultIndex{
		{Engine: "sca", AlternateID: "t1", State: "PROPOSED_NOT_EXPLOITABLE", AI: &aiAssessment{Exploitability: "NOT_EXPLOITABLE", Reachability: "REACHABLE"}},
		{Engine: "sca", AlternateID: "t2", State: "PROPOSED_NOT_EXPLOITABLE", AI: &aiAssessment{Exploitability: "NOT_EXPLOITABLE", Reachability: "NOT_REACHABLE"}},
		{Engine: "sca", AlternateID: "t3", State: "CONFIRMED", AI: &aiAssessment{Exploitability: "EXPLOITABLE", Reachability: "REACHABLE"}},
		{Engine: "sca", AlternateID: "v1", State: "TO_VERIFY"},  // not triaged yet
		{Engine: "sca", AlternateID: "v2", State: "TO_VERIFY"},  // not triaged yet
		{Engine: "sast", AlternateID: "c1", State: "CONFIRMED"}, // remediation requested
		{Engine: "sast", AlternateID: "c2", State: "URGENT"},    // branch already exists
		{Engine: "sast", AlternateID: "c3", State: "CONFIRMED"}, // not reached this run
	}
	c := runCounters{
		Requested:    map[string]bool{"sast/c1": true},
		BranchExists: map[string]bool{"sast/c2": true},
		PRsOpened:    1,
	}
	got := strings.Join(describeRun(index, c), "\n")

	for _, want := range []string{
		"3 finding(s) triaged; resulting states: CONFIRMED 1, PROPOSED_NOT_EXPLOITABLE 2",
		"requested for 1 finding(s), 1 pull request(s) opened, 1 Confirmed/Urgent finding(s) skipped because their branch already exists",
		"2 To_Verify finding(s) not triaged yet, 2 Confirmed/Urgent finding(s) not remediated yet (of 4 Confirmed/Urgent in total)",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

func TestDescribeRunNothingDone(t *testing.T) {
	got := strings.Join(describeRun([]resultIndex{{Engine: "sca", AlternateID: "v1", State: "TO_VERIFY"}}, runCounters{Requested: map[string]bool{}, BranchExists: map[string]bool{}}), "\n")
	if !strings.Contains(got, "no findings were triaged") || !strings.Contains(got, "1 To_Verify finding(s) not triaged yet, 0 Confirmed/Urgent") {
		t.Errorf("unexpected summary:\n%s", got)
	}
}
