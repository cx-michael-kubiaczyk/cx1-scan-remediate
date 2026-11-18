package main

import (
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/cxpsemea/Cx1ClientGo"
	"github.com/sirupsen/logrus"
)

func quietLogger() (*logrus.Logger, *strings.Builder) {
	var out strings.Builder
	l := logrus.New()
	l.SetOutput(&out)
	l.SetLevel(logrus.DebugLevel)
	return l, &out
}

func TestExpectedStates(t *testing.T) {
	cases := []struct {
		ex, re string
		want   []string
	}{
		{"NOT_EXPLOITABLE", "REACHABLE", []string{"PROPOSED_NOT_EXPLOITABLE", "NOT_EXPLOITABLE"}},
		{"TO_VERIFY", "NOT_REACHABLE", []string{"PROPOSED_NOT_EXPLOITABLE", "NOT_EXPLOITABLE"}},
		{"EXPLOITABLE", "REACHABLE", []string{"CONFIRMED", "URGENT"}},
		{"exploitable", "", []string{"CONFIRMED", "URGENT"}},
		{"URGENT", "", []string{"CONFIRMED", "URGENT"}},
		{"TO_VERIFY", "REACHABLE", nil},
		{"", "", nil},
		{"garbage", "", nil},
	}
	for _, c := range cases {
		got := expectedStates(aiAssessment{Exploitability: c.ex, Reachability: c.re})
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("expectedStates(%q, %q) = %v, want %v", c.ex, c.re, got, c.want)
		}
	}
}

func scaSet(states map[string]string) Cx1ClientGo.ScanResultSet {
	var rs Cx1ClientGo.ScanResultSet
	for id, s := range states {
		rs.SCA = append(rs.SCA, Cx1ClientGo.ScanSCAResult{ScanResultBase: Cx1ClientGo.ScanResultBase{AlternateID: id, State: s}})
	}
	return rs
}

func TestRefreshStatesRetriesOnceOnMismatch(t *testing.T) {
	logger, out := quietLogger()
	index := []resultIndex{
		{Engine: "sca", AlternateID: "a1", State: "TO_VERIFY", AI: &aiAssessment{Exploitability: "EXPLOITABLE", Reachability: "REACHABLE"}},
		{Engine: "sca", AlternateID: "a2", State: "TO_VERIFY", AI: &aiAssessment{Exploitability: "NOT_EXPLOITABLE", Reachability: "REACHABLE"}},
		{Engine: "sca", AlternateID: "a3", State: "TO_VERIFY"}, // not triaged: never a mismatch
	}
	calls := 0
	fetch := func() (Cx1ClientGo.ScanResultSet, error) {
		calls++
		if calls == 1 { // the platform has not caught up with the first finding yet
			return scaSet(map[string]string{"a1": "TO_VERIFY", "a2": "PROPOSED_NOT_EXPLOITABLE", "a3": "TO_VERIFY"}), nil
		}
		return scaSet(map[string]string{"a1": "CONFIRMED", "a2": "PROPOSED_NOT_EXPLOITABLE", "a3": "TO_VERIFY"}), nil
	}
	var slept []time.Duration
	err := refreshStates(logger, fetch, index, budget{}, 15*time.Second, func(d time.Duration) { slept = append(slept, d) })
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 || len(slept) != 1 || slept[0] != 15*time.Second {
		t.Errorf("fetches=%d sleeps=%v, want exactly one retry after 15s", calls, slept)
	}
	if index[0].State != "CONFIRMED" || index[1].State != "PROPOSED_NOT_EXPLOITABLE" || index[2].State != "TO_VERIFY" {
		t.Errorf("states after retry: %s, %s, %s", index[0].State, index[1].State, index[2].State)
	}
	if !strings.Contains(out.String(), "AI Triage said") || !strings.Contains(out.String(), "state as TO_VERIFY") {
		t.Errorf("expected a mismatch warning, got:\n%s", out.String())
	}
	if strings.Contains(out.String(), "Still the case") {
		t.Errorf("the mismatch was resolved by the retry, but it was reported as still present:\n%s", out.String())
	}
}

func TestRefreshStatesNoRetryWhenStatesMatch(t *testing.T) {
	logger, _ := quietLogger()
	index := []resultIndex{{Engine: "sca", AlternateID: "a1", State: "TO_VERIFY", AI: &aiAssessment{Exploitability: "NOT_EXPLOITABLE", Reachability: ""}}}
	calls := 0
	fetch := func() (Cx1ClientGo.ScanResultSet, error) {
		calls++
		return scaSet(map[string]string{"a1": "PROPOSED_NOT_EXPLOITABLE"}), nil
	}
	if err := refreshStates(logger, fetch, index, budget{}, time.Second, func(time.Duration) { t.Error("must not wait") }); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Errorf("fetches=%d, want 1", calls)
	}
}

func TestRefreshStatesStillMismatchedAfterRetry(t *testing.T) {
	logger, out := quietLogger()
	index := []resultIndex{{Engine: "sca", AlternateID: "a1", State: "TO_VERIFY", AI: &aiAssessment{Exploitability: "EXPLOITABLE", Reachability: "REACHABLE"}}}
	calls := 0
	fetch := func() (Cx1ClientGo.ScanResultSet, error) {
		calls++
		return scaSet(map[string]string{"a1": "TO_VERIFY"}), nil
	}
	_ = refreshStates(logger, fetch, index, budget{}, time.Second, func(time.Duration) {})
	if calls != 2 {
		t.Errorf("fetches=%d, want exactly 2 (one retry only)", calls)
	}
	if !strings.Contains(out.String(), "Still the case after re-reading") {
		t.Errorf("expected the remaining mismatch to be reported:\n%s", out.String())
	}
	if isVerified(&index[0]) {
		t.Error("a finding the platform still reports as TO_VERIFY must not be remediated")
	}
}

func TestRefreshStatesFetchErrorsAndBudget(t *testing.T) {
	logger, _ := quietLogger()
	logger.SetOutput(io.Discard)
	index := []resultIndex{{Engine: "sca", AlternateID: "a1", State: "TO_VERIFY", AI: &aiAssessment{Exploitability: "EXPLOITABLE", Reachability: ""}}}

	// the first fetch fails: error returned, state untouched
	if err := refreshStates(logger, func() (Cx1ClientGo.ScanResultSet, error) { return Cx1ClientGo.ScanResultSet{}, errors.New("boom") },
		index, budget{}, time.Second, func(time.Duration) {}); err == nil || index[0].State != "TO_VERIFY" {
		t.Errorf("err=%v state=%s", err, index[0].State)
	}

	// the retry fetch fails: no error, states from the first read are kept
	calls := 0
	err := refreshStates(logger, func() (Cx1ClientGo.ScanResultSet, error) {
		calls++
		if calls == 2 {
			return Cx1ClientGo.ScanResultSet{}, errors.New("boom")
		}
		return scaSet(map[string]string{"a1": "TO_VERIFY"}), nil
	}, index, budget{}, time.Second, func(time.Duration) {})
	if err != nil || calls != 2 || index[0].State != "TO_VERIFY" {
		t.Errorf("err=%v calls=%d state=%s", err, calls, index[0].State)
	}

	// not enough budget left: no retry
	calls = 0
	_ = refreshStates(logger, func() (Cx1ClientGo.ScanResultSet, error) {
		calls++
		return scaSet(map[string]string{"a1": "TO_VERIFY"}), nil
	}, index, newBudget(time.Second), 15*time.Second, func(time.Duration) { t.Error("must not wait") })
	if calls != 1 {
		t.Errorf("fetches=%d, want 1 when the budget is nearly spent", calls)
	}
}

func TestApplyFetchedStatesMatchesBySimilarityAndPackage(t *testing.T) {
	logger, out := quietLogger()
	index := []resultIndex{
		// the platform's results carry no alternate ID, only the similarity ID (and package, for SCA)
		{Engine: "sca", AlternateID: "rep1", SimilarityID: "CVE-1", PackageID: "Maven-a-1", State: "TO_VERIFY", AI: &aiAssessment{Exploitability: "NOT_EXPLOITABLE", Reachability: ""}},
		{Engine: "sca", AlternateID: "rep2", SimilarityID: "CVE-1", PackageID: "Maven-b-1", State: "TO_VERIFY", AI: &aiAssessment{Exploitability: "EXPLOITABLE", Reachability: ""}},
		{Engine: "sast", AlternateID: "rep3", SimilarityID: "-123", State: "TO_VERIFY"},
		{Engine: "sca", AlternateID: "rep4", SimilarityID: "CVE-9", PackageID: "Maven-z-1", State: "TO_VERIFY", AI: &aiAssessment{Exploitability: "EXPLOITABLE", Reachability: ""}}, // not returned at all
	}
	var fetched Cx1ClientGo.ScanResultSet
	fetched.SCA = []Cx1ClientGo.ScanSCAResult{
		{ScanResultBase: Cx1ClientGo.ScanResultBase{SimilarityID: "CVE-1", State: "PROPOSED_NOT_EXPLOITABLE"}, Data: Cx1ClientGo.ScanSCAResultData{PackageIdentifier: "Maven-a-1"}},
		{ScanResultBase: Cx1ClientGo.ScanResultBase{SimilarityID: "CVE-1", State: "CONFIRMED"}, Data: Cx1ClientGo.ScanSCAResultData{PackageIdentifier: "Maven-b-1"}},
	}
	fetched.SAST = []Cx1ClientGo.ScanSASTResult{{ScanResultBase: Cx1ClientGo.ScanResultBase{SimilarityID: "-123", State: "CONFIRMED"}}}

	changed, missing := applyFetchedStates(logger, index, &fetched)
	if changed != 3 || missing != 1 {
		t.Errorf("changed=%d missing=%d, want 3 and 1", changed, missing)
	}
	if index[0].State != "PROPOSED_NOT_EXPLOITABLE" || index[1].State != "CONFIRMED" || index[2].State != "CONFIRMED" || index[3].State != "TO_VERIFY" {
		t.Errorf("states: %s %s %s %s", index[0].State, index[1].State, index[2].State, index[3].State)
	}
	if index[3].Refreshed || !index[0].Refreshed {
		t.Error("only findings found in the platform's results are marked as refreshed")
	}
	// a finding that was not found is never reported as a mismatch (nothing is known about it)
	if m := triageMismatches(index); len(m) != 0 {
		t.Errorf("unexpected mismatches: %v", m)
	}
	// one summary warning, not one per finding
	if n := strings.Count(out.String(), "were not found in the"); n != 1 {
		t.Errorf("want one aggregated warning, got %d:\n%s", n, out.String())
	}
}
