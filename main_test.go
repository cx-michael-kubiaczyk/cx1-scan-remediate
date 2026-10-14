package main

import (
	"slices"
	"testing"

	"github.com/cxpsemea/Cx1ClientGo"
)

func TestClampBatchSize(t *testing.T) {
	for in, want := range map[int]int{-3: 1, 0: 1, 1: 1, 4: 4, 5: 5, 6: 5, 100: 5} {
		if got := clampBatchSize(testLogger(), "x", in); got != want {
			t.Errorf("clampBatchSize(%d) = %d, want %d", in, got, want)
		}
	}
}

func TestParseSeverities(t *testing.T) {
	got, err := parseSeverities(" critical, High,,")
	if err != nil || len(got) != 2 || !got["CRITICAL"] || !got["HIGH"] {
		t.Errorf("got %v, %v", got, err)
	}
	for _, bad := range []string{"", " , ", "HIGH,URGENT"} {
		if _, err := parseSeverities(bad); err == nil {
			t.Errorf("parseSeverities(%q) should fail", bad)
		}
	}
}

func TestPickFindings(t *testing.T) {
	index := []resultIndex{
		{AlternateID: "a", State: "TO_VERIFY"},
		{AlternateID: "b", State: "NOT_EXPLOITABLE"},
		{AlternateID: "c", State: "TO_VERIFY"},
		{AlternateID: "d", State: "TO_VERIFY"},
	}
	toVerify := func(f *resultIndex) bool { return f.State == "TO_VERIFY" }

	ids := func(fs []*resultIndex) []string {
		var out []string
		for _, f := range fs {
			out = append(out, f.AlternateID)
		}
		return out
	}

	if got := ids(pickFindings(index, 2, toVerify)); !slices.Equal(got, []string{"a", "c"}) {
		t.Errorf("limit 2: got %v", got)
	}
	// asking for more than exist (including exactly len(index)) must not run past the end
	if got := ids(pickFindings(index, 10, toVerify)); !slices.Equal(got, []string{"a", "c", "d"}) {
		t.Errorf("limit 10: got %v", got)
	}

	// picks alias the index so state updates made by triage are seen by the remediation selection
	picked := pickFindings(index, 1, toVerify)
	picked[0].State = "NOT_EXPLOITABLE"
	if index[0].State != "NOT_EXPLOITABLE" {
		t.Error("picked finding does not alias the index")
	}
}

func TestToBuckets(t *testing.T) {
	got := toBuckets([]*resultIndex{
		{Engine: "sast", AlternateID: "s1"},
		{Engine: "sca", AlternateID: "c1"},
		{Engine: "sast", AlternateID: "s2"},
	})
	want := []Cx1ClientGo.AIRequestBucket{
		{Engine: "sast", AlternateIDs: []string{"s1", "s2"}},
		{Engine: "sca", AlternateIDs: []string{"c1"}},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i := range want {
		if got[i].Engine != want[i].Engine || !slices.Equal(got[i].AlternateIDs, want[i].AlternateIDs) {
			t.Errorf("bucket %d: got %+v, want %+v", i, got[i], want[i])
		}
	}
}
