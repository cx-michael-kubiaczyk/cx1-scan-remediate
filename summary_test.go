package main

import (
	"testing"

	"github.com/cxpsemea/Cx1ClientGo"
)

func res(severity, state string) Cx1ClientGo.ScanResultBase {
	return Cx1ClientGo.ScanResultBase{Severity: severity, State: state}
}

func TestRemainingByEngine(t *testing.T) {
	rs := &Cx1ClientGo.ScanResultSet{
		SAST: []Cx1ClientGo.ScanSASTResult{
			{ScanResultBase: res("HIGH", "TO_VERIFY")},
			{ScanResultBase: res("CRITICAL", "PROPOSED_NOT_EXPLOITABLE")}, // still counts
			{ScanResultBase: res("HIGH", "NOT_EXPLOITABLE")},               // excluded
			{ScanResultBase: res("MEDIUM", "TO_VERIFY")},                   // wrong severity
		},
		SCA: []Cx1ClientGo.ScanSCAResult{
			{ScanResultBase: res("CRITICAL", "confirmed")},
			{ScanResultBase: res("HIGH", "Not Exploitable")}, // excluded, other spelling
		},
		Secrets: []Cx1ClientGo.ScanSecretsResult{{ScanResultBase: res("HIGH", "TO_VERIFY")}},
		IAC:     []Cx1ClientGo.ScanIACResult{{ScanResultBase: res("LOW", "TO_VERIFY")}},
		Unknown: []Cx1ClientGo.ScanUnknownResult{{ScanResultBase: res("CRITICAL", "URGENT")}},
	}
	sev := map[string]bool{"CRITICAL": true, "HIGH": true}
	got := remainingByEngine(rs, sev, enginesInScope{SAST: true, SCA: true})

	want := []engineCount{
		{"SAST", 2, true},
		{"SCA", 1, true},
		{"Secret Detection", 1, false},
		{"Unknown", 1, false},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d: got %+v, want %+v", i, got[i], want[i])
		}
	}
	if s := formatRemaining(got); s != "SAST 2, SCA 1, Secret Detection 1 (not handled by this tool), Unknown 1 (not handled by this tool)" {
		t.Errorf("unexpected format: %s", s)
	}
}

func TestRemainingByEngineEngineNotSelected(t *testing.T) {
	rs := &Cx1ClientGo.ScanResultSet{SCA: []Cx1ClientGo.ScanSCAResult{{ScanResultBase: res("HIGH", "TO_VERIFY")}}}
	got := remainingByEngine(rs, map[string]bool{"HIGH": true}, enginesInScope{SAST: true})
	if len(got) != 1 || got[0].Handled {
		t.Errorf("SCA excluded via -engine must be reported as not handled, got %+v", got)
	}
	if s := formatRemaining(nil); s != "none" {
		t.Errorf("got %q", s)
	}
}
