package main

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/cxpsemea/Cx1ClientGo"
)

func resultWith(id, title, summary string) Cx1ClientGo.AIRemediationResult {
	r := Cx1ClientGo.AIRemediationResult{ResultID: id, RemediationID: "rem-1"}
	r.Data.PRTitle = title
	r.Data.Summary = summary
	return r
}

func TestSelectResult(t *testing.T) {
	failure := "model failed"
	errored := resultWith("a", "", "")
	errored.Data.Error = &failure

	details := func(rs ...Cx1ClientGo.AIRemediationResult) Cx1ClientGo.AIRemediationDetails {
		return Cx1ClientGo.AIRemediationDetails{Results: rs}
	}

	// the matching result is chosen, whatever its position
	got, err := selectResult(details(errored, resultWith("b", "B", "")), "b")
	if err != nil || got.ResultID != "b" {
		t.Errorf("matching result: got %q, %v", got.ResultID, err)
	}
	// a single result is used when its ID does not match
	if got, err := selectResult(details(resultWith("other", "", "")), "b"); err != nil || got.ResultID != "other" {
		t.Errorf("single result: got %q, %v", got.ResultID, err)
	}
	// several results and no match: nothing can be chosen
	if _, err := selectResult(details(resultWith("x", "", ""), resultWith("y", "", "")), "b"); err == nil {
		t.Error("expected an error when no result matches")
	}
	if _, err := selectResult(details(), "b"); err == nil {
		t.Error("expected an error for no results")
	}
	// the finding's own result errored: it must not be replaced by another one
	if _, err := selectResult(details(errored, resultWith("b", "B", "")), "a"); err == nil || !strings.Contains(err.Error(), "model failed") {
		t.Errorf("errored result: got %v", err)
	}
}

func TestFindingLink(t *testing.T) {
	f := &resultIndex{AlternateID: "ab+/=c"}
	if got, want := findingLink("https://eu.ast.checkmarx.net/riskhub/p1", f), "https://eu.ast.checkmarx.net/riskhub/p1?resultId=ab%2B%2F%3Dc"; got != want {
		t.Errorf("findingLink = %q, want %q", got, want)
	}
	if got := findingLink("", f); got != "" {
		t.Errorf("no project link: got %q", got)
	}
}

func TestBuildPRContent(t *testing.T) {
	f := &resultIndex{Engine: "sast", Severity: "HIGH", AlternateID: "id1"}
	r := resultWith("id1", "Fix SQL injection", "Use a prepared statement")
	r.Data.Analysis.What, r.Data.Analysis.Why, r.Data.Analysis.How = "what", "why", "how"

	title, body := buildPRContent(r, f, "https://x/riskhub/p?resultId=id1")
	if title != "Fix SQL injection" {
		t.Errorf("title = %q", title)
	}
	for _, want := range []string{"HIGH SAST", "[View this finding in Checkmarx One](https://x/riskhub/p?resultId=id1)", "Use a prepared statement", "**How:** how", "must be reviewed by a person", "rem-1"} {
		if !strings.Contains(body, want) {
			t.Errorf("body is missing %q:\n%s", want, body)
		}
	}
	if _, body := buildPRContent(r, f, ""); strings.Contains(body, "View this finding") {
		t.Error("no link should be written when none is known")
	}

	// a missing title falls back to the summary, then to a fixed text
	if title, _ := buildPRContent(resultWith("id1", "", "A summary"), f, ""); title != "A summary" {
		t.Errorf("fallback to summary: %q", title)
	}
	if title, _ := buildPRContent(resultWith("id1", "", ""), f, ""); title == "" {
		t.Error("title must never be empty")
	}
}

func TestBuildPRContentLimits(t *testing.T) {
	f := &resultIndex{Engine: "sca", Severity: "CRITICAL", AlternateID: "id1"}
	long := strings.Repeat("é", 500) + "\nsecond line"
	r := resultWith("id1", long, strings.Repeat("s", 100000))

	title, body := buildPRContent(r, f, "")
	if n := utf8.RuneCountInString(title); n > maxPRTitle {
		t.Errorf("title has %d characters, limit %d", n, maxPRTitle)
	}
	if strings.ContainsAny(title, "\r\n") || !utf8.ValidString(title) {
		t.Errorf("title must be one line of valid UTF-8: %q", title)
	}
	if n := utf8.RuneCountInString(body); n > maxPRBody {
		t.Errorf("body has %d characters, limit %d", n, maxPRBody)
	}
	if !strings.Contains(body, "must be reviewed by a person") {
		t.Error("the review footer must survive truncation")
	}
}
