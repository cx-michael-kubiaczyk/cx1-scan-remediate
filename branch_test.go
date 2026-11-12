package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBranchFor(t *testing.T) {
	f := &resultIndex{Engine: "sast", AlternateID: "HLg6+Y/o="}
	cases := []struct {
		name string
		pr   prOptions
		want string
	}{
		{"default", prOptions{}, "cx1-remediate/sast-HLg6-Y-o-"},
		{"prefix", prOptions{Branch: "fix"}, "fix-sast-HLg6-Y-o-"},
		{"prefix ending in slash", prOptions{Branch: "team/fix/"}, "team/fix/sast-HLg6-Y-o-"},
		{"prefix ending in dash", prOptions{Branch: "fix-"}, "fix-sast-HLg6-Y-o-"},
	}
	for _, c := range cases {
		if got := branchFor(c.pr, f); got != c.want {
			t.Errorf("%s: branchFor = %q, want %q", c.name, got, c.want)
		}
	}
	// the name must be stable between runs, or "already remediated" can never be detected
	if branchFor(prOptions{}, f) != branchFor(prOptions{}, f) {
		t.Error("branchFor is not deterministic")
	}
}

func TestBranchExists(t *testing.T) {
	host, tr := fakeGitHub(t, 200, `{}`, "taken")
	client, err := newGithubClient("token", host, tr)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := branchExists(context.Background(), client, "o", "r", "taken"); err != nil || !ok {
		t.Errorf("existing branch: got (%v, %v), want (true, nil)", ok, err)
	}
	if ok, err := branchExists(context.Background(), client, "o", "r", "free"); err != nil || ok {
		t.Errorf("absent branch: got (%v, %v), want (false, nil)", ok, err)
	}

	// anything other than 404 is "could not check", never "absent"
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusInternalServerError) })
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	client, err = newGithubClient("token", strings.TrimPrefix(srv.URL, "https://"), srv.Client().Transport)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := branchExists(context.Background(), client, "o", "r", "x"); err == nil || ok {
		t.Errorf("server error: got (%v, %v), want (false, error)", ok, err)
	}
}
