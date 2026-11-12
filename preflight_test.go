package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeGitHub serves just the endpoints checkRepoAccess uses, for owner "o" and repo "r".
func fakeGitHub(t *testing.T, repoStatus int, repoJSON string, branches ...string) (host string, transport http.RoundTripper) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v3/repos/o/r", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(repoStatus)
		_, _ = w.Write([]byte(repoJSON))
	})
	mux.HandleFunc("/api/v3/repos/o/r/git/", func(w http.ResponseWriter, r *http.Request) {
		for _, b := range branches {
			if strings.HasSuffix(r.URL.Path, "/heads/"+b) {
				_, _ = w.Write([]byte(`{"ref":"refs/heads/` + b + `","object":{"sha":"abc"}}`))
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"Not Found"}`))
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "https://"), srv.Client().Transport
}

func TestCheckRepoAccess(t *testing.T) {
	const writable = `{"default_branch":"main","permissions":{"push":true}}`
	cases := []struct {
		name       string
		status     int
		body       string
		base       string
		wantBase   string
		wantErr    bool
		wantConfig bool
	}{
		{"default branch", 200, writable, "", "main", false, false},
		{"explicit existing branch", 200, writable, "release", "release", false, false},
		{"missing base branch", 200, writable, "nope", "", true, true},
		{"read-only token", 200, `{"default_branch":"main","permissions":{"push":false,"pull":true}}`, "", "", true, true},
		{"permissions not reported", 200, `{"default_branch":"main"}`, "", "main", false, false},
		{"unauthorized", 401, `{"message":"Bad credentials"}`, "", "", true, true},
		{"not found", 404, `{"message":"Not Found"}`, "", "", true, true},
		{"server error", 500, `{"message":"boom"}`, "", "", true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			host, tr := fakeGitHub(t, c.status, c.body, "main", "release")
			client, err := newGithubClient("token", host, tr)
			if err != nil {
				t.Fatal(err)
			}
			got, err := checkRepoAccess(context.Background(), client, "o", "r", c.base)
			if (err != nil) != c.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, c.wantErr)
			}
			if err != nil && errors.Is(err, errConfig) != c.wantConfig {
				t.Errorf("config error = %v, want %v (%v)", errors.Is(err, errConfig), c.wantConfig, err)
			}
			if got != c.wantBase {
				t.Errorf("base = %q, want %q", got, c.wantBase)
			}
		})
	}
}
