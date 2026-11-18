package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
)

// fakePublishServer answers the Git Data and pull request calls publishPR makes, recording them.
func fakePublishServer(t *testing.T, failPR bool) (_ *fakeCalls, host string, tr http.RoundTripper) {
	t.Helper()
	calls := &fakeCalls{}
	reply := func(w http.ResponseWriter, status int, body string) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v3/repos/o/r", func(w http.ResponseWriter, r *http.Request) {
		calls.add("GET repo")
		reply(w, 200, `{"default_branch":"develop"}`)
	})
	mux.HandleFunc("/api/v3/repos/o/r/git/ref/heads/", func(w http.ResponseWriter, r *http.Request) {
		calls.add("GET ref " + strings.TrimPrefix(r.URL.Path, "/api/v3/repos/o/r/git/ref/heads/"))
		reply(w, 200, `{"ref":"refs/heads/x","object":{"sha":"basecommit"}}`)
	})
	mux.HandleFunc("/api/v3/repos/o/r/git/commits/basecommit", func(w http.ResponseWriter, r *http.Request) {
		reply(w, 200, `{"sha":"basecommit","tree":{"sha":"basetree"}}`)
	})
	mux.HandleFunc("/api/v3/repos/o/r/git/blobs", func(w http.ResponseWriter, r *http.Request) {
		calls.add("POST blob")
		reply(w, 201, `{"sha":"blobsha"}`)
	})
	mux.HandleFunc("/api/v3/repos/o/r/git/trees", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			BaseTree string `json:"base_tree"`
			Tree     []struct{ Path, Mode string }
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		for _, e := range body.Tree {
			calls.add("tree " + e.Path + " " + e.Mode)
		}
		calls.add("base_tree " + body.BaseTree)
		reply(w, 201, `{"sha":"newtree"}`)
	})
	mux.HandleFunc("/api/v3/repos/o/r/git/commits", func(w http.ResponseWriter, r *http.Request) {
		reply(w, 201, `{"sha":"newcommit"}`)
	})
	mux.HandleFunc("/api/v3/repos/o/r/git/refs", func(w http.ResponseWriter, r *http.Request) {
		var body struct{ Ref, SHA string }
		_ = json.NewDecoder(r.Body).Decode(&body)
		calls.add("create ref " + body.Ref + " " + body.SHA)
		reply(w, 201, `{"ref":"`+body.Ref+`"}`)
	})
	mux.HandleFunc("/api/v3/repos/o/r/pulls", func(w http.ResponseWriter, r *http.Request) {
		var body struct{ Title, Head, Base string }
		_ = json.NewDecoder(r.Body).Decode(&body)
		calls.add("PR " + body.Head + " -> " + body.Base)
		if failPR {
			reply(w, 422, `{"message":"Validation Failed"}`)
			return
		}
		reply(w, 201, `{"html_url":"https://github.example/o/r/pull/7"}`)
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	return calls, strings.TrimPrefix(srv.URL, "https://"), srv.Client().Transport
}

type fakeCalls struct {
	mu   sync.Mutex
	list []string
}

func (c *fakeCalls) add(s string) { c.mu.Lock(); c.list = append(c.list, s); c.mu.Unlock() }

func TestPublishPR(t *testing.T) {
	opts := prPublishOptions{
		NewBranch: "cx-remediate/sast-1", CommitMessage: "fix", PRTitle: "t", PRBody: "b",
		Files: []patchedFile{{Path: "a.txt", Content: []byte("x")}, {Path: "run.sh", Content: []byte("y"), Executable: true}},
	}

	calls, host, tr := fakePublishServer(t, false)
	client, err := newGithubClient("token", host, tr)
	if err != nil {
		t.Fatal(err)
	}
	// no base branch given: the repository's default branch is used
	url, err := publishPR(context.Background(), client, "o", "r", opts)
	if err != nil || url != "https://github.example/o/r/pull/7" {
		t.Fatalf("publishPR = (%q, %v)", url, err)
	}
	for _, want := range []string{
		"GET ref develop", "tree a.txt 100644", "tree run.sh 100755", "base_tree basetree",
		"create ref refs/heads/cx-remediate/sast-1 newcommit", "PR cx-remediate/sast-1 -> develop",
	} {
		if !slices.Contains(calls.list, want) {
			t.Errorf("missing call %q in %v", want, calls.list)
		}
	}

	// an explicit base branch is used without looking up the default
	calls, host, tr = fakePublishServer(t, false)
	client, _ = newGithubClient("token", host, tr)
	opts.BaseBranch = "main"
	if _, err := publishPR(context.Background(), client, "o", "r", opts); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(calls.list, "GET repo") || !slices.Contains(calls.list, "PR cx-remediate/sast-1 -> main") {
		t.Errorf("unexpected calls %v", calls.list)
	}

	// a failed pull request is an error; the branch is deliberately left in place
	_, host, tr = fakePublishServer(t, true)
	client, _ = newGithubClient("token", host, tr)
	if _, err := publishPR(context.Background(), client, "o", "r", opts); err == nil || !strings.Contains(err.Error(), "pull request") {
		t.Errorf("want a pull request error, got %v", err)
	}

	// nothing to publish
	if _, err := publishPR(context.Background(), client, "o", "r", prPublishOptions{}); err == nil {
		t.Error("want an error for no files")
	}
}

func TestSevcmp(t *testing.T) {
	order := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
	for i := range order {
		for j := range order {
			got := sevcmp(order[i], order[j])
			if (i < j && got >= 0) || (i == j && got != 0) || (i > j && got <= 0) {
				t.Errorf("sevcmp(%s, %s) = %d", order[i], order[j], got)
			}
		}
	}
	// a severity this tool does not know sorts after every known one
	if sevcmp("HIGH", "WEIRD") >= 0 || sevcmp("WEIRD", "HIGH") <= 0 || sevcmp("WEIRD", "ODD") != 0 {
		t.Error("unknown severities must sort last")
	}
}
