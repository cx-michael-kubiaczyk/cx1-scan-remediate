package main

import "testing"

func TestParseOwnerRepo(t *testing.T) {
	cases := []struct {
		in                string
		host, owner, repo string
	}{
		{"o/r", "github.com", "o", "r"},
		{"o/r.git", "github.com", "o", "r"},
		{"https://github.com/o/r", "github.com", "o", "r"},
		{"https://github.com/o/r.git", "github.com", "o", "r"},
		{"https://github.com/o/r/", "github.com", "o", "r"},
		{"https://github.com/o/r/tree/main", "github.com", "o", "r"},
		{"https://github.com/o/r/pull/12", "github.com", "o", "r"},
		{"https://www.github.com/o/r", "github.com", "o", "r"},
		{"HTTPS://GitHub.com/o/r", "github.com", "o", "r"},
		{"https://user:token@github.com/o/r.git", "github.com", "o", "r"},
		{"git@github.com:o/r.git", "github.com", "o", "r"},
		{"ssh://git@github.com/o/r.git", "github.com", "o", "r"},
		{"ssh://git@github.com:22/o/r.git", "github.com", "o", "r"},
		{"git@ghe.example.com:o/r.git", "ghe.example.com", "o", "r"},
		{"ssh://git@ghe.example.com:2222/o/r.git", "ghe.example.com", "o", "r"},
		{"https://ghe.example.com:8443/o/r", "ghe.example.com:8443", "o", "r"},
		{"http://ghe.example.com/o/r", "ghe.example.com", "o", "r"},
		{"https://acme.ghe.com/o/r", "acme.ghe.com", "o", "r"},
		{"git@acme.ghe.com:o/r.git", "acme.ghe.com", "o", "r"},
		{"  o/r  ", "github.com", "o", "r"},
	}
	for _, c := range cases {
		host, owner, repo, err := parseOwnerRepo(c.in)
		if err != nil || host != c.host || owner != c.owner || repo != c.repo {
			t.Errorf("parseOwnerRepo(%q) = %q, %q, %q, %v; want %q, %q, %q", c.in, host, owner, repo, err, c.host, c.owner, c.repo)
		}
	}
}

func TestParseOwnerRepoRejects(t *testing.T) {
	for _, in := range []string{
		"", "o", "/", "o/", "/r", "https://github.com/o", "https://github.com/", "git@github.com:o",
		"https://gitlab.com/o/r", "git@gitlab.com:o/r.git", "https://bitbucket.org/o/r",
		"https://dev.azure.com/org/proj/_git/repo", "git@ssh.dev.azure.com:v3/org/proj/repo",
		"https://org.visualstudio.com/proj/_git/repo", "https://gitlab.example.com/o/r", "https:///o/r",
	} {
		if host, owner, repo, err := parseOwnerRepo(in); err == nil {
			t.Errorf("parseOwnerRepo(%q) = %q, %q, %q; want an error", in, host, owner, repo)
		}
	}
}

func TestGithubClientURLs(t *testing.T) {
	cases := map[string]struct{ base, upload string }{
		"github.com":           {"https://api.github.com/", "https://uploads.github.com/"},
		"ghe.example.com":      {"https://ghe.example.com/api/v3/", "https://ghe.example.com/api/uploads/"},
		"ghe.example.com:8443": {"https://ghe.example.com:8443/api/v3/", "https://ghe.example.com:8443/api/uploads/"},
		"acme.ghe.com":         {"https://api.acme.ghe.com/", "https://uploads.acme.ghe.com/"},
	}
	for host, want := range cases {
		c, err := newGithubClient("token", host, nil)
		if err != nil {
			t.Fatalf("%s: %v", host, err)
		}
		if c.BaseURL() != want.base || c.UploadURL() != want.upload {
			t.Errorf("%s: base %s, upload %s; want %s, %s", host, c.BaseURL(), c.UploadURL(), want.base, want.upload)
		}
	}
}
