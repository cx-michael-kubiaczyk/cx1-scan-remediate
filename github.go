package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"

	"github.com/google/go-github/v92/github"
)

// prPublishOptions describes the branch/commit/PR to create. BaseBranch may be left
// empty to use the repository's default branch.
type prPublishOptions struct {
	BaseBranch    string
	NewBranch     string
	CommitMessage string
	PRTitle       string
	PRBody        string
	Files         []patchedFile
}

// newGithubClient builds a go-github client authenticated with token. host is the
// repo's hostname ("github.com" or a GitHub Enterprise hostname); anything other than
// "github.com" is routed through the Enterprise API/upload base URLs.
func newGithubClient(token, host string) (*github.Client, error) {
	opts := []github.ClientOptionsFunc{github.WithAuthToken(token)}

	if host != "" && !strings.EqualFold(host, "github.com") {
		baseURL := fmt.Sprintf("https://%s/api/v3/", host)
		uploadURL := fmt.Sprintf("https://%s/api/uploads/", host)
		opts = append(opts, github.WithEnterpriseURLs(baseURL, uploadURL))
	}

	return github.NewClient(opts...)
}

// parseOwnerRepo extracts the SCM host, owner and repo name from a repo reference,
// accepting "owner/repo", an HTTPS URL, or an SSH URL (git@host:owner/repo.git).
func parseOwnerRepo(repoURLOrSlug string) (host, owner, repo string, err error) {
	s := strings.TrimSpace(repoURLOrSlug)
	s = strings.TrimSuffix(s, ".git")

	switch {
	case strings.HasPrefix(s, "git@"):
		rest := strings.TrimPrefix(s, "git@")
		parts := strings.SplitN(rest, ":", 2)
		if len(parts) != 2 {
			return "", "", "", fmt.Errorf("could not parse SSH repo URL %q", repoURLOrSlug)
		}
		host = parts[0]
		s = parts[1]
	case strings.Contains(s, "://"):
		u, perr := url.Parse(s)
		if perr != nil {
			return "", "", "", fmt.Errorf("could not parse repo URL %q: %w", repoURLOrSlug, perr)
		}
		host = u.Host
		s = strings.TrimPrefix(u.Path, "/")
	default:
		host = "github.com"
	}

	s = strings.Trim(s, "/")
	parts := strings.SplitN(s, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", "", fmt.Errorf("could not determine owner/repo from %q", repoURLOrSlug)
	}

	return host, parts[0], parts[1], nil
}

// publishPR builds a single commit containing just opts.Files (taken from memory, so the
// local source tree is not involved),
// pushes it to a new branch created directly via the Git Data API, and opens a pull
// request for it - no local git clone, history, or push credentials required.
func publishPR(ctx context.Context, client *github.Client, owner, repo string, opts prPublishOptions) (string, error) {
	if len(opts.Files) == 0 {
		return "", fmt.Errorf("no files to publish")
	}

	base := opts.BaseBranch
	if base == "" {
		r, _, err := client.Repositories.Get(ctx, owner, repo)
		if err != nil {
			return "", fmt.Errorf("failed to look up repository %s/%s: %w", owner, repo, err)
		}
		base = r.GetDefaultBranch()
	}
	if base == "" {
		return "", fmt.Errorf("could not determine a base branch for %s/%s", owner, repo)
	}

	baseRef, _, err := client.Git.GetRef(ctx, owner, repo, "refs/heads/"+base)
	if err != nil {
		return "", fmt.Errorf("failed to look up base branch %q: %w", base, err)
	}
	baseCommitSHA := baseRef.GetObject().GetSHA()

	baseCommit, _, err := client.Git.GetCommit(ctx, owner, repo, baseCommitSHA)
	if err != nil {
		return "", fmt.Errorf("failed to look up base commit %q: %w", baseCommitSHA, err)
	}
	baseTreeSHA := baseCommit.GetTree().GetSHA()

	entries := make([]*github.TreeEntry, 0, len(opts.Files))
	for _, f := range opts.Files {
		encoded := base64.StdEncoding.EncodeToString(f.Content)
		blob, _, err := client.Git.CreateBlob(ctx, owner, repo, github.Blob{
			Content:  new(encoded),
			Encoding: new("base64"),
		})
		if err != nil {
			return "", fmt.Errorf("failed to upload blob for %s: %w", f.Path, err)
		}

		entries = append(entries, &github.TreeEntry{
			Path: new(f.Path),
			Mode: new("100644"),
			Type: new("blob"),
			SHA:  blob.SHA,
		})
	}

	newTree, _, err := client.Git.CreateTree(ctx, owner, repo, baseTreeSHA, entries)
	if err != nil {
		return "", fmt.Errorf("failed to create tree: %w", err)
	}

	newCommit, _, err := client.Git.CreateCommit(ctx, owner, repo, github.Commit{
		Message: new(opts.CommitMessage),
		Tree:    newTree,
		Parents: []*github.Commit{{SHA: new(baseCommitSHA)}},
	}, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create commit: %w", err)
	}

	if _, _, err := client.Git.CreateRef(ctx, owner, repo, github.CreateRef{
		Ref: "refs/heads/" + opts.NewBranch,
		SHA: newCommit.GetSHA(),
	}); err != nil {
		return "", fmt.Errorf("failed to create branch %q: %w", opts.NewBranch, err)
	}

	pr, _, err := client.PullRequests.Create(ctx, owner, repo, github.CreatePullRequest{
		Title: new(opts.PRTitle),
		Head:  opts.NewBranch,
		Base:  base,
		Body:  new(opts.PRBody),
	})
	if err != nil {
		return "", fmt.Errorf("failed to create pull request: %w", err)
	}

	return pr.GetHTMLURL(), nil
}
