package main

import (
	"cmp"
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/cxpsemea/Cx1ClientGo"
	"github.com/google/go-github/v92/github"
	"github.com/sirupsen/logrus"
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
func newGithubClient(token, host string, transport http.RoundTripper) (*github.Client, error) {
	opts := []github.ClientOptionsFunc{github.WithAuthToken(token)}
	if transport != nil {
		opts = append(opts, github.WithTransport(transport))
	}

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

	// NOTE: if PullRequests.Create fails below, the branch created above is left behind. It could
	// be deleted here (client.Git.DeleteRef), but this tool deliberately does not: deleting a
	// branch on an error path risks removing something it should not (for example a branch that
	// someone has since pushed to), and a leftover branch is harmless. The next run skips the
	// finding because the branch exists (see branchExists), and a person can delete the branch
	// to have it retried.
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

// branchExists reports whether the branch already exists in owner/repo. A 404 means it does not;
// any other failure is returned, so the caller never mistakes "could not check" for "absent".
func branchExists(ctx context.Context, client *github.Client, owner, repo, branch string) (bool, error) {
	_, resp, err := client.Git.GetRef(ctx, owner, repo, "refs/heads/"+branch)
	if err == nil {
		return true, nil
	}
	if resp != nil && resp.StatusCode == http.StatusNotFound {
		return false, nil
	}
	return false, err
}

// prOptions configures how a pull request is published for each remediation.
type prOptions struct {
	Token      string
	Transport  http.RoundTripper // shared with the Cx1 client, so GitHub calls honor -proxy, -insecure and -caCert
	Repo       string
	BaseBranch string
	Branch     string
}

// branchFor names the branch for a finding's pull request. The name depends only on the
// finding, so the same finding always gets the same branch and a later run can tell it has
// already been remediated. -prBranch is always a prefix, joined to the finding with "-" (or
// directly, if the prefix already ends in "/" or "-").
func branchFor(pr prOptions, f *resultIndex) string {
	prefix := cmp.Or(pr.Branch, defaultBranchPrefix)
	if !strings.HasSuffix(prefix, "/") && !strings.HasSuffix(prefix, "-") {
		prefix += "-"
	}
	return prefix + sanitizeBranchComponent(f.Engine+"-"+f.AlternateID)
}

const defaultBranchPrefix = "cx1-remediate/"

// maxBranchComponent caps the finding part of a branch name. Result IDs are 28 to 44 characters, so
// this does not shorten them; it only keeps names well inside the 255-byte limit that GitHub and
// filesystems place on a ref name.
const maxBranchComponent = 100

// githubTarget returns a GitHub client and the owner and repo to look for branches in.
// pr.Repo has already been resolved by the preflight.
func githubTarget(pr prOptions) (*github.Client, string, string, error) {
	host, owner, repo, err := parseOwnerRepo(pr.Repo)
	if err != nil {
		return nil, "", "", err
	}
	client, err := newGithubClient(pr.Token, host, pr.Transport)
	if err != nil {
		return nil, "", "", err
	}
	return client, owner, repo, nil
}

// publishRemediationPR opens a GitHub pull request containing exactly the files produced by
// applyRemediationInMemory.
func publishRemediationPR(logger *logrus.Logger, details Cx1ClientGo.AIRemediationDetails, applied []patchedFile, pr prOptions, branch string) {
	if len(applied) == 0 {
		logger.Info("Remediation produced no file changes; skipping pull request creation")
		return
	}
	if len(details.Results) == 0 {
		logger.Info("No remediation results to publish; skipping pull request creation")
		return
	}

	client, owner, repo, err := githubTarget(pr)
	if err != nil {
		recordError(logger, "Failed to set up GitHub access for %q: %s", pr.Repo, err)
		return
	}

	result := details.Results[0]

	title := cmp.Or(result.Data.PRTitle, result.Data.Summary, "Checkmarx One AI remediation")

	htmlURL, err := publishPR(context.Background(), client, owner, repo, prPublishOptions{
		BaseBranch:    pr.BaseBranch,
		NewBranch:     branch,
		CommitMessage: title,
		PRTitle:       title,
		PRBody:        buildPRBody(result),
		Files:         applied,
	})
	if err != nil {
		recordError(logger, "Failed to publish pull request: %s", err)
		return
	}

	logger.Infof("Created pull request: %s", htmlURL)
}

// buildPRBody turns the remediation's analysis and file changes into a PR description.
func buildPRBody(result Cx1ClientGo.AIRemediationResult) string {
	var b strings.Builder

	fmt.Fprintf(&b, "%s\n\n", result.Data.Summary)
	fmt.Fprintf(&b, "**What:** %s\n\n", result.Data.Analysis.What)
	fmt.Fprintf(&b, "**Why:** %s\n\n", result.Data.Analysis.Why)
	fmt.Fprintf(&b, "**How:** %s\n\n", result.Data.Analysis.How)

	if len(result.Data.FileChanges) > 0 {
		b.WriteString("**Files changed:**\n")
		for _, fc := range result.Data.FileChanges {
			fmt.Fprintf(&b, "- `%s`: %s\n", fc.FilePath, fc.Analysis)
		}
		b.WriteString("\n")
	}

	if len(result.Data.TestCreation.TestFiles) > 0 {
		b.WriteString("**Tests added:**\n")
		for _, tf := range result.Data.TestCreation.TestFiles {
			fmt.Fprintf(&b, "- `%s`\n", tf.FilePath)
		}
		b.WriteString("\n")
	}

	fmt.Fprintf(&b, "---\n_Generated by Checkmarx One AI Remediation (remediation ID: %s)._\n", result.RemediationID)

	return b.String()
}

// sanitizeBranchComponent keeps a result/resultID usable as part of a git branch name.
func sanitizeBranchComponent(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}

	out := b.String()
	if len(out) > maxBranchComponent {
		out = out[:maxBranchComponent]
	}
	return out
}
