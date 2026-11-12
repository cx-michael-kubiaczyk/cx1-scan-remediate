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

// newGithubClient builds a go-github client authenticated with token. host is the repo's
// hostname as returned by parseOwnerRepo: "github.com", a GitHub Enterprise Server hostname
// (API at https://<host>/api/v3/), or a GitHub Enterprise Cloud hostname with data residency
// (<name>.ghe.com, API at https://api.<host>/).
func newGithubClient(token, host string, transport http.RoundTripper) (*github.Client, error) {
	opts := []github.ClientOptionsFunc{github.WithAuthToken(token)}
	if transport != nil {
		opts = append(opts, github.WithTransport(transport))
	}

	switch {
	case host == "" || strings.EqualFold(host, "github.com"):
	case isGHECloudHost(host):
		opts = append(opts, github.WithEnterpriseURLs(
			fmt.Sprintf("https://api.%s/", host),
			fmt.Sprintf("https://uploads.%s/", host)))
	default:
		opts = append(opts, github.WithEnterpriseURLs(
			fmt.Sprintf("https://%s/api/v3/", host),
			fmt.Sprintf("https://%s/api/uploads/", host)))
	}

	return github.NewClient(opts...)
}

// isGHECloudHost reports whether host is a GitHub Enterprise Cloud with data residency host.
func isGHECloudHost(host string) bool {
	return strings.HasSuffix(strings.ToLower(host), ".ghe.com")
}

// unsupportedHost reports whether host belongs to another source-control service (GitLab,
// Bitbucket, Azure DevOps). Such hosts would otherwise be mistaken for GitHub Enterprise Server
// and fail with a confusing 404.
func unsupportedHost(host string) bool {
	h := strings.ToLower(host)
	for _, known := range []string{"gitlab.com", "bitbucket.org", "dev.azure.com", "ssh.dev.azure.com", "visualstudio.com"} {
		if h == known || strings.HasSuffix(h, "."+known) {
			return true
		}
	}
	// self-hosted installations of the same products
	return strings.HasPrefix(h, "gitlab.") || strings.HasPrefix(h, "bitbucket.")
}

// parseOwnerRepo extracts the SCM host, owner and repo name from a repo reference: "owner/repo",
// an HTTP(S) URL, an SSH URL (git@host:owner/repo.git or ssh://git@host[:port]/owner/repo.git).
// Anything after the first two path segments (such as /tree/main) is ignored. The host is
// lower-case, without a leading "www." and, for SSH URLs, without the SSH port (an HTTP(S)
// port is kept, as it is part of the web address). A plain http:// URL is used as https://.
// Hosts of other services (GitLab, Bitbucket, Azure DevOps) are rejected.
func parseOwnerRepo(repoURLOrSlug string) (host, owner, repo string, err error) {
	s := strings.TrimSpace(repoURLOrSlug)

	switch {
	case strings.Contains(s, "://"):
		u, perr := url.Parse(s)
		if perr != nil {
			return "", "", "", fmt.Errorf("could not parse repo URL %q: %w", repoURLOrSlug, perr)
		}
		host = u.Hostname()
		if u.Scheme == "http" || u.Scheme == "https" {
			host = u.Host // keeps a port; the user info is not part of it
		}
		s = u.Path
	case strings.Contains(s, "@") && strings.Contains(s, ":"):
		// scp-like SSH syntax: git@host:owner/repo.git
		rest := s[strings.Index(s, "@")+1:]
		host, s, _ = strings.Cut(rest, ":")
	default:
		host = "github.com"
	}

	host = strings.TrimPrefix(strings.ToLower(host), "www.")
	if host == "" {
		return "", "", "", fmt.Errorf("could not determine the host from %q", repoURLOrSlug)
	}
	if unsupportedHost(host) {
		return "", "", "", fmt.Errorf("%q is not a GitHub host; only GitHub pull requests are supported", host)
	}

	parts := strings.Split(strings.Trim(s, "/"), "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", "", "", fmt.Errorf("could not determine owner/repo from %q", repoURLOrSlug)
	}
	repo = strings.TrimSuffix(parts[1], ".git")
	if repo == "" {
		return "", "", "", fmt.Errorf("could not determine owner/repo from %q", repoURLOrSlug)
	}

	return host, parts[0], repo, nil
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

		mode := "100644"
		if f.Executable {
			mode = "100755" // keep the executable bit of e.g. gradlew or a shell script
		}
		entries = append(entries, &github.TreeEntry{
			Path: new(f.Path),
			Mode: new(mode),
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
