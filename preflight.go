package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"

	"github.com/cxpsemea/Cx1ClientGo"
	"github.com/google/go-github/v92/github"
	"github.com/sirupsen/logrus"
)

// errConfig marks a preflight failure the user has to fix (missing git, unusable repository,
// token without access, missing base branch). Any other error is an operational failure, such
// as GitHub being unreachable.
var errConfig = errors.New("configuration problem")

func configErrorf(format string, args ...interface{}) error {
	return fmt.Errorf("%w: %s", errConfig, fmt.Sprintf(format, args...))
}

// githubAccessError classifies a failed GitHub lookup. 401, 403 and 404 mean the token or the
// repository reference needs fixing; anything else (network errors, 5xx) is operational.
func githubAccessError(resp *github.Response, what string, err error) error {
	status := 0
	if resp != nil {
		status = resp.StatusCode
	}
	switch status {
	case http.StatusUnauthorized:
		return configErrorf("GitHub rejected the token while looking up %s (401): check the token is valid and not expired", what)
	case http.StatusForbidden:
		return configErrorf("GitHub refused access to %s (403): the token lacks permission, or the API rate limit was hit", what)
	case http.StatusNotFound:
		return configErrorf("%s not found (404): check the repository and that the token has access to it", what)
	default:
		return fmt.Errorf("failed to look up %s: %w", what, err)
	}
}

// checkRepoAccess confirms the token can push to owner/repo and that the base branch exists. An
// empty baseBranch means the repository's default branch. It returns the resolved base branch.
func checkRepoAccess(ctx context.Context, client *github.Client, owner, repo, baseBranch string) (string, error) {
	r, resp, err := client.Repositories.Get(ctx, owner, repo)
	if err != nil {
		return "", githubAccessError(resp, fmt.Sprintf("repository %s/%s", owner, repo), err)
	}

	// Some token types do not report permissions at all; only reject when they are reported
	// and none of them allows writing.
	if p := r.Permissions; p != nil && !(p.GetPush() || p.GetMaintain() || p.GetAdmin()) {
		return "", configErrorf("the token cannot write to %s/%s: it needs repo scope (classic) or Contents and Pull requests write (fine-grained)", owner, repo)
	}

	if baseBranch == "" {
		baseBranch = r.GetDefaultBranch()
	}
	if baseBranch == "" {
		return "", configErrorf("could not determine a base branch for %s/%s; pass -baseBranch", owner, repo)
	}

	if _, resp, err := client.Git.GetRef(ctx, owner, repo, "refs/heads/"+baseBranch); err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			return "", configErrorf("base branch %q does not exist in %s/%s", baseBranch, owner, repo)
		}
		return "", githubAccessError(resp, fmt.Sprintf("base branch %q of %s/%s", baseBranch, owner, repo), err)
	}

	return baseBranch, nil
}

// resolveRepoRef returns the repository to raise pull requests against: the -repo value, or
// else the repoUrl configured on the Checkmarx One project.
func resolveRepoRef(cx1client *Cx1ClientGo.Cx1Client, scan *Cx1ClientGo.Scan, repoFlag string) (string, error) {
	if repoFlag != "" {
		return repoFlag, nil
	}
	project, err := cx1client.GetProjectByID(scan.ProjectID)
	if err != nil {
		return "", fmt.Errorf("failed to look up project %s to determine its repository: %w", scan.ProjectID, err)
	}
	if project.RepoUrl == "" {
		return "", configErrorf("the Checkmarx One project has no repoUrl configured and -repo was not provided")
	}
	return project.RepoUrl, nil
}

// preflightPR checks everything pull request creation depends on, so that a problem is found
// before AI credits are spent rather than after. On success it returns pr with Repo and
// BaseBranch filled in, so publishing does not look them up again.
func preflightPR(ctx context.Context, logger *logrus.Logger, cx1client *Cx1ClientGo.Cx1Client, scan *Cx1ClientGo.Scan, pr prOptions, sourceDir string) (prOptions, error) {
	if _, err := exec.LookPath("git"); err != nil {
		return pr, configErrorf("git was not found on PATH; it is needed to apply remediation diffs")
	}
	if fi, err := os.Stat(sourceDir); err != nil || !fi.IsDir() {
		return pr, configErrorf("-dir %q is not a readable directory", sourceDir)
	}

	repoRef, err := resolveRepoRef(cx1client, scan, pr.Repo)
	if err != nil {
		return pr, err
	}
	host, owner, repo, err := parseOwnerRepo(repoRef)
	if err != nil {
		return pr, configErrorf("%s", err)
	}
	client, err := newGithubClient(pr.Token, host, pr.Transport)
	if err != nil {
		return pr, fmt.Errorf("failed to create GitHub client: %w", err)
	}
	base, err := checkRepoAccess(ctx, client, owner, repo, pr.BaseBranch)
	if err != nil {
		return pr, err
	}

	logger.Infof("Pull requests will be raised against %s/%s (base branch %s)", owner, repo, base)
	pr.Repo = repoRef
	pr.BaseBranch = base
	return pr, nil
}
