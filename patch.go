package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/cxpsemea/Cx1ClientGo"
	"github.com/sirupsen/logrus"
)

// patchedFile is the complete post-remediation content of one file: Path is where it
// lives in the repo (forward-slash, relative), Content is what it should contain.
type patchedFile struct {
	Path    string
	Content []byte
}

// applyRemediationInMemory computes the result of applying a remediation to the source tree
// rooted at baseDir, without modifying baseDir. File-change diffs are applied with "git apply"
// inside a throwaway copy of just the files they touch; generated test files come back from
// the platform as full content and are used as-is.
//
// Because baseDir is never written to, every remediation is computed against the same
// pristine files regardless of what was remediated before it, so several remediations that
// touch the same file (e.g. pom.xml) each produce an independent, cleanly-applying result.
//
// The remediation is all-or-nothing: if any diff cannot be applied an error is returned and
// nothing is produced, since a half-applied fix is worse than none.
func applyRemediationInMemory(logger *logrus.Logger, details Cx1ClientGo.AIRemediationDetails, baseDir string) ([]patchedFile, error) {
	root, err := os.MkdirTemp("", "cx1-remediate-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create scratch directory: %w", err)
	}
	defer func() {
		if os.Getenv("CX1SR_DEBUG") != "" {
			fmt.Println("Scratch directory kept: ", root)
		} else {
			os.RemoveAll(root)
		}
	}()

	tree := filepath.Join(root, "tree")       // copy of the affected files, patched in place
	patches := filepath.Join(root, "patches") // kept outside tree so they never look like results
	for _, dir := range []string{tree, patches} {
		if err := os.Mkdir(dir, 0700); err != nil {
			return nil, fmt.Errorf("failed to create scratch directory: %w", err)
		}
	}

	originals := map[string][]byte{} // content in baseDir of each patched file; nil if it does not exist there
	generated := map[string][]byte{}

	patchNum := 0
	for _, result := range details.Results {
		if result.Data.Error != nil {
			logger.Errorf("Remediation %s for result %s reported an error, skipping: %s", result.RemediationID, result.ResultID, *result.Data.Error)
			continue
		}

		for _, fc := range result.Data.FileChanges {
			patchNum++
			if err := applyDiffInScratch(baseDir, tree, filepath.Join(patches, fmt.Sprintf("%d.patch", patchNum)), originals, fc); err != nil {
				return nil, fmt.Errorf("failed to apply change to %s: %w", fc.FilePath, err)
			}
			logger.Infof("Applied change to %s", fc.FilePath)
		}

		for _, tf := range result.Data.TestCreation.TestFiles {
			rel, err := cleanRepoPath(tf.FilePath)
			if err != nil {
				return nil, fmt.Errorf("generated test file: %w", err)
			}
			generated[rel] = []byte(tf.FileContent)
			logger.Infof("Generated test file %s", tf.FilePath)
		}
	}

	changed := map[string][]byte{}
	for rel, original := range originals {
		content, err := os.ReadFile(filepath.Join(tree, filepath.FromSlash(rel)))
		switch {
		case errors.Is(err, fs.ErrNotExist) && original == nil:
			return nil, fmt.Errorf("diff for %s did not create the file (its paths do not match file_path)", rel)
		case errors.Is(err, fs.ErrNotExist):
			return nil, fmt.Errorf("diff for %s deletes the file, which is not supported", rel)
		case err != nil:
			return nil, fmt.Errorf("failed to read patched %s: %w", rel, err)
		}
		if original != nil && bytes.Equal(original, content) {
			continue
		}
		changed[rel] = content
	}
	maps.Copy(changed, generated)

	files := make([]patchedFile, 0, len(changed))
	for _, rel := range slices.Sorted(maps.Keys(changed)) {
		files = append(files, patchedFile{Path: rel, Content: changed[rel]})
	}
	return files, nil
}

// applyDiffInScratch applies one file's unified diff inside tree with "git apply", which works
// standalone against a plain directory (tree does not need to be a git repository) and handles
// new-file creation as well as modification. The file named by fc.FilePath is copied in from
// baseDir the first time it is seen, so later diffs to the same file build on earlier ones.
func applyDiffInScratch(baseDir, tree, patchPath string, originals map[string][]byte, fc Cx1ClientGo.AIRemediationFileChange) error {
	if strings.TrimSpace(fc.Diff) == "" {
		return fmt.Errorf("remediation did not include a diff")
	}

	rel, err := cleanRepoPath(fc.FilePath)
	if err != nil {
		return err
	}

	if _, seen := originals[rel]; !seen {
		content, err := os.ReadFile(filepath.Join(baseDir, filepath.FromSlash(rel)))
		switch {
		case errors.Is(err, fs.ErrNotExist):
			originals[rel] = nil
		case err != nil:
			return fmt.Errorf("failed to read %s: %w", rel, err)
		default:
			originals[rel] = content
			dst := filepath.Join(tree, filepath.FromSlash(rel))
			if err := os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
				return err
			}
			if err := os.WriteFile(dst, content, 0600); err != nil {
				return err
			}
		}
	}

	diff := fc.Diff
	if !strings.HasSuffix(diff, "\n") {
		diff += "\n"
	}
	if err := os.WriteFile(patchPath, []byte(diff), 0600); err != nil {
		return fmt.Errorf("failed to write patch file: %w", err)
	}

	// "git apply" is atomic: if any hunk fails, nothing in tree is modified.
	cmd := exec.Command("git", "apply", "--whitespace=nowarn", patchPath)
	cmd.Dir = tree
	// stop git treating tree as part of an enclosing repository if TMPDIR happens to sit inside one
	cmd.Env = append(os.Environ(), "GIT_CEILING_DIRECTORIES="+filepath.Dir(filepath.Dir(tree)))
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("patch would not apply cleanly: %s", strings.TrimSpace(string(out)))
	}

	return nil
}

// cleanRepoPath validates a file path received from the platform and returns it in
// forward-slash form. Absolute paths and anything that escapes the source tree are rejected,
// since the path is used to read from disk and to build paths inside the scratch directory.
func cleanRepoPath(p string) (string, error) {
	local := filepath.FromSlash(strings.TrimSpace(p))
	if !filepath.IsLocal(local) {
		return "", fmt.Errorf("unsafe file path %q: must be relative and stay within the source directory", p)
	}
	return filepath.ToSlash(filepath.Clean(local)), nil
}
