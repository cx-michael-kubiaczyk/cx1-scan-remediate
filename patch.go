package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
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
	// Executable is set when the file in the source directory has an executable bit, so that
	// the pull request keeps it. It is only detectable where the filesystem records it
	// (Linux and macOS); on Windows it is always false.
	Executable bool
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
			logger.Infof("Scratch directory kept (CX1SR_DEBUG is set): %s", root)
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
		// git apply is run with --ignore-whitespace so an LF diff matches a CRLF file, but then
		// writes the added lines with LF; restore the file's own line endings.
		if isCRLF(original) {
			content = toCRLF(content)
		}
		if original != nil && bytes.Equal(original, content) {
			continue
		}
		changed[rel] = content
	}
	maps.Copy(changed, generated)

	files := make([]patchedFile, 0, len(changed))
	for _, rel := range slices.Sorted(maps.Keys(changed)) {
		files = append(files, patchedFile{Path: rel, Content: changed[rel], Executable: isExecutable(baseDir, rel)})
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

	// "git apply" is atomic: if any hunk fails, nothing in tree is modified. Diffs normally carry
	// a/ and b/ prefixes (-p1); some have bare paths, which need -p0.
	var firstFailure string
	for _, strip := range []string{"-p1", "-p0"} {
		out, err := runGitApply(tree, strip, patchPath)
		if err == nil {
			return nil
		}
		if firstFailure == "" {
			firstFailure = out
		}
	}
	return fmt.Errorf("patch would not apply cleanly: %s", firstFailure)
}

// runGitApply applies patchPath inside tree. The runner's own git configuration is ignored and
// line-ending conversion is switched off, so the result is the same on every machine: for
// example core.autocrlf=true, common on Windows, would otherwise write CRLF into new files.
func runGitApply(tree, strip, patchPath string) (string, error) {
	cmd := exec.Command("git",
		"-c", "core.autocrlf=false", "-c", "core.safecrlf=false",
		"apply", strip, "--whitespace=nowarn", "--ignore-whitespace", patchPath)
	cmd.Dir = tree
	cmd.Env = append(os.Environ(),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL="+os.DevNull,
		// stop git treating tree as part of an enclosing repository if TMPDIR happens to sit inside one
		"GIT_CEILING_DIRECTORIES="+filepath.Dir(filepath.Dir(tree)),
	)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// isCRLF reports whether content uses CRLF line endings throughout (and has at least one).
func isCRLF(content []byte) bool {
	crlf := bytes.Count(content, []byte("\r\n"))
	return crlf > 0 && crlf == bytes.Count(content, []byte("\n"))
}

// toCRLF converts every line ending in content to CRLF.
func toCRLF(content []byte) []byte {
	lf := bytes.ReplaceAll(content, []byte("\r\n"), []byte("\n"))
	return bytes.ReplaceAll(lf, []byte("\n"), []byte("\r\n"))
}

// isExecutable reports whether rel has an executable bit in baseDir.
func isExecutable(baseDir, rel string) bool {
	info, err := os.Stat(filepath.Join(baseDir, filepath.FromSlash(rel)))
	return err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0
}

// driveLetter matches a Windows drive prefix such as "C:".
var driveLetter = regexp.MustCompile(`^[A-Za-z]:`)

// cleanRepoPath validates a file path received from the platform and returns it in
// forward-slash form. Backslashes are treated as separators, so a Windows-style path means the
// same thing on every platform. Absolute paths, drive letters and anything that escapes the
// source tree are rejected, since the path is used to read from disk and to build paths inside
// the scratch directory. The check is the same on every platform (it deliberately does not use
// filepath.IsLocal, which also rejects Windows reserved names), so a name such as aux.c is not
// accepted on Windows and rejected on Linux, or the reverse.
func cleanRepoPath(p string) (string, error) {
	s := strings.ReplaceAll(strings.TrimSpace(p), `\`, "/")
	clean := path.Clean(s)
	if s == "" || driveLetter.MatchString(s) || strings.ContainsRune(s, 0) ||
		strings.HasPrefix(clean, "/") || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("unsafe file path %q: must be relative and stay within the source directory", p)
	}
	return clean, nil
}
