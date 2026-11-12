package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cxpsemea/Cx1ClientGo"
)

func fileChange(path, diff string) Cx1ClientGo.AIRemediationFileChange {
	return Cx1ClientGo.AIRemediationFileChange{FilePath: path, Diff: diff}
}

// An LF diff must apply to a CRLF file, and the file must stay CRLF throughout.
func TestApplyToCRLFSource(t *testing.T) {
	requireGit(t)
	base := t.TempDir()
	writeFile(t, base, "a.txt", "one\r\ntwo\r\nthree\r\n")

	files, err := applyRemediationInMemory(testLogger(), remediationWith(fileChange("a.txt",
		"--- a/a.txt\n+++ b/a.txt\n@@ -1,3 +1,3 @@\n one\n-two\n+TWO\n three\n")), base)
	if err != nil {
		t.Fatalf("LF diff should apply to a CRLF file: %v", err)
	}
	if got, want := string(files[0].Content), "one\r\nTWO\r\nthree\r\n"; got != want {
		t.Errorf("content = %q, want %q", got, want)
	}
}

// A file with LF endings must stay LF, whatever the machine's git settings are.
func TestGitConfigIsIgnored(t *testing.T) {
	requireGit(t)
	cfg := filepath.Join(t.TempDir(), "gitconfig")
	if err := os.WriteFile(cfg, []byte("[core]\n\tautocrlf = true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_CONFIG_GLOBAL", cfg) // a developer's or runner's config, set after requireGit neutralized it
	t.Setenv("GIT_CONFIG_NOSYSTEM", "0")

	files, err := applyRemediationInMemory(testLogger(), remediationWith(fileChange("new.txt",
		"--- /dev/null\n+++ b/new.txt\n@@ -0,0 +1,2 @@\n+x\n+y\n")), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if got := string(files[0].Content); got != "x\ny\n" {
		t.Errorf("content = %q, want LF endings despite core.autocrlf=true", got)
	}
}

// Diffs with bare paths (no a/ and b/ prefix) are accepted.
func TestApplyWithoutPathPrefix(t *testing.T) {
	requireGit(t)
	base := t.TempDir()
	writeFile(t, base, "pom.xml", "a\nb\nc\n")

	files, err := applyRemediationInMemory(testLogger(), remediationWith(fileChange("pom.xml",
		"--- pom.xml\n+++ pom.xml\n@@ -1,3 +1,3 @@\n a\n-b\n+B\n c\n")), base)
	if err != nil {
		t.Fatalf("a bare-path diff should apply: %v", err)
	}
	if got := string(files[0].Content); got != "a\nB\nc\n" {
		t.Errorf("content = %q", got)
	}
}

// A file that is executable in the source tree stays executable in the result.
func TestExecutableBitIsKept(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not record an executable bit")
	}
	requireGit(t)
	base := t.TempDir()
	writeFile(t, base, "run.sh", "echo a\n")
	writeFile(t, base, "plain.txt", "a\n")
	if err := os.Chmod(filepath.Join(base, "run.sh"), 0755); err != nil {
		t.Fatal(err)
	}

	for path, want := range map[string]bool{"run.sh": true, "plain.txt": false} {
		files, err := applyRemediationInMemory(testLogger(), remediationWith(fileChange(path,
			"--- a/"+path+"\n+++ b/"+path+"\n@@ -1 +1 @@\n-"+strings.TrimSpace(readFile(t, base, path))+"\n+changed\n")), base)
		if err != nil {
			t.Fatal(err)
		}
		if files[0].Executable != want {
			t.Errorf("%s: Executable = %v, want %v", path, files[0].Executable, want)
		}
	}
}

func readFile(t *testing.T, dir, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, rel))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestCleanRepoPath(t *testing.T) {
	good := map[string]string{
		"src/Foo.java":      "src/Foo.java",
		`src\Foo.java`:      "src/Foo.java",
		"./pom.xml":         "pom.xml",
		"src//util/../a.go": "src/a.go",
		"aux.c":             "aux.c",
	}
	for in, want := range good {
		if got, err := cleanRepoPath(in); err != nil || got != want {
			t.Errorf("cleanRepoPath(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", ".", "..", "../x", `..\x`, "/etc/passwd", `\host\share\x`, `C:\x`, "C:x", "a/../../b", "a\x00b"} {
		if got, err := cleanRepoPath(in); err == nil {
			t.Errorf("cleanRepoPath(%q) = %q, want an error", in, got)
		}
	}
}
