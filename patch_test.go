package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/cxpsemea/Cx1ClientGo"
	"github.com/sirupsen/logrus"
)

const pomOriginal = "<project>\n" +
	"  <dependencies>\n" +
	"    <dependency>log4j 2.14.0</dependency>\n" +
	"    <dependency>junit 4.13</dependency>\n" +
	"    <dependency>guava 20.0</dependency>\n" +
	"    <dependency>commons-io 2.5</dependency>\n" +
	"    <dependency>jackson 2.9.0</dependency>\n" +
	"    <dependency>snakeyaml 1.20</dependency>\n" +
	"    <dependency>okhttp 3.8.0</dependency>\n" +
	"  </dependencies>\n" +
	"</project>\n"

func testLogger() *logrus.Logger {
	l := logrus.New()
	l.SetLevel(logrus.PanicLevel)
	return l
}

func requireGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	// ignore the developer's git config: e.g. core.autocrlf=true makes "git apply" write CRLF
	// into new files, which would make byte-exact assertions machine-dependent
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
}

func writeFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func remediationWith(changes ...Cx1ClientGo.AIRemediationFileChange) Cx1ClientGo.AIRemediationDetails {
	return Cx1ClientGo.AIRemediationDetails{Results: []Cx1ClientGo.AIRemediationResult{
		{ResultID: "r1", Data: Cx1ClientGo.AIRemediationData{FileChanges: changes}},
	}}
}

// pomDiff builds a one-line-change diff for pom.xml with one line of context either side.
// Hunk line numbers are exact; see TestApplyRemediationToleratesLineDrift for the inexact case.
func pomDiff(oldLine, newLine string) Cx1ClientGo.AIRemediationFileChange {
	lines := strings.Split(strings.TrimSuffix(pomOriginal, "\n"), "\n")
	i := slices.Index(lines, oldLine)
	start := i // 1-based line number of the context line above the change
	return Cx1ClientGo.AIRemediationFileChange{
		FilePath: "pom.xml",
		Diff: fmt.Sprintf("--- a/pom.xml\n+++ b/pom.xml\n@@ -%d,3 +%d,3 @@\n %s\n-%s\n+%s\n %s\n",
			start, start, lines[i-1], oldLine, newLine, lines[i+1]),
	}
}

// The scenario from the bug report: two remediations that both modify pom.xml must each apply
// cleanly, and neither may leak into the other or into the source tree.
func TestSameFileRemediationsAreIndependent(t *testing.T) {
	requireGit(t)
	base := t.TempDir()
	writeFile(t, base, "pom.xml", pomOriginal)

	first, err := applyRemediationInMemory(testLogger(), remediationWith(
		pomDiff("    <dependency>log4j 2.14.0</dependency>", "    <dependency>log4j 2.17.1</dependency>")), base)
	if err != nil {
		t.Fatalf("first remediation: %v", err)
	}
	second, err := applyRemediationInMemory(testLogger(), remediationWith(
		pomDiff("    <dependency>snakeyaml 1.20</dependency>", "    <dependency>snakeyaml 2.0</dependency>")), base)
	if err != nil {
		t.Fatalf("second remediation should not be affected by the first: %v", err)
	}

	if len(first) != 1 || first[0].Path != "pom.xml" || len(second) != 1 || second[0].Path != "pom.xml" {
		t.Fatalf("unexpected results: %+v / %+v", first, second)
	}

	want1 := strings.Replace(pomOriginal, "log4j 2.14.0", "log4j 2.17.1", 1)
	want2 := strings.Replace(pomOriginal, "snakeyaml 1.20", "snakeyaml 2.0", 1)
	if string(first[0].Content) != want1 {
		t.Errorf("first result wrong:\n%s", first[0].Content)
	}
	if string(second[0].Content) != want2 {
		t.Errorf("second result wrong (should not include the first fix):\n%s", second[0].Content)
	}

	onDisk, _ := os.ReadFile(filepath.Join(base, "pom.xml"))
	if string(onDisk) != pomOriginal {
		t.Errorf("source tree was modified:\n%s", onDisk)
	}
}

// AI-generated diffs can carry hunk line numbers that are a little off. "git apply" copes with
// this, which is why it is used rather than a library that only applies hunks at the stated position.
func TestApplyRemediationToleratesLineDrift(t *testing.T) {
	requireGit(t)
	base := t.TempDir()
	writeFile(t, base, "pom.xml", pomOriginal)

	fc := pomDiff("    <dependency>guava 20.0</dependency>", "    <dependency>guava 32.0</dependency>")
	fc.Diff = strings.Replace(fc.Diff, "@@ -4,3 +4,3 @@", "@@ -7,3 +7,3 @@", 1) // real position is line 4
	if !strings.Contains(fc.Diff, "@@ -7,3") {
		t.Fatalf("test setup: header not rewritten: %q", fc.Diff)
	}

	files, err := applyRemediationInMemory(testLogger(), remediationWith(fc), base)
	if err != nil {
		t.Fatalf("drifted diff should still apply: %v", err)
	}
	if len(files) != 1 || !strings.Contains(string(files[0].Content), "guava 32.0") {
		t.Errorf("unexpected result: %+v", files)
	}
}

func TestApplyRemediationCreatesAndGenerates(t *testing.T) {
	requireGit(t)
	base := t.TempDir()

	details := remediationWith(Cx1ClientGo.AIRemediationFileChange{
		FilePath: "src/util/Safe.java",
		Diff:     "--- /dev/null\n+++ b/src/util/Safe.java\n@@ -0,0 +1,2 @@\n+class Safe {\n+}\n",
	})
	details.Results[0].Data.TestCreation.TestFiles = []Cx1ClientGo.AIRemediationTestFile{
		{FilePath: "src/test/SafeTest.java", FileContent: "class SafeTest {}\n"},
	}

	files, err := applyRemediationInMemory(testLogger(), details, base)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, f := range files {
		got[f.Path] = string(f.Content)
	}
	if got["src/util/Safe.java"] != "class Safe {\n}\n" || got["src/test/SafeTest.java"] != "class SafeTest {}\n" || len(got) != 2 {
		t.Errorf("unexpected files: %v", got)
	}
	if entries, _ := os.ReadDir(base); len(entries) != 0 {
		t.Errorf("source tree was modified: %v", entries)
	}
}

// A remediation whose diff fails must produce nothing, even if another of its diffs is fine.
func TestApplyRemediationIsAllOrNothing(t *testing.T) {
	requireGit(t)
	base := t.TempDir()
	writeFile(t, base, "pom.xml", pomOriginal)

	good := pomDiff("    <dependency>log4j 2.14.0</dependency>", "    <dependency>log4j 2.17.1</dependency>")
	bad := Cx1ClientGo.AIRemediationFileChange{
		FilePath: "pom.xml",
		Diff:     "--- a/pom.xml\n+++ b/pom.xml\n@@ -1,1 +1,1 @@\n-<nothing like this>\n+<anything>\n",
	}

	files, err := applyRemediationInMemory(testLogger(), remediationWith(good, bad), base)
	if err == nil || files != nil {
		t.Fatalf("expected failure with no files, got %v / %v", files, err)
	}
}

// Two diffs to one file within a single remediation chain onto each other.
func TestApplyRemediationChainsDiffsWithinOneRemediation(t *testing.T) {
	requireGit(t)
	base := t.TempDir()
	writeFile(t, base, "pom.xml", pomOriginal)

	a := pomDiff("    <dependency>log4j 2.14.0</dependency>", "    <dependency>log4j 2.17.1</dependency>")
	b := pomDiff("    <dependency>snakeyaml 1.20</dependency>", "    <dependency>snakeyaml 2.0</dependency>")

	files, err := applyRemediationInMemory(testLogger(), remediationWith(a, b), base)
	if err != nil {
		t.Fatal(err)
	}
	content := string(files[0].Content)
	if !strings.Contains(content, "log4j 2.17.1") || !strings.Contains(content, "snakeyaml 2.0") {
		t.Errorf("expected both changes:\n%s", content)
	}
}

func TestApplyRemediationRejectsUnsafePaths(t *testing.T) {
	requireGit(t)
	base := t.TempDir()

	for _, p := range []string{"../outside.txt", "/etc/passwd", "a/../../b", ""} {
		fc := Cx1ClientGo.AIRemediationFileChange{FilePath: p, Diff: "--- /dev/null\n+++ b/x\n@@ -0,0 +1 @@\n+x\n"}
		if _, err := applyRemediationInMemory(testLogger(), remediationWith(fc), base); err == nil {
			t.Errorf("file change path %q should have been rejected", p)
		}

		details := remediationWith()
		details.Results[0].Data.TestCreation.TestFiles = []Cx1ClientGo.AIRemediationTestFile{{FilePath: p, FileContent: "x"}}
		if _, err := applyRemediationInMemory(testLogger(), details, base); err == nil {
			t.Errorf("test file path %q should have been rejected", p)
		}
	}
}
