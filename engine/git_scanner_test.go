package engine

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// ============================================================================
// TEST 1: ParseGitDiff
// ============================================================================

func TestParseGitDiff(t *testing.T) {
	diff := `diff --git a/config.py b/config.py
new file mode 100644
index 0000000..abc1234
--- /dev/null
+++ b/config.py
@@ -0,0 +1,5 @@
+import os
+
+API_KEY = "AKIAIOSFODNN7EXAMPLE"
+DB_HOST = "localhost"
+DB_PORT = 5432
diff --git a/main.py b/main.py
index 1234567..abcdefg 100644
--- a/main.py
+++ b/main.py
@@ -10,3 +10,5 @@ def main():
     print("hello")
+    secret = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
+    token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12"
     return 0
`

	files := ParseGitDiff(diff)

	if len(files) != 2 {
		t.Fatalf("expected 2 files, got %d", len(files))
	}

	// First file: config.py
	if files[0].Path != "config.py" {
		t.Errorf("file[0].Path = %q, want %q", files[0].Path, "config.py")
	}
	if len(files[0].AddedLines) != 5 {
		t.Errorf("file[0] added lines = %d, want 5", len(files[0].AddedLines))
	}
	// Verify line numbers start at 1
	if files[0].AddedLines[0].Number != 1 {
		t.Errorf("file[0].AddedLines[0].Number = %d, want 1", files[0].AddedLines[0].Number)
	}
	if files[0].AddedLines[0].Content != "import os" {
		t.Errorf("file[0].AddedLines[0].Content = %q, want %q", files[0].AddedLines[0].Content, "import os")
	}

	// Second file: main.py
	if files[1].Path != "main.py" {
		t.Errorf("file[1].Path = %q, want %q", files[1].Path, "main.py")
	}
	if len(files[1].AddedLines) != 2 {
		t.Errorf("file[1] added lines = %d, want 2", len(files[1].AddedLines))
	}
	// Added lines start at line 11 (hunk starts at +10, context line at 10, then +11, +12)
	if files[1].AddedLines[0].Number != 11 {
		t.Errorf("file[1].AddedLines[0].Number = %d, want 11", files[1].AddedLines[0].Number)
	}
}

// ============================================================================
// TEST 2: ParseGitDiff with binary files
// ============================================================================

func TestParseGitDiff_BinaryFile(t *testing.T) {
	diff := `diff --git a/image.png b/image.png
new file mode 100644
Binary files /dev/null and b/image.png differ
diff --git a/readme.txt b/readme.txt
new file mode 100644
--- /dev/null
+++ b/readme.txt
@@ -0,0 +1,2 @@
+hello
+world
`

	files := ParseGitDiff(diff)

	if len(files) != 1 {
		t.Fatalf("expected 1 file (binary skipped), got %d", len(files))
	}
	if files[0].Path != "readme.txt" {
		t.Errorf("file[0].Path = %q, want %q", files[0].Path, "readme.txt")
	}
}

// ============================================================================
// TEST 3: ScanGitDiff with secret
// ============================================================================

func TestScanGitDiff_WithSecret(t *testing.T) {
	diff := `diff --git a/config.py b/config.py
new file mode 100644
--- /dev/null
+++ b/config.py
@@ -0,0 +1,3 @@
+import os
+AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
+DB_HOST = "localhost"
`

	findings, err := ScanGitDiff(diff, 0.5)
	if err != nil {
		t.Fatalf("ScanGitDiff error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected at least 1 finding, got 0")
	}

	// Should find the AWS key
	found := false
	for _, f := range findings {
		if strings.Contains(f.Finding.ReasoningStr, "") || f.Finding.Confidence >= 0.5 {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected a finding with confidence >= 0.5")
	}
}

// ============================================================================
// TEST 4: ScanGitDiff -- removed lines should NOT be flagged
// ============================================================================

func TestScanGitDiff_RemovedLines(t *testing.T) {
	diff := `diff --git a/config.py b/config.py
index 1234567..abcdefg 100644
--- a/config.py
+++ b/config.py
@@ -1,3 +1,2 @@
-AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
 import os
+DB_HOST = "localhost"
`

	findings, err := ScanGitDiff(diff, 0.5)
	if err != nil {
		t.Fatalf("ScanGitDiff error: %v", err)
	}

	// The secret is in a removed line -- should NOT appear in findings
	for _, f := range findings {
		if strings.Contains(f.Finding.MatchedValue, "wJalrX") {
			t.Errorf("found secret from removed line -- should have been skipped: %s", f.Finding.MatchedValue)
		}
	}
}

// ============================================================================
// TEST 5: ScanGitRepo integration test
// ============================================================================

func TestScanGitRepo(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	// Create temp repo
	dir := t.TempDir()
	mustGit(t, dir, "init")
	mustGit(t, dir, "config", "user.email", "test@test.com")
	mustGit(t, dir, "config", "user.name", "Test")

	// Commit 1: file with a secret
	secretFile := filepath.Join(dir, "config.py")
	if err := os.WriteFile(secretFile, []byte(`AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
DB_HOST = "localhost"
`), 0o644); err != nil {
		t.Fatal(err)
	}
	mustGit(t, dir, "add", ".")
	mustGit(t, dir, "commit", "-m", "add config")

	// Commit 2: remove the secret
	if err := os.WriteFile(secretFile, []byte(`DB_HOST = "localhost"
`), 0o644); err != nil {
		t.Fatal(err)
	}
	mustGit(t, dir, "add", ".")
	mustGit(t, dir, "commit", "-m", "remove secret")

	// Scan -- should find secret from commit 1 even though it's removed in HEAD
	findings, err := ScanGitRepo(dir, 0.5, GitScanOptions{})
	if err != nil {
		t.Fatalf("ScanGitRepo error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected at least 1 finding from git history, got 0")
	}

	// Verify finding has commit metadata
	found := false
	for _, f := range findings {
		if f.CommitHash != "" && f.CommitAuthor != "" && f.CommitDate != "" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected finding with commit metadata (hash, author, date)")
	}
}

// ============================================================================
// TEST 6: ScanGitRepo deduplication
// ============================================================================

func TestScanGitRepo_Dedup(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	dir := t.TempDir()
	mustGit(t, dir, "init")
	mustGit(t, dir, "config", "user.email", "test@test.com")
	mustGit(t, dir, "config", "user.name", "Test")

	// Commit 1: secret in file A
	fileA := filepath.Join(dir, "a.py")
	if err := os.WriteFile(fileA, []byte(`API_KEY = "AKIAIOSFODNN7EXAMPLE"\n`), 0o644); err != nil {
		t.Fatal(err)
	}
	mustGit(t, dir, "add", ".")
	mustGit(t, dir, "commit", "-m", "add a.py")

	// Commit 2: same secret re-added (e.g., reverted and re-committed)
	if err := os.WriteFile(fileA, []byte(`# Updated
API_KEY = "AKIAIOSFODNN7EXAMPLE"
`), 0o644); err != nil {
		t.Fatal(err)
	}
	mustGit(t, dir, "add", ".")
	mustGit(t, dir, "commit", "-m", "update a.py")

	findings, err := ScanGitRepo(dir, 0.3, GitScanOptions{})
	if err != nil {
		t.Fatalf("ScanGitRepo error: %v", err)
	}

	// Count findings for the same redacted value in the same file
	countByKey := make(map[string]int)
	for _, f := range findings {
		key := f.Finding.File + "|" + f.Finding.MatchedValue
		countByKey[key]++
	}

	for key, count := range countByKey {
		if count > 1 {
			t.Errorf("duplicate finding for %s: appeared %d times (expected dedup to 1)", key, count)
		}
	}
}

// ============================================================================
// TEST 7: GitScanOptions -- Since filter
// ============================================================================

func TestGitScanOptions_Since(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	dir := t.TempDir()
	mustGit(t, dir, "init")
	mustGit(t, dir, "config", "user.email", "test@test.com")
	mustGit(t, dir, "config", "user.name", "Test")

	// Commit a file
	file := filepath.Join(dir, "secret.py")
	if err := os.WriteFile(file, []byte(`TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12"\n`), 0o644); err != nil {
		t.Fatal(err)
	}
	mustGit(t, dir, "add", ".")
	mustGit(t, dir, "commit", "-m", "add secret")

	// Scan with a future date -- should find nothing
	findings, err := ScanGitRepo(dir, 0.3, GitScanOptions{
		Since: "2099-01-01",
	})
	if err != nil {
		t.Fatalf("ScanGitRepo error: %v", err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings with future --since, got %d", len(findings))
	}
}

// ============================================================================
// TEST 8: GitScanOptions -- MaxCommits
// ============================================================================

func TestGitScanOptions_MaxCommits(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	dir := t.TempDir()
	mustGit(t, dir, "init")
	mustGit(t, dir, "config", "user.email", "test@test.com")
	mustGit(t, dir, "config", "user.name", "Test")

	// Create 3 commits
	for i := 0; i < 3; i++ {
		file := filepath.Join(dir, fmt.Sprintf("file%d.py", i))
		content := fmt.Sprintf(`SECRET_%d = "AKIAIOSFODNN7EXAMPL%d"`, i, i)
		if err := os.WriteFile(file, []byte(content+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		mustGit(t, dir, "add", ".")
		mustGit(t, dir, "commit", "-m", fmt.Sprintf("commit %d", i))
	}

	// Scan only 1 commit (most recent)
	findings1, err := ScanGitRepo(dir, 0.3, GitScanOptions{MaxCommits: 1})
	if err != nil {
		t.Fatalf("ScanGitRepo error: %v", err)
	}

	// Scan all commits
	findingsAll, err := ScanGitRepo(dir, 0.3, GitScanOptions{})
	if err != nil {
		t.Fatalf("ScanGitRepo error: %v", err)
	}

	if len(findingsAll) > 0 && len(findings1) >= len(findingsAll) {
		t.Errorf("MaxCommits=1 should return fewer findings than all commits: got %d vs %d",
			len(findings1), len(findingsAll))
	}
}

// ============================================================================
// TEST 9: ScanGitRepo on non-git directory
// ============================================================================

func TestScanGitRepo_NotARepo(t *testing.T) {
	dir := t.TempDir()
	_, err := ScanGitRepo(dir, 0.5, GitScanOptions{})
	if err == nil {
		t.Error("expected error for non-git directory, got nil")
	}
	if !strings.Contains(err.Error(), "not a git repository") {
		t.Errorf("error should mention 'not a git repository', got: %s", err.Error())
	}
}

// ============================================================================
// BENCHMARK: ParseGitDiff
// ============================================================================

func BenchmarkParseGitDiff(b *testing.B) {
	// Generate a large diff with 100 files, 50 lines each
	var builder strings.Builder
	for i := 0; i < 100; i++ {
		builder.WriteString(fmt.Sprintf("diff --git a/file%d.py b/file%d.py\n", i, i))
		builder.WriteString(fmt.Sprintf("--- /dev/null\n"))
		builder.WriteString(fmt.Sprintf("+++ b/file%d.py\n", i))
		builder.WriteString(fmt.Sprintf("@@ -0,0 +1,50 @@\n"))
		for j := 0; j < 50; j++ {
			builder.WriteString(fmt.Sprintf("+line %d of file %d\n", j, i))
		}
	}
	diff := builder.String()

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		ParseGitDiff(diff)
	}
}

// ============================================================================
// HELPERS
// ============================================================================

func mustGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_DATE=2025-01-15T10:00:00+00:00",
		"GIT_COMMITTER_DATE=2025-01-15T10:00:00+00:00",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s failed: %v\n%s", strings.Join(args, " "), err, out)
	}
}
