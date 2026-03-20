// git_scanner.go implements git history scanning for the SYNAPSE engine.
//
// This enables scanning ALL commits in a repository's history, not just the
// current working tree. Secrets that were committed and later removed are
// still exposed -- a critical capability for detecting rotated credentials.
//
// Implementation uses os/exec to call the git binary directly (no libgit2/go-git).
package engine

import (
	"bufio"
	"crypto/sha256"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"sync"
)

// maxDiffSizeBytes is the maximum diff size per commit before we skip it.
const maxDiffSizeBytes = 1 << 20 // 1 MB

// defaultMaxConcurrentGit limits concurrent git show invocations.
const defaultMaxConcurrentGit = 10

// ============================================================================
// TYPES
// ============================================================================

// GitFinding extends Finding with git-specific metadata.
type GitFinding struct {
	Finding                    // embedded standard finding
	CommitHash   string        `json:"commit_hash"`
	CommitAuthor string        `json:"commit_author"`
	CommitDate   string        `json:"commit_date"`
	CommitMsg    string        `json:"commit_message"`
	Branch       string        `json:"branch,omitempty"`
}

// GitScanOptions controls git history scanning behavior.
type GitScanOptions struct {
	MaxCommits   int      // max commits to scan (0 = all)
	Since        string   // --since date filter (e.g., "2024-01-01")
	Branch       string   // specific branch (empty = --all)
	Workers      int      // concurrent diff processors (0 = NumCPU)
	IncludePaths []string // only scan these paths (glob patterns)
	ExcludePaths []string // skip these paths
}

// DiffLine represents a single added line from a diff hunk.
type DiffLine struct {
	Number  int
	Content string
}

// DiffFile represents a file's added content extracted from a unified diff.
type DiffFile struct {
	Path       string
	AddedLines []DiffLine
}

// commitInfo holds parsed commit metadata from git log.
type commitInfo struct {
	Hash   string
	Author string
	Email  string
	Date   string
	Msg    string
}

// ============================================================================
// DIFF PARSER
// ============================================================================

// ParseGitDiff parses unified diff output into per-file added content.
// It handles standard unified diff format from git diff, git show, etc.
func ParseGitDiff(diff string) []DiffFile {
	var files []DiffFile
	var current *DiffFile
	lineNum := 0
	inHunk := false

	scanner := bufio.NewScanner(strings.NewReader(diff))
	for scanner.Scan() {
		line := scanner.Text()

		// New file in diff: "diff --git a/path b/path"
		if strings.HasPrefix(line, "diff --git ") {
			if current != nil && len(current.AddedLines) > 0 {
				files = append(files, *current)
			}
			current = nil
			inHunk = false
			continue
		}

		// Binary file -- skip entirely
		if strings.HasPrefix(line, "Binary files ") {
			current = nil
			inHunk = false
			continue
		}

		// New file path from +++ header
		if strings.HasPrefix(line, "+++ ") {
			path := line[4:]
			// Strip "b/" prefix from git diffs
			if strings.HasPrefix(path, "b/") {
				path = path[2:]
			}
			if path == "/dev/null" {
				current = nil
				continue
			}
			current = &DiffFile{Path: path}
			inHunk = false
			continue
		}

		// --- header (old file) -- skip
		if strings.HasPrefix(line, "--- ") {
			continue
		}

		// Hunk header: @@ -X,Y +A,B @@
		if strings.HasPrefix(line, "@@ ") {
			if current == nil {
				continue
			}
			// Parse the +A,B part to get starting line number
			plusIdx := strings.Index(line, "+")
			if plusIdx < 0 {
				continue
			}
			rest := line[plusIdx+1:]
			// rest is like "A,B @@" or "A @@"
			spaceIdx := strings.IndexAny(rest, " ,")
			numStr := rest
			if spaceIdx >= 0 {
				numStr = rest[:spaceIdx]
			}
			n := 0
			for _, c := range numStr {
				if c >= '0' && c <= '9' {
					n = n*10 + int(c-'0')
				} else {
					break
				}
			}
			if n > 0 {
				lineNum = n
			} else {
				lineNum = 1
			}
			inHunk = true
			continue
		}

		// Inside a hunk -- process lines
		if !inHunk || current == nil {
			continue
		}

		if len(line) == 0 {
			// Empty context line
			lineNum++
			continue
		}

		switch line[0] {
		case '+':
			// Added line (but not the +++ header, already handled above)
			current.AddedLines = append(current.AddedLines, DiffLine{
				Number:  lineNum,
				Content: line[1:],
			})
			lineNum++
		case '-':
			// Removed line -- do NOT increment lineNum (doesn't exist in new file)
		default:
			// Context line (space prefix or other)
			lineNum++
		}
	}

	// Flush last file
	if current != nil && len(current.AddedLines) > 0 {
		files = append(files, *current)
	}

	return files
}

// ============================================================================
// SCAN GIT DIFF
// ============================================================================

// ScanGitDiff scans a single git diff (e.g., from a PR or commit) for secrets.
// Input is the raw diff text (from git diff or git show).
func ScanGitDiff(diff string, threshold float64) ([]GitFinding, error) {
	files := ParseGitDiff(diff)
	var findings []GitFinding

	for _, file := range files {
		// Reconstruct added content for token extraction
		var contentBuilder strings.Builder
		for _, dl := range file.AddedLines {
			contentBuilder.WriteString(dl.Content)
			contentBuilder.WriteByte('\n')
		}
		content := contentBuilder.String()

		tokens := ExtractTokens(file.Path, content)
		for _, token := range tokens {
			cls := ClassifyToken(token)
			if cls.Prov != ProvenanceAuthCredential && cls.Prov != ProvenanceUncertain {
				continue
			}
			if cls.Conf < threshold {
				continue
			}

			findings = append(findings, makeGitFinding(token, cls, file.Path))
		}
	}

	return findings, nil
}

// ============================================================================
// SCAN GIT REPO
// ============================================================================

// ScanGitRepo scans a git repository's full history for secrets.
// It runs git log to enumerate commits and git show to get diffs,
// then pipes each diff through the SYNAPSE classification pipeline.
func ScanGitRepo(repoPath string, threshold float64, opts GitScanOptions) ([]GitFinding, error) {
	// Validate repoPath to prevent git flag injection.
	if strings.HasPrefix(repoPath, "-") {
		return nil, fmt.Errorf("invalid repo path %q: must not start with '-'", repoPath)
	}

	// Check git binary is available
	gitPath, err := exec.LookPath("git")
	if err != nil {
		return nil, fmt.Errorf("git binary not found in PATH: %w", err)
	}
	_ = gitPath

	// Verify this is a git repo
	cmd := exec.Command("git", "-C", repoPath, "rev-parse", "--git-dir")
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("not a git repository (%s): %s", repoPath, strings.TrimSpace(string(out)))
	}

	// Get commit list
	commits, err := listCommits(repoPath, opts)
	if err != nil {
		return nil, fmt.Errorf("listing commits: %w", err)
	}

	if len(commits) == 0 {
		return nil, nil
	}

	// Set up worker pool
	workers := opts.Workers
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	if workers > len(commits) {
		workers = len(commits)
	}

	// Semaphore to limit concurrent git show calls
	semSize := defaultMaxConcurrentGit
	if workers < semSize {
		semSize = workers
	}

	type result struct {
		findings []GitFinding
	}

	commitCh := make(chan commitInfo, len(commits))
	resultCh := make(chan result, len(commits))

	var wg sync.WaitGroup
	sem := make(chan struct{}, semSize)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ci := range commitCh {
				sem <- struct{}{}
				findings := processCommit(repoPath, ci, threshold, opts)
				<-sem
				resultCh <- result{findings: findings}
			}
		}()
	}

	for _, ci := range commits {
		commitCh <- ci
	}
	close(commitCh)

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	// Collect results and deduplicate
	var allFindings []GitFinding
	for r := range resultCh {
		allFindings = append(allFindings, r.findings...)
	}

	return deduplicateFindings(allFindings), nil
}

// ============================================================================
// INTERNAL HELPERS
// ============================================================================

// listCommits returns the list of commits to scan, respecting options.
func listCommits(repoPath string, opts GitScanOptions) ([]commitInfo, error) {
	args := []string{"-C", repoPath, "log", "--format=%H|%an|%ae|%aI|%s"}

	if opts.Branch != "" {
		args = append(args, opts.Branch)
	} else {
		args = append(args, "--all")
	}

	if opts.Since != "" {
		args = append(args, "--since="+opts.Since)
	}

	if opts.MaxCommits > 0 {
		args = append(args, fmt.Sprintf("--max-count=%d", opts.MaxCommits))
	}

	cmd := exec.Command("git", args...)
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil, fmt.Errorf("git log failed: %s", string(exitErr.Stderr))
		}
		return nil, err
	}

	var commits []commitInfo
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "|", 5)
		if len(parts) < 5 {
			continue
		}
		commits = append(commits, commitInfo{
			Hash:   parts[0],
			Author: parts[1],
			Email:  parts[2],
			Date:   parts[3],
			Msg:    parts[4],
		})
	}

	return commits, nil
}

// processCommit gets the diff for a single commit and scans it.
func processCommit(repoPath string, ci commitInfo, threshold float64, opts GitScanOptions) []GitFinding {
	diff, err := getCommitDiff(repoPath, ci.Hash)
	if err != nil || diff == "" {
		return nil
	}

	// Skip oversized diffs
	if len(diff) > maxDiffSizeBytes {
		return nil
	}

	files := ParseGitDiff(diff)
	var findings []GitFinding

	for _, file := range files {
		// Apply path filters
		if !matchesPathFilters(file.Path, opts.IncludePaths, opts.ExcludePaths) {
			continue
		}

		var contentBuilder strings.Builder
		for _, dl := range file.AddedLines {
			contentBuilder.WriteString(dl.Content)
			contentBuilder.WriteByte('\n')
		}
		content := contentBuilder.String()

		tokens := ExtractTokens(file.Path, content)
		for _, token := range tokens {
			cls := ClassifyToken(token)
			if cls.Prov != ProvenanceAuthCredential && cls.Prov != ProvenanceUncertain {
				continue
			}
			if cls.Conf < threshold {
				continue
			}
			if valueIsNotSecret(token.Value) {
				continue
			}

			gf := makeGitFinding(token, cls, file.Path)
			gf.CommitHash = ci.Hash
			gf.CommitAuthor = ci.Author
			gf.CommitDate = ci.Date
			gf.CommitMsg = ci.Msg
			findings = append(findings, gf)
		}
	}

	return findings
}

// getCommitDiff returns the diff for a single commit.
func getCommitDiff(repoPath, hash string) (string, error) {
	cmd := exec.Command("git", "-C", repoPath, "show", "--format=", "-p", hash)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// matchesPathFilters checks if a file path matches include/exclude patterns.
func matchesPathFilters(path string, include, exclude []string) bool {
	// If include patterns are specified, path must match at least one
	if len(include) > 0 {
		matched := false
		for _, pat := range include {
			if matchGlob(pat, path) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// If exclude patterns are specified, path must not match any
	for _, pat := range exclude {
		if matchGlob(pat, path) {
			return false
		}
	}

	return true
}

// matchGlob performs simple glob matching (supports * and **).
func matchGlob(pattern, path string) bool {
	// Simple implementation: use strings.Contains for patterns without wildcards,
	// and basic matching for patterns with *.
	if !strings.Contains(pattern, "*") {
		return strings.Contains(path, pattern)
	}

	// For "*.ext" patterns
	if strings.HasPrefix(pattern, "*.") {
		return strings.HasSuffix(path, pattern[1:])
	}

	// For "dir/**" patterns
	if strings.HasSuffix(pattern, "/**") {
		prefix := pattern[:len(pattern)-3]
		return strings.HasPrefix(path, prefix+"/") || path == prefix
	}

	// For "**/name" patterns
	if strings.HasPrefix(pattern, "**/") {
		suffix := pattern[3:]
		return strings.HasSuffix(path, "/"+suffix) || path == suffix
	}

	// Fallback: treat * as "match any"
	return strings.Contains(path, strings.ReplaceAll(pattern, "*", ""))
}

// deduplicateFindings keeps only the earliest commit for each (secret_hash, filepath) pair.
func deduplicateFindings(findings []GitFinding) []GitFinding {
	type dedupKey struct {
		secretHash string
		filePath   string
	}

	seen := make(map[dedupKey]int) // key -> index in result
	var result []GitFinding

	// Bloom filter pre-check: O(1) fast path skips SHA-256 + fmt.Sprintf
	// for items that are definitely new (no false negatives).
	bloom := NewFindingBloomFilter()

	// Sort by commit date ascending so we encounter earliest first.
	// Since git log returns newest first, we process in reverse.
	for i := len(findings) - 1; i >= 0; i-- {
		f := findings[i]
		h := sha256.Sum256([]byte(f.Finding.MatchedValue))
		hashStr := fmt.Sprintf("%x", h)

		// Fast path: bloom filter says definitely new → skip exact map check.
		if !bloom.MayContain(hashStr, f.Finding.File) {
			bloom.Add(hashStr, f.Finding.File)
			key := dedupKey{secretHash: hashStr, filePath: f.Finding.File}
			seen[key] = len(result)
			result = append(result, f)
			continue
		}

		// Slow path: bloom filter says maybe seen → check exact map.
		key := dedupKey{secretHash: hashStr, filePath: f.Finding.File}
		if _, exists := seen[key]; !exists {
			bloom.Add(hashStr, f.Finding.File)
			seen[key] = len(result)
			result = append(result, f)
		}
	}

	return result
}

// makeGitFinding constructs a GitFinding from a token and classification.
func makeGitFinding(token Token, cls Classification, filePath string) GitFinding {
	v := token.Value
	var redacted string
	if len(v) > 16 {
		redacted = v[:6] + "..." + v[len(v)-4:]
	} else if len(v) > 8 {
		redacted = v[:4] + "****"
	} else {
		redacted = "****"
	}

	sigs := make([]map[string]interface{}, len(cls.Signals))
	for i, s := range cls.Signals {
		sigs[i] = map[string]interface{}{
			"name":       s.Name,
			"value":      s.Value,
			"confidence": s.Confidence,
			"reasoning":  s.ReasonText,
		}
	}

	return GitFinding{
		Finding: Finding{
			File:         filePath,
			Line:         token.Line,
			MatchedValue: redacted,
			Detector:     "synapse:" + strings.ToLower(string(cls.Prov)),
			Confidence:   cls.Conf,
			Provenance:   string(cls.Prov),
			Signals:      sigs,
			ReasoningStr: cls.Reasoning(),
		},
	}
}
