package synapse

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// IgnoreFile holds patterns loaded from a .morphexignore file.
// Format is one glob pattern per line. Lines starting with # are comments.
// Patterns are matched against the file path relative to the scan root.
type IgnoreFile struct {
	Patterns []string
}

// LoadIgnoreFile reads a .morphexignore file from the given path.
// Returns an empty ignore list (not an error) if the file doesn't exist.
func LoadIgnoreFile(path string) (*IgnoreFile, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &IgnoreFile{}, nil
		}
		return nil, err
	}
	defer f.Close()

	var patterns []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		patterns = append(patterns, line)
	}
	return &IgnoreFile{Patterns: patterns}, scanner.Err()
}

// FindIgnoreFile searches for a .morphexignore file in the given directory
// and its parents, returning the first one found.
func FindIgnoreFile(dir string) string {
	for {
		candidate := filepath.Join(dir, ".morphexignore")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
}

// ShouldIgnore returns true if the given path matches any ignore pattern.
func (ig *IgnoreFile) ShouldIgnore(filePath string) bool {
	if ig == nil || len(ig.Patterns) == 0 {
		return false
	}
	base := filepath.Base(filePath)
	for _, pattern := range ig.Patterns {
		if strings.Contains(pattern, "/") || strings.Contains(pattern, string(filepath.Separator)) {
			if matched, _ := filepath.Match(pattern, filePath); matched {
				return true
			}
			if strings.Contains(filePath, pattern) {
				return true
			}
		} else {
			if matched, _ := filepath.Match(pattern, base); matched {
				return true
			}
		}
	}
	return false
}

// InlineIgnore checks if a line contains an morphex:allow comment.
// Supports: // morphex:allow, # morphex:allow, /* morphex:allow */
func InlineIgnore(line string) bool {
	lower := strings.ToLower(line)
	return strings.Contains(lower, "morphex:allow") ||
		strings.Contains(lower, "morphex:ignore")
}
