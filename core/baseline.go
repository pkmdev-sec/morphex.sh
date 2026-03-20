package synapse

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"
)

// BaselineFinding represents a single finding in a baseline file.
// Findings are identified by a fingerprint (hash of file+line+detector+value).
type BaselineFinding struct {
	Fingerprint string `json:"fingerprint"`
	File        string `json:"file"`
	Line        int    `json:"line"`
	Detector    string `json:"detector"`
	Reason      string `json:"reason,omitempty"`
}

// BaselineFile represents a .morphex-baseline.json file.
type BaselineFile struct {
	Version   string            `json:"version"`
	CreatedAt string            `json:"created_at"`
	Findings  []BaselineFinding `json:"findings"`
	index     map[string]bool
}

// Fingerprint computes a stable hash for a finding.
func Fingerprint(file string, line int, detector string, value string) string {
	data := fmt.Sprintf("%s:%d:%s:%s", file, line, detector, value)
	h := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", h[:16])
}

// LoadBaseline reads a baseline file from disk. Returns an empty baseline
// (not an error) if the file doesn't exist.
func LoadBaseline(path string) (*BaselineFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &BaselineFile{Version: "1.0", index: map[string]bool{}}, nil
		}
		return nil, fmt.Errorf("read baseline: %w", err)
	}

	var bf BaselineFile
	if err := json.Unmarshal(data, &bf); err != nil {
		return nil, fmt.Errorf("parse baseline: %w", err)
	}

	bf.index = make(map[string]bool, len(bf.Findings))
	for _, f := range bf.Findings {
		bf.index[f.Fingerprint] = true
	}
	return &bf, nil
}

// Contains returns true if the fingerprint is in the baseline.
func (b *BaselineFile) Contains(fingerprint string) bool {
	if b == nil || b.index == nil {
		return false
	}
	return b.index[fingerprint]
}

// SaveBaseline writes a baseline file with the given findings.
func SaveBaseline(path string, findings []BaselineFinding) error {
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Fingerprint < findings[j].Fingerprint
	})

	bf := BaselineFile{
		Version:   "1.0",
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		Findings:  findings,
	}

	data, err := json.MarshalIndent(bf, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal baseline: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}
