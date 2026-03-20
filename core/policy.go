package synapse

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	engine "github.com/synapse/engine"
)

// ScanPolicy controls scanner behavior through configurable rules.
type ScanPolicy struct {
	MinConfidence       float64           `json:"min_confidence"`
	MaxFileSize         int64             `json:"max_file_size"`
	IncludePatterns     []string          `json:"include_patterns"`
	ExcludePatterns     []string          `json:"exclude_patterns"`
	SeverityMap         map[string]string `json:"severity_map"`
	IgnoreProvenance    []string          `json:"ignore_provenance"`
	RequireVerification bool              `json:"require_verification"`
	BlockOnFindings     bool              `json:"block_on_findings"`
	AllowList           []AllowListEntry  `json:"allow_list"`
	CustomPrefixes      map[string]string `json:"custom_prefixes"`
}

// AllowListEntry describes an allowed pattern with optional expiration.
type AllowListEntry struct {
	Pattern   string     `json:"pattern"`
	Reason    string     `json:"reason"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// DefaultPolicy returns the default scan policy matching current engine behavior.
var DefaultPolicy = ScanPolicy{
	MinConfidence:       0.3,
	MaxFileSize:         1_000_000,
	IncludePatterns:     nil,
	ExcludePatterns:     nil,
	SeverityMap:         nil,
	IgnoreProvenance:    nil,
	RequireVerification: false,
	BlockOnFindings:     false,
	AllowList:           nil,
	CustomPrefixes:      nil,
}

// LoadPolicy reads a scan policy from a JSON file at the given path.
func LoadPolicy(path string) (*ScanPolicy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file: %w", err)
	}

	policy := DefaultPolicy
	if err := json.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("failed to parse policy file: %w", err)
	}

	if err := policy.Validate(); err != nil {
		return nil, fmt.Errorf("invalid policy: %w", err)
	}

	return &policy, nil
}

// Validate checks that the policy has consistent, valid settings.
func (p *ScanPolicy) Validate() error {
	if p.MinConfidence < 0 || p.MinConfidence > 1 {
		return errors.New("min_confidence must be between 0 and 1")
	}
	if p.MaxFileSize < 0 {
		return errors.New("max_file_size must be non-negative")
	}

	validProvenance := map[string]bool{
		string(engine.ProvenanceAuthCredential): true,
		string(engine.ProvenanceHumanAuthored):  true,
		string(engine.ProvenanceBuildGenerated): true,
		string(engine.ProvenanceDocExample):     true,
		string(engine.ProvenanceDerivedValue):   true,
		string(engine.ProvenanceUncertain):      true,
	}
	for _, prov := range p.IgnoreProvenance {
		if !validProvenance[prov] {
			return fmt.Errorf("unknown provenance in ignore_provenance: %q", prov)
		}
	}

	for i, entry := range p.AllowList {
		if entry.Pattern == "" {
			return fmt.Errorf("allow_list[%d]: pattern must not be empty", i)
		}
	}

	return nil
}

// ShouldScan determines whether a file should be scanned based on the policy.
func (p *ScanPolicy) ShouldScan(filePath string, fileSize int64) bool {
	if p.MaxFileSize > 0 && fileSize > p.MaxFileSize {
		return false
	}

	if len(p.ExcludePatterns) > 0 {
		for _, pattern := range p.ExcludePatterns {
			if matchGlob(pattern, filePath) {
				return false
			}
		}
	}

	if len(p.IncludePatterns) > 0 {
		matched := false
		for _, pattern := range p.IncludePatterns {
			if matchGlob(pattern, filePath) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	return true
}

// ShouldReport determines whether a finding should be included in the report.
func (p *ScanPolicy) ShouldReport(finding engine.Finding) bool {
	if finding.Confidence < p.MinConfidence {
		return false
	}

	for _, prov := range p.IgnoreProvenance {
		if finding.Provenance == prov {
			return false
		}
	}

	if p.isAllowListed(finding.MatchedValue) {
		return false
	}

	return true
}

// SeverityFor returns the severity string for a finding based on the policy.
func (p *ScanPolicy) SeverityFor(finding engine.Finding) string {
	if p.SeverityMap != nil {
		if sev, ok := p.SeverityMap[finding.Provenance]; ok {
			return sev
		}
		if sev, ok := p.SeverityMap[finding.Detector]; ok {
			return sev
		}
	}

	switch {
	case finding.Confidence >= 0.9:
		return "critical"
	case finding.Confidence >= 0.7:
		return "high"
	case finding.Confidence >= 0.5:
		return "medium"
	case finding.Confidence >= 0.3:
		return "low"
	default:
		return "info"
	}
}

// isAllowListed checks if a value matches any non-expired allow list entry.
func (p *ScanPolicy) isAllowListed(value string) bool {
	now := time.Now()
	for _, entry := range p.AllowList {
		if entry.ExpiresAt != nil && now.After(*entry.ExpiresAt) {
			continue
		}
		if strings.Contains(value, entry.Pattern) {
			return true
		}
	}
	return false
}

// matchGlob performs simple glob matching using filepath.Match on the base name,
// or substring matching for directory patterns.
func matchGlob(pattern, path string) bool {
	if strings.Contains(pattern, "/") || strings.Contains(pattern, string(filepath.Separator)) {
		matched, _ := filepath.Match(pattern, path)
		if matched {
			return true
		}
		return strings.Contains(path, pattern)
	}

	base := filepath.Base(path)
	matched, _ := filepath.Match(pattern, base)
	return matched
}
