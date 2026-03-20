package synapse

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"strings"

	engine "github.com/synapse/engine"
)

// SARIFReport represents a SARIF v2.1.0 report.
type SARIFReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

// SARIFRun represents a single analysis run.
type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
}

// SARIFTool describes the analysis tool.
type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

// SARIFDriver describes the tool driver (primary analysis component).
type SARIFDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []SARIFRule `json:"rules,omitempty"`
}

// SARIFRule describes a rule (detector) that produced findings.
type SARIFRule struct {
	ID               string           `json:"id"`
	Name             string           `json:"name"`
	ShortDescription SARIFMessage     `json:"shortDescription"`
	FullDescription  SARIFMessage     `json:"fullDescription,omitempty"`
	DefaultConfig    *SARIFRuleConfig `json:"defaultConfiguration,omitempty"`
	HelpURI          string           `json:"helpUri,omitempty"`
}

// SARIFRuleConfig describes default rule configuration.
type SARIFRuleConfig struct {
	Level string `json:"level"`
}

// SARIFResult represents a single finding.
type SARIFResult struct {
	RuleID     string                 `json:"ruleId"`
	RuleIndex  int                    `json:"ruleIndex"`
	Level      string                 `json:"level"`
	Kind       string                 `json:"kind"`
	Message    SARIFMessage           `json:"message"`
	Locations  []SARIFLocation        `json:"locations,omitempty"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

// SARIFMessage represents a SARIF message with text.
type SARIFMessage struct {
	Text string `json:"text"`
}

// SARIFLocation represents a physical source location.
type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

// SARIFPhysicalLocation is a file + region reference.
type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           *SARIFRegion          `json:"region,omitempty"`
}

// SARIFArtifactLocation identifies a file.
type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

// SARIFRegion identifies a region within a file.
type SARIFRegion struct {
	StartLine   int `json:"startLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
}

// confidenceToLevel maps a confidence score to a SARIF level.
func confidenceToLevel(confidence float64) string {
	switch {
	case confidence >= 0.8:
		return "error"
	case confidence >= 0.5:
		return "warning"
	default:
		return "note"
	}
}

// provenanceToKind maps provenance to SARIF result kind.
func provenanceToKind(provenance string) string {
	switch provenance {
	case string(engine.ProvenanceAuthCredential):
		return "open"
	case string(engine.ProvenanceUncertain):
		return "review"
	default:
		return "pass"
	}
}

// fileToURI converts a file path to a file URI suitable for SARIF.
func fileToURI(filePath string) string {
	abs, err := filepath.Abs(filePath)
	if err != nil {
		abs = filePath
	}
	abs = filepath.ToSlash(abs)
	if !strings.HasPrefix(abs, "/") {
		return "file:///" + url.PathEscape(abs)
	}
	return "file://" + url.PathEscape(abs)
}

// GenerateSARIF converts a slice of engine findings into a SARIF v2.1.0 report.
func GenerateSARIF(findings []engine.Finding, toolVersion string) (*SARIFReport, error) {
	if toolVersion == "" {
		toolVersion = "0.0.0"
	}

	ruleIndex := map[string]int{}
	var rules []SARIFRule
	var results []SARIFResult

	for _, f := range findings {
		ruleID := f.Detector
		if ruleID == "" {
			ruleID = "synapse/unknown"
		}

		idx, exists := ruleIndex[ruleID]
		if !exists {
			idx = len(rules)
			ruleIndex[ruleID] = idx
			rules = append(rules, SARIFRule{
				ID:   ruleID,
				Name: ruleID,
				ShortDescription: SARIFMessage{
					Text: fmt.Sprintf("Secret detected by %s", ruleID),
				},
				FullDescription: SARIFMessage{
					Text: fmt.Sprintf("SYNAPSE detector %s identified a potential credential with provenance %s", ruleID, f.Provenance),
				},
				DefaultConfig: &SARIFRuleConfig{
					Level: confidenceToLevel(f.Confidence),
				},
			})
		}

		messageText := f.ReasoningStr
		if messageText == "" {
			messageText = fmt.Sprintf("Potential secret found (%s, confidence %.0f%%)", f.Provenance, f.Confidence*100)
		}

		result := SARIFResult{
			RuleID:    ruleID,
			RuleIndex: idx,
			Level:     confidenceToLevel(f.Confidence),
			Kind:      provenanceToKind(f.Provenance),
			Message:   SARIFMessage{Text: messageText},
			Properties: map[string]interface{}{
				"confidence": f.Confidence,
				"provenance": f.Provenance,
			},
		}

		if f.File != "" {
			loc := SARIFLocation{
				PhysicalLocation: SARIFPhysicalLocation{
					ArtifactLocation: SARIFArtifactLocation{
						URI: fileToURI(f.File),
					},
				},
			}
			if f.Line > 0 {
				loc.PhysicalLocation.Region = &SARIFRegion{
					StartLine:   f.Line,
					StartColumn: 1,
				}
			}
			result.Locations = []SARIFLocation{loc}
		}

		if len(f.Signals) > 0 {
			result.Properties["signals"] = f.Signals
		}

		results = append(results, result)
	}

	report := &SARIFReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:           "morphex-synapse",
						Version:        toolVersion,
						InformationURI: "https://github.com/morphex/synapse",
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}

	return report, nil
}

// WriteSARIF serializes a SARIF report as JSON to the given writer.
func WriteSARIF(report *SARIFReport, w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(report)
}
