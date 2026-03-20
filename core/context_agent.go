// Package synapse integrates the SYNAPSE secret classification engine as an
// AVAT Context Agent. It bridges SYNAPSE's 5-signal behavioral analysis with
// the detection pipeline and agent orchestration framework.
package synapse

import (
	"context"
	"fmt"
	"strings"

	engine "github.com/synapse/engine"
)

// ContextVerdict represents the AVAT Context Agent's determination about a finding.
type ContextVerdict string

const (
	VerdictLikelyTP    ContextVerdict = "LIKELY_TRUE_POSITIVE"
	VerdictLikelyFP    ContextVerdict = "LIKELY_FALSE_POSITIVE"
	VerdictNeedsVerify ContextVerdict = "NEEDS_VERIFICATION"
	VerdictSuppressed  ContextVerdict = "SUPPRESSED"

	// Zero-FP pipeline verdicts — set by the orchestrator after Phase 2.
	VerdictConfirmed ContextVerdict = "CONFIRMED"  // Verification succeeded — secret is active
	VerdictDropped   ContextVerdict = "DROPPED"     // Verification failed or skipped — not shown to user
)

// CommitContext holds optional git commit metadata for context-aware analysis.
type CommitContext struct {
	Hash    string
	Author  string
	Message string
	Date    string
}

// OrgLearning holds organization-specific pattern data that can refine
// classification accuracy over time.
type OrgLearning struct {
	FalsePositivePatterns []string
	TruePositiveFiles     []string
	KnownTestTokenFormat  string
}

// ContextRequest is the input from the AVAT orchestrator to the Context Agent.
type ContextRequest struct {
	RawSecret   string
	FilePath    string
	LineNumber  int
	LineContent string
	VarName     string
	FileContent string
	CommitInfo  *CommitContext
	OrgPatterns *OrgLearning
	precomputedFP *FPContext // optional; set by ProcessChunk for batch efficiency
}

// ContextResult is the output from the Context Agent to the AVAT orchestrator.
type ContextResult struct {
	Adjustment      float64        // -1.0 to +1.0
	FinalConfidence float64        // adjusted confidence (0.0 to 1.0)
	Verdict         ContextVerdict // classification verdict
	Provenance      string         // from SYNAPSE classification
	Evidence        []EvidenceItem // full reasoning chain
	Signals         []SignalDetail // the SYNAPSE signals
	ShouldVerify    bool           // whether to proceed to Verification Agent
	ShouldNotify    bool           // whether to generate an alert
}

// EvidenceItem represents a single piece of evidence in the reasoning chain.
type EvidenceItem struct {
	Type        string // "syntactic_role", "morphology", "file_provenance", "line_context", "org_pattern"
	Description string
	Impact      float64 // how much this changed the confidence
}

// SignalDetail captures a SYNAPSE signal result in AVAT-friendly format.
type SignalDetail struct {
	Name       string
	Value      string
	Confidence float64
	Reasoning  string
}

// ContextAgentConfig controls the behavior of the Context Agent.
type ContextAgentConfig struct {
	AlertThreshold    float64 // minimum confidence to generate alert (default 0.3)
	SuppressBelow     float64 // suppress findings below this (default 0.1)
	EnableOrgLearning bool    // use org-specific patterns
}

// ContextAgent wraps the SYNAPSE engine as an AVAT Context Agent.
// It receives a potential secret finding from the detection pipeline
// and produces a confidence adjustment with full evidence chain.
type ContextAgent struct {
	config ContextAgentConfig
}

// NewContextAgent creates a new SYNAPSE-powered context agent.
func NewContextAgent(config ContextAgentConfig) *ContextAgent {
	if config.AlertThreshold == 0 {
		config.AlertThreshold = 0.3
	}
	if config.SuppressBelow == 0 {
		config.SuppressBelow = 0.45
	}
	return &ContextAgent{config: config}
}

// Analyze runs the SYNAPSE 5-signal classification pipeline on the finding.
// This is the core method called by the AVAT orchestrator.
func (a *ContextAgent) Analyze(ctx context.Context, req ContextRequest) (*ContextResult, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	tok := engine.Token{
		Value:       req.RawSecret,
		VarName:     req.VarName,
		Line:        req.LineNumber,
		LineContent: req.LineContent,
		FilePath:    req.FilePath,
	}

	classification := engine.ClassifyToken(tok)

	// ML refinement for UNCERTAIN tokens: use the same refineWithML path
	// that ScanFile uses, so the AVAT pipeline gets ML-enhanced verdicts.
	if classification.Prov == engine.ProvenanceUncertain && req.FileContent != "" {
		classification = engine.RefineWithML(tok, req.FileContent, classification)
	}

	signals := make([]SignalDetail, len(classification.Signals))
	evidence := make([]EvidenceItem, 0, len(classification.Signals)+2)

	for i, s := range classification.Signals {
		signals[i] = SignalDetail{
			Name:       s.Name,
			Value:      s.Value,
			Confidence: s.Confidence,
			Reasoning:  s.ReasonText,
		}
		evidence = append(evidence, EvidenceItem{
			Type:        s.Name,
			Description: fmt.Sprintf("%s=%s: %s", s.Name, s.Value, s.ReasonText),
			Impact:      s.Confidence,
		})
	}

	provStr := string(classification.Prov)
	baseConf := classification.Conf

	verdict, shouldVerify, shouldNotify := mapProvenanceToVerdict(classification.Prov)

	// === Apply the 6 FP Elimination Signals (non-regex semantic analysis) ===
	fpAdj, fpEvidence := ApplyFPSignalsWithContext(req, req.precomputedFP)
	evidence = append(evidence, fpEvidence...)

	// Apply org-specific pattern adjustments.
	orgAdj := 0.0
	if a.config.EnableOrgLearning && req.OrgPatterns != nil {
		orgAdj = a.applyOrgLearning(req, classification)
		if orgAdj != 0 {
			evidence = append(evidence, EvidenceItem{
				Type:        "org_pattern",
				Description: fmt.Sprintf("Org-specific adjustment: %+.2f", orgAdj),
				Impact:      orgAdj,
			})
		}
	}

	adjustment := fpAdj + orgAdj
	finalConf := clampFloat(baseConf+adjustment, 0.0, 1.0)

	// If FP signals suppress, override verdict
	if fpAdj <= -0.8 {
		verdict = VerdictLikelyFP
		shouldVerify = false
		shouldNotify = false
	}

	// Suppress low-confidence findings.
	if finalConf < a.config.SuppressBelow {
		verdict = VerdictSuppressed
		shouldVerify = false
		shouldNotify = false
	}

	// Override notification based on threshold.
	if finalConf < a.config.AlertThreshold {
		shouldNotify = false
	}

	return &ContextResult{
		Adjustment:      adjustment,
		FinalConfidence: finalConf,
		Verdict:         verdict,
		Provenance:      provStr,
		Evidence:        evidence,
		Signals:         signals,
		ShouldVerify:    shouldVerify,
		ShouldNotify:    shouldNotify,
	}, nil
}

// AnalyzeChunk processes a raw SDK Chunk through SYNAPSE token extraction
// and classification. This is for integration with the MORPHEX detection
// pipeline (before AVAT).
func (a *ContextAgent) AnalyzeChunk(ctx context.Context, chunk Chunk) ([]ContextResult, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	content := string(chunk.Data)
	filePath := chunk.Metadata.File
	if filePath == "" {
		filePath = chunk.Metadata.Source
	}

	tokens := engine.ExtractTokens(filePath, content)
	if len(tokens) == 0 {
		return nil, nil
	}

	results := make([]ContextResult, 0, len(tokens))
	for _, tok := range tokens {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}

		req := ContextRequest{
			RawSecret:   tok.Value,
			FilePath:    tok.FilePath,
			LineNumber:  tok.Line,
			LineContent: tok.LineContent,
			VarName:     tok.VarName,
			FileContent: content,
		}

		result, err := a.Analyze(ctx, req)
		if err != nil {
			return results, err
		}
		results = append(results, *result)
	}

	return results, nil
}

// mapProvenanceToVerdict maps a SYNAPSE provenance classification to an
// AVAT verdict with routing directives.
func mapProvenanceToVerdict(prov engine.Provenance) (ContextVerdict, bool, bool) {
	switch prov {
	case engine.ProvenanceAuthCredential:
		return VerdictLikelyTP, true, true
	case engine.ProvenanceUncertain:
		return VerdictNeedsVerify, true, false
	case engine.ProvenanceHumanAuthored,
		engine.ProvenanceBuildGenerated,
		engine.ProvenanceDocExample,
		engine.ProvenanceDerivedValue:
		return VerdictLikelyFP, false, false
	default:
		return VerdictNeedsVerify, true, false
	}
}

// applyOrgLearning adjusts classification confidence based on organization-specific
// pattern data.
func (a *ContextAgent) applyOrgLearning(req ContextRequest, cls engine.Classification) float64 {
	adj := 0.0
	org := req.OrgPatterns

	// Check if the raw secret matches known false positive patterns.
	for _, pat := range org.FalsePositivePatterns {
		if strings.Contains(req.RawSecret, pat) {
			adj -= 0.3
			break
		}
	}

	// Boost confidence if file is in the known true positive list.
	for _, f := range org.TruePositiveFiles {
		if strings.Contains(req.FilePath, f) {
			adj += 0.2
			break
		}
	}

	// Check known test token format.
	if org.KnownTestTokenFormat != "" && strings.Contains(req.RawSecret, org.KnownTestTokenFormat) {
		adj -= 0.4
	}

	return adj
}

// clampFloat restricts v to the range [lo, hi].
func clampFloat(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
