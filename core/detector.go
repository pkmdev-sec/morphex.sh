package synapse

import (
	"context"
	"fmt"
	"strings"

	engine "github.com/synapse/engine"
)

// SynapseDetector implements the MORPHEX detector interface using SYNAPSE's
// multi-signal classification instead of regex pattern matching.
// It discovers secrets that NO regex pattern could find by understanding
// code context, variable semantics, and value morphology.
type SynapseDetector struct {
	agent *ContextAgent
}

// NewSynapseDetector creates a new SYNAPSE-backed detector.
func NewSynapseDetector(config ContextAgentConfig) *SynapseDetector {
	return &SynapseDetector{
		agent: NewContextAgent(config),
	}
}

// Name returns "synapse" as the detector name.
func (d *SynapseDetector) Name() string {
	return "synapse"
}

// Keywords returns nil. SYNAPSE does not use keyword pre-filtering;
// it analyzes ALL content through its multi-signal pipeline.
func (d *SynapseDetector) Keywords() []string {
	return nil
}

// Scan processes a chunk through the SYNAPSE pipeline.
// Returns results compatible with the MORPHEX SDK Result type.
func (d *SynapseDetector) Scan(ctx context.Context, chunk Chunk) ([]Result, error) {
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

	var results []Result
	for _, tok := range tokens {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}

		cls := engine.ClassifyToken(tok)

		// Only report AUTH_CREDENTIAL and UNCERTAIN provenance as findings.
		if cls.Prov != engine.ProvenanceAuthCredential && cls.Prov != engine.ProvenanceUncertain {
			continue
		}

		// Apply suppression threshold.
		if cls.Conf < d.agent.config.SuppressBelow {
			continue
		}

		extra := map[string]string{
			"provenance":  string(cls.Prov),
			"confidence":  fmt.Sprintf("%.4f", cls.Conf),
			"var_name":    tok.VarName,
			"reasoning":   cls.Reasoning(),
		}

		for i, s := range cls.Signals {
			prefix := fmt.Sprintf("signal_%d_", i)
			extra[prefix+"name"] = s.Name
			extra[prefix+"value"] = s.Value
			extra[prefix+"confidence"] = fmt.Sprintf("%.4f", s.Confidence)
			extra[prefix+"reasoning"] = s.ReasonText
		}

		results = append(results, Result{
			DetectorName: "synapse:" + strings.ToLower(string(cls.Prov)),
			Raw:          tok.Value,
			Redacted:     redactValue(tok.Value),
			Verified:     cls.Prov == engine.ProvenanceAuthCredential && cls.Conf >= 0.8,
			SourceFile:   tok.FilePath,
			SourceLine:   tok.Line,
			Link:         chunk.Metadata.Link,
			ExtraData:    extra,
		})
	}

	return results, nil
}

// redactValue masks a secret value for safe display.
func redactValue(s string) string {
	if len(s) <= 8 {
		return "****"
	}
	return s[:4] + "..." + s[len(s)-4:]
}
