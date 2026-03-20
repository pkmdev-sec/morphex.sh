package synapse

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func defaultAgent() *ContextAgent {
	return NewContextAgent(ContextAgentConfig{
		AlertThreshold:    0.3,
		SuppressBelow:     0.1,
		EnableOrgLearning: true,
	})
}

func makeRequest(raw, varName, filePath, lineContent string, line int) ContextRequest {
	return ContextRequest{
		RawSecret:   raw,
		FilePath:    filePath,
		LineNumber:  line,
		LineContent: lineContent,
		VarName:     varName,
	}
}

// writeTempFile creates a temporary file with the given content and returns its path.
func writeTempFile(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	fp := filepath.Join(dir, name)
	if err := os.WriteFile(fp, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	return fp
}

// ---------------------------------------------------------------------------
// TestContextAgent_Analyze
// ---------------------------------------------------------------------------

func TestContextAgent_Analyze(t *testing.T) {
	agent := defaultAgent()
	ctx := context.Background()

	tests := []struct {
		name           string
		req            ContextRequest
		wantProvenance string
		wantVerdict    ContextVerdict
		wantVerify     bool
		wantNotify     bool
		minConfidence  float64
	}{
		{
			name: "AWS access key",
			req: makeRequest(
				"AKIA4E2FXJWM7RQBN9KZ",
				"aws_access_key_id",
				"config/settings.py",
				`aws_access_key_id = "AKIA4E2FXJWM7RQBN9KZ"`,
				10,
			),
			wantProvenance: "AUTH_CREDENTIAL",
			wantVerdict:    VerdictLikelyTP,
			wantVerify:     true,
			wantNotify:     true,
			minConfidence:  0.5,
		},
		{
			name: "GitHub PAT",
			req: makeRequest(
				"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12",
				"github_token",
				"deploy.sh",
				`export GITHUB_TOKEN="ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12"`,
				5,
			),
			wantProvenance: "AUTH_CREDENTIAL",
			wantVerdict:    VerdictLikelyTP,
			wantVerify:     true,
			wantNotify:     true,
			minConfidence:  0.5,
		},
		{
			name: "Placeholder value",
			req: makeRequest(
				"your-api-key-here",
				"api_key",
				"README.md",
				`api_key = "your-api-key-here"`,
				42,
			),
			wantVerdict: VerdictLikelyFP,
		},
		{
			name: "Hash/digest value",
			req: makeRequest(
				"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				"checksum",
				"package-lock.json",
				`"integrity": "sha256-e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"`,
				100,
			),
			wantVerdict: VerdictLikelyFP,
		},
		{
			name: "UUID value",
			req: makeRequest(
				"550e8400-e29b-41d4-a716-446655440000",
				"request_id",
				"handlers/api.go",
				`requestID := "550e8400-e29b-41d4-a716-446655440000"`,
				33,
			),
			// UUID with anti-credential var name should not be auth credential.
			wantVerdict: VerdictLikelyFP,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := agent.Analyze(ctx, tt.req)
			if err != nil {
				t.Fatalf("Analyze returned error: %v", err)
			}

			if result.Verdict != tt.wantVerdict {
				t.Errorf("verdict: got %s, want %s (provenance=%s, conf=%.4f)",
					result.Verdict, tt.wantVerdict, result.Provenance, result.FinalConfidence)
			}

			if tt.wantProvenance != "" && result.Provenance != tt.wantProvenance {
				t.Errorf("provenance: got %s, want %s", result.Provenance, tt.wantProvenance)
			}

			if tt.wantVerify && !result.ShouldVerify {
				t.Error("expected ShouldVerify=true")
			}
			if tt.wantNotify && !result.ShouldNotify {
				t.Error("expected ShouldNotify=true")
			}
			if tt.minConfidence > 0 && result.FinalConfidence < tt.minConfidence {
				t.Errorf("confidence %.4f < minimum %.4f", result.FinalConfidence, tt.minConfidence)
			}

			if len(result.Signals) == 0 {
				t.Error("expected at least one signal")
			}
			if len(result.Evidence) == 0 {
				t.Error("expected at least one evidence item")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestContextAgent_AnalyzeChunk
// ---------------------------------------------------------------------------

func TestContextAgent_AnalyzeChunk(t *testing.T) {
	agent := defaultAgent()
	ctx := context.Background()

	content := `# Configuration
DB_HOST=localhost
DB_PASSWORD="SuperSecretP@ssw0rd123!"
API_KEY=AKIA4E2FXJWM7RQBN9KZ
PLACEHOLDER=your-token-here
`
	chunk := Chunk{
		Data: []byte(content),
		Metadata: ChunkMetadata{
			File:   "config/.env",
			Source: "filesystem",
		},
	}

	results, err := agent.AnalyzeChunk(ctx, chunk)
	if err != nil {
		t.Fatalf("AnalyzeChunk returned error: %v", err)
	}

	if len(results) == 0 {
		t.Fatal("expected at least one result from chunk analysis")
	}

	// At least one result should be a likely true positive (the DB_PASSWORD or API_KEY).
	foundTP := false
	for _, r := range results {
		if r.Verdict == VerdictLikelyTP || r.Verdict == VerdictNeedsVerify {
			foundTP = true
			break
		}
	}
	if !foundTP {
		t.Error("expected at least one true positive or needs-verify result")
	}
}

// ---------------------------------------------------------------------------
// TestSynapseDetector_Scan
// ---------------------------------------------------------------------------

func TestSynapseDetector_Scan(t *testing.T) {
	det := NewSynapseDetector(ContextAgentConfig{
		AlertThreshold: 0.3,
		SuppressBelow:  0.1,
	})

	if det.Name() != "synapse" {
		t.Errorf("Name: got %q, want %q", det.Name(), "synapse")
	}
	if det.Keywords() != nil {
		t.Errorf("Keywords: got %v, want nil", det.Keywords())
	}

	ctx := context.Background()
	content := `export AWS_SECRET_ACCESS_KEY="a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0"
`
	chunk := Chunk{
		Data: []byte(content),
		Metadata: ChunkMetadata{
			File:   "deploy/env.sh",
			Source: "git",
			Link:   "https://github.com/example/repo/blob/main/deploy/env.sh#L1",
		},
	}

	results, err := det.Scan(ctx, chunk)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	if len(results) == 0 {
		t.Fatal("expected at least one result from detector scan")
	}

	r := results[0]
	if !strings.HasPrefix(r.DetectorName, "synapse:") {
		t.Errorf("DetectorName: got %q, want prefix 'synapse:'", r.DetectorName)
	}
	if r.Raw == "" {
		t.Error("Raw should not be empty")
	}
	if r.Redacted == "" || r.Redacted == r.Raw {
		t.Error("Redacted should mask the raw value")
	}
	if r.ExtraData == nil {
		t.Error("ExtraData should contain signal information")
	}
	if _, ok := r.ExtraData["provenance"]; !ok {
		t.Error("ExtraData should contain 'provenance' key")
	}
	if r.Link != chunk.Metadata.Link {
		t.Errorf("Link: got %q, want %q", r.Link, chunk.Metadata.Link)
	}
}

// ---------------------------------------------------------------------------
// TestOrchestrator_ProcessFinding
// ---------------------------------------------------------------------------

func TestOrchestrator_ProcessFinding(t *testing.T) {
	orch := NewOrchestrator(OrchestratorConfig{
		MaxConcurrentTeams: 2,
		ContextTimeout:     5 * time.Second,
		AlertThreshold:     0.3,
	})

	ctx := context.Background()
	req := makeRequest(
		"AKIA4E2FXJWM7RQBN9KZ",
		"aws_access_key_id",
		"config/prod.env",
		`AWS_ACCESS_KEY_ID=AKIA4E2FXJWM7RQBN9KZ`,
		1,
	)

	result, err := orch.ProcessFinding(ctx, req)
	if err != nil {
		t.Fatalf("ProcessFinding returned error: %v", err)
	}

	if result.ProcessingTime == 0 {
		t.Error("ProcessingTime should be > 0")
	}

	fv := result.FinalVerdict
	if fv.RiskLevel == "" {
		t.Error("RiskLevel should not be empty")
	}
	if len(fv.EvidenceChain) == 0 {
		t.Error("EvidenceChain should not be empty")
	}

	// Stubs should be nil.
	if result.VerificationResult != nil {
		t.Error("VerificationResult should be nil (stub)")
	}
	if result.BlastRadius != nil {
		t.Error("BlastRadius should be nil (stub)")
	}
	if result.Remediation != nil {
		t.Error("Remediation should be nil (stub)")
	}
}

// ---------------------------------------------------------------------------
// TestOrchestrator_ScanFile
// ---------------------------------------------------------------------------

func TestOrchestrator_ScanFile(t *testing.T) {
	content := `# Production Config
DATABASE_URL="postgres://admin:RealPassword123@db.prod.internal:5432/myapp"
API_SECRET_KEY="sk_live_4eC39HqLyjWDarjtT1zdp7dc"
PLACEHOLDER_KEY="your-key-here"
`
	fp := writeTempFile(t, "prod.env", content)

	orch := NewOrchestrator(OrchestratorConfig{
		AlertThreshold: 0.3,
	})

	ctx := context.Background()
	results, err := orch.ScanFile(ctx, fp)
	if err != nil {
		t.Fatalf("ScanFile returned error: %v", err)
	}

	if len(results) == 0 {
		t.Fatal("expected at least one result from file scan")
	}

	// Verify each result has a final verdict.
	for i, r := range results {
		if r.FinalVerdict.RiskLevel == "" {
			t.Errorf("result[%d]: RiskLevel should not be empty", i)
		}
	}
}

// ---------------------------------------------------------------------------
// TestVerdictMapping
// ---------------------------------------------------------------------------

func TestVerdictMapping(t *testing.T) {
	tests := []struct {
		provenance  string
		wantVerdict ContextVerdict
		wantVerify  bool
		wantNotify  bool
	}{
		{"AUTH_CREDENTIAL", VerdictLikelyTP, true, true},
		{"UNCERTAIN", VerdictNeedsVerify, true, false},
		{"HUMAN_AUTHORED", VerdictLikelyFP, false, false},
		{"BUILD_GENERATED", VerdictLikelyFP, false, false},
		{"DOC_EXAMPLE", VerdictLikelyFP, false, false},
		{"DERIVED_VALUE", VerdictLikelyFP, false, false},
	}

	// Import the engine provenance constants to test mapping.
	// We test via the exported mapProvenanceToVerdict indirectly
	// through Analyze since mapProvenanceToVerdict is unexported.
	agent := defaultAgent()
	ctx := context.Background()

	// Map provenance strings to test scenarios that produce that classification.
	scenarios := map[string]ContextRequest{
		"AUTH_CREDENTIAL": makeRequest(
			"AKIA4E2FXJWM7RQBN9KZ",
			"aws_secret_access_key",
			"config/settings.py",
			`aws_secret_access_key = "AKIA4E2FXJWM7RQBN9KZ"`,
			1,
		),
	}

	// Test the AUTH_CREDENTIAL case via Analyze.
	for _, tt := range tests {
		t.Run(tt.provenance, func(t *testing.T) {
			req, ok := scenarios[tt.provenance]
			if !ok {
				// For non-AUTH_CREDENTIAL, just verify the constants are defined.
				if tt.wantVerdict == "" {
					t.Error("verdict constant is empty")
				}
				return
			}

			result, err := agent.Analyze(ctx, req)
			if err != nil {
				t.Fatalf("Analyze error: %v", err)
			}

			if result.Verdict != tt.wantVerdict {
				t.Errorf("verdict: got %s, want %s", result.Verdict, tt.wantVerdict)
			}
			if result.ShouldVerify != tt.wantVerify {
				t.Errorf("ShouldVerify: got %v, want %v", result.ShouldVerify, tt.wantVerify)
			}
			if result.ShouldNotify != tt.wantNotify {
				t.Errorf("ShouldNotify: got %v, want %v", result.ShouldNotify, tt.wantNotify)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestOrgLearning
// ---------------------------------------------------------------------------

func TestOrgLearning(t *testing.T) {
	agent := NewContextAgent(ContextAgentConfig{
		AlertThreshold:    0.3,
		SuppressBelow:     0.1,
		EnableOrgLearning: true,
	})

	ctx := context.Background()

	t.Run("false positive pattern reduces confidence", func(t *testing.T) {
		reqNoOrg := makeRequest(
			"AKIA4E2FXJWM7RQBN9KZ",
			"aws_access_key_id",
			"config/settings.py",
			`aws_access_key_id = "AKIA4E2FXJWM7RQBN9KZ"`,
			10,
		)
		resultNoOrg, err := agent.Analyze(ctx, reqNoOrg)
		if err != nil {
			t.Fatal(err)
		}

		reqWithOrg := reqNoOrg
		reqWithOrg.OrgPatterns = &OrgLearning{
			FalsePositivePatterns: []string{"RQBN9KZ"},
		}
		resultWithOrg, err := agent.Analyze(ctx, reqWithOrg)
		if err != nil {
			t.Fatal(err)
		}

		if resultWithOrg.FinalConfidence >= resultNoOrg.FinalConfidence {
			t.Errorf("org FP pattern should reduce confidence: %.4f >= %.4f",
				resultWithOrg.FinalConfidence, resultNoOrg.FinalConfidence)
		}
	})

	t.Run("true positive file boosts confidence", func(t *testing.T) {
		reqBase := makeRequest(
			"sk_live_4eC39HqLyjWDarjtT1zdp7dc",
			"api_key",
			"deploy/production.env",
			`API_KEY=sk_live_4eC39HqLyjWDarjtT1zdp7dc`,
			1,
		)
		resultBase, err := agent.Analyze(ctx, reqBase)
		if err != nil {
			t.Fatal(err)
		}

		reqBoosted := reqBase
		reqBoosted.OrgPatterns = &OrgLearning{
			TruePositiveFiles: []string{"production.env"},
		}
		resultBoosted, err := agent.Analyze(ctx, reqBoosted)
		if err != nil {
			t.Fatal(err)
		}

		if resultBoosted.FinalConfidence < resultBase.FinalConfidence {
			t.Errorf("org TP file should boost confidence: %.4f < %.4f",
				resultBoosted.FinalConfidence, resultBase.FinalConfidence)
		}
	})

	t.Run("known test token format suppresses", func(t *testing.T) {
		req := makeRequest(
			"test_token_abc123",
			"api_key",
			"tests/helper.py",
			`api_key = "test_token_abc123"`,
			5,
		)
		req.OrgPatterns = &OrgLearning{
			KnownTestTokenFormat: "test_token_",
		}

		result, err := agent.Analyze(ctx, req)
		if err != nil {
			t.Fatal(err)
		}

		// The test token pattern should have reduced confidence.
		if result.Adjustment >= 0 {
			t.Errorf("known test token should produce negative adjustment: got %.4f", result.Adjustment)
		}
	})
}

// ---------------------------------------------------------------------------
// BenchmarkContextAgent_Analyze
// ---------------------------------------------------------------------------

func BenchmarkContextAgent_Analyze(b *testing.B) {
	agent := defaultAgent()
	ctx := context.Background()

	req := makeRequest(
		"AKIA4E2FXJWM7RQBN9KZ",
		"aws_access_key_id",
		"config/settings.py",
		`aws_access_key_id = "AKIA4E2FXJWM7RQBN9KZ"`,
		10,
	)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := agent.Analyze(ctx, req)
		if err != nil {
			b.Fatal(err)
		}
	}
}
