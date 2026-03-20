package synapse

import (
	"context"
	"time"
)

// Stubs for optional verification, blast-radius, and remediation agents.
// These are no-op implementations so the orchestrator compiles cleanly
// without the full agent backends.

// --- Verification Agent stubs ---

type VerificationStatus string

const (
	VerifyActive     VerificationStatus = "ACTIVE"
	VerifyInactive   VerificationStatus = "INACTIVE"
	VerifyRevoked    VerificationStatus = "REVOKED"
	VerifyRestricted VerificationStatus = "RESTRICTED"
	VerifyUnknown    VerificationStatus = "UNKNOWN"
	VerifySkipped    VerificationStatus = "SKIPPED"
	VerifyError      VerificationStatus = "ERROR"
)

type VerificationAgent struct{}

type VerificationAgentConfig struct {
	APIKey      string
	Model       string
	BaseURL     string
	MaxAPICalls int
	Timeout     time.Duration
	DryRun      bool
}

type FullVerificationResult struct {
	Status          VerificationStatus
	Verified        bool
	Confidence      float64
	HTTPStatusCode  int
	ResponseSummary string
	Evidence        []EvidenceItem
	ErrorMessage    string
	Duration        time.Duration
	HTTPCode        int
}

func NewVerificationAgent(_ VerificationAgentConfig) *VerificationAgent { return &VerificationAgent{} }

func (v *VerificationAgent) Verify(_ context.Context, _ string, _ string, _ ContextResult) (*FullVerificationResult, error) {
	return &FullVerificationResult{Status: VerifySkipped, Evidence: []EvidenceItem{{
		Type: "verification_skipped", Description: "Verification agent not configured.",
	}}}, nil
}

func (v *VerificationAgent) VerifyWithFastPath(_ context.Context, _ string, _ string, _ ContextResult) (*FullVerificationResult, error) {
	return &FullVerificationResult{Status: VerifySkipped, Evidence: []EvidenceItem{{
		Type: "verification_skipped", Description: "Verification agent not configured.",
	}}}, nil
}

// --- Verification Cache stubs ---

type VerificationCache struct{}
type CacheStats struct {
	Hits   int
	Misses int
	Size   int
}

func NewVerificationCache(_ time.Duration, _ int) *VerificationCache { return &VerificationCache{} }
func (vc *VerificationCache) Get(_ string) (*FullVerificationResult, bool) { return nil, false }
func (vc *VerificationCache) Set(_ string, _ *FullVerificationResult)      {}
func (vc *VerificationCache) Stats() CacheStats                            { return CacheStats{} }
func HashSecret(_ string) string                                           { return "" }

// --- Blast Radius Agent stubs ---

type BlastRadiusAgent struct{}
type BlastRadiusConfig struct{}
type FullBlastRadiusResult struct {
	RiskLevel   string
	RiskScore   int
	AccessScope []AccessItem
	Summary     string
	Evidence    []EvidenceItem
}
type AccessItem struct {
	Resource    string
	Permission  string
	Sensitivity string
}

func NewBlastRadiusAgent(_ BlastRadiusConfig) *BlastRadiusAgent { return nil }

func (b *BlastRadiusAgent) Analyze(_ interface{}, _ string, _ string, _ *FullVerificationResult) (*FullBlastRadiusResult, error) {
	return nil, nil
}

// --- Remediation Agent stubs ---

type RemediationAgent struct{}
type RemediationConfig struct{}
type FullRemediationResult struct {
	RotationSteps  []string
	RotationScript string
	JiraTicketURL  string
	Evidence       []EvidenceItem
}

func NewRemediationAgent(_ RemediationConfig) *RemediationAgent { return nil }

func (r *RemediationAgent) Plan(_ interface{}, _ ContextResult, _ string, _ *FullBlastRadiusResult) (*FullRemediationResult, error) {
	return nil, nil
}
