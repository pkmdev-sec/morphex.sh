package synapse

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	engine "github.com/synapse/engine"
)

// OrchestratorConfig controls the AVAT orchestrator behavior.
type OrchestratorConfig struct {
	MaxConcurrentTeams int
	ContextTimeout     time.Duration
	VerifyTimeout      time.Duration
	AlertThreshold     float64

	// Phase 2: Verification Agent config (optional)
	EnableVerification bool
	VerificationConfig *VerificationAgentConfig

	// Phase 3: Blast Radius Agent config (optional)
	EnableBlastRadius bool
	BlastRadiusConfig *BlastRadiusConfig

	// Phase 4: Remediation Agent config (optional)
	EnableRemediation bool
	RemediationConfig *RemediationConfig
}

// AgentTeamResult aggregates results from all AVAT agent phases.
type AgentTeamResult struct {
	// Source context from the original request
	File       string
	Line       int
	RawSecret  string
	VarName    string

	Finding            ContextResult
	VerificationResult *VerificationResult // nil until Verification Agent is built
	BlastRadius        *BlastRadiusResult  // nil until BR Agent is built
	Remediation        *RemediationResult  // nil until Remediation Agent is built
	FinalVerdict       FinalVerdict
	ProcessingTime     time.Duration
}

// FinalVerdict is the orchestrator's combined determination.
type FinalVerdict struct {
	IsSecret      bool
	Confidence    float64
	RiskLevel     string // "critical", "high", "medium", "low", "none"
	ShouldAlert   bool
	ShouldBlock   bool // for CI/CD gate mode
	EvidenceChain []EvidenceItem
}

// VerificationResult is a stub for the future Verification Agent.
type VerificationResult struct {
	Status   string
	HTTPCode int
	Verified bool
}

// BlastRadiusResult is a stub for the future Blast Radius Agent.
type BlastRadiusResult struct {
	RiskLevel   string
	AccessScope []string
	Description string
}

// RemediationResult is a stub for the future Remediation Agent.
type RemediationResult struct {
	Steps          []string
	RotationScript string
	JiraTicket     string
}

// Orchestrator routes findings through the AVAT agent pipeline.
// Phase 1: Context Agent (SYNAPSE) — deterministic, 100% precision
// Phase 2: Verification Agent (Claude) — AI-powered credential testing
// Phase 3: Blast Radius Agent — access scope mapping
// Phase 4: Remediation Agent — actionable remediation plans
type Orchestrator struct {
	contextAgent      *ContextAgent
	verificationAgent *VerificationAgent  // nil unless --verify is enabled
	blastRadiusAgent  *BlastRadiusAgent   // nil if blast radius disabled
	remediationAgent  *RemediationAgent   // nil if remediation disabled
	config            OrchestratorConfig
	verifyCache       *VerificationCache  // caches verification results across scans
	rateLimiter       *RateLimiter        // prevents overwhelming target APIs
}

// NewOrchestrator creates a new AVAT orchestrator with the given config.
func NewOrchestrator(config OrchestratorConfig) *Orchestrator {
	if config.MaxConcurrentTeams <= 0 {
		config.MaxConcurrentTeams = 4
	}
	if config.ContextTimeout == 0 {
		config.ContextTimeout = 30 * time.Second
	}
	if config.VerifyTimeout == 0 {
		config.VerifyTimeout = 25 * time.Second
	}
	if config.AlertThreshold == 0 {
		config.AlertThreshold = 0.3
	}

	agentCfg := ContextAgentConfig{
		AlertThreshold:    config.AlertThreshold,
		SuppressBelow:     0.1,
		EnableOrgLearning: false,
	}

	orch := &Orchestrator{
		contextAgent: NewContextAgent(agentCfg),
		config:       config,
		verifyCache:  NewVerificationCache(1*time.Hour, 10000),
		rateLimiter:  NewRateLimiter(RateLimitConfig{RequestsPerSecond: 10, BurstSize: 20}),
	}

	// Initialize Verification Agent only when --verify is enabled.
	// OSS default is engine-only (no Claude, no HTTP verification calls).
	if config.EnableVerification && config.VerificationConfig != nil {
		orch.verificationAgent = NewVerificationAgent(*config.VerificationConfig)
	} else if config.EnableVerification {
		orch.verificationAgent = NewVerificationAgent(VerificationAgentConfig{})
	}

	// Initialize Blast Radius Agent if enabled
	if config.EnableBlastRadius {
		brConfig := BlastRadiusConfig{}
		if config.BlastRadiusConfig != nil {
			brConfig = *config.BlastRadiusConfig
		}
		orch.blastRadiusAgent = NewBlastRadiusAgent(brConfig)
	}

	// Initialize Remediation Agent if enabled
	if config.EnableRemediation {
		remConfig := RemediationConfig{}
		if config.RemediationConfig != nil {
			remConfig = *config.RemediationConfig
		}
		orch.remediationAgent = NewRemediationAgent(remConfig)
	}

	return orch
}

// ProcessFinding runs a finding through the AVAT agent pipeline.
// Phase 1: Context Agent (SYNAPSE) — deterministic classification
// Phase 2: Verification Agent (Claude) — AI-powered liveness check
// Phase 3: Blast Radius Agent — access scope mapping
// Phase 4: Remediation Agent — actionable remediation plans
//
// AVAT Decision Matrix for Phase 3+4:
//   Confidence >= 0.9 + Verified ACTIVE -> Phase 3 (blast radius) + Phase 4 (remediation)
//   Confidence 0.7-0.9 + Verified ACTIVE -> Phase 3 only
//   Confidence 0.4-0.7 + Verified -> Log for review
//   Others -> Context only
func (o *Orchestrator) ProcessFinding(ctx context.Context, req ContextRequest) (*AgentTeamResult, error) {
	start := time.Now()

	ctxTimeout, cancel := context.WithTimeout(ctx, o.config.ContextTimeout)
	defer cancel()

	// Phase 1: Context Agent (always runs, deterministic, nanoseconds).
	ctxResult, err := o.contextAgent.Analyze(ctxTimeout, req)
	if err != nil {
		return nil, fmt.Errorf("context agent failed: %w", err)
	}

	result := &AgentTeamResult{
		File:      req.FilePath,
		Line:      req.LineNumber,
		RawSecret: req.RawSecret,
		VarName:   req.VarName,
		Finding:   *ctxResult,
	}

	// Phase 2: Verification Agent (runs only for findings that need verification).
	// Use contextConfidence for tiering decisions so verification cannot inflate
	// the tier; verifiedConfidence is stored separately on the result.
	var fullVerResult *FullVerificationResult
	ecosystem := detectEcosystem(ctxResult)
	contextConfidence := ctxResult.FinalConfidence

	// Smart gate: only verify candidates the Context Agent flagged as potential secrets.
	// SUPPRESSED and LIKELY_FP candidates were already killed by the 7 FP signals +
	// SYNAPSE engine — verifying them would waste HTTP calls on known non-secrets.
	// The zero-FP guarantee holds: anything that passes this gate AND verification = shown.
	// Anything that doesn't pass this gate = dropped (VerdictDropped is the default).
	shouldVerify := ctxResult.Verdict == VerdictLikelyTP || ctxResult.Verdict == VerdictNeedsVerify
	if o.verificationAgent != nil && shouldVerify {
		// Check verification cache first (P0 fix: wire the cache).
		secretHash := HashSecret(req.RawSecret)
		if cached, ok := o.verifyCache.Get(secretHash); ok {
			fullVerResult = cached
			result.VerificationResult = &VerificationResult{
				Status:   string(cached.Status),
				HTTPCode: cached.HTTPStatusCode,
				Verified: cached.Verified,
			}
			ctxResult.Evidence = append(ctxResult.Evidence, cached.Evidence...)
			ctxResult.Evidence = append(ctxResult.Evidence, EvidenceItem{
				Type:        "cache_hit",
				Description: "Verification result from cache (avoiding redundant API call)",
				Impact:      0,
			})
		} else {
			verifyCtx, verifyCancel := context.WithTimeout(ctx, o.config.VerifyTimeout)
			defer verifyCancel()

			verResult, verErr := o.verificationAgent.VerifyWithFastPath(verifyCtx, req.RawSecret, ecosystem, *ctxResult)
			if verErr == nil && verResult != nil {
				fullVerResult = verResult
				result.VerificationResult = &VerificationResult{
					Status:   string(verResult.Status),
					HTTPCode: verResult.HTTPStatusCode,
					Verified: verResult.Verified,
				}
				ctxResult.Evidence = append(ctxResult.Evidence, verResult.Evidence...)

				// Cache the result for future scans.
				o.verifyCache.Set(secretHash, verResult)
			}
		}

		// Zero-FP pipeline: verification result determines the final verdict.
		// Verified=true  → VerdictConfirmed  (shown to user)
		// Verified=false → VerdictDropped    (never shown to user)
		if fullVerResult != nil {
			if fullVerResult.Verified {
				ctxResult.FinalConfidence = maxf(ctxResult.FinalConfidence, fullVerResult.Confidence)
				ctxResult.Verdict = VerdictConfirmed
				ctxResult.ShouldNotify = true
			} else {
				ctxResult.Verdict = VerdictDropped
				ctxResult.ShouldNotify = false
			}
			result.Finding = *ctxResult
		} else {
			// Verification agent exists but returned no result (error/timeout).
			// Unverified = not shown. Zero-FP means we don't guess.
			ctxResult.Verdict = VerdictDropped
			ctxResult.ShouldNotify = false
			result.Finding = *ctxResult
		}
	}

	// Phase 3: Blast Radius Agent
	// Uses contextConfidence for tiering so verification can't inflate the tier.
	var fullBRResult *FullBlastRadiusResult
	if o.blastRadiusAgent != nil && fullVerResult != nil && fullVerResult.Verified && contextConfidence >= 0.7 {
		brResult, brErr := o.blastRadiusAgent.Analyze(ctx, req.RawSecret, ecosystem, fullVerResult)
		if brErr == nil && brResult != nil {
			fullBRResult = brResult
			result.BlastRadius = &BlastRadiusResult{
				RiskLevel:   brResult.RiskLevel,
				AccessScope: accessItemsToStrings(brResult.AccessScope),
				Description: brResult.Summary,
			}
			ctxResult.Evidence = append(ctxResult.Evidence, brResult.Evidence...)
			result.Finding = *ctxResult
		}
	}

	// Phase 4: Remediation Agent
	// Uses contextConfidence for tiering so verification can't inflate the tier.
	if o.remediationAgent != nil && fullVerResult != nil && fullVerResult.Verified && contextConfidence >= 0.9 {
		remResult, remErr := o.remediationAgent.Plan(ctx, *ctxResult, ecosystem, fullBRResult)
		if remErr == nil && remResult != nil {
			result.Remediation = &RemediationResult{
				Steps:          remResult.RotationSteps,
				RotationScript: remResult.RotationScript,
				JiraTicket:     remResult.JiraTicketURL,
			}
			ctxResult.Evidence = append(ctxResult.Evidence, remResult.Evidence...)
			result.Finding = *ctxResult
		}
	}

	// Build final verdict incorporating all phases
	result.FinalVerdict = buildFinalVerdict(&result.Finding)
	result.ProcessingTime = time.Since(start)

	return result, nil
}

// accessItemsToStrings converts AccessItem slice to string slice for the stub type.
func accessItemsToStrings(items []AccessItem) []string {
	result := make([]string, len(items))
	for i, item := range items {
		result[i] = fmt.Sprintf("%s (%s) [%s]", item.Resource, item.Permission, item.Sensitivity)
	}
	return result
}

// detectEcosystem extracts the credential ecosystem from SYNAPSE signals.
func detectEcosystem(cr *ContextResult) string {
	for _, sig := range cr.Signals {
		if sig.Name == "morphology" {
			// Parse ecosystem from morphology reasoning
			r := sig.Reasoning
			if idx := strings.Index(r, "-> "); idx >= 0 {
				return strings.TrimSpace(r[idx+3:])
			}
		}
	}
	return ""
}

// max returns the larger of two float64 values.
func maxf(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

// ProcessChunk runs an entire chunk through extraction, classification,
// and orchestration.
func (o *Orchestrator) ProcessChunk(ctx context.Context, chunk Chunk) ([]AgentTeamResult, error) {
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
	tokens = append(tokens, engine.AdvancedExtractTokens(filePath, content)...)
	if len(tokens) == 0 {
		return nil, nil
	}

	// ── OPTIMIZATION: Pre-classify with SYNAPSE engine first ──────────
	// Only tokens that SYNAPSE classifies as AUTH_CREDENTIAL or UNCERTAIN
	// need the expensive AVAT pipeline (Context Agent + FP signals).
	// HUMAN_AUTHORED, BUILD_GENERATED, DOC_EXAMPLE, DERIVED_VALUE are
	// already correctly classified and can be skipped.
	//
	// On crypto-heavy repos (go-ethereum) this eliminates ~85% of tokens
	// from the AVAT pipeline, turning a 10s scan into a 3s scan.
	classifications := engine.ClassifyTokenBatch(tokens)

	// Pre-compute per-file context once for all FP signal calls.
	// Previously fp_signals.go computed strings.ToLower(fileContent)
	// and strings.Split(fileContent, "\n") per-token — O(N*T).
	fpCtx := PrecomputeFPContext(content)

	// ── Stage 1: Fast-filter tokens (sequential, nanoseconds per token) ──
	var qualified []ContextRequest
	for i, tok := range tokens {
		cls := classifications[i]
		switch cls.Prov {
		case engine.ProvenanceHumanAuthored,
			engine.ProvenanceBuildGenerated,
			engine.ProvenanceDocExample,
			engine.ProvenanceDerivedValue:
			continue
		}
		if engine.IsEngineFalsePositive(tok) {
			continue
		}
		qualified = append(qualified, ContextRequest{
			RawSecret:     tok.Value,
			FilePath:      tok.FilePath,
			LineNumber:    tok.Line,
			LineContent:   tok.LineContent,
			VarName:       tok.VarName,
			FileContent:   content,
			precomputedFP: fpCtx,
		})
	}

	if len(qualified) == 0 {
		return nil, nil
	}

	// ── Stage 2: Process findings in parallel (Claude calls are the bottleneck) ──
	type indexedResult struct {
		idx    int
		result *AgentTeamResult
	}

	maxParallel := o.config.MaxConcurrentTeams
	if maxParallel <= 0 {
		maxParallel = 4
	}
	if maxParallel > 10 {
		maxParallel = 10
	}

	resultCh := make(chan indexedResult, len(qualified))
	sem := make(chan struct{}, maxParallel)

	for i, req := range qualified {
		select {
		case <-ctx.Done():
			break
		case sem <- struct{}{}:
		}

		go func(idx int, r ContextRequest) {
			defer func() { <-sem }()
			res, err := o.ProcessFinding(ctx, r)
			if err == nil && res != nil {
				resultCh <- indexedResult{idx: idx, result: res}
			}
		}(i, req)
	}

	// Wait for all goroutines to finish
	for i := 0; i < cap(sem); i++ {
		sem <- struct{}{}
	}
	close(resultCh)

	// Collect results in order
	collected := make([]*AgentTeamResult, len(qualified))
	for ir := range resultCh {
		collected[ir.idx] = ir.result
	}

	var results []AgentTeamResult
	for _, r := range collected {
		if r != nil {
			results = append(results, *r)
		}
	}

	return results, nil
}

// ScanFile is a convenience method that scans a file end-to-end through
// the full AVAT pipeline.
func (o *Orchestrator) ScanFile(ctx context.Context, filepath string) ([]AgentTeamResult, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", filepath, err)
	}

	chunk := Chunk{
		Data: data,
		Metadata: ChunkMetadata{
			Source: filepath,
			File:   filepath,
		},
	}

	return o.ProcessChunk(ctx, chunk)
}

// ScanDirectory scans a directory with full AVAT orchestration.
// It walks all scannable files and processes each through ScanFile,
// which reads raw content (not redacted values) for accurate classification.
func (o *Orchestrator) ScanDirectory(ctx context.Context, root string, workers int) ([]AgentTeamResult, error) {
	if workers <= 0 {
		workers = o.config.MaxConcurrentTeams
	}

	// Stream file paths into a channel so workers start immediately
	// instead of waiting for the full directory walk to complete.
	pathCh := make(chan string, workers*4)
	go func() {
		defer close(pathCh)
		walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				fmt.Fprintf(os.Stderr, "warning: skipping %s: %v\n", path, err)
				return nil
			}
		if d.IsDir() {
			name := d.Name()
				// Only skip VCS internals and known non-code directories.
				// Do NOT skip .github/, .circleci/, .env etc. — they
				// contain CI configs and secrets.
				skips := map[string]struct{}{
					".git": {}, ".svn": {}, ".hg": {},
					"node_modules": {}, "vendor": {}, "__pycache__": {},
					".venv": {}, "venv": {}, ".tox": {}, "dist": {}, "build": {},
					".cache": {}, ".npm": {}, ".next": {},
				}
			if _, skip := skips[name]; skip {
				return filepath.SkipDir
			}
			// Skip Apple/IDE bundles and build output directories
			// by extension-like suffixes.
			if strings.HasSuffix(name, ".app") ||
				strings.HasSuffix(name, ".framework") ||
				strings.HasSuffix(name, ".xcodeproj") ||
				strings.HasSuffix(name, ".xcworkspace") ||
				strings.HasSuffix(name, ".dSYM") ||
				strings.HasSuffix(name, ".xcassets") {
				return filepath.SkipDir
			}
			// Skip generated documentation directories.
			// Skip static asset dirs inside website/documentation roots.
			if name == "public" || name == "static" {
				parent := filepath.Base(filepath.Dir(path))
				if parent == "website" || parent == "site" || parent == "docs" || parent == "doc" {
					return filepath.SkipDir
				}
			}
			// Javadoc dirs contain package-list; Doxygen/Sphinx dirs
			// contain similar markers. Check via fast file existence.
			if isGeneratedDocDir(path) {
				return filepath.SkipDir
			}
			return nil
		}
		if engine.FileDefinitelySafe(d.Name()) {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() == 0 || info.Size() > 1_000_000 {
			return nil
		}
			// Skip large JSON/data files that are clearly not config.
			// Lottie animations, test fixtures, and data blobs generate
			// thousands of tokens but never contain real secrets.
			fname := strings.ToLower(d.Name())
			if info.Size() > 200_000 {
				ext := filepath.Ext(fname)
				if ext == ".json" || ext == ".xml" || ext == ".csv" || ext == ".html" {
					// Allow config-named files through
					if !strings.Contains(fname, "config") &&
						!strings.Contains(fname, "secret") &&
						!strings.Contains(fname, "credential") &&
						!strings.Contains(fname, ".env") &&
						!strings.Contains(fname, "package") {
						return nil
					}
				}
			}
			// Skip files without extensions that are large (likely binaries)
			if filepath.Ext(fname) == "" && info.Size() > 100_000 {
				return nil
			}
			pathCh <- path
		return nil
	})
		if walkErr != nil {
			fmt.Fprintf(os.Stderr, "warning: walk error: %v\n", walkErr)
		}
	}()

	// Process files concurrently as they arrive from the walker.
	type fileResult struct {
		results []AgentTeamResult
		err     error
	}

	resultCh := make(chan fileResult, workers*4)
	var wg sync.WaitGroup

	// Fixed worker pool: spawn exactly `workers` goroutines that pull from
	// pathCh. This replaces the goroutine-per-file pattern that created 100K+
	// goroutines on large repos (each consuming ~4KB stack = 400MB).
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					fmt.Fprintf(os.Stderr, "panic in scan worker: %v\n", r)
				}
			}()
			for path := range pathCh {
				results, err := o.ScanFile(ctx, path)
				resultCh <- fileResult{results: results, err: err}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	var allResults []AgentTeamResult
	for fr := range resultCh {
		if fr.err != nil {
			fmt.Fprintf(os.Stderr, "warning: %v\n", fr.err)
			continue
		}
		allResults = append(allResults, fr.results...)
	}

	return allResults, nil
}

// buildFinalVerdict produces a FinalVerdict from a ContextResult.
func buildFinalVerdict(cr *ContextResult) FinalVerdict {
	// IsSecret is true for CONFIRMED (verified) or LIKELY_TRUE_POSITIVE (engine-only high-confidence).
	isSecret := cr.Verdict == VerdictConfirmed || cr.Verdict == VerdictLikelyTP
	riskLevel := confidenceToRisk(cr.FinalConfidence, cr.Verdict)

	return FinalVerdict{
		IsSecret:      isSecret,
		Confidence:    cr.FinalConfidence,
		RiskLevel:     riskLevel,
		ShouldAlert:   isSecret,
		ShouldBlock:   isSecret && cr.FinalConfidence >= 0.8,
		EvidenceChain: cr.Evidence,
	}
}

// confidenceToRisk maps confidence and verdict to a risk level string.
func confidenceToRisk(conf float64, verdict ContextVerdict) string {
	if verdict == VerdictSuppressed || verdict == VerdictLikelyFP {
		if conf >= 0.5 {
			return "low"
		}
		return "none"
	}

	switch {
	case conf >= 0.9:
		return "critical"
	case conf >= 0.7:
		return "high"
	case conf >= 0.4:
		return "medium"
	case conf >= 0.2:
		return "low"
	default:
		return "none"
	}
}

// isGeneratedDocDir returns true if the directory appears to be generated
// documentation output (javadoc, doxygen, sphinx, typedoc, etc.).
// Uses fast os.Stat checks for telltale marker files.
func isGeneratedDocDir(dirPath string) bool {
	// Only check directories that look like they might be documentation
	// output. Running 6 os.Stat calls on every directory is too expensive.
	lower := strings.ToLower(filepath.Base(dirPath))
	parentLower := strings.ToLower(filepath.Base(filepath.Dir(dirPath)))

	// Fast check: is this directory or its parent named something doc-like?
	docNames := map[string]bool{
		"docs": true, "doc": true, "documentation": true,
		"api": true, "apidoc": true, "apidocs": true,
		"javadoc": true, "jsdoc": true, "typedoc": true,
		"reference": true, "html": true,
	}
	if !docNames[lower] && !docNames[parentLower] {
		// Also check for versioned javadoc dirs like "1.x", "2.x"
		if !(len(lower) <= 4 && strings.Contains(lower, ".")) {
			return false
		}
	}

	markers := []string{
		"package-list",
		"allclasses-frame.html",
		"index-all.html",
		"searchindex.js",
		"genindex.html",
		"_modules",
	}
	for _, m := range markers {
		candidate := filepath.Join(dirPath, m)
		if _, err := os.Stat(candidate); err == nil {
			return true
		}
	}
	return false
}
