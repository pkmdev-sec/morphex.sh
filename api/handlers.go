package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	engine "github.com/synapse/engine"
	synapse "github.com/morphex/integrations/synapse"
)

const (
	toolName       = "morphex"
	toolVersion    = "2.0.0-synapse-v2"
	engineVersion  = "SYNAPSE v2 (Algorithmically Reinvented)"
	defaultTimeout = 5 * time.Minute
)

// Handlers holds shared state (orchestrator, metrics, health checker) for
// all HTTP handler functions.
type Handlers struct {
	orchestrator *synapse.Orchestrator
	metrics      *synapse.MetricsCollector
	health       *synapse.HealthChecker
	startTime    time.Time
}

// NewHandlers creates a new Handlers instance with a default orchestrator.
func NewHandlers() *Handlers {
	orch := synapse.NewOrchestrator(synapse.OrchestratorConfig{
		MaxConcurrentTeams: runtime.NumCPU(),
		ContextTimeout:     30 * time.Second,
		AlertThreshold:     0.3,
	})
	return &Handlers{
		orchestrator: orch,
		metrics:      synapse.NewMetricsCollector(),
		health:       synapse.NewHealthChecker(toolVersion),
		startTime:    time.Now(),
	}
}

// =========================================================================
// Output format helpers
// =========================================================================

func outputFormat(r *http.Request) string {
	f := r.URL.Query().Get("format")
	switch strings.ToLower(f) {
	case "sarif", "csv", "junit":
		return strings.ToLower(f)
	default:
		return "json"
	}
}

func writeScanResponse(w http.ResponseWriter, r *http.Request, resp ScanResponse, elapsed time.Duration) {
	format := outputFormat(r)
	switch format {
	case "sarif":
		engineFindings := apiToEngineFindings(resp.Findings)
		report, err := synapse.GenerateSARIF(engineFindings, toolVersion)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "sarif generation failed: "+err.Error(), "FORMAT_ERROR")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = synapse.WriteSARIF(report, w)

	case "csv":
		engineFindings := apiToEngineFindings(resp.Findings)
		w.Header().Set("Content-Type", "text/csv")
		w.WriteHeader(http.StatusOK)
		_ = synapse.WriteCSV(engineFindings, w)

	case "junit":
		engineFindings := apiToEngineFindings(resp.Findings)
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		_ = synapse.WriteJUnit(engineFindings, elapsed, w)

	default:
		writeJSON(w, http.StatusOK, resp)
	}
}

func apiToEngineFindings(findings []Finding) []engine.Finding {
	out := make([]engine.Finding, len(findings))
	for i, f := range findings {
		out[i] = engine.Finding{
			File:         f.File,
			Line:         f.Line,
			Detector:     f.Detector,
			Confidence:   f.Confidence,
			Provenance:   f.Provenance,
			MatchedValue: f.MatchedValue,
			ReasoningStr: f.Description,
		}
	}
	return out
}

// =========================================================================
// Conversion helpers
// =========================================================================

func redactValue(v string) string {
	if len(v) > 16 {
		return v[:6] + "..." + v[len(v)-4:]
	}
	if len(v) > 8 {
		return v[:4] + "****"
	}
	return "****"
}

func severityFromConfidence(conf float64) string {
	switch {
	case conf >= 0.9:
		return "critical"
	case conf >= 0.7:
		return "high"
	case conf >= 0.5:
		return "medium"
	case conf >= 0.3:
		return "low"
	default:
		return "info"
	}
}

func engineFindingToAPI(ef engine.Finding) Finding {
	return Finding{
		File:         ef.File,
		Line:         ef.Line,
		Detector:     ef.Detector,
		Confidence:   ef.Confidence,
		Provenance:   ef.Provenance,
		MatchedValue: ef.MatchedValue,
		Description:  ef.ReasoningStr,
		Severity:     severityFromConfidence(ef.Confidence),
		Fingerprint:  synapse.Fingerprint(ef.File, ef.Line, ef.Detector, ef.MatchedValue),
	}
}

func orchestratorResultsToFindings(results []synapse.AgentTeamResult) []Finding {
	findings := make([]Finding, 0, len(results))
	for _, r := range results {
		f := Finding{
			File:         r.File,
			Line:         r.Line,
			Detector:     "synapse:" + strings.ToLower(r.Finding.Provenance),
			Confidence:   r.Finding.FinalConfidence,
			Provenance:   r.Finding.Provenance,
			MatchedValue: redactValue(r.RawSecret),
			Description:  evidenceToDescription(r.Finding.Evidence),
			Severity:     severityFromConfidence(r.Finding.FinalConfidence),
			Fingerprint:  synapse.Fingerprint(r.File, r.Line, "synapse:"+strings.ToLower(r.Finding.Provenance), redactValue(r.RawSecret)),
		}
		findings = append(findings, f)
	}
	return findings
}

func evidenceToDescription(evidence []synapse.EvidenceItem) string {
	parts := make([]string, 0, len(evidence))
	for _, e := range evidence {
		parts = append(parts, e.Description)
	}
	return strings.Join(parts, " | ")
}

func defaultThreshold(t float64) float64 {
	if t <= 0 {
		return 0.7
	}
	return t
}

func decodeJSONBody(r *http.Request, dst interface{}) error {
	if r.Body == nil {
		return fmt.Errorf("empty request body")
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

// =========================================================================
// Scan Handlers
// =========================================================================

// ScanContent handles POST /api/v1/scan/content.
func (h *Handlers) ScanContent(w http.ResponseWriter, r *http.Request) {
	var req ScanContentRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error(), "BAD_REQUEST")
		return
	}
	if req.Content == "" {
		writeError(w, http.StatusBadRequest, "content is required", "BAD_REQUEST")
		return
	}

	threshold := defaultThreshold(req.Threshold)
	scanID := generateScanID()
	start := time.Now()

	ctx, cancel := context.WithTimeout(r.Context(), defaultTimeout)
	defer cancel()

	fileName := req.FileName
	if fileName == "" {
		fileName = "stdin.txt"
	}

	tmpFile, err := os.CreateTemp("", "morphex-scan-*.txt")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create temp file", "INTERNAL_ERROR")
		return
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if _, err := tmpFile.WriteString(req.Content); err != nil {
		tmpFile.Close()
		writeError(w, http.StatusInternalServerError, "failed to write temp file", "INTERNAL_ERROR")
		return
	}
	tmpFile.Close()

	var findings []Finding

	if req.Deep {
		results, err := h.orchestrator.ScanFile(ctx, tmpPath)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "scan failed: "+err.Error(), "SCAN_ERROR")
			return
		}
		findings = orchestratorResultsToFindings(results)
	} else {
		engineFindings := engine.ScanFile(tmpPath, threshold)
		findings = make([]Finding, 0, len(engineFindings))
		for _, ef := range engineFindings {
			findings = append(findings, engineFindingToAPI(ef))
		}
	}

	elapsed := time.Since(start)
	resp := ScanResponse{
		Tool:          toolName,
		Version:       toolVersion,
		ScanID:        scanID,
		Status:        "completed",
		TotalFindings: len(findings),
		ScanTime:      elapsed.String(),
		Findings:      findings,
	}

	writeScanResponse(w, r, resp, elapsed)
}

// ScanFile handles POST /api/v1/scan/file (multipart upload).
func (h *Handlers) ScanFile(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		writeError(w, http.StatusBadRequest, "invalid multipart form: "+err.Error(), "BAD_REQUEST")
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "missing file field: "+err.Error(), "BAD_REQUEST")
		return
	}
	defer file.Close()

	ext := filepath.Ext(header.Filename)
	tmpFile, err := os.CreateTemp("", "morphex-upload-*"+ext)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create temp file", "INTERNAL_ERROR")
		return
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if _, err := io.Copy(tmpFile, file); err != nil {
		tmpFile.Close()
		writeError(w, http.StatusInternalServerError, "failed to save upload", "INTERNAL_ERROR")
		return
	}
	tmpFile.Close()

	thresholdStr := r.FormValue("threshold")
	threshold := 0.7
	if thresholdStr != "" {
		fmt.Sscanf(thresholdStr, "%f", &threshold)
	}

	deep := r.FormValue("deep") == "true"
	scanID := generateScanID()
	start := time.Now()

	ctx, cancel := context.WithTimeout(r.Context(), defaultTimeout)
	defer cancel()

	var findings []Finding

	if deep {
		results, err := h.orchestrator.ScanFile(ctx, tmpPath)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "scan failed: "+err.Error(), "SCAN_ERROR")
			return
		}
		findings = orchestratorResultsToFindings(results)
	} else {
		engineFindings := engine.ScanFile(tmpPath, threshold)
		findings = make([]Finding, 0, len(engineFindings))
		for _, ef := range engineFindings {
			findings = append(findings, engineFindingToAPI(ef))
		}
	}

	_ = ctx

	elapsed := time.Since(start)
	resp := ScanResponse{
		Tool:          toolName,
		Version:       toolVersion,
		ScanID:        scanID,
		Status:        "completed",
		TotalFindings: len(findings),
		ScanTime:      elapsed.String(),
		Findings:      findings,
	}

	writeScanResponse(w, r, resp, elapsed)
}

// ScanDirectory handles POST /api/v1/scan/directory.
func (h *Handlers) ScanDirectory(w http.ResponseWriter, r *http.Request) {
	var req ScanDirectoryRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error(), "BAD_REQUEST")
		return
	}
	if req.Path == "" {
		writeError(w, http.StatusBadRequest, "path is required", "BAD_REQUEST")
		return
	}

	info, err := os.Stat(req.Path)
	if err != nil || !info.IsDir() {
		writeError(w, http.StatusBadRequest, "path is not a valid directory", "BAD_REQUEST")
		return
	}

	threshold := defaultThreshold(req.Threshold)
	workers := req.Workers
	if workers <= 0 {
		workers = runtime.NumCPU()
	}

	scanID := generateScanID()
	start := time.Now()

	ctx, cancel := context.WithTimeout(r.Context(), defaultTimeout)
	defer cancel()

	var findings []Finding

	if req.Deep {
		results, err := h.orchestrator.ScanDirectory(ctx, req.Path, workers)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "scan failed: "+err.Error(), "SCAN_ERROR")
			return
		}
		findings = orchestratorResultsToFindings(results)
	} else {
		engineFindings := engine.ScanDirectory(req.Path, threshold, workers)
		findings = make([]Finding, 0, len(engineFindings))
		for _, ef := range engineFindings {
			findings = append(findings, engineFindingToAPI(ef))
		}
	}

	elapsed := time.Since(start)
	resp := ScanResponse{
		Tool:          toolName,
		Version:       toolVersion,
		ScanID:        scanID,
		Status:        "completed",
		TotalFindings: len(findings),
		ScanTime:      elapsed.String(),
		Findings:      findings,
	}

	writeScanResponse(w, r, resp, elapsed)
}

// ScanGit handles POST /api/v1/scan/git.
func (h *Handlers) ScanGit(w http.ResponseWriter, r *http.Request) {
	var req ScanGitRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error(), "BAD_REQUEST")
		return
	}
	if req.RepoPath == "" {
		writeError(w, http.StatusBadRequest, "repo_path is required", "BAD_REQUEST")
		return
	}

	threshold := defaultThreshold(req.Threshold)
	workers := req.Workers
	if workers <= 0 {
		workers = runtime.NumCPU()
	}

	scanID := generateScanID()
	start := time.Now()

	ctx, cancel := context.WithTimeout(r.Context(), defaultTimeout)
	defer cancel()

	_ = ctx

	opts := engine.GitScanOptions{
		MaxCommits: req.MaxCommits,
		Since:      req.Since,
		Branch:     req.Branch,
		Workers:    workers,
	}

	gitFindings, err := engine.ScanGitRepo(req.RepoPath, threshold, opts)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "git scan failed: "+err.Error(), "SCAN_ERROR")
		return
	}

	findings := make([]Finding, 0, len(gitFindings))
	for _, gf := range gitFindings {
		f := engineFindingToAPI(gf.Finding)
		findings = append(findings, f)
	}

	elapsed := time.Since(start)
	resp := ScanResponse{
		Tool:          toolName,
		Version:       toolVersion,
		ScanID:        scanID,
		Status:        "completed",
		TotalFindings: len(findings),
		ScanTime:      elapsed.String(),
		Findings:      findings,
	}

	writeScanResponse(w, r, resp, elapsed)
}

// =========================================================================
// Analysis Handlers
// =========================================================================

// AnalyzeClassify handles POST /api/v1/analyze/classify.
func (h *Handlers) AnalyzeClassify(w http.ResponseWriter, r *http.Request) {
	var req ClassifyRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error(), "BAD_REQUEST")
		return
	}
	if req.Value == "" {
		writeError(w, http.StatusBadRequest, "value is required", "BAD_REQUEST")
		return
	}

	tok := engine.Token{
		Value:       req.Value,
		VarName:     req.VarName,
		FilePath:    req.FilePath,
		Line:        req.Line,
		LineContent: req.LineContent,
	}

	cls := engine.ClassifyToken(tok)

	var morphology, syntacticRole string
	signals := make([]SignalDetail, 0, len(cls.Signals))
	for _, s := range cls.Signals {
		sd := SignalDetail{
			Name:       s.Name,
			Value:      s.Value,
			Confidence: s.Confidence,
			Reasoning:  s.ReasonText,
		}
		signals = append(signals, sd)
		if s.Name == "morphology" {
			morphology = s.Value
		}
		if s.Name == "syntactic_role" {
			syntacticRole = s.Value
		}
	}

	resp := ClassifyResponse{
		Provenance:    string(cls.Prov),
		Confidence:    cls.Conf,
		Morphology:    morphology,
		SyntacticRole: syntacticRole,
		Signals:       signals,
		Reasoning:     cls.Reasoning(),
	}

	writeJSON(w, http.StatusOK, resp)
}

// AnalyzeExtract handles POST /api/v1/analyze/extract.
func (h *Handlers) AnalyzeExtract(w http.ResponseWriter, r *http.Request) {
	var req ExtractRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error(), "BAD_REQUEST")
		return
	}
	if req.Content == "" {
		writeError(w, http.StatusBadRequest, "content is required", "BAD_REQUEST")
		return
	}

	fileName := req.FileName
	if fileName == "" {
		fileName = "stdin.txt"
	}

	tokens := engine.ExtractTokens(fileName, req.Content)
	if req.Deep {
		tokens = append(tokens, engine.AdvancedExtractTokens(fileName, req.Content)...)
	}

	candidates := make([]TokenCandidate, 0, len(tokens))
	for _, tok := range tokens {
		candidates = append(candidates, TokenCandidate{
			Value:       redactValue(tok.Value),
			VarName:     tok.VarName,
			Line:        tok.Line,
			LineContent: tok.LineContent,
		})
	}

	resp := ExtractResponse{
		FileName:   fileName,
		Total:      len(candidates),
		Candidates: candidates,
	}

	writeJSON(w, http.StatusOK, resp)
}

// AnalyzeVerify handles POST /api/v1/analyze/verify.
func (h *Handlers) AnalyzeVerify(w http.ResponseWriter, r *http.Request) {
	var req VerifyRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error(), "BAD_REQUEST")
		return
	}
	if req.Value == "" {
		writeError(w, http.StatusBadRequest, "value is required", "BAD_REQUEST")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	tok := engine.Token{
		Value:    req.Value,
		VarName:  req.VarName,
		FilePath: req.FilePath,
	}
	cls := engine.ClassifyToken(tok)

	ctxReq := synapse.ContextRequest{
		RawSecret:  req.Value,
		FilePath:   req.FilePath,
		VarName:    req.VarName,
	}

	ctxAgent := synapse.NewContextAgent(synapse.ContextAgentConfig{
		AlertThreshold: 0.3,
		SuppressBelow:  0.1,
	})

	ctxResult, err := ctxAgent.Analyze(ctx, ctxReq)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "analysis failed: "+err.Error(), "ANALYSIS_ERROR")
		return
	}

	_ = cls

	resp := VerifyResponse{
		Status:     string(ctxResult.Verdict),
		Verified:   ctxResult.Verdict == synapse.VerdictLikelyTP,
		Confidence: ctxResult.FinalConfidence,
		Ecosystem:  req.Ecosystem,
	}

	writeJSON(w, http.StatusOK, resp)
}

// =========================================================================
// Policy Handlers
// =========================================================================

// PolicyValidate handles POST /api/v1/policy/validate.
func (h *Handlers) PolicyValidate(w http.ResponseWriter, r *http.Request) {
	var req PolicyValidateRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error(), "BAD_REQUEST")
		return
	}

	var policy synapse.ScanPolicy
	if err := json.Unmarshal(req.Policy, &policy); err != nil {
		writeJSON(w, http.StatusOK, PolicyValidateResponse{
			Valid:  false,
			Errors: []string{"invalid JSON: " + err.Error()},
		})
		return
	}

	if err := policy.Validate(); err != nil {
		writeJSON(w, http.StatusOK, PolicyValidateResponse{
			Valid:  false,
			Errors: []string{err.Error()},
		})
		return
	}

	writeJSON(w, http.StatusOK, PolicyValidateResponse{Valid: true})
}

// PolicyApply handles POST /api/v1/policy/apply.
func (h *Handlers) PolicyApply(w http.ResponseWriter, r *http.Request) {
	var req PolicyApplyRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error(), "BAD_REQUEST")
		return
	}

	var policy synapse.ScanPolicy
	if err := json.Unmarshal(req.Policy, &policy); err != nil {
		writeError(w, http.StatusBadRequest, "invalid policy JSON: "+err.Error(), "BAD_REQUEST")
		return
	}
	if err := policy.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid policy: "+err.Error(), "BAD_REQUEST")
		return
	}

	original := len(req.Findings)
	filtered := make([]Finding, 0, original)
	for _, f := range req.Findings {
		ef := engine.Finding{
			File:         f.File,
			Line:         f.Line,
			Detector:     f.Detector,
			Confidence:   f.Confidence,
			Provenance:   f.Provenance,
			MatchedValue: f.MatchedValue,
		}
		if policy.ShouldReport(ef) {
			sev := policy.SeverityFor(ef)
			f.Severity = sev
			filtered = append(filtered, f)
		}
	}

	writeJSON(w, http.StatusOK, PolicyApplyResponse{
		Original: original,
		Filtered: len(filtered),
		Findings: filtered,
	})
}

// =========================================================================
// Baseline Handlers
// =========================================================================

// BaselineCreate handles POST /api/v1/baseline/create.
func (h *Handlers) BaselineCreate(w http.ResponseWriter, r *http.Request) {
	var req BaselineCreateRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error(), "BAD_REQUEST")
		return
	}

	entries := make([]BaselineEntry, 0, len(req.Findings))
	for _, f := range req.Findings {
		fp := f.Fingerprint
		if fp == "" {
			fp = synapse.Fingerprint(f.File, f.Line, f.Detector, f.MatchedValue)
		}
		entries = append(entries, BaselineEntry{
			Fingerprint: fp,
			File:        f.File,
			Line:        f.Line,
			Detector:    f.Detector,
		})
	}

	writeJSON(w, http.StatusOK, BaselineCreateResponse{
		Version:   "1.0",
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		Total:     len(entries),
		Findings:  entries,
	})
}

// BaselineApply handles POST /api/v1/baseline/apply.
func (h *Handlers) BaselineApply(w http.ResponseWriter, r *http.Request) {
	var req BaselineApplyRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error(), "BAD_REQUEST")
		return
	}

	index := make(map[string]bool, len(req.Baseline))
	for _, b := range req.Baseline {
		index[b.Fingerprint] = true
	}

	original := len(req.Findings)
	remaining := make([]Finding, 0, original)
	for _, f := range req.Findings {
		fp := f.Fingerprint
		if fp == "" {
			fp = synapse.Fingerprint(f.File, f.Line, f.Detector, f.MatchedValue)
		}
		if !index[fp] {
			remaining = append(remaining, f)
		}
	}

	writeJSON(w, http.StatusOK, BaselineApplyResponse{
		Original:   original,
		Suppressed: original - len(remaining),
		Remaining:  len(remaining),
		Findings:   remaining,
	})
}

// BaselineDiff handles POST /api/v1/baseline/diff.
func (h *Handlers) BaselineDiff(w http.ResponseWriter, r *http.Request) {
	var req BaselineDiffRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error(), "BAD_REQUEST")
		return
	}

	index := make(map[string]bool, len(req.Baseline))
	for _, b := range req.Baseline {
		index[b.Fingerprint] = true
	}

	newFindings := make([]Finding, 0)
	for _, f := range req.Findings {
		fp := f.Fingerprint
		if fp == "" {
			fp = synapse.Fingerprint(f.File, f.Line, f.Detector, f.MatchedValue)
		}
		if !index[fp] {
			newFindings = append(newFindings, f)
		}
	}

	writeJSON(w, http.StatusOK, BaselineDiffResponse{
		Total:       len(req.Findings),
		NewFindings: len(newFindings),
		Findings:    newFindings,
	})
}

// =========================================================================
// Operations Handlers
// =========================================================================

// Health handles GET /api/v1/health.
func (h *Handlers) Health(w http.ResponseWriter, r *http.Request) {
	status := h.health.RunChecks()

	checks := make(map[string]interface{}, len(status.Checks))
	for name, check := range status.Checks {
		checks[name] = map[string]interface{}{
			"status":  check.Status,
			"message": check.Message,
		}
	}

	resp := HealthResponse{
		Status:  status.Status,
		Version: toolVersion,
		Uptime:  time.Since(h.startTime).String(),
		Checks:  checks,
	}

	writeJSON(w, http.StatusOK, resp)
}

// Metrics handles GET /api/v1/metrics.
func (h *Handlers) Metrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, h.metrics.PrometheusExport())
}

// Version handles GET /api/v1/version.
func (h *Handlers) Version(w http.ResponseWriter, r *http.Request) {
	features := []string{
		"synapse_v2",
		"avat_context_agent",
		"git_history_scan",
		"sarif_output",
		"csv_output",
		"junit_output",
		"policy_engine",
		"baseline_management",
	}

	resp := VersionResponse{
		Tool:     toolName,
		Version:  toolVersion,
		Engine:   engineVersion,
		Go:       runtime.Version(),
		Features: features,
	}

	writeJSON(w, http.StatusOK, resp)
}

// Ensure bytes import is used.
var _ = bytes.NewReader
