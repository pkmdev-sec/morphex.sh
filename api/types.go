package api

import "encoding/json"

// ---------------------------------------------------------------------------
// Scan Requests
// ---------------------------------------------------------------------------

// ScanContentRequest is the body for POST /api/v1/scan/content.
type ScanContentRequest struct {
	Content    string           `json:"content"`
	FileName   string           `json:"file_name,omitempty"`
	Threshold  float64          `json:"threshold,omitempty"`
	Deep       bool             `json:"deep,omitempty"`
	PolicyJSON *json.RawMessage `json:"policy,omitempty"`
}

// ScanDirectoryRequest is the body for POST /api/v1/scan/directory.
type ScanDirectoryRequest struct {
	Path      string   `json:"path"`
	Threshold float64  `json:"threshold,omitempty"`
	Workers   int      `json:"workers,omitempty"`
	Deep      bool     `json:"deep,omitempty"`
	Recursive bool     `json:"recursive,omitempty"`
	Include   []string `json:"include,omitempty"`
	Exclude   []string `json:"exclude,omitempty"`
}

// ScanGitRequest is the body for POST /api/v1/scan/git.
type ScanGitRequest struct {
	RepoPath   string  `json:"repo_path"`
	Branch     string  `json:"branch,omitempty"`
	Since      string  `json:"since,omitempty"`
	MaxCommits int     `json:"max_commits,omitempty"`
	Threshold  float64 `json:"threshold,omitempty"`
	Workers    int     `json:"workers,omitempty"`
}

// ---------------------------------------------------------------------------
// Scan Response
// ---------------------------------------------------------------------------

// ScanResponse is the envelope returned by every scan endpoint.
type ScanResponse struct {
	Tool          string    `json:"tool"`
	Version       string    `json:"version"`
	ScanID        string    `json:"scan_id"`
	Status        string    `json:"status"`
	TotalFindings int       `json:"total_findings"`
	ScanTime      string    `json:"scan_time"`
	Findings      []Finding `json:"findings"`
	Error         string    `json:"error,omitempty"`
}

// Finding is an API-level finding (values are always redacted).
type Finding struct {
	File         string  `json:"file"`
	Line         int     `json:"line"`
	Detector     string  `json:"detector"`
	Confidence   float64 `json:"confidence"`
	Provenance   string  `json:"provenance"`
	MatchedValue string  `json:"matched_value"`
	Description  string  `json:"description"`
	Severity     string  `json:"severity"`
	Fingerprint  string  `json:"fingerprint"`
}

// ---------------------------------------------------------------------------
// Analysis Requests / Responses
// ---------------------------------------------------------------------------

// ClassifyRequest is the body for POST /api/v1/analyze/classify.
type ClassifyRequest struct {
	Value       string `json:"value"`
	VarName     string `json:"var_name"`
	FilePath    string `json:"file_path,omitempty"`
	Line        int    `json:"line,omitempty"`
	LineContent string `json:"line_content,omitempty"`
}

// SignalDetail captures a single SYNAPSE classification signal.
type SignalDetail struct {
	Name       string  `json:"name"`
	Value      string  `json:"value"`
	Confidence float64 `json:"confidence"`
	Reasoning  string  `json:"reasoning"`
}

// ClassifyResponse is the response for POST /api/v1/analyze/classify.
type ClassifyResponse struct {
	Provenance    string         `json:"provenance"`
	Confidence    float64        `json:"confidence"`
	Morphology    string         `json:"morphology"`
	SyntacticRole string         `json:"syntactic_role"`
	Signals       []SignalDetail `json:"signals"`
	Reasoning     string         `json:"reasoning"`
}

// ExtractRequest is the body for POST /api/v1/analyze/extract.
type ExtractRequest struct {
	Content  string `json:"content"`
	FileName string `json:"file_name,omitempty"`
	Deep     bool   `json:"deep,omitempty"`
}

// TokenCandidate is a single extracted token returned by the extract endpoint.
type TokenCandidate struct {
	Value       string `json:"value"`
	VarName     string `json:"var_name"`
	Line        int    `json:"line"`
	LineContent string `json:"line_content"`
}

// ExtractResponse is the response for POST /api/v1/analyze/extract.
type ExtractResponse struct {
	FileName   string           `json:"file_name"`
	Total      int              `json:"total"`
	Candidates []TokenCandidate `json:"candidates"`
}

// VerifyRequest is the body for POST /api/v1/analyze/verify.
type VerifyRequest struct {
	Value     string `json:"value"`
	Ecosystem string `json:"ecosystem,omitempty"`
	VarName   string `json:"var_name,omitempty"`
	FilePath  string `json:"file_path,omitempty"`
}

// VerifyResponse is the response for POST /api/v1/analyze/verify.
type VerifyResponse struct {
	Status     string  `json:"status"`
	Verified   bool    `json:"verified"`
	Confidence float64 `json:"confidence"`
	Ecosystem  string  `json:"ecosystem"`
	Error      string  `json:"error,omitempty"`
}

// ---------------------------------------------------------------------------
// Policy Requests / Responses
// ---------------------------------------------------------------------------

// PolicyValidateRequest is the body for POST /api/v1/policy/validate.
type PolicyValidateRequest struct {
	Policy json.RawMessage `json:"policy"`
}

// PolicyValidateResponse is the response for POST /api/v1/policy/validate.
type PolicyValidateResponse struct {
	Valid  bool     `json:"valid"`
	Errors []string `json:"errors,omitempty"`
}

// PolicyApplyRequest is the body for POST /api/v1/policy/apply.
type PolicyApplyRequest struct {
	Policy   json.RawMessage `json:"policy"`
	Findings []Finding       `json:"findings"`
}

// PolicyApplyResponse is the response for POST /api/v1/policy/apply.
type PolicyApplyResponse struct {
	Original int       `json:"original"`
	Filtered int       `json:"filtered"`
	Findings []Finding `json:"findings"`
}

// ---------------------------------------------------------------------------
// Baseline Requests / Responses
// ---------------------------------------------------------------------------

// BaselineCreateRequest is the body for POST /api/v1/baseline/create.
type BaselineCreateRequest struct {
	Findings []Finding `json:"findings"`
}

// BaselineEntry is a single fingerprinted finding.
type BaselineEntry struct {
	Fingerprint string `json:"fingerprint"`
	File        string `json:"file"`
	Line        int    `json:"line"`
	Detector    string `json:"detector"`
}

// BaselineCreateResponse is the response for POST /api/v1/baseline/create.
type BaselineCreateResponse struct {
	Version   string          `json:"version"`
	CreatedAt string          `json:"created_at"`
	Total     int             `json:"total"`
	Findings  []BaselineEntry `json:"findings"`
}

// BaselineApplyRequest is the body for POST /api/v1/baseline/apply.
type BaselineApplyRequest struct {
	Baseline []BaselineEntry `json:"baseline"`
	Findings []Finding       `json:"findings"`
}

// BaselineApplyResponse is the response for POST /api/v1/baseline/apply.
type BaselineApplyResponse struct {
	Original   int       `json:"original"`
	Suppressed int       `json:"suppressed"`
	Remaining  int       `json:"remaining"`
	Findings   []Finding `json:"findings"`
}

// BaselineDiffRequest is the body for POST /api/v1/baseline/diff.
type BaselineDiffRequest struct {
	Baseline []BaselineEntry `json:"baseline"`
	Findings []Finding       `json:"findings"`
}

// BaselineDiffResponse is the response for POST /api/v1/baseline/diff.
type BaselineDiffResponse struct {
	Total       int       `json:"total"`
	NewFindings int       `json:"new_findings"`
	Findings    []Finding `json:"findings"`
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

// HealthResponse is returned by GET /api/v1/health.
type HealthResponse struct {
	Status  string                 `json:"status"`
	Version string                 `json:"version"`
	Uptime  string                 `json:"uptime"`
	Checks  map[string]interface{} `json:"checks"`
}

// VersionResponse is returned by GET /api/v1/version.
type VersionResponse struct {
	Tool     string   `json:"tool"`
	Version  string   `json:"version"`
	Engine   string   `json:"engine"`
	Go       string   `json:"go_version"`
	Features []string `json:"features"`
}

// ErrorResponse is the standard error envelope.
type ErrorResponse struct {
	Error string `json:"error"`
	Code  string `json:"code"`
}
