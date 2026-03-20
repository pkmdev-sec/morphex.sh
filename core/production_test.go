package synapse

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	engine "github.com/synapse/engine"
)

// =========================================================================
// SARIF Tests
// =========================================================================

func TestGenerateSARIF_EmptyFindings(t *testing.T) {
	report, err := GenerateSARIF(nil, "1.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.Version != "2.1.0" {
		t.Errorf("expected SARIF version 2.1.0, got %s", report.Version)
	}
	if len(report.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(report.Runs))
	}
	if len(report.Runs[0].Results) != 0 {
		t.Errorf("expected 0 results, got %d", len(report.Runs[0].Results))
	}
	if report.Runs[0].Tool.Driver.Version != "1.0.0" {
		t.Errorf("expected tool version 1.0.0, got %s", report.Runs[0].Tool.Driver.Version)
	}
}

func TestGenerateSARIF_DefaultVersion(t *testing.T) {
	report, err := GenerateSARIF(nil, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.Runs[0].Tool.Driver.Version != "0.0.0" {
		t.Errorf("expected default version 0.0.0, got %s", report.Runs[0].Tool.Driver.Version)
	}
}

func TestGenerateSARIF_WithFindings(t *testing.T) {
	findings := []engine.Finding{
		{
			File:         "/app/config.py",
			Line:         42,
			MatchedValue: "AKIA...9KZ",
			Detector:     "synapse:auth_credential",
			Confidence:   0.95,
			Provenance:   "AUTH_CREDENTIAL",
			ReasoningStr: "AWS access key found in config",
			Signals: []map[string]interface{}{
				{"name": "morphology", "value": "prefixed_random"},
			},
		},
		{
			File:         "/app/utils.py",
			Line:         10,
			MatchedValue: "****",
			Detector:     "synapse:uncertain",
			Confidence:   0.45,
			Provenance:   "UNCERTAIN",
			ReasoningStr: "Uncertain token in utility code",
		},
	}

	report, err := GenerateSARIF(findings, "2.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(report.Runs[0].Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(report.Runs[0].Results))
	}

	r0 := report.Runs[0].Results[0]
	if r0.Level != "error" {
		t.Errorf("expected level error for 0.95 confidence, got %s", r0.Level)
	}
	if r0.Kind != "open" {
		t.Errorf("expected kind open for AUTH_CREDENTIAL, got %s", r0.Kind)
	}
	if r0.RuleID != "synapse:auth_credential" {
		t.Errorf("expected ruleId synapse:auth_credential, got %s", r0.RuleID)
	}
	if len(r0.Locations) != 1 {
		t.Fatalf("expected 1 location, got %d", len(r0.Locations))
	}
	if r0.Locations[0].PhysicalLocation.Region == nil {
		t.Fatal("expected region to be set")
	}
	if r0.Locations[0].PhysicalLocation.Region.StartLine != 42 {
		t.Errorf("expected line 42, got %d", r0.Locations[0].PhysicalLocation.Region.StartLine)
	}

	r1 := report.Runs[0].Results[1]
	if r1.Level != "note" {
		t.Errorf("expected level note for 0.45 confidence, got %s", r1.Level)
	}
	if r1.Kind != "review" {
		t.Errorf("expected kind review for UNCERTAIN, got %s", r1.Kind)
	}
}

func TestGenerateSARIF_RuleDedup(t *testing.T) {
	findings := []engine.Finding{
		{File: "a.py", Line: 1, Detector: "synapse:auth_credential", Confidence: 0.9, Provenance: "AUTH_CREDENTIAL"},
		{File: "b.py", Line: 2, Detector: "synapse:auth_credential", Confidence: 0.85, Provenance: "AUTH_CREDENTIAL"},
		{File: "c.py", Line: 3, Detector: "synapse:uncertain", Confidence: 0.5, Provenance: "UNCERTAIN"},
	}

	report, err := GenerateSARIF(findings, "1.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(report.Runs[0].Tool.Driver.Rules) != 2 {
		t.Errorf("expected 2 unique rules, got %d", len(report.Runs[0].Tool.Driver.Rules))
	}
	if len(report.Runs[0].Results) != 3 {
		t.Errorf("expected 3 results, got %d", len(report.Runs[0].Results))
	}

	if report.Runs[0].Results[0].RuleIndex != report.Runs[0].Results[1].RuleIndex {
		t.Error("first two results should share the same ruleIndex")
	}
}

func TestWriteSARIF(t *testing.T) {
	report, _ := GenerateSARIF([]engine.Finding{
		{File: "x.go", Line: 1, Detector: "synapse:auth_credential", Confidence: 0.9, Provenance: "AUTH_CREDENTIAL"},
	}, "1.0.0")

	var buf bytes.Buffer
	if err := WriteSARIF(report, &buf); err != nil {
		t.Fatalf("WriteSARIF failed: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	if parsed["version"] != "2.1.0" {
		t.Errorf("expected version 2.1.0 in output, got %v", parsed["version"])
	}
}

func TestConfidenceToLevel(t *testing.T) {
	tests := []struct {
		conf float64
		want string
	}{
		{0.95, "error"},
		{0.80, "error"},
		{0.79, "warning"},
		{0.50, "warning"},
		{0.49, "note"},
		{0.0, "note"},
	}
	for _, tc := range tests {
		got := confidenceToLevel(tc.conf)
		if got != tc.want {
			t.Errorf("confidenceToLevel(%v) = %q, want %q", tc.conf, got, tc.want)
		}
	}
}

func TestProvenanceToKind(t *testing.T) {
	tests := []struct {
		prov string
		want string
	}{
		{"AUTH_CREDENTIAL", "open"},
		{"UNCERTAIN", "review"},
		{"DOC_EXAMPLE", "pass"},
		{"BUILD_GENERATED", "pass"},
	}
	for _, tc := range tests {
		got := provenanceToKind(tc.prov)
		if got != tc.want {
			t.Errorf("provenanceToKind(%q) = %q, want %q", tc.prov, got, tc.want)
		}
	}
}

// =========================================================================
// Metrics Tests
// =========================================================================

func TestMetricsCollector_BasicRecording(t *testing.T) {
	mc := NewMetricsCollector()

	mc.RecordFileScanned()
	mc.RecordFileScanned()
	mc.RecordFileSkipped()
	mc.RecordTokensExtracted(5)
	mc.RecordFinding("AUTH_CREDENTIAL", "critical")
	mc.RecordFinding("UNCERTAIN", "medium")
	mc.RecordBytesProcessed(1024)
	mc.RecordError()
	mc.RecordTokenExtractionDuration(10 * time.Millisecond)
	mc.RecordClassificationDuration(5 * time.Millisecond)
	mc.RecordMLRefinementDuration(3 * time.Millisecond)
	mc.FinishScan()

	snap := mc.Snapshot()

	if snap.FilesScanned != 2 {
		t.Errorf("FilesScanned = %d, want 2", snap.FilesScanned)
	}
	if snap.FilesSkipped != 1 {
		t.Errorf("FilesSkipped = %d, want 1", snap.FilesSkipped)
	}
	if snap.TokensExtracted != 5 {
		t.Errorf("TokensExtracted = %d, want 5", snap.TokensExtracted)
	}
	if snap.FindingsTotal != 2 {
		t.Errorf("FindingsTotal = %d, want 2", snap.FindingsTotal)
	}
	if snap.FindingsByProvenance["AUTH_CREDENTIAL"] != 1 {
		t.Errorf("FindingsByProvenance[AUTH_CREDENTIAL] = %d, want 1", snap.FindingsByProvenance["AUTH_CREDENTIAL"])
	}
	if snap.FindingsBySeverity["critical"] != 1 {
		t.Errorf("FindingsBySeverity[critical] = %d, want 1", snap.FindingsBySeverity["critical"])
	}
	if snap.BytesProcessed != 1024 {
		t.Errorf("BytesProcessed = %d, want 1024", snap.BytesProcessed)
	}
	if snap.ErrorCount != 1 {
		t.Errorf("ErrorCount = %d, want 1", snap.ErrorCount)
	}
	if snap.ScanDuration <= 0 {
		t.Error("ScanDuration should be positive")
	}
}

func TestMetricsCollector_ThreadSafety(t *testing.T) {
	mc := NewMetricsCollector()
	var wg sync.WaitGroup
	goroutines := 100
	iterations := 1000

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				mc.RecordFileScanned()
				mc.RecordFinding("AUTH_CREDENTIAL", "high")
				mc.RecordBytesProcessed(10)
				mc.RecordTokensExtracted(1)
				mc.RecordTokenExtractionDuration(time.Microsecond)
				_ = mc.Snapshot()
			}
		}()
	}
	wg.Wait()

	snap := mc.Snapshot()
	expected := goroutines * iterations

	if snap.FilesScanned != expected {
		t.Errorf("FilesScanned = %d, want %d", snap.FilesScanned, expected)
	}
	if snap.FindingsTotal != expected {
		t.Errorf("FindingsTotal = %d, want %d", snap.FindingsTotal, expected)
	}
	if snap.BytesProcessed != int64(expected*10) {
		t.Errorf("BytesProcessed = %d, want %d", snap.BytesProcessed, expected*10)
	}
}

func TestMetricsCollector_Reset(t *testing.T) {
	mc := NewMetricsCollector()
	mc.RecordFileScanned()
	mc.RecordFinding("AUTH_CREDENTIAL", "critical")
	mc.RecordBytesProcessed(512)
	mc.FinishScan()

	mc.Reset()
	snap := mc.Snapshot()

	if snap.FilesScanned != 0 {
		t.Errorf("FilesScanned after reset = %d, want 0", snap.FilesScanned)
	}
	if snap.FindingsTotal != 0 {
		t.Errorf("FindingsTotal after reset = %d, want 0", snap.FindingsTotal)
	}
	if snap.BytesProcessed != 0 {
		t.Errorf("BytesProcessed after reset = %d, want 0", snap.BytesProcessed)
	}
	if len(snap.FindingsByProvenance) != 0 {
		t.Errorf("FindingsByProvenance should be empty after reset")
	}
}

func TestMetricsCollector_PrometheusExport(t *testing.T) {
	mc := NewMetricsCollector()
	mc.RecordFileScanned()
	mc.RecordFinding("AUTH_CREDENTIAL", "critical")
	mc.FinishScan()

	output := mc.PrometheusExport()

	if !strings.Contains(output, "morphex_scan_files_scanned_total") {
		t.Error("prometheus output missing files_scanned metric")
	}
	if !strings.Contains(output, "morphex_scan_findings_total") {
		t.Error("prometheus output missing findings_total metric")
	}
	if !strings.Contains(output, "morphex_scan_findings_by_provenance") {
		t.Error("prometheus output missing findings_by_provenance metric")
	}
	if !strings.Contains(output, "# HELP") {
		t.Error("prometheus output missing HELP lines")
	}
	if !strings.Contains(output, "# TYPE") {
		t.Error("prometheus output missing TYPE lines")
	}
}

func TestMetricsCollector_SnapshotIsolation(t *testing.T) {
	mc := NewMetricsCollector()
	mc.RecordFinding("AUTH_CREDENTIAL", "high")

	snap := mc.Snapshot()
	mc.RecordFinding("UNCERTAIN", "medium")

	if snap.FindingsTotal != 1 {
		t.Errorf("snapshot should be isolated; got FindingsTotal=%d, want 1", snap.FindingsTotal)
	}
	if _, ok := snap.FindingsByProvenance["UNCERTAIN"]; ok {
		t.Error("snapshot should not contain findings recorded after snapshot was taken")
	}
}

// =========================================================================
// Health Tests
// =========================================================================

func TestHealthChecker_NewWithVersion(t *testing.T) {
	hc := NewHealthChecker("3.0.0")
	status := hc.RunChecks()

	if status.Version != "3.0.0" {
		t.Errorf("Version = %q, want 3.0.0", status.Version)
	}
	if status.Uptime <= 0 {
		t.Error("Uptime should be positive")
	}
}

func TestHealthChecker_BuiltinChecks(t *testing.T) {
	hc := NewHealthChecker("1.0.0")
	status := hc.RunChecks()

	requiredChecks := []string{"ml_classifier", "disk_space", "goroutines"}
	for _, name := range requiredChecks {
		if _, ok := status.Checks[name]; !ok {
			t.Errorf("missing builtin check %q", name)
		}
	}
}

func TestHealthChecker_RegisterCustomCheck(t *testing.T) {
	hc := NewHealthChecker("1.0.0")

	hc.RegisterCheck("custom_db", func() CheckResult {
		return CheckResult{
			Status:  "healthy",
			Message: "database connected",
		}
	})

	status := hc.RunChecks()
	cr, ok := status.Checks["custom_db"]
	if !ok {
		t.Fatal("custom check not found")
	}
	if cr.Status != "healthy" {
		t.Errorf("custom check status = %q, want healthy", cr.Status)
	}
}

func TestHealthChecker_DegradedStatus(t *testing.T) {
	hc := NewHealthChecker("1.0.0")
	hc.RegisterCheck("failing_check", func() CheckResult {
		return CheckResult{
			Status:  "unhealthy",
			Message: "something is broken",
		}
	})

	status := hc.RunChecks()
	if status.Status != "degraded" {
		t.Errorf("overall status = %q, want degraded", status.Status)
	}
}

func TestHealthChecker_ServeHTTP_Healthz(t *testing.T) {
	hc := NewHealthChecker("1.0.0")
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	hc.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK && rec.Code != http.StatusServiceUnavailable {
		t.Errorf("unexpected status code: %d", rec.Code)
	}

	var status HealthStatus
	if err := json.Unmarshal(rec.Body.Bytes(), &status); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if status.Version != "1.0.0" {
		t.Errorf("version in response = %q, want 1.0.0", status.Version)
	}
}

func TestHealthChecker_ServeHTTP_Readyz(t *testing.T) {
	hc := NewHealthChecker("1.0.0")
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()

	hc.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK && rec.Code != http.StatusServiceUnavailable {
		t.Errorf("unexpected status code: %d", rec.Code)
	}

	var status HealthStatus
	if err := json.Unmarshal(rec.Body.Bytes(), &status); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
}

func TestHealthChecker_ServeHTTP_NotFound(t *testing.T) {
	hc := NewHealthChecker("1.0.0")
	req := httptest.NewRequest(http.MethodGet, "/unknown", nil)
	rec := httptest.NewRecorder()

	hc.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
}

func TestHealthChecker_ServeHTTP_Unhealthy503(t *testing.T) {
	hc := NewHealthChecker("1.0.0")
	hc.RegisterCheck("bad", func() CheckResult {
		return CheckResult{Status: "unhealthy", Message: "fail"}
	})

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	hc.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 for unhealthy service, got %d", rec.Code)
	}
}

func TestCheckGoroutines(t *testing.T) {
	result := checkGoroutines()
	if result.Status != "healthy" {
		t.Errorf("goroutine check should be healthy in tests, got %q: %s", result.Status, result.Message)
	}
}

func TestCheckDiskSpace(t *testing.T) {
	result := checkDiskSpace()
	if result.Status != "healthy" {
		t.Errorf("disk check should be healthy, got %q: %s", result.Status, result.Message)
	}
}

// =========================================================================
// Policy Tests
// =========================================================================

func TestDefaultPolicy(t *testing.T) {
	p := DefaultPolicy
	if err := p.Validate(); err != nil {
		t.Fatalf("default policy should be valid: %v", err)
	}
	if p.MinConfidence != 0.3 {
		t.Errorf("default MinConfidence = %v, want 0.3", p.MinConfidence)
	}
	if p.MaxFileSize != 1_000_000 {
		t.Errorf("default MaxFileSize = %v, want 1000000", p.MaxFileSize)
	}
}

func TestLoadPolicy(t *testing.T) {
	dir := t.TempDir()
	policyJSON := `{
		"min_confidence": 0.5,
		"max_file_size": 500000,
		"exclude_patterns": ["*.lock", "vendor/*"],
		"ignore_provenance": ["DOC_EXAMPLE"],
		"block_on_findings": true
	}`
	path := filepath.Join(dir, "policy.json")
	os.WriteFile(path, []byte(policyJSON), 0644)

	policy, err := LoadPolicy(path)
	if err != nil {
		t.Fatalf("LoadPolicy failed: %v", err)
	}

	if policy.MinConfidence != 0.5 {
		t.Errorf("MinConfidence = %v, want 0.5", policy.MinConfidence)
	}
	if policy.MaxFileSize != 500000 {
		t.Errorf("MaxFileSize = %v, want 500000", policy.MaxFileSize)
	}
	if !policy.BlockOnFindings {
		t.Error("BlockOnFindings should be true")
	}
	if len(policy.ExcludePatterns) != 2 {
		t.Errorf("expected 2 exclude patterns, got %d", len(policy.ExcludePatterns))
	}
}

func TestLoadPolicy_InvalidFile(t *testing.T) {
	_, err := LoadPolicy("/nonexistent/path/policy.json")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestLoadPolicy_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	os.WriteFile(path, []byte("{invalid json"), 0644)

	_, err := LoadPolicy(path)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestPolicyValidate_InvalidConfidence(t *testing.T) {
	p := ScanPolicy{MinConfidence: 1.5}
	if err := p.Validate(); err == nil {
		t.Error("expected validation error for MinConfidence > 1")
	}

	p2 := ScanPolicy{MinConfidence: -0.1}
	if err := p2.Validate(); err == nil {
		t.Error("expected validation error for MinConfidence < 0")
	}
}

func TestPolicyValidate_InvalidProvenance(t *testing.T) {
	p := ScanPolicy{IgnoreProvenance: []string{"BOGUS_PROVENANCE"}}
	if err := p.Validate(); err == nil {
		t.Error("expected validation error for unknown provenance")
	}
}

func TestPolicyValidate_EmptyAllowListPattern(t *testing.T) {
	p := ScanPolicy{
		AllowList: []AllowListEntry{{Pattern: "", Reason: "test"}},
	}
	if err := p.Validate(); err == nil {
		t.Error("expected validation error for empty allow list pattern")
	}
}

func TestPolicy_ShouldScan(t *testing.T) {
	p := ScanPolicy{
		MaxFileSize:     1000,
		IncludePatterns: []string{"*.py", "*.go"},
		ExcludePatterns: []string{"*.lock"},
	}

	tests := []struct {
		path string
		size int64
		want bool
	}{
		{"app.py", 500, true},
		{"main.go", 500, true},
		{"main.rs", 500, false},
		{"go.lock", 100, false},
		{"app.py", 2000, false},
	}

	for _, tc := range tests {
		got := p.ShouldScan(tc.path, tc.size)
		if got != tc.want {
			t.Errorf("ShouldScan(%q, %d) = %v, want %v", tc.path, tc.size, got, tc.want)
		}
	}
}

func TestPolicy_ShouldScan_NoPatterns(t *testing.T) {
	p := ScanPolicy{MaxFileSize: 1000}
	if !p.ShouldScan("anything.txt", 500) {
		t.Error("should scan any file when no patterns are specified")
	}
}

func TestPolicy_ShouldReport(t *testing.T) {
	p := ScanPolicy{
		MinConfidence:    0.5,
		IgnoreProvenance: []string{"DOC_EXAMPLE"},
	}

	tests := []struct {
		name    string
		finding engine.Finding
		want    bool
	}{
		{
			name:    "high confidence auth",
			finding: engine.Finding{Confidence: 0.9, Provenance: "AUTH_CREDENTIAL", MatchedValue: "secret123456"},
			want:    true,
		},
		{
			name:    "low confidence filtered",
			finding: engine.Finding{Confidence: 0.3, Provenance: "AUTH_CREDENTIAL", MatchedValue: "secret123456"},
			want:    false,
		},
		{
			name:    "ignored provenance",
			finding: engine.Finding{Confidence: 0.9, Provenance: "DOC_EXAMPLE", MatchedValue: "example_key_"},
			want:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := p.ShouldReport(tc.finding)
			if got != tc.want {
				t.Errorf("ShouldReport() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestPolicy_SeverityFor(t *testing.T) {
	p := ScanPolicy{
		SeverityMap: map[string]string{
			"AUTH_CREDENTIAL": "critical",
		},
	}

	f1 := engine.Finding{Confidence: 0.9, Provenance: "AUTH_CREDENTIAL"}
	if sev := p.SeverityFor(f1); sev != "critical" {
		t.Errorf("SeverityFor(AUTH_CREDENTIAL) = %q, want critical", sev)
	}

	f2 := engine.Finding{Confidence: 0.6, Provenance: "UNCERTAIN"}
	if sev := p.SeverityFor(f2); sev != "medium" {
		t.Errorf("SeverityFor(UNCERTAIN, 0.6) = %q, want medium", sev)
	}
}

func TestPolicy_SeverityFor_DefaultMapping(t *testing.T) {
	p := ScanPolicy{}

	tests := []struct {
		conf float64
		want string
	}{
		{0.95, "critical"},
		{0.75, "high"},
		{0.55, "medium"},
		{0.35, "low"},
		{0.1, "info"},
	}

	for _, tc := range tests {
		f := engine.Finding{Confidence: tc.conf}
		if sev := p.SeverityFor(f); sev != tc.want {
			t.Errorf("SeverityFor(conf=%v) = %q, want %q", tc.conf, sev, tc.want)
		}
	}
}

func TestPolicy_AllowList(t *testing.T) {
	future := time.Now().Add(24 * time.Hour)
	past := time.Now().Add(-24 * time.Hour)

	p := ScanPolicy{
		AllowList: []AllowListEntry{
			{Pattern: "AKIA_TEST", Reason: "test key", ExpiresAt: &future},
			{Pattern: "EXPIRED_PATTERN", Reason: "old exception", ExpiresAt: &past},
			{Pattern: "PERMANENT", Reason: "always allowed"},
		},
	}

	f1 := engine.Finding{Confidence: 0.9, MatchedValue: "AKIA_TEST_VALUE", Provenance: "AUTH_CREDENTIAL"}
	if p.ShouldReport(f1) {
		t.Error("allow-listed (non-expired) finding should not be reported")
	}

	f2 := engine.Finding{Confidence: 0.9, MatchedValue: "EXPIRED_PATTERN_VALUE", Provenance: "AUTH_CREDENTIAL"}
	if !p.ShouldReport(f2) {
		t.Error("expired allow-list entry should not suppress the finding")
	}

	f3 := engine.Finding{Confidence: 0.9, MatchedValue: "PERMANENT_TOKEN", Provenance: "AUTH_CREDENTIAL"}
	if p.ShouldReport(f3) {
		t.Error("permanent allow-list entry should suppress the finding")
	}
}

func TestPolicy_AllowList_Expiration(t *testing.T) {
	expired := time.Now().Add(-1 * time.Second)
	p := ScanPolicy{
		AllowList: []AllowListEntry{
			{Pattern: "TEMPORARY", Reason: "will expire", ExpiresAt: &expired},
		},
	}

	f := engine.Finding{Confidence: 0.9, MatchedValue: "TEMPORARY_SECRET", Provenance: "AUTH_CREDENTIAL"}
	if !p.ShouldReport(f) {
		t.Error("expired allow-list should not suppress findings")
	}
}

func TestLoadPolicy_WithAllowList(t *testing.T) {
	dir := t.TempDir()
	policyJSON := `{
		"min_confidence": 0.4,
		"allow_list": [
			{"pattern": "test_key_", "reason": "test keys"}
		]
	}`
	path := filepath.Join(dir, "policy.json")
	os.WriteFile(path, []byte(policyJSON), 0644)

	policy, err := LoadPolicy(path)
	if err != nil {
		t.Fatalf("LoadPolicy failed: %v", err)
	}

	if len(policy.AllowList) != 1 {
		t.Fatalf("expected 1 allow list entry, got %d", len(policy.AllowList))
	}
	if policy.AllowList[0].Pattern != "test_key_" {
		t.Errorf("pattern = %q, want test_key_", policy.AllowList[0].Pattern)
	}
}
