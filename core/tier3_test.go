package synapse

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// ===========================================================================
// Encrypted Storage Tests
// ===========================================================================

func TestEncryptedStorage_EncryptDecrypt(t *testing.T) {
	// 32-byte key in hex (64 hex chars)
	keyHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	es, err := NewEncryptedStorage(keyHex)
	if err != nil {
		t.Fatalf("NewEncryptedStorage failed: %v", err)
	}

	testCases := []string{
		"AKIA4E2FXJWM7RQBN9KZ",
		"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12",
		"sk_live_4eC39HqLyjWDarjtT1zdp7dc",
		"", // empty string
		"short",
		strings.Repeat("a", 1000), // long value
	}

	for _, plaintext := range testCases {
		ciphertext, err := es.Encrypt(plaintext)
		if err != nil {
			t.Errorf("Encrypt(%q) error: %v", plaintext, err)
			continue
		}

		if plaintext != "" && ciphertext == plaintext {
			t.Errorf("Encrypt(%q) returned plaintext unchanged", plaintext)
		}

		decrypted, err := es.Decrypt(ciphertext)
		if err != nil {
			t.Errorf("Decrypt error for %q: %v", plaintext, err)
			continue
		}

		if decrypted != plaintext {
			t.Errorf("roundtrip failed: got %q, want %q", decrypted, plaintext)
		}
	}
}

func TestEncryptedStorage_DifferentNonces(t *testing.T) {
	keyHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	es, err := NewEncryptedStorage(keyHex)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := "AKIA4E2FXJWM7RQBN9KZ"
	ct1, err := es.Encrypt(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	ct2, err := es.Encrypt(plaintext)
	if err != nil {
		t.Fatal(err)
	}

	if ct1 == ct2 {
		t.Error("same plaintext produced identical ciphertext; nonces should differ")
	}

	// Both should still decrypt correctly
	d1, _ := es.Decrypt(ct1)
	d2, _ := es.Decrypt(ct2)
	if d1 != plaintext || d2 != plaintext {
		t.Error("both ciphertexts should decrypt to the same plaintext")
	}
}

func TestEncryptedStorage_InvalidKey(t *testing.T) {
	// Too short
	_, err := NewEncryptedStorage("0123456789abcdef")
	if err == nil {
		t.Error("expected error for short key")
	}

	// Not hex
	_, err = NewEncryptedStorage("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")
	if err == nil {
		t.Error("expected error for non-hex key")
	}
}

func TestEncryptedStorage_FindingRoundtrip(t *testing.T) {
	keyHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	es, err := NewEncryptedStorage(keyHex)
	if err != nil {
		t.Fatal(err)
	}

	finding := &AgentTeamResult{
		RawSecret: "AKIA4E2FXJWM7RQBN9KZ",
		File:      "config/prod.env",
	}

	original := finding.RawSecret

	if err := es.EncryptFinding(finding); err != nil {
		t.Fatalf("EncryptFinding error: %v", err)
	}
	if finding.RawSecret == original {
		t.Error("EncryptFinding did not encrypt the secret")
	}

	if err := es.DecryptFinding(finding); err != nil {
		t.Fatalf("DecryptFinding error: %v", err)
	}
	if finding.RawSecret != original {
		t.Errorf("DecryptFinding: got %q, want %q", finding.RawSecret, original)
	}
}

func TestEncryptedStorage_WrongKey(t *testing.T) {
	key1 := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	key2 := "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

	es1, _ := NewEncryptedStorage(key1)
	es2, _ := NewEncryptedStorage(key2)

	ct, err := es1.Encrypt("secret-value")
	if err != nil {
		t.Fatal(err)
	}

	_, err = es2.Decrypt(ct)
	if err == nil {
		t.Error("decrypting with wrong key should fail")
	}
}

// ===========================================================================
// Audit Logger Tests
// ===========================================================================

func TestAuditLogger_LogAndRetrieve(t *testing.T) {
	var buf bytes.Buffer
	al := NewAuditLogger(&buf)

	before := time.Now().Add(-time.Second)

	al.Log("scan_started", "scanner-1", "/repo/path", "success", map[string]string{"files": "100"})
	al.Log("secret_found", "scanner-1", "/repo/path/config.py", "success", map[string]string{"type": "aws_key"})
	al.Log("secret_verified", "scanner-1", "/repo/path/config.py", "success", map[string]string{"status": "active"})

	entries := al.GetEntries(before)
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}

	if entries[0].Action != "scan_started" {
		t.Errorf("first entry action: got %q, want 'scan_started'", entries[0].Action)
	}
	if entries[1].Actor != "scanner-1" {
		t.Errorf("second entry actor: got %q, want 'scanner-1'", entries[1].Actor)
	}
	if entries[2].Outcome != "success" {
		t.Errorf("third entry outcome: got %q, want 'success'", entries[2].Outcome)
	}

	// Verify output was written
	output := buf.String()
	if !strings.Contains(output, "scan_started") {
		t.Error("output should contain 'scan_started'")
	}

	// Test time filter
	future := time.Now().Add(time.Hour)
	noEntries := al.GetEntries(future)
	if len(noEntries) != 0 {
		t.Errorf("expected 0 entries for future time, got %d", len(noEntries))
	}
}

func TestAuditLogger_Export_JSON(t *testing.T) {
	al := NewAuditLogger(nil) // no output writer

	al.Log("scan_started", "scanner-1", "/repo", "success", nil)
	al.Log("secret_found", "scanner-1", "/repo/file.py", "success", map[string]string{"type": "aws"})

	data, err := al.Export("json")
	if err != nil {
		t.Fatalf("Export JSON error: %v", err)
	}

	var entries []AuditEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("expected 2 entries in JSON, got %d", len(entries))
	}
}

func TestAuditLogger_Export_CSV(t *testing.T) {
	al := NewAuditLogger(nil)

	al.Log("scan_started", "scanner-1", "/repo", "success", nil)
	al.Log("secret_found", "scanner-1", "/repo/file.py", "success", map[string]string{"type": "aws"})

	data, err := al.Export("csv")
	if err != nil {
		t.Fatalf("Export CSV error: %v", err)
	}

	csv := string(data)
	lines := strings.Split(strings.TrimSpace(csv), "\n")
	if len(lines) != 3 { // header + 2 rows
		t.Errorf("expected 3 CSV lines (header + 2 rows), got %d", len(lines))
	}
	if !strings.Contains(lines[0], "timestamp") {
		t.Error("CSV header should contain 'timestamp'")
	}
}

func TestAuditLogger_Export_InvalidFormat(t *testing.T) {
	al := NewAuditLogger(nil)
	_, err := al.Export("xml")
	if err == nil {
		t.Error("expected error for unsupported format")
	}
}

// ===========================================================================
// Rate Limiter Tests
// ===========================================================================

func TestRateLimiter_TryAcquire(t *testing.T) {
	rl := NewRateLimiter(RateLimitConfig{
		RequestsPerSecond: 100,
		BurstSize:         5,
	})

	// Should succeed for initial burst
	for i := 0; i < 5; i++ {
		if !rl.TryAcquire("test.com") {
			t.Errorf("TryAcquire should succeed for burst token %d", i+1)
		}
	}

	// Should fail after burst is exhausted (without waiting for refill)
	if rl.TryAcquire("test.com") {
		t.Error("TryAcquire should fail after burst exhausted")
	}
}

func TestRateLimiter_Wait(t *testing.T) {
	rl := NewRateLimiter(RateLimitConfig{
		RequestsPerSecond: 1000, // fast for testing
		BurstSize:         2,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Exhaust burst
	rl.TryAcquire("fast.com")
	rl.TryAcquire("fast.com")

	// Wait should eventually succeed after refill
	start := time.Now()
	err := rl.Wait(ctx, "fast.com")
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("Wait returned error: %v", err)
	}
	// Should have waited at least a bit but not too long (1ms refill at 1000 rps)
	if elapsed > 500*time.Millisecond {
		t.Errorf("Wait took too long: %v", elapsed)
	}
}

func TestRateLimiter_Wait_ContextCancelled(t *testing.T) {
	rl := NewRateLimiter(RateLimitConfig{
		RequestsPerSecond: 0.1, // very slow: 1 per 10 seconds
		BurstSize:         1,
	})

	// Exhaust the single burst token
	rl.TryAcquire("slow.com")

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err := rl.Wait(ctx, "slow.com")
	if err == nil {
		t.Error("Wait should return error on cancelled context")
	}
}

func TestRateLimiter_DefaultServiceLimits(t *testing.T) {
	rl := NewRateLimiter(RateLimitConfig{
		RequestsPerSecond: 1,
		BurstSize:         1,
	})

	// github.com has default burst of 10
	for i := 0; i < 10; i++ {
		if !rl.TryAcquire("github.com") {
			t.Errorf("github.com should allow burst token %d (default burst: 10)", i+1)
		}
	}

	// Custom service uses default config (burst: 1)
	if !rl.TryAcquire("custom.com") {
		t.Error("custom.com should allow first request")
	}
	if rl.TryAcquire("custom.com") {
		t.Error("custom.com should be rate limited after burst of 1")
	}
}

// ===========================================================================
// Verification Cache Tests
// ===========================================================================

func TestVerificationCache_SetGetExpiry(t *testing.T) {
	cache := NewVerificationCache(100*time.Millisecond, 100)

	result := &FullVerificationResult{
		Status:   VerifyActive,
		Verified: true,
		Confidence: 0.95,
	}

	hash := HashSecret("test-secret")
	cache.Set(hash, result)

	// Should hit
	got, ok := cache.Get(hash)
	if !ok {
		t.Fatal("expected cache hit")
	}
	if got.Confidence != 0.95 {
		t.Errorf("confidence: got %.2f, want 0.95", got.Confidence)
	}

	// Wait for expiry
	time.Sleep(150 * time.Millisecond)

	_, ok = cache.Get(hash)
	if ok {
		t.Error("expected cache miss after expiry")
	}

	// Stats
	stats := cache.Stats()
	if stats.Hits != 1 {
		t.Errorf("hits: got %d, want 1", stats.Hits)
	}
	if stats.Misses != 1 {
		t.Errorf("misses: got %d, want 1", stats.Misses)
	}
}

func TestVerificationCache_MaxSize(t *testing.T) {
	cache := NewVerificationCache(time.Hour, 3) // max 3 entries

	for i := 0; i < 5; i++ {
		hash := HashSecret(string(rune('a' + i)))
		cache.Set(hash, &FullVerificationResult{
			Status: VerifyActive,
		})
	}

	stats := cache.Stats()
	if stats.Size > 3 {
		t.Errorf("cache size %d exceeds max 3", stats.Size)
	}
}

func TestVerificationCache_Invalidate(t *testing.T) {
	cache := NewVerificationCache(time.Hour, 100)

	hash := HashSecret("my-secret")
	cache.Set(hash, &FullVerificationResult{Status: VerifyActive})

	_, ok := cache.Get(hash)
	if !ok {
		t.Fatal("expected hit before invalidation")
	}

	cache.Invalidate(hash)

	_, ok = cache.Get(hash)
	if ok {
		t.Error("expected miss after invalidation")
	}
}

func TestVerificationCache_Clear(t *testing.T) {
	cache := NewVerificationCache(time.Hour, 100)

	for i := 0; i < 10; i++ {
		cache.Set(HashSecret(string(rune('a'+i))), &FullVerificationResult{Status: VerifyActive})
	}

	if cache.Stats().Size != 10 {
		t.Fatalf("expected 10 entries, got %d", cache.Stats().Size)
	}

	cache.Clear()
	if cache.Stats().Size != 0 {
		t.Errorf("expected 0 entries after clear, got %d", cache.Stats().Size)
	}
}

func TestVerificationCache_HitRate(t *testing.T) {
	cache := NewVerificationCache(time.Hour, 100)
	hash := HashSecret("test")
	cache.Set(hash, &FullVerificationResult{Status: VerifyActive})

	// 3 hits
	cache.Get(hash)
	cache.Get(hash)
	cache.Get(hash)

	// 1 miss
	cache.Get(HashSecret("nonexistent"))

	stats := cache.Stats()
	if stats.Hits != 3 {
		t.Errorf("hits: got %d, want 3", stats.Hits)
	}
	if stats.Misses != 1 {
		t.Errorf("misses: got %d, want 1", stats.Misses)
	}
	expectedRate := 0.75
	if stats.HitRate < expectedRate-0.01 || stats.HitRate > expectedRate+0.01 {
		t.Errorf("hit rate: got %.2f, want %.2f", stats.HitRate, expectedRate)
	}
}

// ===========================================================================
// Blast Radius Agent Tests
// ===========================================================================

func TestBlastRadiusAgent_AWS_DryRun(t *testing.T) {
	agent := NewBlastRadiusAgent(BlastRadiusConfig{
		DryRun: true,
	})

	verResult := &FullVerificationResult{
		Status:   VerifyActive,
		Verified: true,
		Confidence: 0.95,
	}

	result, err := agent.Analyze(context.Background(), "AKIA4E2FXJWM7RQBN9KZ", "aws_access_key", verResult)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}

	if !strings.Contains(result.Summary, "DryRun") {
		t.Error("DryRun analysis should mention DryRun in summary")
	}
	if len(result.Evidence) == 0 {
		t.Error("expected evidence in dry run result")
	}
}

func TestBlastRadiusAgent_NotVerified(t *testing.T) {
	agent := NewBlastRadiusAgent(BlastRadiusConfig{})

	// Nil verification result
	result, err := agent.Analyze(context.Background(), "secret", "aws", nil)
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}
	if result.RiskLevel != "low" {
		t.Errorf("unverified should be low risk, got %s", result.RiskLevel)
	}

	// Not verified
	result, err = agent.Analyze(context.Background(), "secret", "aws", &FullVerificationResult{Verified: false})
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}
	if result.RiskLevel != "low" {
		t.Errorf("unverified should be low risk, got %s", result.RiskLevel)
	}
}

func TestBlastRadiusAgent_GitHub_DryRun(t *testing.T) {
	agent := NewBlastRadiusAgent(BlastRadiusConfig{DryRun: true})

	result, err := agent.Analyze(context.Background(), "ghp_test123", "github_pat", &FullVerificationResult{
		Verified: true, Confidence: 0.9,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result.Evidence[0].Description, "GitHub") {
		t.Error("GitHub DryRun should reference GitHub in evidence")
	}
}

func TestBlastRadiusAgent_Stripe_DryRun(t *testing.T) {
	agent := NewBlastRadiusAgent(BlastRadiusConfig{DryRun: true})

	result, err := agent.Analyze(context.Background(), "sk_live_test", "stripe_live", &FullVerificationResult{
		Verified: true, Confidence: 0.9,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result.Evidence[0].Description, "Stripe") {
		t.Error("Stripe DryRun should reference Stripe in evidence")
	}
}

func TestBlastRadiusAgent_Generic(t *testing.T) {
	agent := NewBlastRadiusAgent(BlastRadiusConfig{})

	result, err := agent.Analyze(context.Background(), "secret123", "unknown_service", &FullVerificationResult{
		Verified: true, Confidence: 0.6,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.RiskScore > 50 {
		t.Errorf("generic risk score should be <= 50, got %d", result.RiskScore)
	}
}

// ===========================================================================
// Remediation Agent Tests
// ===========================================================================

func TestRemediationAgent_Plan_AWS(t *testing.T) {
	agent := NewRemediationAgent(RemediationConfig{})

	finding := ContextResult{
		FinalConfidence: 0.95,
		Verdict:         VerdictLikelyTP,
		Provenance:      "AUTH_CREDENTIAL",
	}

	result, err := agent.Plan(context.Background(), finding, "aws_access_key", nil)
	if err != nil {
		t.Fatalf("Plan error: %v", err)
	}

	if result.ImmediateAction == "" {
		t.Error("ImmediateAction should not be empty")
	}
	if !strings.Contains(result.ImmediateAction, "Deactivate") {
		t.Error("AWS immediate action should mention deactivation")
	}
	if len(result.RotationSteps) == 0 {
		t.Error("RotationSteps should not be empty")
	}
	if result.RotationScript == "" {
		t.Error("RotationScript should not be empty")
	}
	if !strings.Contains(result.RotationScript, "aws iam") {
		t.Error("AWS rotation script should contain aws iam commands")
	}
	if len(result.PreventionTips) == 0 {
		t.Error("PreventionTips should not be empty")
	}
	if result.Duration == 0 {
		t.Error("Duration should be > 0")
	}
}

func TestRemediationAgent_Plan_GitHub(t *testing.T) {
	agent := NewRemediationAgent(RemediationConfig{})

	finding := ContextResult{
		FinalConfidence: 0.9,
		Verdict:         VerdictLikelyTP,
	}

	result, err := agent.Plan(context.Background(), finding, "github_pat", nil)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(result.ImmediateAction, "github.com/settings/tokens") {
		t.Error("GitHub remediation should link to token settings")
	}
	if len(result.RotationSteps) < 3 {
		t.Error("GitHub should have at least 3 rotation steps")
	}
}

func TestRemediationAgent_Plan_Stripe(t *testing.T) {
	agent := NewRemediationAgent(RemediationConfig{})

	finding := ContextResult{FinalConfidence: 0.9}

	result, err := agent.Plan(context.Background(), finding, "stripe_live", nil)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(result.ImmediateAction, "URGENT") {
		t.Error("Live Stripe key should be marked URGENT")
	}
}

func TestRemediationAgent_Plan_Database(t *testing.T) {
	agent := NewRemediationAgent(RemediationConfig{})

	finding := ContextResult{FinalConfidence: 0.85}

	result, err := agent.Plan(context.Background(), finding, "postgres", nil)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(result.RotationScript, "ALTER USER") {
		t.Error("Database rotation script should contain ALTER USER")
	}
}

func TestRemediationAgent_Plan_Generic(t *testing.T) {
	agent := NewRemediationAgent(RemediationConfig{})

	finding := ContextResult{FinalConfidence: 0.7}

	result, err := agent.Plan(context.Background(), finding, "unknown_api", nil)
	if err != nil {
		t.Fatal(err)
	}

	if result.ImmediateAction == "" {
		t.Error("Generic plan should have an immediate action")
	}
	if len(result.RotationSteps) == 0 {
		t.Error("Generic plan should have rotation steps")
	}
}

// ===========================================================================
// Orchestrator Integration Tests (Phase 3+4 wiring)
// ===========================================================================

func TestOrchestrator_WithBlastRadiusAndRemediation(t *testing.T) {
	// Create orchestrator with all phases enabled (DryRun for blast radius)
	orch := NewOrchestrator(OrchestratorConfig{
		MaxConcurrentTeams: 2,
		ContextTimeout:     5 * time.Second,
		AlertThreshold:     0.3,
		EnableBlastRadius:  true,
		BlastRadiusConfig:  &BlastRadiusConfig{DryRun: true},
		EnableRemediation:  true,
	})

	// Verify agents are initialized
	if orch.blastRadiusAgent == nil {
		t.Error("blastRadiusAgent should be initialized when enabled")
	}
	if orch.remediationAgent == nil {
		t.Error("remediationAgent should be initialized when enabled")
	}

	// ProcessFinding should still work (blast radius and remediation need verification first)
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
		t.Fatalf("ProcessFinding error: %v", err)
	}

	// Without verification agent, Phase 3+4 should not run
	if result.BlastRadius != nil {
		t.Error("BlastRadius should be nil without verification")
	}
	if result.Remediation != nil {
		t.Error("Remediation should be nil without verification")
	}

	// Final verdict should still work
	if result.FinalVerdict.RiskLevel == "" {
		t.Error("RiskLevel should not be empty")
	}
}

// ===========================================================================
// Helper function tests
// ===========================================================================

func TestScoreToRiskLevel(t *testing.T) {
	tests := []struct {
		score int
		want  string
	}{
		{95, "critical"},
		{90, "critical"},
		{80, "high"},
		{70, "high"},
		{50, "medium"},
		{40, "medium"},
		{30, "low"},
		{0, "low"},
	}

	for _, tt := range tests {
		got := scoreToRiskLevel(tt.score)
		if got != tt.want {
			t.Errorf("scoreToRiskLevel(%d) = %q, want %q", tt.score, got, tt.want)
		}
	}
}

func TestEcosystemDetection(t *testing.T) {
	tests := []struct {
		eco    string
		isAWS  bool
		isGH   bool
		isSt   bool
		isDB   bool
	}{
		{"aws_access_key", true, false, false, false},
		{"github_pat", false, true, false, false},
		{"stripe_live", false, false, true, false},
		{"postgres", false, false, false, true},
		{"mysql", false, false, false, true},
		{"unknown", false, false, false, false},
	}

	for _, tt := range tests {
		if isAWSEcosystem(tt.eco) != tt.isAWS {
			t.Errorf("isAWSEcosystem(%q) = %v", tt.eco, !tt.isAWS)
		}
		if isGitHubEcosystem(tt.eco) != tt.isGH {
			t.Errorf("isGitHubEcosystem(%q) = %v", tt.eco, !tt.isGH)
		}
		if isStripeEcosystem(tt.eco) != tt.isSt {
			t.Errorf("isStripeEcosystem(%q) = %v", tt.eco, !tt.isSt)
		}
		if isDatabaseEcosystem(tt.eco) != tt.isDB {
			t.Errorf("isDatabaseEcosystem(%q) = %v", tt.eco, !tt.isDB)
		}
	}
}

// ===========================================================================
// Benchmarks
// ===========================================================================

func BenchmarkEncryptDecrypt(b *testing.B) {
	keyHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	es, err := NewEncryptedStorage(keyHex)
	if err != nil {
		b.Fatal(err)
	}

	plaintext := "AKIA4E2FXJWM7RQBN9KZ"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ct, err := es.Encrypt(plaintext)
		if err != nil {
			b.Fatal(err)
		}
		_, err = es.Decrypt(ct)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerificationCache_SetGet(b *testing.B) {
	cache := NewVerificationCache(time.Hour, 10000)
	result := &FullVerificationResult{Status: VerifyActive, Verified: true}
	hash := HashSecret("benchmark-secret")
	cache.Set(hash, result)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.Get(hash)
	}
}
