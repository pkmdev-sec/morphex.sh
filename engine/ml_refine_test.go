package engine

import (
	"os"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// refineWithML tests
// ---------------------------------------------------------------------------

func TestRefineWithML_NotLoaded(t *testing.T) {
	// When the classifier is not loaded, refineWithML should be a no-op.
	tok := makeToken("AKIA1234567890ABCDEF", "aws_key", "config.py", 5)
	cls := Classification{
		Prov: ProvenanceUncertain,
		Conf: 0.55,
	}

	result := refineWithML(tok, "line1\nline2\nline3\nline4\naws_key = AKIA1234567890ABCDEF\nline6", cls)
	if result.Prov != ProvenanceUncertain {
		t.Errorf("expected UNCERTAIN, got %s", result.Prov)
	}
	if result.Conf != 0.55 {
		t.Errorf("expected confidence 0.55, got %.4f", result.Conf)
	}
}

func TestRefineWithML_EmptyContent(t *testing.T) {
	tok := makeToken("some_secret", "api_key", "app.py", 1)
	cls := Classification{
		Prov: ProvenanceUncertain,
		Conf: 0.5,
	}

	result := refineWithML(tok, "", cls)
	if result.Prov != ProvenanceUncertain {
		t.Errorf("expected UNCERTAIN for empty content, got %s", result.Prov)
	}
}

func TestRefineWithML_WithLoadedClassifier_SecretSignals(t *testing.T) {
	// Initialize the classifier with a minimal vocab to enable heuristic mode.
	tmpDir := t.TempDir()
	vocabPath := tmpDir + "/vocab.txt"
	os.WriteFile(vocabPath, []byte("[PAD]\n[UNK]\n[CLS]\n[SEP]\n"), 0644)

	if err := InitClassifier(tmpDir); err != nil {
		t.Fatalf("InitClassifier failed: %v", err)
	}
	defer func() {
		// Reset the singleton for other tests.
		clf := GetClassifier()
		clf.mu.Lock()
		clf.loaded = false
		clf.mu.Unlock()
	}()

	// Build content with credential signals that the heuristic will pick up.
	content := strings.Join([]string{
		"import os",
		"import boto3",
		"",
		"# AWS credentials for production",
		"aws_access_key = 'AKIAIOSFODNN7EXAMPLE'",
		"aws_secret_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'",
		"password = 'SuperSecretPwd123!'",
		"token = 'ghp_1234567890abcdef1234567890abcdef12345678'",
		"",
		"client = boto3.client('s3')",
	}, "\n")

	tok := makeToken("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "aws_secret_key", "deploy.py", 6)
	cls := Classification{
		Prov: ProvenanceUncertain,
		Conf: 0.55,
	}

	result := refineWithML(tok, content, cls)

	// The heuristic should detect "secret", "password", "token", "akia" -> boost score.
	// The result should have an ml_classifier signal appended.
	hasMLSignal := false
	for _, s := range result.Signals {
		if s.Name == "ml_classifier" {
			hasMLSignal = true
			break
		}
	}
	if !hasMLSignal {
		t.Error("expected ml_classifier signal in result")
	}
}

func TestRefineWithML_WithLoadedClassifier_AntiSignals(t *testing.T) {
	tmpDir := t.TempDir()
	vocabPath := tmpDir + "/vocab.txt"
	os.WriteFile(vocabPath, []byte("[PAD]\n[UNK]\n[CLS]\n[SEP]\n"), 0644)

	if err := InitClassifier(tmpDir); err != nil {
		t.Fatalf("InitClassifier failed: %v", err)
	}
	defer func() {
		clf := GetClassifier()
		clf.mu.Lock()
		clf.loaded = false
		clf.mu.Unlock()
	}()

	// Content full of anti-signals: test, example, mock, fake, placeholder.
	content := strings.Join([]string{
		"// This is a test file with example credentials",
		"// These are fake dummy placeholder values",
		"test_key = 'example_mock_fake_dummy_placeholder'",
		"mock_token = 'test_sample_changeme_todo_fixme'",
		"// hash checksum digest uuid values",
	}, "\n")

	tok := makeToken("example_mock_fake_dummy_placeholder", "test_key", "test_config.py", 3)
	cls := Classification{
		Prov: ProvenanceUncertain,
		Conf: 0.5,
	}

	result := refineWithML(tok, content, cls)

	// Anti-signals should dominate, confidence should drop.
	if result.Conf >= 0.5 {
		t.Errorf("expected reduced confidence from anti-signals, got %.4f", result.Conf)
	}
}

// ---------------------------------------------------------------------------
// clamp64 tests
// ---------------------------------------------------------------------------

func TestClamp64(t *testing.T) {
	tests := []struct {
		v, lo, hi, want float64
	}{
		{0.5, 0.0, 1.0, 0.5},
		{-0.1, 0.0, 1.0, 0.0},
		{1.5, 0.0, 1.0, 1.0},
		{0.3, 0.05, 0.95, 0.3},
	}
	for _, tt := range tests {
		got := clamp64(tt.v, tt.lo, tt.hi)
		if got != tt.want {
			t.Errorf("clamp64(%f, %f, %f) = %f, want %f", tt.v, tt.lo, tt.hi, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// RefineWithML exported wrapper test
// ---------------------------------------------------------------------------

func TestRefineWithML_Exported(t *testing.T) {
	tok := makeToken("test_value", "key", "app.py", 1)
	cls := Classification{
		Prov: ProvenanceUncertain,
		Conf: 0.5,
	}

	// Should not panic when classifier is not loaded.
	result := RefineWithML(tok, "some content", cls)
	if result.Prov != ProvenanceUncertain {
		t.Errorf("expected UNCERTAIN from exported wrapper, got %s", result.Prov)
	}
}

// ---------------------------------------------------------------------------
// predictHeuristic tests
// ---------------------------------------------------------------------------

func TestPredictHeuristic_SecretKeywords(t *testing.T) {
	tmpDir := t.TempDir()
	os.WriteFile(tmpDir+"/vocab.txt", []byte("[PAD]\n[UNK]\n[CLS]\n[SEP]\n"), 0644)
	if err := InitClassifier(tmpDir); err != nil {
		t.Fatal(err)
	}
	defer func() {
		clf := GetClassifier()
		clf.mu.Lock()
		clf.loaded = false
		clf.mu.Unlock()
	}()

	clf := GetClassifier()
	pred := clf.predictHeuristic("password = 'secret' token = 'api_key' bearer akia")
	if pred.Label != 1 {
		t.Errorf("expected SECRET label for credential keywords, got %d (%s)", pred.Label, pred.LabelName)
	}
	if pred.Confidence < 0.7 {
		t.Errorf("expected high confidence for credential keywords, got %.4f", pred.Confidence)
	}
}

func TestPredictHeuristic_AntiKeywords(t *testing.T) {
	tmpDir := t.TempDir()
	os.WriteFile(tmpDir+"/vocab.txt", []byte("[PAD]\n[UNK]\n[CLS]\n[SEP]\n"), 0644)
	if err := InitClassifier(tmpDir); err != nil {
		t.Fatal(err)
	}
	defer func() {
		clf := GetClassifier()
		clf.mu.Lock()
		clf.loaded = false
		clf.mu.Unlock()
	}()

	clf := GetClassifier()
	pred := clf.predictHeuristic("test example sample mock fake dummy placeholder changeme hash uuid")
	if pred.Label != 0 {
		t.Errorf("expected NOT_SECRET for anti-keywords, got %d (%s)", pred.Label, pred.LabelName)
	}
}

// ---------------------------------------------------------------------------
// BuildContextWindow tests
// ---------------------------------------------------------------------------

func TestBuildContextWindow_Normal(t *testing.T) {
	lines := []string{"a", "b", "c", "target", "e", "f", "g"}
	content := strings.Join(lines, "\n")

	window := BuildContextWindow(content, 4, 2)
	if !strings.Contains(window, ">>> LINE 4 <<<") {
		t.Error("expected target line marker in context window")
	}
	if !strings.Contains(window, "target") {
		t.Error("expected target content in window")
	}
}

func TestBuildContextWindow_EdgeStart(t *testing.T) {
	content := "first\nsecond\nthird"
	window := BuildContextWindow(content, 1, 10)
	if !strings.Contains(window, ">>> LINE 1 <<<") {
		t.Error("expected line 1 marker")
	}
}
