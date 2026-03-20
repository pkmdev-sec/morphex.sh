package engine

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func assertStringSliceEqual(t *testing.T, got, want []string, msg string) {
	t.Helper()
	if len(got) == 0 && len(want) == 0 {
		return // both empty/nil — equivalent
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s: got %v, want %v", msg, got, want)
	}
}

func writeTestFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// makeToken is a convenience constructor matching the Python _make_token helper.
func makeToken(value, varName, filePath string, line int) Token {
	return Token{
		Value:       value,
		VarName:     varName,
		Line:        line,
		LineContent: varName + ` = "` + value + `"`,
		FilePath:    filePath,
	}
}

// ============================================================================
// TEST 1: State-Machine Variable Name Splitting
// ============================================================================

func TestSplitVariableName(t *testing.T) {
	cases := []struct {
		input string
		want  []string
	}{
		// snake_case
		{"api_key", []string{"api", "key"}},
		{"AWS_SECRET_KEY", []string{"aws", "secret", "key"}},
		{"db_password", []string{"db", "password"}},

		// camelCase
		{"apiKey", []string{"api", "key"}},
		{"clientSecret", []string{"client", "secret"}},
		{"accessToken", []string{"access", "token"}},

		// PascalCase
		{"ApiKey", []string{"api", "key"}},
		{"ClientSecret", []string{"client", "secret"}},

		// Acronyms
		{"myAPIKey", []string{"my", "api", "key"}},
		{"AWSSecretKey", []string{"aws", "secret", "key"}},
		{"HTMLParser", []string{"html", "parser"}},

		// kebab-case
		{"db-password", []string{"db", "password"}},
		{"api-key-secret", []string{"api", "key", "secret"}},

		// mixed separators
		{"my.api_key", []string{"my", "api", "key"}},
		{"config/db_pass", []string{"config", "db", "pass"}},

		// SCREAMING_SNAKE
		{"SECRET_KEY", []string{"secret", "key"}},
		{"DATABASE_URL", []string{"database", "url"}},

		// empty and single
		{"", []string{}},
		{"key", []string{"key"}},
		{"K", []string{"k"}},

		// numbers
		{"key2", []string{"key2"}},
		{"oauth2_token", []string{"oauth2", "token"}},

		// leading separators
		{"_private_key", []string{"private", "key"}},
		{"__init__", []string{"init"}},
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got := SplitVariableName(tc.input)
			assertStringSliceEqual(t, got, tc.want, tc.input)
		})
	}
}

// ============================================================================
// TEST 2: Hand-Rolled Byte Checks
// ============================================================================

func TestIsHexOnly(t *testing.T) {
	// valid hex
	for _, s := range []string{"0123456789abcdef", "ABCDEF", "aAbBcCdDeEfF"} {
		if !IsHexOnly(s) {
			t.Errorf("expected IsHexOnly(%q) == true", s)
		}
	}
	// invalid
	for _, s := range []string{"0123456789abcdefg", "xyz", "", "abc-def", "abc def"} {
		if IsHexOnly(s) {
			t.Errorf("expected IsHexOnly(%q) == false", s)
		}
	}
	// hash lengths
	for _, n := range []int{32, 40, 64} {
		s := strings.Repeat("a", n)
		if !IsHexOnly(s) {
			t.Errorf("expected IsHexOnly(%d-char hex) == true", n)
		}
	}
}

func TestIsUUIDFormat(t *testing.T) {
	valid := []string{
		"550e8400-e29b-41d4-a716-446655440000",
		"AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE",
	}
	for _, s := range valid {
		if !IsUUIDFormat(s) {
			t.Errorf("expected IsUUIDFormat(%q) == true", s)
		}
	}

	invalid := []string{
		"not-a-uuid",
		"550e8400e29b41d4a716446655440000",       // no dashes
		"550e8400-e29b-41d4-a716-44665544000",    // too short
		"",                                        // empty
		"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",    // non-hex
	}
	for _, s := range invalid {
		if IsUUIDFormat(s) {
			t.Errorf("expected IsUUIDFormat(%q) == false", s)
		}
	}
}

func TestClassifyCharset(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"0123456789abcdef", "hex"},
		{"ABCDEF0123", "hex"},
		{"abc123+/xyz==", "base64"},
		{"SGVsbG8gV29ybGQ=", "base64"},
		{"AbcXyz123", "alphanum"},
		{"ghp1234567890abcdef", "alphanum"},
		{"abc!@#$%", "mixed"},
		{"key=value&foo", "mixed"},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got := ClassifyCharset(tc.input)
			if got != tc.want {
				t.Errorf("ClassifyCharset(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// ============================================================================
// TEST 3: Fast Entropy Screening
// ============================================================================

func TestFastEntropyCheck(t *testing.T) {
	// short strings rejected
	for _, s := range []string{"short", "abc", ""} {
		if FastEntropyCheck(s) {
			t.Errorf("expected FastEntropyCheck(%q) == false (short)", s)
		}
	}

	// low entropy rejected
	if FastEntropyCheck("aaaaaaaaaaaaaaaa") {
		t.Error("expected FastEntropyCheck(all-same-char) == false")
	}
	if FastEntropyCheck("aabbccddaabbccdd") {
		t.Error("expected FastEntropyCheck(low-unique-ratio) == false")
	}

	// high entropy accepted — deterministic pseudo-random string
	highEntropy := "xK9mP2nQ8rT5vW3yB7cF0hJ4lN6pS1uA2bC3dE4f"
	if !FastEntropyCheck(highEntropy) {
		t.Errorf("expected FastEntropyCheck(%q) == true", highEntropy)
	}

	// known API keys
	if !FastEntropyCheck("sk_live_4eC39HqLyjWDarjtT1zdp7dc") {
		t.Error("expected FastEntropyCheck(stripe key) == true")
	}
	if !FastEntropyCheck("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcd") {
		t.Error("expected FastEntropyCheck(github PAT) == true")
	}
}

// ============================================================================
// TEST 4: Shannon Entropy
// ============================================================================

func TestShannonEntropy(t *testing.T) {
	// zero entropy
	if e := ShannonEntropy("aaaa"); math.Abs(e) > 0.001 {
		t.Errorf("ShannonEntropy(aaaa) = %f, want ~0.0", e)
	}
	if e := ShannonEntropy(""); math.Abs(e) > 0.001 {
		t.Errorf("ShannonEntropy('') = %f, want 0.0", e)
	}

	// binary entropy (two equally likely chars -> 1 bit)
	if e := ShannonEntropy("ab"); math.Abs(e-1.0) > 0.001 {
		t.Errorf("ShannonEntropy(ab) = %f, want ~1.0", e)
	}
	if e := ShannonEntropy("aabb"); math.Abs(e-1.0) > 0.001 {
		t.Errorf("ShannonEntropy(aabb) = %f, want ~1.0", e)
	}

	// high entropy
	if e := ShannonEntropy("abcdefghijklmnop"); e <= 3.5 {
		t.Errorf("ShannonEntropy(16 unique chars) = %f, want > 3.5", e)
	}

	// API key entropy
	if e := ShannonEntropy("sk_live_4eC39HqLyjWDarjtT1zdp7dc"); e <= 3.5 {
		t.Errorf("ShannonEntropy(stripe key) = %f, want > 3.5", e)
	}
}

// ============================================================================
// TEST 5: Prefix Matching
// ============================================================================

func TestMatchKnownPrefix(t *testing.T) {
	// All 22 known prefixes should match correctly
	for prefix, ecosystem := range KnownPrefixes {
		testValue := prefix + "xyzabc123456"
		matchedPrefix, matchedEcosystem, found := MatchKnownPrefix(testValue)
		if !found {
			t.Errorf("MatchKnownPrefix(%q) not found, expected prefix %q", testValue, prefix)
			continue
		}
		if matchedPrefix != prefix {
			t.Errorf("MatchKnownPrefix(%q) prefix = %q, want %q", testValue, matchedPrefix, prefix)
		}
		if matchedEcosystem != ecosystem {
			t.Errorf("MatchKnownPrefix(%q) ecosystem = %q, want %q", testValue, matchedEcosystem, ecosystem)
		}
	}

	// Unknown prefix -> not found
	for _, s := range []string{"unknown_prefix_value", "hello_world_12345"} {
		_, _, found := MatchKnownPrefix(s)
		if found {
			t.Errorf("MatchKnownPrefix(%q) should not match", s)
		}
	}

	// Longest prefix match: github_pat_ vs ghp_
	_, eco1, ok1 := MatchKnownPrefix("github_pat_11ABCD_xyz")
	if !ok1 || eco1 != "github_pat_v2" {
		t.Errorf("expected github_pat_v2, got %q (found=%v)", eco1, ok1)
	}

	_, eco2, ok2 := MatchKnownPrefix("ghp_ABCDEFGHIJKLMNop")
	if !ok2 || eco2 != "github_pat" {
		t.Errorf("expected github_pat, got %q (found=%v)", eco2, ok2)
	}

	// Empty string -> not found
	_, _, found := MatchKnownPrefix("")
	if found {
		t.Error("MatchKnownPrefix('') should not match")
	}

	// Exact prefix with no trailing chars
	_, eco, ok := MatchKnownPrefix("AKIA")
	if !ok || eco != "aws_access_key" {
		t.Errorf("MatchKnownPrefix(AKIA) = (%q, %v), want (aws_access_key, true)", eco, ok)
	}
}

// ============================================================================
// TEST 6: Syntactic Role Classification
// ============================================================================

func TestClassifySyntacticRole(t *testing.T) {
	// Strong credentials
	for _, name := range []string{"api_key", "access_token", "client_secret", "db_password"} {
		role, conf, _ := ClassifySyntacticRole(name)
		if role != RoleStrongCredential {
			t.Errorf("ClassifySyntacticRole(%q) role = %v, want STRONG_CREDENTIAL", name, role)
		}
		if conf < 0.8 {
			t.Errorf("ClassifySyntacticRole(%q) confidence = %f, want >= 0.8", name, conf)
		}
	}

	// Strong credential atoms
	for _, name := range []string{"my_secret", "auth_data", "password_field"} {
		role, _, _ := ClassifySyntacticRole(name)
		if role != RoleStrongCredential {
			t.Errorf("ClassifySyntacticRole(%q) role = %v, want STRONG_CREDENTIAL", name, role)
		}
	}

	// Anti-credential
	for _, name := range []string{"hash_value", "checksum", "file_path", "url_string"} {
		role, _, _ := ClassifySyntacticRole(name)
		if role != RoleAntiCredential && role != RoleNeutral {
			t.Errorf("ClassifySyntacticRole(%q) role = %v, want ANTI_CREDENTIAL or NEUTRAL", name, role)
		}
	}

	// Neutral
	role, _, _ := ClassifySyntacticRole("foo_bar")
	if role != RoleNeutral {
		t.Errorf("ClassifySyntacticRole(foo_bar) = %v, want NEUTRAL", role)
	}

	// Ambiguous (password_hash has both cred and anti-cred atoms)
	role, _, _ = ClassifySyntacticRole("password_hash")
	if role != RoleNeutral {
		t.Errorf("ClassifySyntacticRole(password_hash) = %v, want NEUTRAL", role)
	}

	// Empty
	role, _, _ = ClassifySyntacticRole("")
	if role != RoleNeutral {
		t.Errorf("ClassifySyntacticRole('') = %v, want NEUTRAL", role)
	}

	// camelCase
	role, _, _ = ClassifySyntacticRole("apiKey")
	if role != RoleStrongCredential {
		t.Errorf("ClassifySyntacticRole(apiKey) = %v, want STRONG_CREDENTIAL", role)
	}

	role, _, _ = ClassifySyntacticRole("clientSecret")
	if role != RoleStrongCredential {
		t.Errorf("ClassifySyntacticRole(clientSecret) = %v, want STRONG_CREDENTIAL", role)
	}
}

// ============================================================================
// TEST 7: Morphology Classification
// ============================================================================

func TestClassifyMorphology(t *testing.T) {
	// Known prefix - AWS
	morph, meta, _ := ClassifyMorphology("AKIAIOSFODNN7EXAMPLE", RoleNeutral)
	if morph != MorphologyPrefixedRandom {
		t.Errorf("AWS morph = %v, want PREFIXED_RANDOM", morph)
	}
	if meta["ecosystem"] != "aws_access_key" {
		t.Errorf("AWS ecosystem = %v, want aws_access_key", meta["ecosystem"])
	}

	// Known prefix - GitHub
	morph, meta, _ = ClassifyMorphology("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef", RoleNeutral)
	if morph != MorphologyPrefixedRandom {
		t.Errorf("GitHub morph = %v, want PREFIXED_RANDOM", morph)
	}
	if meta["ecosystem"] != "github_pat" {
		t.Errorf("GitHub ecosystem = %v, want github_pat", meta["ecosystem"])
	}

	// Known prefix - Stripe
	morph, meta, _ = ClassifyMorphology("sk_live_4eC39HqLyjWDarjtT1zdp7dc", RoleNeutral)
	if morph != MorphologyPrefixedRandom {
		t.Errorf("Stripe morph = %v, want PREFIXED_RANDOM", morph)
	}
	if meta["ecosystem"] != "stripe_live" {
		t.Errorf("Stripe ecosystem = %v, want stripe_live", meta["ecosystem"])
	}

	// Private key
	morph, _, _ = ClassifyMorphology("-----BEGIN RSA PRIVATE KEY-----", RoleNeutral)
	if morph != MorphologyPrivateKey {
		t.Errorf("private key morph = %v, want PRIVATE_KEY", morph)
	}

	// Connection string with real password
	morph, meta, _ = ClassifyMorphology("postgres://admin:s3cretP4ss@db.example.com:5432/mydb", RoleNeutral)
	if morph != MorphologyConnectionString {
		t.Errorf("conn string morph = %v, want CONNECTION_STRING", morph)
	}
	if meta["has_real_password"] != true {
		t.Errorf("conn string has_real_password = %v, want true", meta["has_real_password"])
	}

	// Connection string with placeholder password
	morph, meta, _ = ClassifyMorphology("postgres://user:password@localhost/testdb", RoleNeutral)
	if morph != MorphologyConnectionString {
		t.Errorf("placeholder conn morph = %v, want CONNECTION_STRING", morph)
	}
	if meta["has_real_password"] != false {
		t.Errorf("placeholder conn has_real_password = %v, want false", meta["has_real_password"])
	}

	// JWT
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
	morph, _, _ = ClassifyMorphology(jwt, RoleNeutral)
	if morph != MorphologyJWT {
		t.Errorf("JWT morph = %v, want JWT", morph)
	}

	// Placeholder
	morph, _, _ = ClassifyMorphology("changeme", RoleNeutral)
	if morph != MorphologyTemplatePlaceholder {
		t.Errorf("changeme morph = %v, want TEMPLATE_PLACEHOLDER", morph)
	}

	morph, _, _ = ClassifyMorphology("XXXXXXXX", RoleNeutral)
	if morph != MorphologyTemplatePlaceholder {
		t.Errorf("XXXXXXXX morph = %v, want TEMPLATE_PLACEHOLDER", morph)
	}

	morph, _, _ = ClassifyMorphology("your-api-key-here", RoleNeutral)
	if morph != MorphologyTemplatePlaceholder {
		t.Errorf("your-api-key-here morph = %v, want TEMPLATE_PLACEHOLDER", morph)
	}

	// UUID
	morph, meta, _ = ClassifyMorphology("550e8400-e29b-41d4-a716-446655440000", RoleNeutral)
	if morph != MorphologyStructuredRandom {
		t.Errorf("UUID morph = %v, want STRUCTURED_RANDOM", morph)
	}
	if meta["subtype"] != "uuid" {
		t.Errorf("UUID subtype = %v, want uuid", meta["subtype"])
	}

	// Hex hash in non-credential variable
	morph, meta, _ = ClassifyMorphology(strings.Repeat("a", 64), RoleAntiCredential)
	if morph != MorphologyStructuredRandom {
		t.Errorf("hash morph = %v, want STRUCTURED_RANDOM", morph)
	}
	if meta["subtype"] != "hash" {
		t.Errorf("hash subtype = %v, want hash", meta["subtype"])
	}

	// Hex in credential variable -> MACHINE_RANDOM (not hash)
	morph, meta, _ = ClassifyMorphology("abcdef1234567890abcdef1234567890", RoleStrongCredential)
	if morph != MorphologyMachineRandom {
		t.Errorf("hex-in-cred morph = %v, want MACHINE_RANDOM", morph)
	}
	if note, ok := meta["note"]; !ok || !strings.Contains(note.(string), "NOT classified as hash") {
		t.Errorf("hex-in-cred note = %v, want contains 'NOT classified as hash'", meta["note"])
	}

	// Machine-random (high entropy)
	morph, _, _ = ClassifyMorphology("xK9mP2nQ8rT5vW3yB7cF0hJ4lN6pS1u", RoleNeutral)
	if morph != MorphologyMachineRandom {
		t.Errorf("machine random morph = %v, want MACHINE_RANDOM", morph)
	}

	// Human-typed (low entropy)
	morph, _, _ = ClassifyMorphology("helloworld", RoleNeutral)
	if morph != MorphologyHumanTyped {
		t.Errorf("human typed morph = %v, want HUMAN_TYPED", morph)
	}
}

// ============================================================================
// TEST 8: Decision Tree (ClassifyToken)
// ============================================================================

func TestClassifyToken(t *testing.T) {
	t.Run("known_prefix_auth_credential", func(t *testing.T) {
		tok := makeToken("AKIAIOSFODNN7EXAMPLE1", "aws_key", "src/app.py", 1)
		c := ClassifyToken(tok)
		if c.Prov != ProvenanceAuthCredential {
			t.Errorf("got %v, want AUTH_CREDENTIAL", c.Prov)
		}
		if c.Conf < 0.5 {
			t.Errorf("confidence %f < 0.5", c.Conf)
		}
	})

	t.Run("known_prefix_in_test_file", func(t *testing.T) {
		tok := makeToken("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcd", "token", "tests/test_auth.py", 1)
		c := ClassifyToken(tok)
		if c.Prov != ProvenanceAuthCredential {
			t.Errorf("got %v, want AUTH_CREDENTIAL", c.Prov)
		}
		if c.Conf <= 0.1 {
			t.Errorf("confidence %f should be > 0.1", c.Conf)
		}
	})

	t.Run("private_key", func(t *testing.T) {
		tok := makeToken("-----BEGIN RSA PRIVATE KEY-----", "private_key_header", "src/app.py", 1)
		c := ClassifyToken(tok)
		if c.Prov != ProvenanceAuthCredential {
			t.Errorf("got %v, want AUTH_CREDENTIAL", c.Prov)
		}
	})

	t.Run("connection_string_real", func(t *testing.T) {
		tok := makeToken("postgres://admin:s3cretP4ss@db.example.com/mydb", "db_url", "src/app.py", 1)
		c := ClassifyToken(tok)
		if c.Prov != ProvenanceAuthCredential {
			t.Errorf("got %v, want AUTH_CREDENTIAL", c.Prov)
		}
	})

	t.Run("connection_string_placeholder", func(t *testing.T) {
		tok := makeToken("postgres://user:password@localhost/testdb", "db_url", "src/app.py", 1)
		c := ClassifyToken(tok)
		if c.Prov != ProvenanceDocExample {
			t.Errorf("got %v, want DOC_EXAMPLE", c.Prov)
		}
	})

	t.Run("strong_credential_machine_random", func(t *testing.T) {
		tok := makeToken("xK9mP2nQ8rT5vW3yB7cF0hJ4lN6pS1u", "api_key", "src/app.py", 1)
		c := ClassifyToken(tok)
		if c.Prov != ProvenanceAuthCredential {
			t.Errorf("got %v, want AUTH_CREDENTIAL", c.Prov)
		}
	})

	t.Run("template_placeholder", func(t *testing.T) {
		tok := makeToken("changeme", "password", "src/app.py", 1)
		c := ClassifyToken(tok)
		if c.Prov != ProvenanceDocExample {
			t.Errorf("got %v, want DOC_EXAMPLE", c.Prov)
		}
	})

	t.Run("uuid_build_generated", func(t *testing.T) {
		tok := makeToken("550e8400-e29b-41d4-a716-446655440000", "request_id", "src/app.py", 1)
		c := ClassifyToken(tok)
		if c.Prov != ProvenanceBuildGenerated {
			t.Errorf("got %v, want BUILD_GENERATED", c.Prov)
		}
	})

	t.Run("hash_build_generated", func(t *testing.T) {
		tok := makeToken(strings.Repeat("a", 64), "file_hash", "src/app.py", 1)
		c := ClassifyToken(tok)
		if c.Prov != ProvenanceBuildGenerated {
			t.Errorf("got %v, want BUILD_GENERATED", c.Prov)
		}
	})

	t.Run("test_file_non_credential_suppressed", func(t *testing.T) {
		tok := makeToken("xK9mP2nQ8rT5vW3yB7cF0hJ4lN6pS1u", "config_value", "tests/test_app.py", 1)
		c := ClassifyToken(tok)
		if c.Prov == ProvenanceAuthCredential {
			t.Error("non-credential in test file should NOT be AUTH_CREDENTIAL")
		}
	})

	t.Run("revoked_context_reduces_confidence", func(t *testing.T) {
		tok := Token{
			Value:       "AKIAIOSFODNN7EXAMPLE1",
			VarName:     "old_key",
			Line:        1,
			LineContent: `old_key = "AKIAIOSFODNN7EXAMPLE1"  # revoked`,
			FilePath:    "src/app.py",
		}
		c := ClassifyToken(tok)
		if c.Prov != ProvenanceAuthCredential {
			t.Errorf("got %v, want AUTH_CREDENTIAL", c.Prov)
		}
		if c.Conf >= 0.95 {
			t.Errorf("confidence %f should be < 0.95 due to revocation context", c.Conf)
		}
	})

	t.Run("all_four_signals_present", func(t *testing.T) {
		tok := makeToken("XXXXXXXX", "placeholder", "src/app.py", 1)
		c := ClassifyToken(tok)
		if c.Prov != ProvenanceDocExample {
			t.Errorf("got %v, want DOC_EXAMPLE", c.Prov)
		}
		if len(c.Signals) != 4 {
			t.Errorf("got %d signals, want 4", len(c.Signals))
		}
		names := make(map[string]bool)
		for _, s := range c.Signals {
			names[s.Name] = true
		}
		for _, expected := range []string{"syntactic_role", "morphology", "file_provenance", "line_context"} {
			if !names[expected] {
				t.Errorf("missing signal %q", expected)
			}
		}
	})

	t.Run("hex_in_credential_var_detected", func(t *testing.T) {
		tok := makeToken("abcdef1234567890abcdef1234567890", "api_key", "src/app.py", 1)
		c := ClassifyToken(tok)
		if c.Prov != ProvenanceAuthCredential {
			t.Errorf("got %v, want AUTH_CREDENTIAL", c.Prov)
		}
	})
}

// ============================================================================
// TEST 9: File Provenance
// ============================================================================

func TestFileProvenance(t *testing.T) {
	// Clear cache before tests
	ClearFileProvenanceCache()

	tests := []struct {
		path     string
		wantCat  string
	}{
		// test files
		{"src/tests/test_auth.py", "test"},
		{"src/__tests__/auth.test.js", "test"},
		{"auth_test.go", "test"},
		{"auth.spec.ts", "test"},

		// example configs
		{".env.example", "example_config"},
		{"config.sample.yml", "example_config"},

		// documentation
		{"README.md", "documentation"},
		{"docs/setup.rst", "documentation"},

		// build artifacts
		{"project/vendor/pkg/file.go", "build_artifact"},
		{"app/node_modules/pkg/index.js", "build_artifact"},

		// env config
		{".env", "env_config"},
		{"docker-compose.yml", "env_config"},

		// IaC
		{"infra/main.tf", "iac"},
		{"vars.tfvars", "iac"},

		// CI/CD
		{".github/workflows/ci.yml", "cicd"},

		// source
		{"src/auth/handler.py", "source"},

		// lock files -> build_artifact
		{"package-lock.json", "build_artifact"},
		{"yarn.lock", "build_artifact"},
	}

	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			cat, _, _ := ClassifyFileProvenance(tc.path)
			if cat != tc.wantCat {
				t.Errorf("ClassifyFileProvenance(%q) category = %q, want %q", tc.path, cat, tc.wantCat)
			}
		})
	}

	// Caching works: same result on repeated calls
	ClearFileProvenanceCache()
	r1cat, r1adj, r1reason := ClassifyFileProvenance("src/app.py")
	r2cat, r2adj, r2reason := ClassifyFileProvenance("src/app.py")
	if r1cat != r2cat || r1adj != r2adj || r1reason != r2reason {
		t.Errorf("cache mismatch: (%q,%f,%q) vs (%q,%f,%q)", r1cat, r1adj, r1reason, r2cat, r2adj, r2reason)
	}

	// Clear and re-call should not crash
	ClearFileProvenanceCache()
	cat, _, _ := ClassifyFileProvenance("src/app.py")
	if cat == "" {
		t.Error("ClassifyFileProvenance returned empty after cache clear")
	}
}

// ============================================================================
// TEST 10: Line Context
// ============================================================================

func TestLineContext(t *testing.T) {
	// Comment detection
	adj, reason := ClassifyLineContext("# this is a comment with secret")
	if adj >= 0 {
		t.Errorf("comment adj = %f, want < 0", adj)
	}
	if !strings.Contains(reason, "comment") {
		t.Errorf("comment reason = %q, want contains 'comment'", reason)
	}

	adj, _ = ClassifyLineContext("// javascript comment")
	if adj >= 0 {
		t.Errorf("// comment adj = %f, want < 0", adj)
	}

	// Revocation context
	adj, reason = ClassifyLineContext(`old_key = "AKIA1234567890ABCDEF"  # revoked`)
	if adj > -0.5 {
		t.Errorf("revoked adj = %f, want <= -0.5", adj)
	}
	if !strings.Contains(strings.ToLower(reason), "revoc") {
		t.Errorf("revoked reason = %q, want contains 'revoc'", reason)
	}

	// Expired
	adj, _ = ClassifyLineContext(`token = "expired_token_value_here"  # expired 2024-01`)
	if adj > -0.5 {
		t.Errorf("expired adj = %f, want <= -0.5", adj)
	}

	// DO NOT USE
	adj, _ = ClassifyLineContext("# DO NOT USE this key: sk_live_xxx")
	if adj >= 0 {
		t.Errorf("DO NOT USE adj = %f, want < 0", adj)
	}

	// Normal line
	adj, reason = ClassifyLineContext(`api_key = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"`)
	if adj != 0.0 {
		t.Errorf("normal adj = %f, want 0.0", adj)
	}
	if !strings.Contains(reason, "no special") {
		t.Errorf("normal reason = %q, want contains 'no special'", reason)
	}

	// Deprecated
	adj, _ = ClassifyLineContext(`token = "old_value"  # deprecated`)
	if adj > -0.5 {
		t.Errorf("deprecated adj = %f, want <= -0.5", adj)
	}

	// Disabled
	adj, _ = ClassifyLineContext(`key = "value12345678"  # disabled`)
	if adj > -0.5 {
		t.Errorf("disabled adj = %f, want <= -0.5", adj)
	}
}

// ============================================================================
// TEST 11: Extract Tokens
// ============================================================================

func TestExtractTokens(t *testing.T) {
	t.Run("quoted_assignment", func(t *testing.T) {
		tokens := ExtractTokens("test.py", `api_key = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"`)
		if len(tokens) != 1 {
			t.Fatalf("got %d tokens, want 1", len(tokens))
		}
		if tokens[0].VarName != "api_key" {
			t.Errorf("var_name = %q, want api_key", tokens[0].VarName)
		}
		if tokens[0].Value != "sk_live_4eC39HqLyjWDarjtT1zdp7dc" {
			t.Errorf("value = %q, want sk_live_...", tokens[0].Value)
		}
	})

	t.Run("single_quoted_assignment", func(t *testing.T) {
		tokens := ExtractTokens("test.py", "secret = 'mysecretvalue12345'")
		if len(tokens) != 1 {
			t.Fatalf("got %d tokens, want 1", len(tokens))
		}
		if tokens[0].Value != "mysecretvalue12345" {
			t.Errorf("value = %q, want mysecretvalue12345", tokens[0].Value)
		}
	})

	t.Run("colon_assignment", func(t *testing.T) {
		tokens := ExtractTokens("test.py", `token: "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcd"`)
		found := false
		for _, tok := range tokens {
			if tok.Value == "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcd" {
				found = true
			}
		}
		if !found {
			t.Error("did not find ghp_ token in colon assignment")
		}
	})

	t.Run("shell_export", func(t *testing.T) {
		tokens := ExtractTokens("test.sh", "export AWS_SECRET_KEY=AKIAIOSFODNN7EXAMPLE12345")
		found := false
		for _, tok := range tokens {
			if tok.VarName == "AWS_SECRET_KEY" {
				found = true
			}
		}
		if !found {
			t.Error("did not find AWS_SECRET_KEY in shell export")
		}
	})

	t.Run("env_file", func(t *testing.T) {
		tokens := ExtractTokens(".env", "DATABASE_URL=postgres://user:realpass123@host/db")
		if len(tokens) < 1 {
			t.Error("expected at least 1 token from .env line")
		}
	})

	t.Run("json_key_value", func(t *testing.T) {
		tokens := ExtractTokens("config.json", `  "api_key": "sk_live_4eC39HqLyjWDarjtT1zdp7dc"`)
		found := false
		for _, tok := range tokens {
			if tok.VarName == "api_key" {
				found = true
			}
		}
		if !found {
			t.Error("did not find api_key in JSON key-value")
		}
	})

	t.Run("private_key_detection", func(t *testing.T) {
		tokens := ExtractTokens("key.pem", "-----BEGIN RSA PRIVATE KEY-----")
		found := false
		for _, tok := range tokens {
			if strings.Contains(tok.Value, "PRIVATE KEY") {
				found = true
			}
		}
		if !found {
			t.Error("did not detect PRIVATE KEY")
		}
	})

	t.Run("connection_string", func(t *testing.T) {
		tokens := ExtractTokens("config.py", `DB_URL = "postgres://admin:s3cretP4ss@db.example.com:5432/mydb"`)
		found := false
		for _, tok := range tokens {
			if strings.Contains(tok.Value, "postgres://") {
				found = true
			}
		}
		if !found {
			t.Error("did not detect connection string")
		}
	})

	t.Run("short_lines_skipped", func(t *testing.T) {
		tokens := ExtractTokens("test.py", "x = 1\ny = 2\na = 'b'\nshort")
		if len(tokens) != 0 {
			t.Errorf("got %d tokens from short lines, want 0", len(tokens))
		}
	})

	t.Run("deduplication_different_lines", func(t *testing.T) {
		tokens := ExtractTokens("test.py", "key = \"duplicatevalue1234\"\nkey: \"duplicatevalue1234\"")
		count := 0
		for _, tok := range tokens {
			if tok.Value == "duplicatevalue1234" {
				count++
			}
		}
		if count != 2 {
			t.Errorf("same value on different lines: got %d, want 2", count)
		}
	})

	t.Run("same_line_dedup", func(t *testing.T) {
		tokens := ExtractTokens("test.py", `api_key = "testvalue12345678"  # "testvalue12345678"`)
		count := 0
		for _, tok := range tokens {
			if tok.Value == "testvalue12345678" {
				count++
			}
		}
		if count != 1 {
			t.Errorf("same value on same line: got %d, want 1", count)
		}
	})

	t.Run("yaml_style", func(t *testing.T) {
		tokens := ExtractTokens("config.yml", "  password: supersecretpassword123")
		found := false
		for _, tok := range tokens {
			if tok.VarName == "password" {
				found = true
			}
		}
		if !found {
			t.Error("did not find password in YAML")
		}
	})

	t.Run("value_length_minimum", func(t *testing.T) {
		tokens := ExtractTokens("test.py", `key = "short"`)
		if len(tokens) != 0 {
			t.Errorf("short value: got %d tokens, want 0", len(tokens))
		}
	})

	t.Run("multiline_extraction", func(t *testing.T) {
		content := `api_key = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
db_password = "supersecretpassword123"
version = "1.0.0-beta"
hash = "abc12345"
`
		tokens := ExtractTokens("app.py", content)
		if len(tokens) == 0 {
			t.Fatal("expected tokens from multiline content")
		}
		varNames := make(map[string]bool)
		for _, tok := range tokens {
			varNames[tok.VarName] = true
		}
		if !varNames["api_key"] {
			t.Error("missing api_key")
		}
		if !varNames["db_password"] {
			t.Error("missing db_password")
		}
	})
}

// ============================================================================
// TEST 12: End-to-End File Scanning
// ============================================================================

func TestScanFile(t *testing.T) {
	tmpDir := t.TempDir()
	ClearFileProvenanceCache()

	t.Run("detect_aws_key", func(t *testing.T) {
		path := writeTestFile(t, tmpDir, "config.py", "AWS_ACCESS_KEY = \"AKIAIOSFODNN7EXAMPLE1\"\n")
		findings := ScanFile(path, 0.0)
		if len(findings) == 0 {
			t.Fatal("expected findings for AWS key")
		}
		hasAuth := false
		for _, f := range findings {
			if f.Provenance == string(ProvenanceAuthCredential) {
				hasAuth = true
			}
		}
		if !hasAuth {
			t.Error("expected AUTH_CREDENTIAL finding for AWS key")
		}
	})

	t.Run("detect_github_pat", func(t *testing.T) {
		path := writeTestFile(t, tmpDir, "app.js", "const token = \"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcd\";\n")
		findings := ScanFile(path, 0.0)
		if len(findings) == 0 {
			t.Fatal("expected findings for GitHub PAT")
		}
	})

	t.Run("detect_stripe_key", func(t *testing.T) {
		path := writeTestFile(t, tmpDir, "billing.py", "STRIPE_KEY = \"sk_live_4eC39HqLyjWDarjtT1zdp7dc\"\n")
		findings := ScanFile(path, 0.0)
		if len(findings) == 0 {
			t.Fatal("expected findings for Stripe key")
		}
	})

	t.Run("detect_connection_string", func(t *testing.T) {
		path := writeTestFile(t, tmpDir, "db.py", "DB_URL = \"postgres://admin:s3cretP4ss@db.prod.example.com:5432/mydb\"\n")
		findings := ScanFile(path, 0.0)
		if len(findings) == 0 {
			t.Fatal("expected findings for connection string")
		}
	})

	t.Run("suppress_placeholder", func(t *testing.T) {
		content := `API_KEY = "changeme"
SECRET = "your-api-key-here"
TOKEN = "XXXXXXXX"
`
		path := writeTestFile(t, tmpDir, "config.example.py", content)
		findings := ScanFile(path, 0.0)
		for _, f := range findings {
			if f.Provenance == string(ProvenanceAuthCredential) {
				t.Errorf("placeholder should not be AUTH_CREDENTIAL, got finding: %+v", f)
			}
		}
	})

	t.Run("suppress_hash", func(t *testing.T) {
		path := writeTestFile(t, tmpDir, "checksums.py",
			`file_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"`+"\n")
		findings := ScanFile(path, 0.0)
		for _, f := range findings {
			if f.Provenance == string(ProvenanceAuthCredential) {
				t.Error("hash should not be AUTH_CREDENTIAL")
			}
		}
	})

	t.Run("suppress_uuid", func(t *testing.T) {
		path := writeTestFile(t, tmpDir, "ids.py",
			`request_id = "550e8400-e29b-41d4-a716-446655440000"`+"\n")
		findings := ScanFile(path, 0.0)
		for _, f := range findings {
			if f.Provenance == string(ProvenanceAuthCredential) {
				t.Error("UUID should not be AUTH_CREDENTIAL")
			}
		}
	})

	t.Run("env_file_detection", func(t *testing.T) {
		content := `API_KEY=sk_live_4eC39HqLyjWDarjtT1zdp7dc
DATABASE_URL=postgres://admin:realpassword123@host/db
`
		path := writeTestFile(t, tmpDir, ".env", content)
		findings := ScanFile(path, 0.0)
		if len(findings) == 0 {
			t.Fatal("expected findings in .env file")
		}
	})

	t.Run("mixed_file", func(t *testing.T) {
		content := `# Configuration
VERSION = "1.0.0-beta"
APP_NAME = "my-application"
API_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
file_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
request_id = "550e8400-e29b-41d4-a716-446655440000"
`
		path := writeTestFile(t, tmpDir, "app.py", content)
		findings := ScanFile(path, 0.0)
		authFindings := 0
		hasStripe := false
		for _, f := range findings {
			if f.Provenance == string(ProvenanceAuthCredential) {
				authFindings++
				if strings.Contains(f.MatchedValue, "sk_liv") {
					hasStripe = true
				}
			}
		}
		if authFindings == 0 {
			t.Error("expected AUTH_CREDENTIAL findings in mixed file")
		}
		if !hasStripe {
			t.Error("expected Stripe key detection in mixed file")
		}
	})
}

// ============================================================================
// TEST 13: Concurrent Directory Scanning
// ============================================================================

func TestScanDirectory(t *testing.T) {
	t.Run("finds_secrets_across_files", func(t *testing.T) {
		tmpDir := t.TempDir()
		ClearFileProvenanceCache()
		writeTestFile(t, tmpDir, "src/config.py", `API_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"`)
		writeTestFile(t, tmpDir, "src/utils.py", "VERSION = \"1.0.0\"\nname = \"myapp\"")
		findings := ScanDirectory(tmpDir, 0.0, 0)
		if len(findings) == 0 {
			t.Error("expected findings in directory scan")
		}
	})

	t.Run("skip_node_modules", func(t *testing.T) {
		tmpDir := t.TempDir()
		ClearFileProvenanceCache()
		writeTestFile(t, tmpDir, "node_modules/pkg/index.js", `secret = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"`)
		writeTestFile(t, tmpDir, "src/app.py", `version = "1.0.0-beta-release"`)
		findings := ScanDirectory(tmpDir, 0.0, 0)
		for _, f := range findings {
			if strings.Contains(f.File, "node_modules") {
				t.Error("should not scan files in node_modules")
			}
		}
	})

	t.Run("skip_binary_files", func(t *testing.T) {
		tmpDir := t.TempDir()
		ClearFileProvenanceCache()
		writeTestFile(t, tmpDir, "image.png", `fake_key = "AKIAIOSFODNN7EXAMPLE1"`)
		findings := ScanDirectory(tmpDir, 0.0, 0)
		if len(findings) != 0 {
			t.Errorf("expected 0 findings for binary file, got %d", len(findings))
		}
	})

	t.Run("concurrent_workers", func(t *testing.T) {
		tmpDir := t.TempDir()
		ClearFileProvenanceCache()
		for i := 0; i < 60; i++ {
			name := filepath.Join("src", fmt.Sprintf("file_%03d.py", i))
			writeTestFile(t, tmpDir, name, fmt.Sprintf(`api_key_%d = "sk_live_4eC39Hq%04djWDarjtT1zdp7dc"`, i, i))
		}
		findings := ScanDirectory(tmpDir, 0.0, 4)
		if len(findings) == 0 {
			t.Error("expected findings from concurrent scan of 60 files")
		}
	})

	t.Run("empty_directory", func(t *testing.T) {
		tmpDir := t.TempDir()
		ClearFileProvenanceCache()
		findings := ScanDirectory(tmpDir, 0.0, 0)
		if len(findings) != 0 {
			t.Errorf("expected 0 findings for empty dir, got %d", len(findings))
		}
	})
}

// ============================================================================
// TEST 14: JSON Output
// ============================================================================

func TestOutputJSON(t *testing.T) {
	findings := []Finding{
		{
			File:         "src/app.py",
			Line:         42,
			MatchedValue: "sk_liv...7dc",
			Detector:     "synapse:auth_credential",
			Confidence:   0.95,
			Provenance:   string(ProvenanceAuthCredential),
			Signals: []map[string]interface{}{
				{
					"name":       "morphology",
					"value":      "prefixed_random",
					"confidence": 0.8,
					"reasoning":  "matches known prefix",
				},
			},
			ReasoningStr: "test reasoning",
		},
	}

	output, err := OutputJSON(findings)
	if err != nil {
		t.Fatal(err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(output), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if int(parsed["total_findings"].(float64)) != 1 {
		t.Errorf("total_findings = %v, want 1", parsed["total_findings"])
	}
	if parsed["tool"] != "morphex" {
		t.Errorf("tool = %v, want morphex", parsed["tool"])
	}

	findingsArr, ok := parsed["findings"].([]interface{})
	if !ok {
		t.Fatal("findings is not an array")
	}
	if len(findingsArr) != 1 {
		t.Errorf("findings length = %d, want 1", len(findingsArr))
	}

	first := findingsArr[0].(map[string]interface{})
	if first["file"] != "src/app.py" {
		t.Errorf("finding file = %v, want src/app.py", first["file"])
	}

	// Empty findings
	output, err = OutputJSON([]Finding{})
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(output), &parsed); err != nil {
		t.Fatalf("empty JSON invalid: %v", err)
	}
	if int(parsed["total_findings"].(float64)) != 0 {
		t.Errorf("empty total_findings = %v, want 0", parsed["total_findings"])
	}
}

// ============================================================================
// TEST 15: Benchmarks
// ============================================================================

func BenchmarkExtractTokens(b *testing.B) {
	lines := make([]string, 1000)
	for i := range lines {
		lines[i] = `api_key = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"`
	}
	content := strings.Join(lines, "\n")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ExtractTokens("test.py", content)
	}
}

func BenchmarkClassifyToken(b *testing.B) {
	tok := makeToken("AKIAIOSFODNN7EXAMPLE1", "aws_key", "src/app.py", 1)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ClassifyToken(tok)
	}
}

func BenchmarkSplitVariableName(b *testing.B) {
	names := []string{"myAPIKey", "clientSecret", "AWS_SECRET_KEY", "db_password"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		SplitVariableName(names[i%len(names)])
	}
}

func BenchmarkMatchKnownPrefix(b *testing.B) {
	val := "AKIAIOSFODNN7EXAMPLE1"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		MatchKnownPrefix(val)
	}
}

func BenchmarkShannonEntropy(b *testing.B) {
	val := "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ShannonEntropy(val)
	}
}

// ============================================================================
// TEST 16: Parity with Python — Direct ClassifyToken Tests
// ============================================================================

func TestClassifyTokenParity(t *testing.T) {
	type parityCase struct {
		name               string
		value              string
		varName            string
		lineContent        string
		filePath           string
		expectedProvenance Provenance
	}

	cases := []parityCase{
		{
			name:               "AWS key (AKIA prefix)",
			value:              "AKIAIOSFODNN7EXAMPLE1",
			varName:            "AWS_ACCESS_KEY_ID",
			lineContent:        `AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE1"`,
			filePath:           "src/config.py",
			expectedProvenance: ProvenanceAuthCredential,
		},
		{
			name:               "GitHub PAT (ghp_ prefix)",
			value:              "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh",
			varName:            "GITHUB_TOKEN",
			lineContent:        `GITHUB_TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh"`,
			filePath:           "src/github.py",
			expectedProvenance: ProvenanceAuthCredential,
		},
		{
			name:               "Stripe live key",
			value:              "sk_live_4eC39HqLyjWDarjtT1zdp7dc",
			varName:            "STRIPE_LIVE_KEY",
			lineContent:        `STRIPE_LIVE_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"`,
			filePath:           "src/payments.py",
			expectedProvenance: ProvenanceAuthCredential,
		},
		{
			name:               "Stripe test key",
			value:              "sk_test_4eC39HqLyjWDarjtT1zdp7dc",
			varName:            "STRIPE_TEST_KEY",
			lineContent:        `STRIPE_TEST_KEY = "sk_test_4eC39HqLyjWDarjtT1zdp7dc"`,
			filePath:           "src/payments.py",
			expectedProvenance: ProvenanceAuthCredential,
		},
		{
			name:               "Slack bot token",
			value:              "xoxb-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx",
			varName:            "SLACK_BOT_TOKEN",
			lineContent:        `SLACK_BOT_TOKEN = "xoxb-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx"`,
			filePath:           "src/slack.py",
			expectedProvenance: ProvenanceAuthCredential,
		},
		{
			name:               "Connection string with real password",
			value:              "postgres://admin:SuperS3cr3tP4ss@db.example.com:5432/myapp",
			varName:            "DATABASE_URL",
			lineContent:        `DATABASE_URL = "postgres://admin:SuperS3cr3tP4ss@db.example.com:5432/myapp"`,
			filePath:           "src/database.py",
			expectedProvenance: ProvenanceAuthCredential,
		},
		{
			name:               "Connection string with placeholder password",
			value:              "mysql://root:changeme@localhost:3306/test",
			varName:            "MYSQL_CONN",
			lineContent:        `MYSQL_CONN = "mysql://root:changeme@localhost:3306/test"`,
			filePath:           "src/database.py",
			expectedProvenance: ProvenanceDocExample,
		},
		{
			name:               "Private key PEM header",
			value:              "-----BEGIN RSA PRIVATE KEY----- MIIEowIBAAKCAQEA...",
			varName:            "private_key_header",
			lineContent:        `PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY----- MIIEowIBAAKCAQEA..."`,
			filePath:           "src/certs.py",
			expectedProvenance: ProvenanceAuthCredential,
		},
		{
			name:               "JWT token",
			value:              "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			varName:            "AUTH_TOKEN",
			lineContent:        `AUTH_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"`,
			filePath:           "src/auth.py",
			expectedProvenance: ProvenanceAuthCredential,
		},
		{
			name:               "32-char hex in credential var",
			value:              "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
			varName:            "api_key",
			lineContent:        `api_key = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"`,
			filePath:           "src/api.py",
			expectedProvenance: ProvenanceAuthCredential,
		},
		{
			name:               "64-char hex in hash var",
			value:              "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
			varName:            "file_hash",
			lineContent:        `file_hash = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"`,
			filePath:           "src/integrity.py",
			expectedProvenance: ProvenanceBuildGenerated,
		},
		{
			name:               "UUID",
			value:              "550e8400-e29b-41d4-a716-446655440000",
			varName:            "request_id",
			lineContent:        `request_id = "550e8400-e29b-41d4-a716-446655440000"`,
			filePath:           "src/ids.py",
			expectedProvenance: ProvenanceBuildGenerated,
		},
		{
			name:               "Placeholder changeme",
			value:              "changeme",
			varName:            "api_key",
			lineContent:        `api_key = "changeme"`,
			filePath:           "src/placeholder.py",
			expectedProvenance: ProvenanceDocExample,
		},
		{
			name:               "Placeholder XXXXXXXX",
			value:              "XXXXXXXX",
			varName:            "secret_key",
			lineContent:        `secret_key = "XXXXXXXX"`,
			filePath:           "src/placeholder.py",
			expectedProvenance: ProvenanceDocExample,
		},
		{
			name:               "Normal description string",
			value:              "This is a normal description string that is long enough",
			varName:            "description",
			lineContent:        `description = "This is a normal description string that is long enough"`,
			filePath:           "src/normal.py",
			expectedProvenance: ProvenanceBuildGenerated, // anti-credential var + machine-random → BUILD_GENERATED (same as Python)
		},
		{
			name:               "AWS key in test file",
			value:              "AKIAIOSFODNN7EXAMPLETEST",
			varName:            "API_KEY",
			lineContent:        `API_KEY = "AKIAIOSFODNN7EXAMPLETEST"`,
			filePath:           "tests/test_auth.py",
			expectedProvenance: ProvenanceAuthCredential,
		},
		{
			name:               "Stripe key in example config",
			value:              "sk_live_ExampleConfigKeyThatShouldBeSuppressed",
			varName:            "api_key",
			lineContent:        `api_key: "sk_live_ExampleConfigKeyThatShouldBeSuppressed"`,
			filePath:           "config.example.yaml",
			expectedProvenance: ProvenanceAuthCredential,
		},
		{
			name:               "Connection string with placeholder password",
			value:              "postgres://user:password@localhost/db",
			varName:            "database_url",
			lineContent:        `database_url: "postgres://user:password@localhost/db"`,
			filePath:           "config.example.yaml",
			expectedProvenance: ProvenanceDocExample,
		},
		{
			name:               "High-entropy in neutral var",
			value:              "Kj8mNpL2qR4sT6uV8wX0yZ1aB3cD5eF",
			varName:            "session_data",
			lineContent:        `session_data = "Kj8mNpL2qR4sT6uV8wX0yZ1aB3cD5eF"`,
			filePath:           "src/random_val.py",
			expectedProvenance: ProvenanceUncertain,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ClearFileProvenanceCache()
			tok := Token{
				Value:       tc.value,
				VarName:     tc.varName,
				Line:        1,
				LineContent: tc.lineContent,
				FilePath:    tc.filePath,
			}
			c := ClassifyToken(tok)
			if c.Prov != tc.expectedProvenance {
				t.Errorf("ClassifyToken(%q) provenance = %v, want %v\n  signals: %v",
					tc.name, c.Prov, tc.expectedProvenance, c.Signals)
			}
		})
	}
}

// ============================================================================
// TEST 17: File-Level Gates
// ============================================================================

func TestFileDefinitelySafe(t *testing.T) {
	// Binary extensions should be safe
	for _, ext := range []string{".exe", ".png", ".zip", ".pdf", ".woff"} {
		if !FileDefinitelySafe("file" + ext) {
			t.Errorf("FileDefinitelySafe(file%s) should be true", ext)
		}
	}

	// Lock files should be safe
	for _, lf := range []string{"package-lock.json", "yarn.lock", "go.sum", "cargo.lock"} {
		if !FileDefinitelySafe(lf) {
			t.Errorf("FileDefinitelySafe(%s) should be true", lf)
		}
	}

	// Source files should not be safe
	for _, ext := range []string{".py", ".js", ".go", ".java", ".rb"} {
		if FileDefinitelySafe("file" + ext) {
			t.Errorf("FileDefinitelySafe(file%s) should be false", ext)
		}
	}

	// Minified files should be safe
	if !FileDefinitelySafe("app.min.js") {
		t.Error("FileDefinitelySafe(app.min.js) should be true")
	}
	if !FileDefinitelySafe("styles.min.css") {
		t.Error("FileDefinitelySafe(styles.min.css) should be true")
	}
}

