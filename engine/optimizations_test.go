package engine

import (
	"fmt"
	"math"
	"strings"
	"testing"
)

// ============================================================================
// 1. Trie prefix matching tests
// ============================================================================

func TestMatchKnownPrefixTrie_AllPrefixes(t *testing.T) {
	for prefix, ecosystem := range KnownPrefixes {
		value := prefix + "SomeRandomSuffix1234"
		gotPrefix, gotEco, found := MatchKnownPrefixTrie(value)
		if !found {
			t.Errorf("MatchKnownPrefixTrie(%q): want found=true, got false", value)
			continue
		}
		if gotPrefix != prefix {
			t.Errorf("MatchKnownPrefixTrie(%q): prefix got %q, want %q", value, gotPrefix, prefix)
		}
		if gotEco != ecosystem {
			t.Errorf("MatchKnownPrefixTrie(%q): ecosystem got %q, want %q", value, gotEco, ecosystem)
		}
	}
}

func TestMatchKnownPrefixTrie_MatchesOriginal(t *testing.T) {
	testValues := []string{
		"AKIAxxxxxxxxxxxxxxxxxxxx",
		"ASIAxxxxxxxxxxxxxxxxxxxx",
		"ghp_abcdefghijklmnopqrst",
		"gho_abcdefghijklmnopqrst",
		"ghs_abcdefghijklmnopqrst",
		"ghu_abcdefghijklmnopqrst",
		"github_pat_abcdefghijklmnopqrst",
		"sk_live_abcdefghijklmnopqrst",
		"pk_live_abcdefghijklmnopqrst",
		"rk_live_abcdefghijklmnopqrst",
		"sk_test_abcdefghijklmnopqrst",
		"xoxb-12345-abcdef",
		"xoxp-12345-abcdef",
		"xoxa-12345-abcdef",
		"xoxr-12345-abcdef",
		"SG.abcdefghijklmnopqrst",
		"hf_abcdefghijklmnopqrst",
		"sq0csp-abcdefghijklmnopqrst",
		"EAACEdEose0cBAabcdefghijklmnopqrst",
		"ya29.abcdefghijklmnopqrst",
		"AIzaabcdefghijklmnopqrst",
		"glpat-abcdefghijklmnopqrst",
		"no_match_here",
		"",
		"x",
		"AKIA",
		"ghp_",
	}

	for _, v := range testValues {
		origPrefix, origEco, origFound := MatchKnownPrefix(v)
		triePrefix, trieEco, trieFound := MatchKnownPrefixTrie(v)

		if origFound != trieFound {
			t.Errorf("value=%q: found mismatch orig=%v trie=%v", v, origFound, trieFound)
			continue
		}
		if origPrefix != triePrefix {
			t.Errorf("value=%q: prefix mismatch orig=%q trie=%q", v, origPrefix, triePrefix)
		}
		if origEco != trieEco {
			t.Errorf("value=%q: ecosystem mismatch orig=%q trie=%q", v, origEco, trieEco)
		}
	}
}

func TestMatchKnownPrefixTrie_NoMatch(t *testing.T) {
	noMatch := []string{
		"random_string",
		"akia_lowercase",
		"AKIB_close_but_no",
		"xxxx",
		"",
	}
	for _, v := range noMatch {
		_, _, found := MatchKnownPrefixTrie(v)
		if found {
			t.Errorf("MatchKnownPrefixTrie(%q): expected no match, got match", v)
		}
	}
}

func TestMatchKnownPrefixTrie_LongestMatch(t *testing.T) {
	value := "github_pat_abcdefghijklmnopqrst"
	prefix, eco, found := MatchKnownPrefixTrie(value)
	if !found {
		t.Fatal("expected match for github_pat_ prefix")
	}
	if prefix != "github_pat_" {
		t.Errorf("expected longest prefix github_pat_, got %q", prefix)
	}
	if eco != "github_pat_v2" {
		t.Errorf("expected ecosystem github_pat_v2, got %q", eco)
	}
}

// ============================================================================
// Benchmark: Trie vs Original
// ============================================================================

func BenchmarkMatchKnownPrefixOrig(b *testing.B) {
	values := []string{
		"AKIAxxxxxxxxxxxxxxxxxxxx",
		"ghp_abcdefghijklmnopqrst",
		"sk_live_abcdefghijklmnopqrst",
		"no_match_here_at_all_nope",
		"xoxb-12345-abcdef-ghijk",
		"github_pat_abcdefghijklmnopqrst",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, v := range values {
			MatchKnownPrefix(v)
		}
	}
}

func BenchmarkMatchKnownPrefixTrie(b *testing.B) {
	values := []string{
		"AKIAxxxxxxxxxxxxxxxxxxxx",
		"ghp_abcdefghijklmnopqrst",
		"sk_live_abcdefghijklmnopqrst",
		"no_match_here_at_all_nope",
		"xoxb-12345-abcdef-ghijk",
		"github_pat_abcdefghijklmnopqrst",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, v := range values {
			MatchKnownPrefixTrie(v)
		}
	}
}

// ============================================================================
// 2. Batch Classification tests
// ============================================================================

func TestClassifyTokenBatch_Empty(t *testing.T) {
	result := ClassifyTokenBatch(nil)
	if result != nil {
		t.Errorf("expected nil for nil input, got %v", result)
	}
	result = ClassifyTokenBatch([]Token{})
	if result != nil {
		t.Errorf("expected nil for empty input, got %v", result)
	}
}

func TestClassifyTokenBatch_MatchesSerial(t *testing.T) {
	tokens := []Token{
		{Value: "AKIAxxxxxxxxxxxxxxxxxxxx", VarName: "aws_key", Line: 1, LineContent: "aws_key = AKIAxxxxxxxxxxxxxxxxxxxx", FilePath: "config.env"},
		{Value: "ghp_abcdefghijklmnopqrst", VarName: "token", Line: 2, LineContent: "token: ghp_abcdefghijklmnopqrst", FilePath: "config.env"},
		{Value: "sk_live_abcdefghijklmnopqrst", VarName: "stripe_key", Line: 3, LineContent: "stripe_key = sk_live_abcdefghijklmnopqrst", FilePath: "app.py"},
		{Value: "not_a_secret_value_1234", VarName: "title", Line: 4, LineContent: "title = not_a_secret_value_1234", FilePath: "readme.md"},
		{Value: "password123456789", VarName: "password", Line: 5, LineContent: "password = password123456789", FilePath: "test_config.py"},
	}

	batchResults := ClassifyTokenBatch(tokens)
	if len(batchResults) != len(tokens) {
		t.Fatalf("batch len=%d, want %d", len(batchResults), len(tokens))
	}

	for i, tok := range tokens {
		serialResult := ClassifyToken(tok)
		batchResult := batchResults[i]

		if batchResult.Prov != serialResult.Prov {
			t.Errorf("token %d (%q): prov batch=%s serial=%s", i, tok.VarName, batchResult.Prov, serialResult.Prov)
		}
		if batchResult.Conf != serialResult.Conf {
			t.Errorf("token %d (%q): conf batch=%f serial=%f", i, tok.VarName, batchResult.Conf, serialResult.Conf)
		}
		if len(batchResult.Signals) != len(serialResult.Signals) {
			t.Errorf("token %d (%q): signals batch=%d serial=%d", i, tok.VarName, len(batchResult.Signals), len(serialResult.Signals))
		}
	}
}

func TestClassifyTokenBatch_SharedFilePaths(t *testing.T) {
	tokens := []Token{
		{Value: "AKIAxxxxxxxxxxxxxxxxxxxx", VarName: "key1", Line: 1, LineContent: "key1 = AKIAxxxxxxxxxxxxxxxxxxxx", FilePath: "shared.env"},
		{Value: "ghp_abcdefghijklmnopqrst", VarName: "key2", Line: 2, LineContent: "key2 = ghp_abcdefghijklmnopqrst", FilePath: "shared.env"},
		{Value: "sk_live_abcdefghijklmnopqrst", VarName: "key3", Line: 3, LineContent: "key3 = sk_live_abcdefghijklmnopqrst", FilePath: "shared.env"},
	}

	results := ClassifyTokenBatch(tokens)
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}
	for i, r := range results {
		if r.Prov == "" {
			t.Errorf("result %d: empty provenance", i)
		}
	}
}

// ============================================================================
// 3. Shannon Entropy LUT tests
// ============================================================================

func TestShannonEntropyLUT_Empty(t *testing.T) {
	if got := ShannonEntropyLUT(""); got != 0.0 {
		t.Errorf("ShannonEntropyLUT empty: got %f, want 0.0", got)
	}
}

func TestShannonEntropyLUT_SingleChar(t *testing.T) {
	got := ShannonEntropyLUT("aaaa")
	if got != 0.0 {
		t.Errorf("ShannonEntropyLUT aaaa: got %f, want 0.0", got)
	}
}

func TestShannonEntropyLUT_AccuracyVsOriginal(t *testing.T) {
	testStrings := []string{
		"aB3xY9kL",
		"AKIAxxxxxxxxxxxxxxxxxxxx",
		"ghp_abcdefghijklmnopqrstuvwxyz0123456789",
		"sk_live_4eC39HqLyjWDarjtT1zdp7dc",
		"aaaaaaaaaaaaaaaa",
		"abcdefghijklmnop",
		"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
		strings.Repeat("abcdefghijklmnopqrstuvwxyz0123456789", 5),
		strings.Repeat("a", 512),
		strings.Repeat("xyz", 170),
	}

	for _, s := range testStrings {
		original := ShannonEntropy(s)
		lut := ShannonEntropyLUT(s)
		diff := math.Abs(original - lut)
		if diff > 1e-10 {
			t.Errorf("ShannonEntropyLUT(%q): got %f, want %f (diff=%e)", s, lut, original, diff)
		}
	}
}

func TestShannonEntropyLUT_LongString(t *testing.T) {
	long := strings.Repeat("abcdefghijklmnopqrstuvwxyz0123456789", 20)
	if len(long) <= 512 {
		t.Skip("string not long enough to test fallback path")
	}
	original := ShannonEntropy(long)
	lut := ShannonEntropyLUT(long)
	diff := math.Abs(original - lut)
	if diff > 1e-10 {
		t.Errorf("ShannonEntropyLUT long: got %f, want %f (diff=%e)", lut, original, diff)
	}
}

func BenchmarkShannonEntropyOrig(b *testing.B) {
	s := "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ShannonEntropy(s)
	}
}

func BenchmarkShannonEntropyLUT(b *testing.B) {
	s := "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ShannonEntropyLUT(s)
	}
}

// ============================================================================
// 4. LineHasExtractSignal tests
// ============================================================================

func TestLineHasExtractSignal_Positive(t *testing.T) {
	cases := []struct {
		line string
		want bool
	}{
		{"api_key = AKIA...", true},
		{"token: ghp_...", true},
		{"-----BEGIN PRIVATE KEY-----", true},
		{"password=changeme", true},
		{"export AWS_KEY=abcdef", true},
		{"- SECRET_KEY=value", true},
	}
	for _, tc := range cases {
		got := LineHasExtractSignal(tc.line)
		if got != tc.want {
			t.Errorf("LineHasExtractSignal(%q): got %v, want %v", tc.line, got, tc.want)
		}
	}
}

func TestLineHasExtractSignal_Negative(t *testing.T) {
	cases := []string{
		"this line has no signal chars",
		"just some plain text here",
		"",
		"all letters ABCDEFG",
		"12345 67890",
	}
	for _, line := range cases {
		if LineHasExtractSignal(line) {
			t.Errorf("LineHasExtractSignal(%q): expected false", line)
		}
	}
}

func TestLineHasExtractSignal_EdgeCases(t *testing.T) {
	if LineHasExtractSignal("") {
		t.Error("empty string should return false")
	}
	if !LineHasExtractSignal("=") {
		t.Error("single = should return true")
	}
	if !LineHasExtractSignal(":") {
		t.Error("single : should return true")
	}
	if !LineHasExtractSignal("-") {
		t.Error("single - should return true")
	}
}

// ============================================================================
// 5. Bloom filter tests
// ============================================================================

func TestFindingBloomFilter_Basic(t *testing.T) {
	bf := NewFindingBloomFilter()

	bf.Add("secret_hash_1", "path/to/file1.go")
	bf.Add("secret_hash_2", "path/to/file2.py")

	if !bf.MayContain("secret_hash_1", "path/to/file1.go") {
		t.Error("expected bloom filter to contain (secret_hash_1, file1.go)")
	}
	if !bf.MayContain("secret_hash_2", "path/to/file2.py") {
		t.Error("expected bloom filter to contain (secret_hash_2, file2.py)")
	}
}

func TestFindingBloomFilter_DifferentPairs(t *testing.T) {
	bf := NewFindingBloomFilter()

	bf.Add("hash_a", "file_x")

	if bf.MayContain("hash_a", "file_y") {
		t.Log("WARN: false positive for (hash_a, file_y) -- acceptable but noted")
	}
	if bf.MayContain("hash_b", "file_x") {
		t.Log("WARN: false positive for (hash_b, file_x) -- acceptable but noted")
	}
}

func TestFindingBloomFilter_NoFalseNegatives(t *testing.T) {
	bf := NewFindingBloomFilter()

	entries := make([][2]string, 1000)
	for i := 0; i < 1000; i++ {
		entries[i] = [2]string{
			fmt.Sprintf("secret_%d", i),
			fmt.Sprintf("path/file_%d.go", i),
		}
		bf.Add(entries[i][0], entries[i][1])
	}

	for i, e := range entries {
		if !bf.MayContain(e[0], e[1]) {
			t.Errorf("false negative at entry %d: (%s, %s)", i, e[0], e[1])
		}
	}
}

func TestFindingBloomFilter_Reset(t *testing.T) {
	bf := NewFindingBloomFilter()

	bf.Add("hash1", "file1")
	if !bf.MayContain("hash1", "file1") {
		t.Fatal("expected to contain after Add")
	}

	bf.Reset()
	if bf.MayContain("hash1", "file1") {
		t.Error("expected not to contain after Reset")
	}
}

func TestFindingBloomFilter_FalsePositiveRate(t *testing.T) {
	bf := NewFindingBloomFilter()

	numInsert := 5000
	for i := 0; i < numInsert; i++ {
		bf.Add(fmt.Sprintf("secret_%d", i), fmt.Sprintf("file_%d", i))
	}

	falsePositives := 0
	numTest := 10000
	for i := numInsert; i < numInsert+numTest; i++ {
		if bf.MayContain(fmt.Sprintf("secret_%d", i), fmt.Sprintf("file_%d", i)) {
			falsePositives++
		}
	}

	fpRate := float64(falsePositives) / float64(numTest)
	t.Logf("Bloom filter false positive rate: %.4f%% (%d/%d)", fpRate*100, falsePositives, numTest)
	if fpRate > 0.05 {
		t.Errorf("false positive rate %.4f exceeds 5%% threshold", fpRate)
	}
}
