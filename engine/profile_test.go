package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// BenchmarkFullPipeline profiles the complete scan pipeline on 200 files
func BenchmarkFullPipeline(b *testing.B) {
	dir := b.TempDir()
	for i := 0; i < 200; i++ {
		content := fmt.Sprintf(`
VERSION = "1.0.0"
APP_NAME = "my-application-%d"
api_key_%d = "sk_live_4eC39Hq%04djWDarjtT1zdp7dc"
file_hash = "%s"
request_id = "550e8400-e29b-41d4-a716-446655440000"
db_url = "postgres://admin:s3cretP4ss@host/db"
password = "changeme"
token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcd"
`, i, i, i, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
		for j := 0; j < 100; j++ {
			content += fmt.Sprintf("line_%d = \"value_%d\"\n", j, j)
		}
		os.WriteFile(filepath.Join(dir, fmt.Sprintf("file_%d.py", i)), []byte(content), 0644)
	}

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		ClearFileProvenanceCache()
		_ = ScanDirectory(dir, 0.3, runtime.NumCPU())
	}
}

// BenchmarkExtractTokensLargeFile benchmarks extraction on a 1000-line file
func BenchmarkExtractTokensLargeFile(b *testing.B) {
	var content string
	for i := 0; i < 1000; i++ {
		if i%10 == 0 {
			content += fmt.Sprintf("api_key_%d = \"sk_live_4eC39Hq%04djWDarjtT1zdp7dc\"\n", i, i)
		} else {
			content += fmt.Sprintf("line_%d = \"value_%d_padding\"\n", i, i)
		}
	}
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		_ = ExtractTokens("test.py", content)
	}
}

// BenchmarkClassifyMorphologyEntropy benchmarks the entropy code path
func BenchmarkClassifyMorphologyEntropy(b *testing.B) {
	value := "xK9mP2nQ8rT5vW3yB7cF0hJ4lN6pS1u"
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		ClassifyMorphology(value, RoleNeutral)
	}
}

// BenchmarkClassifySyntacticRole benchmarks variable name classification
func BenchmarkClassifySyntacticRole(b *testing.B) {
	names := []string{"api_key", "hash_value", "config_val", "clientSecret", "AWS_SECRET_KEY"}
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		for _, name := range names {
			ClassifySyntacticRole(name)
		}
	}
}

// BenchmarkFileProvenanceCached benchmarks cached provenance lookup
func BenchmarkFileProvenanceCached(b *testing.B) {
	ClearFileProvenanceCache()
	ClassifyFileProvenance("src/app.py") // prime
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		ClassifyFileProvenance("src/app.py")
	}
}

// BenchmarkFileProvenanceUncached benchmarks uncached provenance
func BenchmarkFileProvenanceUncached(b *testing.B) {
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		ClearFileProvenanceCache()
		ClassifyFileProvenance("src/app.py")
	}
}

// BenchmarkClassifyLineContext benchmarks line context analysis
func BenchmarkClassifyLineContext(b *testing.B) {
	line := `api_key = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"`
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		ClassifyLineContext(line)
	}
}

// BenchmarkIsHexOnly benchmarks hex validation on 64-char string
func BenchmarkIsHexOnly(b *testing.B) {
	s := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		IsHexOnly(s)
	}
}

// BenchmarkClassifyCharset benchmarks charset classification
func BenchmarkClassifyCharset(b *testing.B) {
	s := "sk_live_4eC39HqLyjWDarjtT1zdp7dc1234"
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		ClassifyCharset(s)
	}
}

// BenchmarkFastEntropyCheck benchmarks the fast entropy screen
func BenchmarkFastEntropyCheck(b *testing.B) {
	s := "sk_live_4eC39HqLyjWDarjtT1zdp7dc1234"
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		FastEntropyCheck(s)
	}
}

// TestPerformanceReport generates a performance report
func TestPerformanceReport(t *testing.T) {
	N := 100000

	benchmarks := []struct {
		name string
		fn   func()
	}{
		{"SplitVariableName", func() { SplitVariableName("myAPIKeySecret") }},
		{"IsHexOnly(64)", func() { IsHexOnly("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") }},
		{"IsUUIDFormat", func() { IsUUIDFormat("550e8400-e29b-41d4-a716-446655440000") }},
		{"ClassifyCharset", func() { ClassifyCharset("sk_live_4eC39HqLyjWDarjtT1zdp7dc1234") }},
		{"FastEntropyCheck", func() { FastEntropyCheck("sk_live_4eC39HqLyjWDarjtT1zdp7dc1234") }},
		{"ShannonEntropy", func() { ShannonEntropy("sk_live_4eC39HqLyjWDarjtT1zdp7dc1234") }},
		{"MatchKnownPrefix(hit)", func() { MatchKnownPrefix("sk_live_4eC39HqLyjWDarjtT1zdp7dc") }},
		{"MatchKnownPrefix(miss)", func() { MatchKnownPrefix("xK9mP2nQ8rT5vW3yB7cF0hJ4lN6pS1u") }},
		{"ClassifyLineContext", func() { ClassifyLineContext(`api_key = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"`) }},
	}

	// Prime caches
	ClearFileProvenanceCache()
	ClassifyFileProvenance("src/app.py")

	t.Log("\n=== Go Engine Per-Function Performance (100K iterations) ===")
	t.Logf("%-30s %10s %10s", "Function", "Total", "Per-call")
	t.Logf("%-30s %10s %10s", "--------", "-----", "--------")

	for _, bm := range benchmarks {
		start := time.Now()
		for i := 0; i < N; i++ {
			bm.fn()
		}
		elapsed := time.Since(start)
		perCall := elapsed / time.Duration(N)
		t.Logf("%-30s %10s %10s", bm.name, elapsed.Round(time.Millisecond), perCall)
	}

	// File provenance cached
	start := time.Now()
	for i := 0; i < N; i++ {
		ClassifyFileProvenance("src/app.py")
	}
	t.Logf("%-30s %10s %10s", "FileProvenance(cached)", time.Since(start).Round(time.Millisecond), time.Since(start)/time.Duration(N))

	// Classify token
	tok := Token{Value: "sk_live_4eC39HqLyjWDarjtT1zdp7dc", VarName: "api_key", Line: 1,
		LineContent: `api_key = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"`, FilePath: "src/app.py"}
	start = time.Now()
	for i := 0; i < N/10; i++ {
		ClassifyToken(tok)
	}
	elapsed := time.Since(start)
	t.Logf("%-30s %10s %10s", "ClassifyToken(10K)", elapsed.Round(time.Millisecond), elapsed/time.Duration(N/10))
}
