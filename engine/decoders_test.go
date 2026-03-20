package engine

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestDecodeBase64_WithSecret(t *testing.T) {
	// Encode a string that looks like a secret.
	secret := "API_KEY=sk_live_abc123def456ghi789jkl012mno345"
	encoded := base64.StdEncoding.EncodeToString([]byte(secret))

	results := DecodeContent("some prefix " + encoded + " some suffix")

	found := false
	for _, dc := range results {
		if dc.Encoding == "base64" && strings.Contains(dc.Content, "sk_live_abc123") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected base64 decoder to find secret in encoded content; got %d results", len(results))
		for _, dc := range results {
			t.Logf("  encoding=%s content=%q", dc.Encoding, dc.Content)
		}
	}
}

func TestDecodeBase64_SkipNonSecret(t *testing.T) {
	// Encode random binary-looking data that doesn't have secret hints.
	// Using a string that is valid UTF-8 but has no secret-like content.
	data := "The quick brown fox jumps over the lazy dog repeatedly until we have enough chars"
	encoded := base64.StdEncoding.EncodeToString([]byte(data))

	results := DecodeContent(encoded)

	for _, dc := range results {
		if dc.Encoding == "base64" {
			t.Errorf("expected base64 decoder to skip non-secret content, but got: %q", dc.Content)
		}
	}
}

func TestDecodeEscapedUnicode(t *testing.T) {
	// \u0041\u004B\u0049\u0041 = "AKIA"
	input := `prefix \u0041\u004B\u0049\u0041 suffix`

	results := DecodeContent(input)

	found := false
	for _, dc := range results {
		if dc.Encoding == "escaped_unicode" && strings.Contains(dc.Content, "AKIA") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected escaped_unicode decoder to decode \\uXXXX to AKIA")
		for _, dc := range results {
			t.Logf("  encoding=%s content=%q", dc.Encoding, dc.Content)
		}
	}
}

func TestDecodeHexEscaped(t *testing.T) {
	// \x41\x4B\x49\x41 = "AKIA"
	input := `value = "\x41\x4B\x49\x41"`

	results := DecodeContent(input)

	found := false
	for _, dc := range results {
		if dc.Encoding == "hex_escaped" && strings.Contains(dc.Content, "AKIA") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected hex_escaped decoder to decode \\xNN to AKIA")
		for _, dc := range results {
			t.Logf("  encoding=%s content=%q", dc.Encoding, dc.Content)
		}
	}
}

func TestDecodeContent_RawAlwaysFirst(t *testing.T) {
	results := DecodeContent("hello world")
	if len(results) == 0 {
		t.Fatal("expected at least one result (raw)")
	}
	if results[0].Encoding != "raw" {
		t.Errorf("expected first result to be raw, got %q", results[0].Encoding)
	}
	if results[0].Content != "hello world" {
		t.Errorf("expected raw content to match input, got %q", results[0].Content)
	}
}

func TestDecodeBase64_ConnectionString(t *testing.T) {
	// A base64-encoded connection string.
	secret := "mongodb://admin:p4ssw0rd@db.example.com:27017/production"
	encoded := base64.StdEncoding.EncodeToString([]byte(secret))

	results := DecodeContent("CONFIG=" + encoded)

	found := false
	for _, dc := range results {
		if dc.Encoding == "base64" && strings.Contains(dc.Content, "mongodb://") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected base64 decoder to find connection string")
	}
}
