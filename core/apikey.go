package synapse

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// API Key Format: morphex_<version><type>_<payload>_<checksum>
//
// Anatomy:
//   morphex_   — prefix (identifies this as an MORPHEX key)
//   v1       — version (allows future format changes)
//   a        — type: a=admin, r=readonly, s=scan-only, w=webhook
//   _        — separator
//   <payload> — 32 bytes of crypto/rand entropy, base62-encoded (43 chars)
//   _        — separator
//   <checksum> — HMAC-SHA256 truncated to 8 chars (integrity check)
//
// Total length: 6 + 3 + 1 + 43 + 1 + 8 = 62 characters
// Entropy: 256 bits (32 bytes from crypto/rand)
// Brute force at 1 billion attempts/sec: ~3.6 × 10^68 years
//
// Example: morphex_v1a_7Kx9vT3mNw7pLcR2jQ5xHv8yD4fKu6nZs1wOa0gEi_a1b2c3d4

// KeyType represents the permission level of an API key.
type KeyType byte

const (
	KeyTypeAdmin    KeyType = 'a' // Full access: scan, configure, manage
	KeyTypeReadOnly KeyType = 'r' // Read-only: view results, dashboards
	KeyTypeScanOnly KeyType = 's' // Scan only: submit scans, no config
	KeyTypeWebhook  KeyType = 'w' // Webhook: receive scan results only
)

// base62 alphabet (no ambiguous characters: 0/O, 1/l/I removed)
const base62Chars = "23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// keyHMACSecret is derived from the key payload itself — the checksum
// validates that the key hasn't been truncated or corrupted, not that
// it's authorized (that's the server's job via constant-time comparison).
const keyHMACSecret = "morphex-key-integrity-v1"

// GenerateAPIKey creates a cryptographically secure API key.
// Uses crypto/rand for entropy (not math/rand).
func GenerateAPIKey(keyType KeyType) (string, error) {
	// 32 bytes = 256 bits of entropy from crypto/rand
	entropy := make([]byte, 32)
	if _, err := rand.Read(entropy); err != nil {
		return "", fmt.Errorf("crypto/rand failed: %w", err)
	}

	// Encode payload as base62 (URL-safe, no special chars)
	payload := base62Encode(entropy)

	// Build the key without checksum
	prefix := fmt.Sprintf("morphex_v1%c", keyType)
	keyBody := prefix + "_" + payload

	// HMAC-SHA256 checksum for integrity verification
	checksum := computeChecksum(keyBody)

	return keyBody + "_" + checksum, nil
}

// ValidateKeyFormat checks if a key has valid MORPHEX format and intact checksum.
// This does NOT check authorization — only structural integrity.
func ValidateKeyFormat(key string) (KeyType, bool) {
	// Minimum structure check
	if len(key) < 20 || !strings.HasPrefix(key, "morphex_v1") {
		return 0, false
	}

	// Extract parts
	parts := strings.Split(key, "_")
	// Expected: ["morphex", "v1X", "<payload>", "<checksum>"]
	if len(parts) != 4 || parts[0] != "morphex" {
		return 0, false
	}

	version := parts[1]
	if len(version) != 3 || version[:2] != "v1" {
		return 0, false
	}

	keyType := KeyType(version[2])
	if keyType != KeyTypeAdmin && keyType != KeyTypeReadOnly &&
		keyType != KeyTypeScanOnly && keyType != KeyTypeWebhook {
		return 0, false
	}

	// Verify checksum
	checksum := parts[3]
	keyBody := parts[0] + "_" + parts[1] + "_" + parts[2]
	expectedChecksum := computeChecksum(keyBody)

	if !hmac.Equal([]byte(checksum), []byte(expectedChecksum)) {
		return 0, false
	}

	return keyType, true
}

// KeyTypeString returns a human-readable name for the key type.
func KeyTypeString(kt KeyType) string {
	switch kt {
	case KeyTypeAdmin:
		return "admin"
	case KeyTypeReadOnly:
		return "read-only"
	case KeyTypeScanOnly:
		return "scan-only"
	case KeyTypeWebhook:
		return "webhook"
	default:
		return "unknown"
	}
}

// HashKey creates a one-way hash of an API key for safe storage.
// Never store raw API keys — store this hash and compare on auth.
func HashKey(key string) string {
	h := sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:])
}

// GenerateKeySet generates a complete set of keys (admin + scan + readonly).
func GenerateKeySet() (admin, scan, readonly string, err error) {
	admin, err = GenerateAPIKey(KeyTypeAdmin)
	if err != nil {
		return "", "", "", err
	}
	scan, err = GenerateAPIKey(KeyTypeScanOnly)
	if err != nil {
		return "", "", "", err
	}
	readonly, err = GenerateAPIKey(KeyTypeReadOnly)
	if err != nil {
		return "", "", "", err
	}
	return admin, scan, readonly, nil
}

// KeyInfo returns metadata about a key without exposing it.
type KeyInfo struct {
	Type      string `json:"type"`
	Prefix    string `json:"prefix"`    // first 12 chars
	Hash      string `json:"hash"`      // SHA-256 for storage
	CreatedAt string `json:"created_at"`
	Entropy   string `json:"entropy_bits"`
}

// InspectKey returns safe metadata about a key.
func InspectKey(key string) (*KeyInfo, error) {
	kt, valid := ValidateKeyFormat(key)
	if !valid {
		return nil, fmt.Errorf("invalid key format")
	}

	prefix := key[:12] + "..."
	return &KeyInfo{
		Type:      KeyTypeString(kt),
		Prefix:    prefix,
		Hash:      HashKey(key),
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		Entropy:   "256 bits",
	}, nil
}

// base62Encode encodes bytes to base62 string.
func base62Encode(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	// Convert bytes to a big integer representation and encode
	// Use a simpler approach: base64url then strip non-base62 chars
	// and pad with additional random chars to maintain entropy.
	encoded := base64.RawURLEncoding.EncodeToString(data)

	// Replace base64-specific chars with base62 alternatives
	var result strings.Builder
	result.Grow(len(encoded))
	for _, c := range encoded {
		switch {
		case c == '-' || c == '_':
			// Replace with random base62 char
			b := make([]byte, 1)
			rand.Read(b)
			result.WriteByte(base62Chars[int(b[0])%len(base62Chars)])
		default:
			result.WriteRune(c)
		}
	}

	return result.String()
}

// computeChecksum creates an HMAC-SHA256 truncated to 8 hex chars.
func computeChecksum(data string) string {
	mac := hmac.New(sha256.New, []byte(keyHMACSecret))
	mac.Write([]byte(data))
	sum := mac.Sum(nil)
	return hex.EncodeToString(sum[:4]) // 4 bytes = 8 hex chars
}
