package engine

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// DecodedContent represents a decoded variant of some content that may
// contain secrets invisible in the original encoding.
type DecodedContent struct {
	Content  string
	Encoding string // "raw", "base64", "utf16", "escaped_unicode", "hex_escaped"
	Offset   int    // byte offset in original content where this was found
}

// DecodeContent applies all decoders to content and returns decoded variants.
// The first element is always the raw content itself. Subsequent elements are
// decoded fragments that may reveal hidden secrets.
func DecodeContent(content string) []DecodedContent {
	results := []DecodedContent{
		{Content: content, Encoding: "raw", Offset: 0},
	}

	results = append(results, decodeBase64Chunks(content)...)
	results = append(results, decodeUTF16(content)...)
	results = append(results, decodeEscapedUnicode(content)...)
	results = append(results, decodeHexEscaped(content)...)

	return results
}

// ---------------------------------------------------------------------------
// Decoder 1: Base64
// ---------------------------------------------------------------------------

// base64RE matches base64-encoded chunks of at least 16 characters whose
// length is divisible by 4. It captures runs of the base64 charset (including
// standard and URL-safe) with optional trailing '=' padding.
var base64RE = regexp.MustCompile(`[A-Za-z0-9+/\-_]{16,}={0,3}`)

// secretHints are substrings that, if present in decoded base64 content,
// suggest the content may harbour a secret.
var secretHints = []string{
	"=", "key", "token", "secret", "password", "passwd", "pwd",
	"api", "auth", "bearer", "credential", "conn", "dsn",
	"private", "-----BEGIN", "mysql://", "postgres://", "mongodb://",
	"redis://", "amqp://", "sk_live", "sk_test", "rk_live", "rk_test",
	"AKIA", "ghp_", "gho_", "ghs_", "github_pat_",
	"xox", "hook.slack.com",
}

func decodeBase64Chunks(content string) []DecodedContent {
	var results []DecodedContent

	matches := base64RE.FindAllStringIndex(content, -1)
	for _, loc := range matches {
		chunk := content[loc[0]:loc[1]]

		// Length must be divisible by 4 (after stripping whitespace).
		raw := strings.TrimRight(chunk, "=")
		padded := chunk
		if len(raw)%4 != 0 {
			// Try to fix padding.
			padded = raw + strings.Repeat("=", (4-len(raw)%4)%4)
		}
		if len(padded)%4 != 0 {
			continue
		}

		// Try standard base64 first, then URL-safe.
		decoded, err := base64.StdEncoding.DecodeString(padded)
		if err != nil {
			decoded, err = base64.URLEncoding.DecodeString(padded)
			if err != nil {
				continue
			}
		}

		// Only keep if the decoded output looks like it could contain a secret.
		if !utf8.Valid(decoded) {
			continue
		}

		decodedStr := string(decoded)
		if looksLikeSecret(decodedStr) {
			results = append(results, DecodedContent{
				Content:  decodedStr,
				Encoding: "base64",
				Offset:   loc[0],
			})
		}
	}

	return results
}

// looksLikeSecret performs a lightweight heuristic check to decide whether
// decoded content is worth scanning for secrets.
func looksLikeSecret(s string) bool {
	lower := strings.ToLower(s)
	for _, hint := range secretHints {
		if strings.Contains(lower, strings.ToLower(hint)) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Decoder 2: UTF-16
// ---------------------------------------------------------------------------

func decodeUTF16(content string) []DecodedContent {
	data := []byte(content)
	if len(data) < 2 {
		return nil
	}

	var order binary.ByteOrder
	var bomLen int

	switch {
	case data[0] == 0xFF && data[1] == 0xFE:
		order = binary.LittleEndian
		bomLen = 2
	case data[0] == 0xFE && data[1] == 0xFF:
		order = binary.BigEndian
		bomLen = 2
	default:
		return nil
	}

	payload := data[bomLen:]
	// Need an even number of bytes.
	if len(payload)%2 != 0 {
		payload = payload[:len(payload)-1]
	}
	if len(payload) == 0 {
		return nil
	}

	u16s := make([]uint16, len(payload)/2)
	for i := range u16s {
		if order == binary.LittleEndian {
			u16s[i] = binary.LittleEndian.Uint16(payload[i*2:])
		} else {
			u16s[i] = binary.BigEndian.Uint16(payload[i*2:])
		}
	}

	runes := utf16.Decode(u16s)
	decoded := string(runes)

	if len(decoded) == 0 {
		return nil
	}

	return []DecodedContent{
		{Content: decoded, Encoding: "utf16", Offset: 0},
	}
}

// ---------------------------------------------------------------------------
// Decoder 3: Escaped Unicode (\uXXXX and \UXXXXXXXX)
// ---------------------------------------------------------------------------

var escapedUnicodeRE = regexp.MustCompile(`(?:\\u[0-9a-fA-F]{4})+`)
var escapedUnicodeLongRE = regexp.MustCompile(`(?:\\U[0-9a-fA-F]{8})+`)

func decodeEscapedUnicode(content string) []DecodedContent {
	var results []DecodedContent

	// \uXXXX sequences
	for _, loc := range escapedUnicodeRE.FindAllStringIndex(content, -1) {
		chunk := content[loc[0]:loc[1]]
		decoded := decodeUnicodeEscapes(chunk, 6) // \uXXXX = 6 chars each
		if decoded != "" && decoded != chunk {
			results = append(results, DecodedContent{
				Content:  decoded,
				Encoding: "escaped_unicode",
				Offset:   loc[0],
			})
		}
	}

	// \UXXXXXXXX sequences
	for _, loc := range escapedUnicodeLongRE.FindAllStringIndex(content, -1) {
		chunk := content[loc[0]:loc[1]]
		decoded := decodeUnicodeEscapesLong(chunk)
		if decoded != "" && decoded != chunk {
			results = append(results, DecodedContent{
				Content:  decoded,
				Encoding: "escaped_unicode",
				Offset:   loc[0],
			})
		}
	}

	return results
}

func decodeUnicodeEscapes(s string, unitLen int) string {
	var b strings.Builder
	for i := 0; i+unitLen <= len(s); i += unitLen {
		// Each unit is \uXXXX
		unit := s[i : i+unitLen]
		if !strings.HasPrefix(unit, `\u`) && !strings.HasPrefix(unit, `\U`) {
			return ""
		}
		hex := unit[2:]
		var cp uint32
		if _, err := fmt.Sscanf(hex, "%x", &cp); err != nil {
			return ""
		}
		b.WriteRune(rune(cp))
	}
	return b.String()
}

func decodeUnicodeEscapesLong(s string) string {
	var b strings.Builder
	unitLen := 10 // \UXXXXXXXX
	for i := 0; i+unitLen <= len(s); i += unitLen {
		unit := s[i : i+unitLen]
		if !strings.HasPrefix(unit, `\U`) {
			return ""
		}
		hex := unit[2:]
		var cp uint32
		if _, err := fmt.Sscanf(hex, "%x", &cp); err != nil {
			return ""
		}
		b.WriteRune(rune(cp))
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// Decoder 4: Hex-escaped strings (\xNN sequences)
// ---------------------------------------------------------------------------

var hexEscapedRE = regexp.MustCompile(`(?:\\x[0-9a-fA-F]{2}){2,}`)

func decodeHexEscaped(content string) []DecodedContent {
	var results []DecodedContent

	for _, loc := range hexEscapedRE.FindAllStringIndex(content, -1) {
		chunk := content[loc[0]:loc[1]]
		decoded := decodeHexEscapeSeq(chunk)
		if decoded != "" && decoded != chunk {
			results = append(results, DecodedContent{
				Content:  decoded,
				Encoding: "hex_escaped",
				Offset:   loc[0],
			})
		}
	}

	return results
}

func decodeHexEscapeSeq(s string) string {
	var bytes []byte
	for i := 0; i+4 <= len(s); i += 4 {
		unit := s[i : i+4]
		if !strings.HasPrefix(unit, `\x`) {
			return ""
		}
		hex := unit[2:]
		var b byte
		if _, err := fmt.Sscanf(hex, "%x", &b); err != nil {
			return ""
		}
		bytes = append(bytes, b)
	}
	if !utf8.Valid(bytes) {
		// Return it anyway; it might be ASCII.
		return string(bytes)
	}
	return string(bytes)
}
