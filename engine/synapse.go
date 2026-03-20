// Package engine implements SYNAPSE v2 -- Algorithmically Reinvented Secret Scanner.
//
// This is a behavioral-exact Go port of synapse_v2.py. Every classification,
// confidence value, and decision tree path produces identical output.
package engine

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
)

// ============================================================================
// TYPES
// ============================================================================

// Provenance indicates the origin classification of a secret candidate.
type Provenance string

const (
	ProvenanceAuthCredential Provenance = "AUTH_CREDENTIAL"
	ProvenanceHumanAuthored  Provenance = "HUMAN_AUTHORED"
	ProvenanceBuildGenerated Provenance = "BUILD_GENERATED"
	ProvenanceDocExample     Provenance = "DOC_EXAMPLE"
	ProvenanceDerivedValue   Provenance = "DERIVED_VALUE"
	ProvenanceUncertain      Provenance = "UNCERTAIN"
)

// Morphology describes the structural shape of a value.
type Morphology string

const (
	MorphologyPrefixedRandom      Morphology = "prefixed_random"
	MorphologyStructuredRandom    Morphology = "structured_random"
	MorphologyHumanTyped          Morphology = "human_typed"
	MorphologyMachineRandom       Morphology = "machine_random"
	MorphologyEncodedPayload      Morphology = "encoded_payload"
	MorphologyTemplatePlaceholder Morphology = "template_placeholder"
	MorphologyConnectionString    Morphology = "connection_string"
	MorphologyPrivateKey          Morphology = "private_key"
	MorphologyJWT                 Morphology = "jwt"
)

// SyntacticRole describes the variable name's credential relevance.
type SyntacticRole string

const (
	RoleStrongCredential SyntacticRole = "strong_credential"
	RoleWeakCredential   SyntacticRole = "weak_credential"
	RoleAntiCredential   SyntacticRole = "anti_credential"
	RoleNeutral          SyntacticRole = "neutral"
)

// Token represents an extracted key-value pair from source code.
type Token struct {
	Value       string
	VarName     string
	Line        int
	LineContent string
	FilePath    string
}

// SignalResult captures a single classification signal.
type SignalResult struct {
	Name       string  `json:"name"`
	Value      string  `json:"value"`
	Confidence float64 `json:"confidence"`
	ReasonText string  `json:"reasoning"`
}

// Classification is the full classification of a token.
type Classification struct {
	Prov    Provenance
	Conf    float64
	Signals []SignalResult
	Tok     Token
}

// Reasoning returns a human-readable summary of all signals.
func (c Classification) Reasoning() string {
	parts := make([]string, len(c.Signals))
	for i, s := range c.Signals {
		parts[i] = fmt.Sprintf("%s=%s(%.0f%%): %s", s.Name, s.Value, s.Confidence*100, s.ReasonText)
	}
	return strings.Join(parts, " | ")
}

// Finding is the JSON-serializable output of a detected secret.
type Finding struct {
	File         string                   `json:"file"`
	Line         int                      `json:"line"`
	MatchedValue string                   `json:"matched_value"`
	Detector     string                   `json:"detector"`
	Confidence   float64                  `json:"confidence"`
	Provenance   string                   `json:"provenance"`
	Signals      []map[string]interface{} `json:"signals"`
	ReasoningStr string                   `json:"description"`
}

// ============================================================================
// VOCABULARY
// ============================================================================

var credentialAtoms map[string]struct{}
var credentialCompounds map[string]struct{}
var antiCredentialAtoms map[string]struct{}
var placeholderWords map[string]struct{}
var placeholderPasswords map[string]struct{}
var lockFiles map[string]struct{}
var skipExtensions map[string]struct{}
var skipDirs map[string]struct{}

func toSet(items []string) map[string]struct{} {
	m := make(map[string]struct{}, len(items))
	for _, item := range items {
		m[item] = struct{}{}
	}
	return m
}

func init() {
	credentialAtoms = toSet([]string{
		"key", "token", "secret", "password", "passwd", "pwd", "pass",
		"credential", "auth", "bearer", "oauth",
		"apikey",
		"private", "signing", "encryption", "master",
		"dsn", "conn",
	})

	credentialCompounds = toSet([]string{
		"api_key", "apikey", "api_secret", "apisecret",
		"access_key", "accesskey", "access_token", "accesstoken",
		"secret_key", "secretkey", "private_key", "privatekey",
		"auth_token", "authtoken", "bearer_token", "bearertoken",
		"client_secret", "clientsecret", "client_id",
		"session_token", "sessiontoken", "refresh_token", "refreshtoken",
		"webhook_secret", "webhooksecret", "app_secret", "appsecret",
		"consumer_secret", "consumersecret", "signing_key", "signingkey",
		"encryption_key", "encryptionkey", "master_key", "masterkey",
		"db_password", "db_pass", "database_password", "database_url",
		"connection_string", "connectionstring", "conn_str", "connstr",
		"aws_secret", "aws_access", "stripe_key", "slack_token",
		"github_token", "gitlab_token",
	})

	antiCredentialAtoms = toSet([]string{
		"hash", "digest", "checksum", "sha", "md5", "crc", "fingerprint",
		"uuid", "guid",
		"version", "revision", "build",
		"encoding", "encoded", "format", "pattern", "regex",
		"description", "comment", "note", "label", "title", "name",
		"color", "colour", "font", "size", "width", "height",
		"message", "msg", "text", "content", "body",
		"path", "file", "dir", "directory", "folder",
		"url", "uri", "endpoint", "host", "port", "address",
		"test", "mock", "fake", "dummy", "sample", "example",
		"nist", "fixture", "stub", "placeholder",
		"cipher", "plaintext", "ciphertext", "iv", "nonce", "tag",
	})

	placeholderWords = toSet([]string{
		"changeme", "placeholder", "replaceme", "yourkeyhere",
		"replacewithyourkey", "insertyourkeyhere", "addyourkeyhere",
		"replacewithyourtoken", "insertyourtokenhere", "yourtokenhere",
		"replacewithyoursecret", "yoursecrethere", "enteryourkeyhere",
		"insertkeyhere", "addyourkeyhere", "putyourkeyhere",
		"xxxxxxxx", "abcdefgh", "example_key", "sample_key",
		"your_api_key", "your_token", "dummy_key", "fake_key",
	})

	placeholderPasswords = toSet([]string{
		"password", "changeme", "secret", "pass",
		"test", "admin", "root", "123456", "default",
	})

	lockFiles = toSet([]string{
		"package-lock.json", "yarn.lock", "cargo.lock", "go.sum",
		"composer.lock", "gemfile.lock", "poetry.lock", "pnpm-lock.yaml",
	})

	skipExtensions = toSet([]string{
		".exe", ".dll", ".so", ".dylib", ".bin", ".o", ".a", ".lib",
		".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".bmp", ".webp",
		".mp3", ".mp4", ".wav", ".avi", ".mov", ".flv",
		".zip", ".tar", ".gz", ".bz2", ".xz", ".rar", ".7z",
		".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
		".woff", ".woff2", ".ttf", ".eot", ".otf",
		".pyc", ".pyo", ".class", ".jar", ".war",
		".min.js", ".min.css", ".map",
		".snap", ".snapshot",
		".parquet", ".avro", ".orc", ".arrow",
		".pb", ".pb.go", ".pb.h", ".pb.cc",
		".lp", ".lottie",
		".nib", ".storyboardc", ".car",
		".wasm", ".dex",
		".sqlite", ".db", ".mdb", ".ldb",
		".pem.bak", ".der", ".crt", ".cer", ".p12", ".pfx",
		".dat", ".dump", ".core",
		".tsbuildinfo",
		".beam", ".elc",
		".sublime-completions", ".sublime-snippet", ".sublime-syntax",
		".tmLanguage", ".tmTheme", ".tmSnippet", ".tmPreferences",
		".vsix",
	})

	skipDirs = toSet([]string{
		".git", "node_modules", "vendor", "__pycache__", ".venv", "venv",
		".tox", ".eggs", "dist", "build", ".cache", ".npm",
		".gradle", ".idea", ".vs", ".vscode",
		"target", "Pods", "DerivedData",
		".next", ".nuxt", ".output",
		"coverage", ".nyc_output",
		"test_fixtures", "testdata", "fixtures",
		"javadoc", "apidocs", "typedoc",
		"_site", "site-packages",
	})
}

// ============================================================================
// INDEX-BASED VARIABLE NAME SPLITTING
// ============================================================================

// SplitVariableName splits a variable name into lowercase atoms using
// index-based slicing. Handles camelCase, PascalCase, ACRONYMS, and
// separator characters (-_./\ \t).
// OPTIMIZATION: Inline lowercase during word emit. Avoids per-word
// strings.ToLower allocation (was 16% of total CPU via pprof).
// Uses a stack buffer for words up to 32 chars (zero heap alloc for common names).
func SplitVariableName(name string) []string {
	if len(name) == 0 {
		return nil
	}

	var words []string
	n := len(name)
	i := 0

	// Skip leading separators
	for i < n && !isAlphaNumeric(name[i]) {
		i++
	}
	wordStart := i

	for i < n {
		ch := name[i]

		// Separator: emit word, skip separators
		if ch == '-' || ch == '_' || ch == '.' || ch == '/' || ch == '\\' || ch == ' ' || ch == '\t' {
			if i > wordStart {
				words = append(words, toLowerInline(name[wordStart:i]))
			}
			i++
			for i < n {
				c := name[i]
				if c == '-' || c == '_' || c == '.' || c == '/' || c == '\\' || c == ' ' || c == '\t' {
					i++
				} else {
					break
				}
			}
			wordStart = i
			continue
		}

		// camelCase boundary: lowercase -> uppercase
		if i > wordStart && isUpper(ch) && isLower(name[i-1]) {
			words = append(words, toLowerInline(name[wordStart:i]))
			wordStart = i
			i++
			continue
		}

		// Acronym boundary: "APIKey" -> ["api", "key"]
		if i > wordStart+1 && isLower(ch) && isUpper(name[i-1]) && isUpper(name[i-2]) {
			words = append(words, toLowerInline(name[wordStart:i-1]))
			wordStart = i - 1
			i++
			continue
		}

		i++
	}

	if i > wordStart {
		words = append(words, toLowerInline(name[wordStart:i]))
	}

	return words
}

// toLowerInline converts ASCII string to lowercase without allocation
// when the input is already lowercase (common case for snake_case atoms).
func toLowerInline(s string) string {
	// Fast path: check if already lowercase
	allLower := true
	for i := 0; i < len(s); i++ {
		if s[i] >= 'A' && s[i] <= 'Z' {
			allLower = false
			break
		}
	}
	if allLower {
		return s // zero-copy return
	}

	// Need conversion — use stack buffer for short words
	buf := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			buf[i] = c + 32
		} else {
			buf[i] = c
		}
	}
	return string(buf)
}

func isAlphaNumeric(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

func isAlpha(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isUpper(c byte) bool {
	return c >= 'A' && c <= 'Z'
}

func isLower(c byte) bool {
	return c >= 'a' && c <= 'z'
}

// toLowerByte converts an ASCII byte to lowercase.
func toLowerByte(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 32
	}
	return c
}

// indexFold finds the first case-insensitive occurrence of needle in haystack.
// Zero-allocation: no strings.ToLower needed.
func indexFold(haystack, needle string) int {
	hn := len(haystack)
	nn := len(needle)
	if nn == 0 {
		return 0
	}
	if nn > hn {
		return -1
	}
	firstLower := toLowerByte(needle[0])
	for i := 0; i <= hn-nn; i++ {
		if toLowerByte(haystack[i]) != firstLower {
			continue
		}
		match := true
		for j := 1; j < nn; j++ {
			if toLowerByte(haystack[i+j]) != toLowerByte(needle[j]) {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// ============================================================================
// CHARACTER CHECKS
// ============================================================================

// IsHexOnly returns true if s is non-empty and contains only hex characters.
func IsHexOnly(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// IsUUIDFormat returns true if s matches UUID format (8-4-4-4-12 hex with dashes).
func IsUUIDFormat(s string) bool {
	if len(s) != 36 {
		return false
	}
	if !(s[8] == '-' && s[13] == '-' && s[18] == '-' && s[23] == '-') {
		return false
	}
	for i := 0; i < 36; i++ {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			continue
		}
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// ============================================================================
// CHARSET CLASSIFICATION (LUT)
// ============================================================================

// charsetLUT: 0=mixed, 1=hex, 2=alpha-non-hex, 3=base64-special, 4=padding
var charsetLUT [128]byte

func init() {
	for _, c := range "0123456789abcdefABCDEF" {
		charsetLUT[c] = 1
	}
	for _, c := range "ghijklmnopqrstuvwxyzGHIJKLMNOPQRSTUVWXYZ" {
		charsetLUT[c] = 2
	}
	charsetLUT['+'] = 3
	charsetLUT['/'] = 3
	charsetLUT['='] = 4
}

// ClassifyCharset classifies the character set of a string using a lookup table.
func ClassifyCharset(s string) string {
	hasHexOnly := true
	hasNonAlnum := false
	hasBase64Signal := false

	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 128 {
			hasNonAlnum = true
			hasHexOnly = false
			continue
		}
		cls := charsetLUT[c]
		switch cls {
		case 0: // mixed/unknown
			hasNonAlnum = true
			hasHexOnly = false
		case 1: // hex
			// pass
		case 2: // alpha non-hex
			hasHexOnly = false
		case 3: // base64 special (+/)
			hasBase64Signal = true
			hasHexOnly = false
		case 4: // padding (=)
			hasBase64Signal = true
			hasHexOnly = false
		}
	}

	if hasHexOnly && len(s) > 0 {
		return "hex"
	}
	if hasBase64Signal && !hasNonAlnum {
		return "base64"
	}
	if !hasNonAlnum && !hasBase64Signal {
		return "alphanum"
	}
	return "mixed"
}

// ============================================================================
// ENTROPY
// ============================================================================

// FastEntropyCheck performs a fast screen to reject low-entropy strings.
func FastEntropyCheck(s string) bool {
	n := len(s)
	if n < 16 {
		return false
	}
	// Count unique bytes
	var seen [256]bool
	unique := 0
	for i := 0; i < n; i++ {
		if !seen[s[i]] {
			seen[s[i]] = true
			unique++
		}
	}
	ratio := float64(unique) / float64(n)
	if ratio <= 0.25 {
		return false
	}
	if ratio > 0.85 && n > 20 {
		return true
	}
	if ratio < 0.35 && n < 30 {
		return false
	}
	return true
}

// ShannonEntropy computes the Shannon entropy of a string in bits.
func ShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}
	var freq [256]int
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	length := float64(len(s))
	entropy := 0.0
	for _, count := range freq {
		if count == 0 {
			continue
		}
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// IsBase64Binary returns true if s is valid base64 that decodes to mostly binary data.
func IsBase64Binary(s string) bool {
	n := len(s)
	if n < 16 || n%4 != 0 {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return false
	}
	if len(decoded) == 0 {
		return false
	}
	printable := 0
	for _, b := range decoded {
		if b >= 32 && b <= 126 {
			printable++
		}
	}
	return float64(printable)/float64(len(decoded)) < 0.7
}

// ============================================================================
// HYBRID PREFIX MATCHING
// ============================================================================

// KnownPrefixes is the exported map of prefix strings to ecosystem names.
// knownPrefixes is used internally.
var KnownPrefixes = map[string]string{
	"AKIA":           "aws_access_key",
	"ASIA":           "aws_session_key",
	"ghp_":           "github_pat",
	"gho_":           "github_oauth",
	"ghs_":           "github_app",
	"ghu_":           "github_user",
	"github_pat_":    "github_pat_v2",
	"sk_live_":       "stripe_live",
	"pk_live_":       "stripe_publishable",
	"rk_live_":       "stripe_restricted",
	"sk_test_":       "stripe_test",
	"xoxb-":          "slack_bot",
	"xoxp-":          "slack_user",
	"xoxa-":          "slack_app",
	"xoxr-":          "slack_refresh",
	"SG.":            "sendgrid",
	"hf_":            "huggingface",
	"sq0csp-":        "square",
	"EAACEdEose0cBA": "facebook",
	"ya29.":          "google_oauth",
	"AIza":           "google_api",
	"glpat-":         "gitlab_pat",
}

type prefixEntry struct {
	prefix    string
	ecosystem string
}

// prefixByFirstChar maps first character to list of (prefix, ecosystem) sorted by prefix length descending.
var prefixByFirstChar map[byte][]prefixEntry
var prefixFirstChars [256]bool

func init() {
	prefixByFirstChar = make(map[byte][]prefixEntry)
	for p, e := range KnownPrefixes {
		fc := p[0]
		prefixByFirstChar[fc] = append(prefixByFirstChar[fc], prefixEntry{p, e})
	}
	// Sort each bucket by prefix length descending (longest match first)
	for k := range prefixByFirstChar {
		bucket := prefixByFirstChar[k]
		sort.Slice(bucket, func(i, j int) bool {
			return len(bucket[i].prefix) > len(bucket[j].prefix)
		})
		prefixFirstChars[k] = true
	}
}

// MatchKnownPrefix performs hybrid prefix matching with first-char bucket index.
// Returns (prefix, ecosystem, true) on match, or ("", "", false) on miss.
func MatchKnownPrefix(value string) (string, string, bool) {
	if len(value) == 0 || !prefixFirstChars[value[0]] {
		return "", "", false
	}
	for _, entry := range prefixByFirstChar[value[0]] {
		if strings.HasPrefix(value, entry.prefix) {
			return entry.prefix, entry.ecosystem, true
		}
	}
	return "", "", false
}

// ============================================================================
// VALUE SHAPE ANALYSIS — Identifier vs Random Token Detection
// ============================================================================

// commonIdentWords contains English words that commonly appear in snake_case
// variable/function/file names. If the remainder after a known prefix consists
// entirely of these words joined by underscores, the value is an identifier
// (e.g. hf_model_name) not a credential (e.g. hf_aBcDeFgHiJk).
var commonIdentWords = map[string]struct{}{
	"model": {}, "name": {}, "text": {}, "generation": {}, "conversational": {},
	"models": {}, "names": {}, "data": {}, "file": {}, "path": {}, "dir": {},
	"type": {}, "types": {}, "list": {}, "config": {}, "info": {}, "meta": {},
	"metadata": {}, "task": {}, "tasks": {}, "hub": {}, "repo": {}, "id": {},
	"url": {}, "uri": {}, "api": {}, "key": {}, "token": {}, "secret": {},
	"auth": {}, "user": {}, "account": {}, "project": {}, "org": {},
	"test": {}, "prod": {}, "dev": {}, "staging": {}, "env": {},
	"input": {}, "output": {}, "result": {}, "results": {}, "value": {},
	"cache": {}, "client": {}, "server": {}, "host": {}, "port": {},
	"index": {}, "count": {}, "size": {}, "length": {}, "max": {}, "min": {},
	"format": {}, "string": {}, "int": {}, "bool": {}, "float": {},
	"params": {}, "param": {}, "args": {}, "arg": {}, "options": {}, "option": {},
	"response": {}, "request": {}, "header": {}, "headers": {}, "body": {},
	"status": {}, "code": {}, "error": {}, "message": {}, "log": {},
	"version": {}, "tag": {}, "tags": {}, "label": {}, "labels": {},
	"prefix": {}, "suffix": {}, "base": {}, "root": {}, "home": {},
	"endpoint": {}, "endpoints": {}, "service": {}, "provider": {},
	"region": {}, "zone": {}, "cluster": {}, "namespace": {},
	"manager": {}, "handler": {}, "callback": {}, "hook": {},
	"deploy": {}, "build": {}, "run": {}, "start": {}, "stop": {},
}

// looksLikeIdentifier returns true when the string looks like a programming
// identifier rather than a random credential token. An identifier is:
//   - all lowercase (or all uppercase) letters, digits, and underscores
//   - contains at least one underscore (multi-word identifier) OR
//     is a single word >= 4 chars that exists in commonIdentWords
//   - every underscore-delimited segment is a recognisable word
func looksLikeIdentifier(s string) bool {
	if len(s) < 3 {
		return false
	}
	hasLower := false
	hasUpper := false
	hasUnderscore := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
			hasLower = true
		case c >= 'A' && c <= 'Z':
			hasUpper = true
		case c == '_':
			hasUnderscore = true
		case c >= '0' && c <= '9':
			// digits are fine
		default:
			return false
		}
	}
	if hasLower && hasUpper {
		return false
	}
	if !hasUnderscore {
		_, ok := commonIdentWords[strings.ToLower(s)]
		return ok
	}
	for _, seg := range strings.Split(strings.ToLower(s), "_") {
		if seg == "" || len(seg) <= 2 {
			continue
		}
		if _, ok := commonIdentWords[seg]; !ok {
			return false
		}
	}
	return true
}

// isFileExtension returns true for common source/data file extensions.
func isFileExtension(ext string) bool {
	switch ext {
	case ".txt", ".json", ".yaml", ".yml", ".xml", ".csv", ".log",
		".py", ".go", ".js", ".ts", ".rb", ".java", ".rs", ".c", ".h",
		".cfg", ".ini", ".conf", ".toml", ".md", ".html", ".css":
		return true
	}
	return false
}

// ============================================================================
// SIGNAL 1: SYNTACTIC ROLE
// ============================================================================

// ClassifySyntacticRole classifies a variable name's credential relevance.
// OPTIMIZATION: Zero-alloc matching. Eliminates toSet(), intersect(), sortedKeys()
// which previously created 3 maps + 1 slice per call. Now uses direct slice iteration
// against vocab maps (2-4 atoms, linear scan faster than hash creation).
func ClassifySyntacticRole(varName string) (SyntacticRole, float64, string) {
	if varName == "" {
		return RoleNeutral, 0.5, "no variable name available"
	}

	normalized := strings.ToLower(strings.ReplaceAll(varName, "-", "_"))

	if _, ok := credentialCompounds[normalized]; ok {
		return RoleStrongCredential, 0.9, "'" + varName + "' is a known credential variable name"
	}

	atoms := SplitVariableName(varName)

	// Direct matching against vocab maps — no intermediate map allocation
	var credHits []string
	var antiHits []string
	hasApi := false

	for _, atom := range atoms {
		if _, ok := credentialAtoms[atom]; ok {
			credHits = append(credHits, atom)
		}
		if _, ok := antiCredentialAtoms[atom]; ok {
			antiHits = append(antiHits, atom)
		}
		if atom == "api" {
			hasApi = true
		}
	}

	if len(credHits) > 0 && len(antiHits) == 0 {
		sort.Strings(credHits)
		return RoleStrongCredential, 0.8, "contains credential terms: " + strings.Join(credHits, ", ")
	}

	if len(credHits) > 0 && len(antiHits) > 0 {
		sort.Strings(credHits)
		sort.Strings(antiHits)
		return RoleNeutral, 0.4, "ambiguous: cred=" + fmt.Sprint(credHits) + " anti=" + fmt.Sprint(antiHits)
	}

	if len(antiHits) > 0 {
		sort.Strings(antiHits)
		return RoleAntiCredential, 0.2, "contains anti-credential terms: " + strings.Join(antiHits, ", ")
	}

	if hasApi {
		return RoleWeakCredential, 0.6, "'api' in name but no key/token/secret"
	}

	return RoleNeutral, 0.5, "no credential signal in '" + varName + "'"
}

// ============================================================================
// SIGNAL 2: VALUE MORPHOLOGY
// ============================================================================

var (
	connectionStringRE   = regexp.MustCompile(`(?i)(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|mssql|sqlserver)://`)
	connectionStringPwRE = regexp.MustCompile(`://[^:]*:([^@]+)@`)
	placeholderPatternRE = regexp.MustCompile(`^[xX]{4,}$`)
	placeholderDotsRE    = regexp.MustCompile(`^[.]{4,}$`)
	placeholderYourRE    = regexp.MustCompile(`(?i)^your[_-].*[_-]here$`)
	jwtPartRE            = regexp.MustCompile(`^[A-Za-z0-9_-]+={0,2}$`)
)

// ClassifyMorphology classifies the structural shape of a value.
func ClassifyMorphology(value string, varRole SyntacticRole) (Morphology, map[string]interface{}, string) {
	// Fast path: known prefix
	prefix, ecosystem, found := MatchKnownPrefixTrie(value)
	if found {
		// Check if the value after the prefix is a placeholder
		remainder := strings.ToLower(value[len(prefix):])
		if strings.Contains(remainder, "your") || strings.Contains(remainder, "here") ||
			strings.Contains(remainder, "replace") || strings.Contains(remainder, "insert") ||
			strings.Contains(remainder, "example") || strings.Contains(remainder, "xxxxx") ||
			strings.Contains(remainder, "dummy") || strings.Contains(remainder, "fake") ||
			strings.Contains(remainder, "todo") || strings.Contains(remainder, "change") ||
			strings.Contains(remainder, "sample") || strings.Contains(remainder, "notreal") ||
			strings.Contains(remainder, "placeholder") || strings.Contains(remainder, "default") {
			return MorphologyTemplatePlaceholder, map[string]interface{}{},
				fmt.Sprintf("known prefix '%s' but placeholder value '%s'", prefix, remainder)
		}
		// Check if the value is an identifier (variable/function name) rather than
		// a credential. Real tokens like hf_aBcDeFgHiJk have random chars after
		// the prefix. Identifiers like hf_model_name are all lowercase with
		// underscores and recognisable English words.
		if looksLikeIdentifier(remainder) {
			return MorphologyHumanTyped, map[string]interface{}{},
				fmt.Sprintf("prefix '%s' but remainder '%s' is an identifier, not a token", prefix, remainder)
		}
		// Also catch file names: hf_text_generation_models.txt
		if dotIdx := strings.LastIndex(remainder, "."); dotIdx > 0 {
			base := remainder[:dotIdx]
			ext := remainder[dotIdx:]
			if isFileExtension(ext) && looksLikeIdentifier(base) {
				return MorphologyHumanTyped, map[string]interface{}{},
					fmt.Sprintf("prefix '%s' but '%s' is a filename, not a token", prefix, remainder)
			}
		}
		return MorphologyPrefixedRandom,
			map[string]interface{}{"ecosystem": ecosystem, "prefix": prefix},
			fmt.Sprintf("matches known prefix '%s' -> %s", prefix, ecosystem)
	}

	// Private key
	// Public keys, certificates, and SSH public keys are NOT secrets.
	if strings.HasPrefix(value, "ssh-rsa ") || strings.HasPrefix(value, "ssh-ed25519 ") ||
		strings.HasPrefix(value, "ssh-dss ") || strings.HasPrefix(value, "ecdsa-sha2-") {
		return MorphologyHumanTyped, map[string]interface{}{},
			"SSH public key (not a secret)"
	}
	if strings.Contains(value, "-----BEGIN PUBLIC KEY") ||
		strings.Contains(value, "-----BEGIN CERTIFICATE") {
		return MorphologyHumanTyped, map[string]interface{}{},
			"public key or certificate (not a secret)"
	}

	if strings.Contains(value, "-----BEGIN") && strings.Contains(value, "PRIVATE KEY") {
		return MorphologyPrivateKey, map[string]interface{}{}, "contains private key PEM header"
	}

	// Connection strings
	if strings.Contains(value, "://") && connectionStringRE.MatchString(value) {
		loc := connectionStringPwRE.FindStringSubmatch(value)
		if loc != nil {
			pw := loc[1]
			_, isPlaceholder := placeholderPasswords[strings.ToLower(pw)]
			return MorphologyConnectionString,
				map[string]interface{}{
					"has_real_password": !isPlaceholder,
					"password_entropy":  ShannonEntropyLUT(pw),
				},
				fmt.Sprintf("connection string with %s password", func() string {
					if isPlaceholder {
						return "placeholder"
					}
					return "real-looking"
				}())
		}
	}

	// JWT
	if strings.Count(value, ".") == 2 {
		parts := strings.Split(value, ".")
		allMatch := true
		for _, p := range parts {
			if p != "" && !jwtPartRE.MatchString(p) {
				allMatch = false
				break
			}
		}
		if allMatch && strings.HasPrefix(parts[0], "eyJ") {
			return MorphologyJWT, map[string]interface{}{}, "JWT structure (header.payload.signature)"
		}
	}

	// Placeholder
	valueLower := strings.ToLower(strings.Trim(value, "\"'"))
	if _, ok := placeholderWords[valueLower]; ok {
		return MorphologyTemplatePlaceholder, map[string]interface{}{},
			fmt.Sprintf("matches known placeholder '%s'", valueLower)
	}
	if placeholderPatternRE.MatchString(value) || placeholderDotsRE.MatchString(value) {
		return MorphologyTemplatePlaceholder, map[string]interface{}{}, "placeholder pattern (repeated chars)"
	}
	if placeholderYourRE.MatchString(value) {
		return MorphologyTemplatePlaceholder, map[string]interface{}{}, "placeholder pattern (your-*-here)"
	}

	// UUID
	if IsUUIDFormat(value) {
		return MorphologyStructuredRandom, map[string]interface{}{"subtype": "uuid"}, "UUID format (8-4-4-4-12)"
	}

	// Hex strings of hash-like lengths
	hashLengths := map[int]struct{}{32: {}, 40: {}, 48: {}, 64: {}, 96: {}, 128: {}}
	if IsHexOnly(value) {
		if _, isHashLen := hashLengths[len(value)]; isHashLen {
			// Check for repeating patterns (e.g., "abcdef0123456789" x 2)
			// Real secrets don't have repeating 8-16 char blocks.
			isRepeating := false
			for blockSize := 8; blockSize <= 16; blockSize++ {
				if len(value) >= blockSize*2 && len(value)%blockSize == 0 {
					block := value[:blockSize]
					repeats := true
					for j := blockSize; j < len(value); j += blockSize {
						if value[j:j+blockSize] != block {
							repeats = false
							break
						}
					}
					if repeats {
						isRepeating = true
						break
					}
				}
			}
			if isRepeating {
				return MorphologyStructuredRandom,
					map[string]interface{}{"subtype": "repeating_pattern", "length": len(value)},
					fmt.Sprintf("%d-char hex with repeating pattern, not a real secret", len(value))
			}
			if varRole == RoleStrongCredential || varRole == RoleWeakCredential {
				return MorphologyMachineRandom,
					map[string]interface{}{
						"charset": "hex", "length": len(value), "entropy": ShannonEntropyLUT(value),
						"note": "hex string in credential-named variable -- NOT classified as hash",
					},
					fmt.Sprintf("%d-char hex but credential variable overrides hash classification", len(value))
			}
			return MorphologyStructuredRandom,
				map[string]interface{}{"subtype": "hash", "length": len(value)},
				fmt.Sprintf("%d-char hex string, likely hash/digest", len(value))
		}
	}

	// ── Structural value-shape pre-screen (signal-based, technology-agnostic) ──

	// File paths: /path/to/file, ./relative, C:\windows
	if len(value) > 1 && value[0] == '/' && !strings.Contains(value, " ") && !strings.Contains(value, "://") {
		return MorphologyHumanTyped, map[string]interface{}{"subtype": "file_path"}, fmt.Sprintf("Unix file path (len=%d)", len(value))
	}
	if strings.HasPrefix(value, "./") || strings.HasPrefix(value, "../") {
		return MorphologyHumanTyped, map[string]interface{}{"subtype": "relative_path"}, "relative file path"
	}

	// HTTP/HTTPS URLs
	if strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") {
		return MorphologyHumanTyped, map[string]interface{}{"subtype": "url"}, fmt.Sprintf("HTTP URL (len=%d)", len(value))
	}

	// Domain-name-shaped: word.word.tld (2+ dots, all DNS-valid segments)
	if !strings.Contains(value, " ") && !strings.Contains(value, "://") && strings.Count(value, ".") >= 2 {
		allDNS := true
		for _, seg := range strings.Split(value, ".") {
			if len(seg) == 0 { allDNS = false; break }
			for _, c := range seg {
				if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') { allDNS = false; break }
			}
			if !allDNS { break }
		}
		if allDNS {
			return MorphologyHumanTyped, map[string]interface{}{"subtype": "domain"}, "domain-name structure"
		}
	}

	// Domain/path references: contains both / and a dot-separated domain prefix
	if strings.Contains(value, "/") && strings.Contains(value, ".") && !strings.Contains(value, " ") {
		parts := strings.SplitN(value, "/", 2)
		if strings.Contains(parts[0], ".") && len(parts) > 1 && len(parts[1]) > 0 {
			return MorphologyHumanTyped, map[string]interface{}{"subtype": "domain_path"}, "domain/path reference"
		}
	}

	// Email: word@domain.tld
	if strings.Contains(value, "@") && strings.Contains(value, ".") && !strings.Contains(value, " ") {
		atIdx := strings.Index(value, "@")
		if atIdx > 0 && atIdx < len(value)-3 && strings.Contains(value[atIdx+1:], ".") {
			return MorphologyHumanTyped, map[string]interface{}{"subtype": "email"}, "email address"
		}
	}

	// Colon-separated identifier (4+ colons): URN/ARN scheme:a:b:c:d
	if strings.Count(value, ":") >= 4 && !strings.Contains(value, " ") {
		return MorphologyHumanTyped, map[string]interface{}{"subtype": "colon_id"}, "colon-separated identifier"
	}

	// Base64 binary data
	if IsBase64Binary(value) {
		if varRole == RoleStrongCredential || varRole == RoleWeakCredential {
			return MorphologyMachineRandom,
				map[string]interface{}{
					"charset": "base64", "length": len(value), "entropy": ShannonEntropyLUT(value),
					"note": "base64 in credential-named variable -- NOT classified as encoded data",
				},
				"base64 decodable but credential variable overrides encoded classification"
		}
		return MorphologyEncodedPayload,
			map[string]interface{}{"encoding": "base64"},
			"valid base64 that decodes to binary data"
	}

	// Compute-once entropy (cached via closure-like local)
	entropyComputed := false
	var cachedEntropy float64
	getEntropy := func() float64 {
		if !entropyComputed {
			cachedEntropy = ShannonEntropyLUT(value)
			entropyComputed = true
		}
		return cachedEntropy
	}

	// Entropy-based classification
	if len(value) >= 16 && len(value) <= 512 {
		if FastEntropyCheck(value) {
			entropy := getEntropy()
			if entropy > 3.5 {
				charset := ClassifyCharset(value)
				return MorphologyMachineRandom,
					map[string]interface{}{"charset": charset, "length": len(value), "entropy": entropy},
					fmt.Sprintf("machine-random (entropy=%.1f, charset=%s, len=%d)", entropy, charset, len(value))
			}
		}
	}

	// Default: human-typed
	// Exception: short values (8-20 chars) with special characters in
	// credential-named variables are likely real passwords. Human passwords
	// use leet-speak (Pr0duct10n, P@ssw0rd) which has low entropy but high
	// credential probability.
	if len(value) >= 8 && len(value) <= 20 && varRole == RoleStrongCredential {
		hasSpecial := false
		for i := 0; i < len(value); i++ {
			c := value[i]
			if c == '@' || c == '!' || c == '#' || c == '$' || c == '%' || c == '&' || c == '*' {
				hasSpecial = true
				break
			}
		}
		if hasSpecial {
			return MorphologyMachineRandom,
				map[string]interface{}{"charset": "password", "length": len(value), "entropy": getEntropy()},
				fmt.Sprintf("short credential with special chars (len=%d, entropy=%.1f) — likely password", len(value), getEntropy())
		}
	}

	return MorphologyHumanTyped, map[string]interface{}{},
		fmt.Sprintf("appears human-typed (len=%d, entropy=%.1f)", len(value), getEntropy())
}

// ============================================================================
// SIGNAL 3: FILE PROVENANCE (cached with RWMutex)
// ============================================================================

var (
	testPatternRE = regexp.MustCompile(
		`(?:^|[/\\])tests?[/\\]|(?:^|[/\\])__tests__[/\\]|(?:^|[/\\])spec[/\\]|` +
			`(?:^|[/\\])fixtures?[/\\]|(?:^|[/\\])mocks?[/\\]|(?:^|[/\\])testdata[/\\]|` +
			`_test\.|\.test\.|\.spec\.|_spec\.|Tests?\.`)
	buildArtifactRE = regexp.MustCompile(`/vendor/|/node_modules/|/dist/|/build/|/\.git/|/\.next/|(?:^|/)\.next/`)
	cicdRE          = regexp.MustCompile(`\.github/workflows|\.gitlab-ci|[Jj]enkinsfile|\.circleci`)
	docsDirRE       = regexp.MustCompile(`[/\\]docs?[/\\]|(?:^|[/\\])codebase_mindmap[/\\]|(?:^|[/\\])arch_diagram[/\\]`)
	envSuffixRE     = regexp.MustCompile(`^\.env\.[a-z]+$`)
)

var (
	fileProvenanceCache = make(map[string]fileProvResult)
	fileProvenanceMu    sync.RWMutex
)

type fileProvResult struct {
	category   string
	likelihood float64
	reason     string
}

// ClassifyFileProvenance classifies a file path's provenance with caching.
// OPTIMIZATION: Cache stores float64 directly instead of string-encoding it.
// Eliminates fmt.Sscanf on every cached lookup (was ~200ns overhead).
func ClassifyFileProvenance(filePath string) (string, float64, string) {
	fileProvenanceMu.RLock()
	if cached, ok := fileProvenanceCache[filePath]; ok {
		fileProvenanceMu.RUnlock()
		return cached.category, cached.likelihood, cached.reason
	}
	fileProvenanceMu.RUnlock()

	cat, lk, reason := classifyFileProvenanceInner(filePath)

	fileProvenanceMu.Lock()
	fileProvenanceCache[filePath] = fileProvResult{cat, lk, reason}
	fileProvenanceMu.Unlock()

	return cat, lk, reason
}

func classifyFileProvenanceInner(filePath string) (string, float64, string) {
	fp := strings.ToLower(filePath)
	fname := filepath.Base(fp)

	if _, ok := lockFiles[fname]; ok {
		return "build_artifact", 0.02, fmt.Sprintf("lock file (%s)", fname)
	}

	exampleSuffixes := []string{".example", ".sample", ".template", ".dist", ".default"}
	for _, suf := range exampleSuffixes {
		if strings.Contains(fname, suf) {
			return "example_config", 0.05, fmt.Sprintf("example config file (%s)", fname)
		}
	}

	if testPatternRE.MatchString(filePath) {
		return "test", 0.15, "test file (combined pattern match)"
	}

	docExts := []string{".md", ".rst", ".txt", ".adoc"}
	for _, ext := range docExts {
		if strings.HasSuffix(fname, ext) {
			return "documentation", 0.1, fmt.Sprintf("documentation file (%s)", fname)
		}
	}

	if docsDirRE.MatchString(fp) || strings.HasPrefix(fname, "readme") ||
		strings.HasPrefix(fname, "contributing") || strings.HasPrefix(fname, "changelog") {
		return "documentation", 0.1, "documentation directory/file"
	}

	if buildArtifactRE.MatchString(fp) {
		return "build_artifact", 0.05, "build artifact / vendored dependency"
	}

	if fname == ".env" || envSuffixRE.MatchString(fname) {
		if !strings.Contains(fname, "example") && !strings.Contains(fname, "sample") {
			return "env_config", 0.85, fmt.Sprintf("environment config file (%s)", fname)
		}
	}

	if fname == "docker-compose.yml" || fname == "docker-compose.yaml" {
		return "env_config", 0.75, "Docker Compose file (may contain secrets)"
	}

	iacExts := []string{".tf", ".tfvars", ".hcl"}
	for _, ext := range iacExts {
		if strings.HasSuffix(fname, ext) {
			return "iac", 0.7, fmt.Sprintf("infrastructure-as-code (%s)", fname)
		}
	}

	if cicdRE.MatchString(fp) {
		return "cicd", 0.6, "CI/CD pipeline config"
	}

	return "source", 0.5, "application source code"
}

// ClearFileProvenanceCache clears the file provenance cache.
func ClearFileProvenanceCache() {
	fileProvenanceMu.Lock()
	fileProvenanceCache = make(map[string]fileProvResult)
	fileProvenanceMu.Unlock()
}

// ============================================================================
// SIGNAL 4: LINE CONTEXT
// ============================================================================

// OPTIMIZATION: Replace regex-based revocation detection with string matching.
// Benchmarked: regex was 3.6µs per call (81% of ClassifyToken time).
// String matching: ~100-200ns per call (18-36x speedup).

var commentPrefixes = []string{"#", "//", "/*", "*", "--", "<!--", `"""`, "'''"}
var commentFirstChars = [256]bool{'#': true, '/': true, '*': true, '-': true, '<': true, '"': true, '\'': true}

// revokeWords are checked via strings.Contains on the lowered line.
// Order: most common first for early exit.
// revokeWords: stems that match with word boundary.
// Includes both base and -d/-ed forms since we check word boundaries.
var revokeWords = []string{
	"revoked", "revoke",
	"expired", "expire",
	"disabled", "disable",
	"deactivated", "deactivate",
	"deprecated",
	"invalid",
	"previous",
	"rotated",
}

// isWordBoundaryAt checks if position idx in s has a word boundary before the word
// and the word ends at idx+wordLen with a word boundary after.
func isWordBoundaryAt(s string, idx int, wordLen int) bool {
	// Check before: must be start of string or non-alpha char
	if idx > 0 {
		c := s[idx-1]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			return false
		}
	}
	// Check after: must be end of string or non-alpha char
	end := idx + wordLen
	if end < len(s) {
		c := s[end]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			return false
		}
	}
	return true
}

// ClassifyLineContext returns a confidence adjustment and reason for line context.
// OPTIMIZATION: Uses string matching instead of regex (18x faster).
func ClassifyLineContext(line string) (float64, string) {
	stripped := strings.TrimSpace(line)
	var reasons []string
	adjustment := 0.0

	// Comment detection (fast first-char check)
	if len(stripped) > 0 && commentFirstChars[stripped[0]] {
		for _, prefix := range commentPrefixes {
			if strings.HasPrefix(stripped, prefix) {
				adjustment -= 0.3
				reasons = append(reasons, "in comment")
				break
			}
		}
	}

	// OPTIMIZATION: Case-insensitive word search WITHOUT strings.ToLower allocation.
	// Uses containsFoldWord which does case-insensitive scan at byte level.
	for _, word := range revokeWords {
		idx := indexFold(stripped, word)
		if idx >= 0 && isWordBoundaryAt(stripped, idx, len(word)) {
			adjustment -= 0.5
			reasons = append(reasons, "revocation context: '"+word+"'")
			break
		}
	}

	// Check "DO NOT USE" pattern
	if adjustment > -0.5 {
		doIdx := indexFold(stripped, "do")
		if doIdx >= 0 && isWordBoundaryAt(stripped, doIdx, 2) {
			rest := stripped[doIdx+2:]
			notIdx := indexFold(rest, "not")
			if notIdx >= 0 {
				rest2 := rest[notIdx+3:]
				if indexFold(rest2, "use") >= 0 {
					adjustment -= 0.5
					reasons = append(reasons, "revocation context: 'DO NOT USE'")
				}
			}
		}
	}

	// Check "old_" or "old " pattern
	if adjustment > -0.5 {
		idx := indexFold(stripped, "old")
		if idx >= 0 && idx+3 < len(stripped) {
			nextChar := stripped[idx+3]
			if nextChar == '_' || nextChar == ' ' || nextChar == '\t' {
				if idx == 0 || !isAlpha(stripped[idx-1]) {
					adjustment -= 0.5
					reasons = append(reasons, "revocation context: 'old'")
				}
			}
		}
	}

	// Credential-processing code detection: lines that READ credentials from
	// env vars / config are not hardcoded secrets. Demote aggressively.
	if adjustment > -0.5 {
		if lineReferencesEnvVar(stripped) {
			adjustment -= 0.8
			reasons = append(reasons, "credential-processing code (env-var reference)")
		}
	}

	if len(reasons) == 0 {
		reasons = append(reasons, "no special line context")
	}

	return adjustment, strings.Join(reasons, "; ")
}

// envVarPatterns are substrings that indicate a line is reading a credential
// from an environment variable or external config rather than containing one.
var envVarPatterns = []string{
	"os.environ",
	"os.getenv",
	"os.Getenv",
	"process.env.",
	"System.getenv",
	"ENV[",
	"ENV.fetch",
	"getenv(",
	"${",
	"${{",
	"$((",
}

// lineReferencesEnvVar checks if a line is reading credentials from environment
// variables or external configuration rather than hardcoding them.
func lineReferencesEnvVar(line string) bool {
	for _, pat := range envVarPatterns {
		if strings.Contains(line, pat) {
			return true
		}
	}
	// Shell-style $UPPER_CASE_VAR references (but not $lower or $1)
	for i := 0; i < len(line)-1; i++ {
		if line[i] == '$' && line[i+1] >= 'A' && line[i+1] <= 'Z' {
			return true
		}
	}
	return false
}

// ============================================================================
// DECISION TREE (Zero-closure)
// ============================================================================

// formatAdj formats a float adjustment as "adj=+X.Y" without fmt.Sprintf overhead.
func formatAdj(v float64) string {
	// Common cases: +0.0, -0.3, -0.5, -0.8
	switch {
	case v == 0.0:
		return "adj=+0.0"
	case v == -0.3:
		return "adj=-0.3"
	case v == -0.5:
		return "adj=-0.5"
	case v == -0.8:
		return "adj=-0.8"
	default:
		return fmt.Sprintf("adj=%+.1f", v)
	}
}

// ClassifyToken applies the 14-rule decision tree to classify a token.
func ClassifyToken(token Token) Classification {
	signals := make([]SignalResult, 0, 4) // Pre-allocate for 4 signals, eliminates growslice

	// Signal 1: Syntactic Role
	synRole, synConf, synReason := ClassifySyntacticRole(token.VarName)
	signals = append(signals, SignalResult{"syntactic_role", string(synRole), synConf, synReason})

	// Signal 2: Morphology
	morphology, morphMeta, morphReason := ClassifyMorphology(token.Value, synRole)
	signals = append(signals, SignalResult{"morphology", string(morphology), 0.8, morphReason})

	// Lazy state
	var fileCat string
	var fileCred float64
	var fileReason string
	fileComputed := false

	var lineAdj float64
	var lineReason string
	lineComputed := false

	ensureFileProvenance := func() {
		if !fileComputed {
			fileCat, fileCred, fileReason = ClassifyFileProvenance(token.FilePath)
			fileComputed = true
		}
	}

	ensureLineContext := func() {
		if !lineComputed {
			lineAdj, lineReason = ClassifyLineContext(token.LineContent)
			lineComputed = true
		}
	}

	finalize := func(provenance Provenance, conf float64, hasFloor bool, floor float64) Classification {
		ensureFileProvenance()
		signals = append(signals, SignalResult{"file_provenance", fileCat, fileCred, fileReason})
		ensureLineContext()
		signals = append(signals, SignalResult{"line_context", formatAdj(lineAdj), 0.5 + lineAdj, lineReason})
		if hasFloor && conf < floor {
			conf = floor
		}
		return Classification{provenance, conf, signals, token}
	}

	// === DECISION TREE ===

	// RULE 1: Known prefix -> AUTH_CREDENTIAL
	if morphology == MorphologyPrefixedRandom {
		ensureFileProvenance()
		conf := 0.95
		if fileCat == "test" || fileCat == "documentation" || fileCat == "example_config" {
			conf = 0.6
		}
		ensureLineContext()
		if lineAdj < -0.3 {
			conf -= 0.3
		}
		return finalize(ProvenanceAuthCredential, conf, true, 0.1)
	}

	// RULE 2: Private key
	if morphology == MorphologyPrivateKey {
		ensureFileProvenance()
		conf := 0.9
		if fileCat == "test" || fileCat == "documentation" || fileCat == "example_config" {
			conf = 0.5
		}
		return finalize(ProvenanceAuthCredential, conf, false, 0)
	}

	// RULE 3: Connection string with real password
	if morphology == MorphologyConnectionString {
		hasReal, _ := morphMeta["has_real_password"].(bool)
		if hasReal {
			ensureFileProvenance()
			ensureLineContext()
			conf := 0.85
			if fileCat == "test" {
				conf = 0.55
			}
			if fileCat == "documentation" || fileCat == "example_config" {
				conf = 0.2
			}
			return finalize(ProvenanceAuthCredential, conf+lineAdj*0.3, true, 0.1)
		}
		return finalize(ProvenanceDocExample, 0.9, false, 0)
	}

	// RULE 4: JWT
	if morphology == MorphologyJWT {
		ensureFileProvenance()
		ensureLineContext()
		conf := 0.8
		if fileCat == "test" || fileCat == "documentation" {
			conf = 0.4
		}
		return finalize(ProvenanceAuthCredential, conf+lineAdj*0.3, true, 0.1)
	}

	// RULE 5: Strong credential + machine-random
	if synRole == RoleStrongCredential && morphology == MorphologyMachineRandom {
		ensureFileProvenance()
		ensureLineContext()
		conf := 0.85
		if fileCat == "test" || fileCat == "example_config" {
			conf = 0.5
		}
		if fileCat == "documentation" {
			conf = 0.3
		}
		return finalize(ProvenanceAuthCredential, conf+lineAdj*0.3, true, 0.1)
	}

	// RULE 6: Template -> DOC_EXAMPLE
	if morphology == MorphologyTemplatePlaceholder {
		return finalize(ProvenanceDocExample, 0.95, false, 0)
	}

	// RULE 7: UUID
	subtypeVal, _ := morphMeta["subtype"].(string)
	if morphology == MorphologyStructuredRandom && subtypeVal == "uuid" {
		return finalize(ProvenanceBuildGenerated, 0.95, false, 0)
	}

	// RULE 8: Hash
	if morphology == MorphologyStructuredRandom && subtypeVal == "hash" {
		return finalize(ProvenanceBuildGenerated, 0.9, false, 0)
	}

	// RULE 9: Encoded payload
	if morphology == MorphologyEncodedPayload {
		return finalize(ProvenanceDerivedValue, 0.85, false, 0)
	}

	// RULE 10: Test/doc + non-credential
	ensureFileProvenance()
	if fileCat == "test" || fileCat == "documentation" || fileCat == "example_config" || fileCat == "build_artifact" {
		if synRole != RoleStrongCredential && synRole != RoleWeakCredential {
			return finalize(ProvenanceDocExample, 0.8, false, 0)
		}
	}

	// RULE 11: Weak credential + machine-random
	if synRole == RoleWeakCredential && morphology == MorphologyMachineRandom {
		return finalize(ProvenanceUncertain, 0.5, false, 0)
	}

	// RULE 12: Machine-random in high-risk file
	if morphology == MorphologyMachineRandom && (fileCat == "env_config" || fileCat == "iac" || fileCat == "cicd") {
		return finalize(ProvenanceUncertain, 0.5, false, 0)
	}

	// RULE 13: Human-typed
	if morphology == MorphologyHumanTyped {
		return finalize(ProvenanceHumanAuthored, 0.9, false, 0)
	}

	// RULE 14: Machine-random, no credential signals
	if morphology == MorphologyMachineRandom {
		if synRole == RoleAntiCredential {
			return finalize(ProvenanceBuildGenerated, 0.7, false, 0)
		}
		return finalize(ProvenanceUncertain, 0.4, false, 0)
	}

	return finalize(ProvenanceHumanAuthored, 0.85, false, 0)
}

// ============================================================================
// TOKEN EXTRACTION
// ============================================================================

var combinedExtractRE = regexp.MustCompile(
	`(?:([A-Za-z_][A-Za-z0-9_]*)\s*[:=]\s*["']([^"']{8,})["'])` +
		`|(?:export\s+([A-Z_][A-Z0-9_]*)\s*=\s*([^\s"'#]{8,}))` +
		`|(?:^([A-Z_][A-Z0-9_]*)\s*=\s*(.{8,}))` +
		`|(?:"([A-Za-z_][A-Za-z0-9_]*)"\s*:\s*"([^"]{8,})")` +
		`|(?:(-----BEGIN\s+\w+\s+PRIVATE KEY-----))` +
		`|((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|mssql)://[^\s"']+)`)

var yamlExtractRE = regexp.MustCompile(
	`^\s*([A-Za-z_][A-Za-z0-9_.x-]*)\s*:\s*([^\s#"']{8,})`)

// --- Additional extraction patterns for formats the base patterns miss ---

// Dockerfile: ENV KEY=value or ENV KEY value
var dockerEnvRE = regexp.MustCompile(
	`(?i)^ENV\s+([A-Z_][A-Z0-9_]*)\s*[=\s]\s*([^\s]{8,})`)

// Docker-compose / YAML list: - KEY=value (with optional whitespace/dash prefix)
var yamlListEnvRE = regexp.MustCompile(
	`^\s*-\s*([A-Z_][A-Z0-9_]*)\s*=\s*([^\s"']{8,})`)

// npm .npmrc: _authToken=value or //registry...:_authToken=value
var npmAuthRE = regexp.MustCompile(
	`(?:^|:)_authToken\s*=\s*([^\s]{8,})`)

// ADO.NET / JDBC connection string: Password=value; or pwd=value;
var adoConnPwRE = regexp.MustCompile(
	`(?i)(?:Password|pwd)\s*=\s*([^;"\s]{8,})`)

// URL-embedded credentials: https://TOKEN@host or https://user:TOKEN@host
var urlEmbeddedTokenRE = regexp.MustCompile(
	`https?://([A-Za-z0-9_-]{20,})@[A-Za-z0-9.-]+`)

// CLI argument with known prefix: -p sk_live_xxx or --password=ghp_xxx
var cliArgPrefixRE = regexp.MustCompile(
	`(?:^|\s)-\w*[pP]\s+((?:sk_live_|sk_test_|ghp_|gho_|ghs_|ghu_|glpat-|xoxb-|xoxp-|AKIA|hf_|npm_)[A-Za-z0-9_/+=.-]{8,})`)
// Generic: any quoted string matching a known credential prefix inside any context
// Catches function arguments like NewStaticCredentials("AKIA...", "secret", "")
var quotedPrefixRE = regexp.MustCompile(
	`"[^"]*?((?:AKIA|ASIA|ghp_|gho_|ghs_|ghu_|github_pat_|sk_live_|sk_test_|pk_live_|rk_live_|xoxb-|xoxp-|xoxa-|xoxr-|SG\.|hf_|sq0csp-|AIza|glpat-|ya29\.)[A-Za-z0-9_/+=.-]{8,})"`)

// Generic: any quoted high-entropy string (20+ chars) next to another quoted string in function args
var funcArgSecretRE = regexp.MustCompile(
	`"([A-Za-z0-9+/=]{20,})"`)

type dedupKey struct {
	line  int
	value string
}

// ExtractTokens extracts key-value tokens from file content.
func ExtractTokens(filepath string, content string) []Token {
	var tokens []Token
	seen := make(map[dedupKey]struct{})
	lines := strings.Split(content, "\n")

	for lineNum, line := range lines {
		lineNo := lineNum + 1

		if len(line) < 10 {
			continue
		}
		// Pre-filter: must contain = or : or ----- or a quoted known prefix
		hasAssign := LineHasExtractSignal(line)
		hasQuotedPrefix := !hasAssign && strings.Contains(line, "\"") && containsKnownPrefix(line)
		if !hasAssign && !hasQuotedPrefix {
			continue
		}

		matches := combinedExtractRE.FindAllStringSubmatch(line, -1)
		for _, m := range matches {
			var varName, value string
			switch {
			case m[1] != "":
				varName, value = m[1], m[2]
			case m[3] != "":
				varName, value = m[3], m[4]
			case m[5] != "":
				varName = m[5]
				value = strings.Trim(strings.TrimSpace(m[6]), "\"'")
			case m[7] != "":
				varName, value = m[7], m[8]
			case m[9] != "":
				varName, value = "private_key_header", m[9]
			case m[10] != "":
				varName, value = "connection_string", m[10]
			}

			if varName != "" && value != "" {
				if valueIsNotSecret(value) {
					continue
				}
				dk := dedupKey{lineNo, value}
				if _, exists := seen[dk]; !exists {
					seen[dk] = struct{}{}
					tokens = append(tokens, Token{value, varName, lineNo, line, filepath})
				}
			}
		}

		// YAML extraction
		ym := yamlExtractRE.FindStringSubmatch(line)
		if ym != nil {
			varName, value := ym[1], ym[2]
			dk := dedupKey{lineNo, value}
			if _, exists := seen[dk]; !exists {
				seen[dk] = struct{}{}
				tokens = append(tokens, Token{value, varName, lineNo, line, filepath})
			}
		}

		// --- Extended extraction patterns ---

		// Dockerfile ENV directive
		if dm := dockerEnvRE.FindStringSubmatch(line); dm != nil {
			addUnique(&tokens, seen, dm[1], dm[2], lineNo, line, filepath)
		}

		// Docker-compose / YAML list: - KEY=value
		if dm := yamlListEnvRE.FindStringSubmatch(line); dm != nil {
			addUnique(&tokens, seen, dm[1], dm[2], lineNo, line, filepath)
		}

		// npm _authToken
		if dm := npmAuthRE.FindStringSubmatch(line); dm != nil {
			addUnique(&tokens, seen, "_authToken", dm[1], lineNo, line, filepath)
		}

		// ADO.NET Password=value; in connection strings
		if dm := adoConnPwRE.FindStringSubmatch(line); dm != nil {
			pw := strings.TrimRight(dm[1], ";\"'")
			if len(pw) >= 8 {
				addUnique(&tokens, seen, "password", pw, lineNo, line, filepath)
			}
		}

		// URL-embedded tokens: https://TOKEN@host
		if dm := urlEmbeddedTokenRE.FindStringSubmatch(line); dm != nil {
			tok := dm[1]
			// Only extract if token looks like a known prefix or is high-entropy
			if _, _, found := MatchKnownPrefixTrie(tok); found {
				addUnique(&tokens, seen, "url_embedded_token", tok, lineNo, line, filepath)
			}
		}

		// Quoted strings matching known credential prefixes (catches function args)
		for _, dm := range quotedPrefixRE.FindAllStringSubmatch(line, -1) {
			addUnique(&tokens, seen, "credential_value", dm[1], lineNo, line, filepath)
		}

		// CLI argument with known prefix: docker -p sk_live_xxx
		if dm := cliArgPrefixRE.FindStringSubmatch(line); dm != nil {
			addUnique(&tokens, seen, "cli_arg_credential", dm[1], lineNo, line, filepath)
		}

		// Generic function argument: look for high-entropy quoted strings next to known-prefix matches
		// Only if we already found a known-prefix match on this line
		if quotedPrefixRE.MatchString(line) {
			for _, dm := range funcArgSecretRE.FindAllStringSubmatch(line, -1) {
				val := dm[1]
				// Skip if it's a known prefix (already caught above) or too short
				if _, _, found := MatchKnownPrefixTrie(val); !found && len(val) >= 20 {
					addUnique(&tokens, seen, "credential_secret", val, lineNo, line, filepath)
				}
			}
		}
	}

	return tokens
}

// containsKnownPrefix does a fast check if a line contains any known credential prefix.
func containsKnownPrefix(line string) bool {
	for i := 0; i < len(line); i++ {
		if prefixFirstChars[line[i]] {
			remaining := line[i:]
			if _, _, found := MatchKnownPrefixTrie(remaining); found {
				return true
			}
		}
	}
	return false
}

// addUnique adds a token if not already seen (dedup by line+value).
func addUnique(tokens *[]Token, seen map[dedupKey]struct{}, varName, value string, line int, lineContent, filepath string) {
	dk := dedupKey{line, value}
	if _, exists := seen[dk]; !exists {
		if valueIsNotSecret(value) {
			return
		}
		seen[dk] = struct{}{}
		*tokens = append(*tokens, Token{value, varName, line, lineContent, filepath})
	}
}

// wellKnownDefaults are credential-shaped values that are universally known
// test/default passwords and should never be flagged.
var wellKnownDefaults = map[string]struct{}{
	"postgres:postgres":     {},
	"root:root":             {},
	"admin:admin":           {},
	"user:password":         {},
	"username:password":     {},
	"test:test":             {},
	"redis://localhost":     {},
	"localhost:6379":        {},
	"127.0.0.1":             {},
	"AKIAIOSFODNN7EXAMPLE":  {},
	"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY": {},
}

// valueIsNotSecret returns true if a value is definitely not a credential and
// should be excluded from token extraction. This catches:
//  1. Programming identifiers (snake_case / camelCase variable names)
//  2. Well-known default/example credentials (postgres:postgres, AWS example keys)
//  3. Values that are env-var references ($VAR, ${VAR})
//  4. Python/Go/JS function-call patterns used to READ secrets
func valueIsNotSecret(value string) bool {
	if len(value) < 8 {
		return false
	}
	// Unresolved template/substitution markers: ${}, $(), %%, {{, `backtick`
	for i := 0; i < len(value)-1; i++ {
		if value[i] == '$' && (value[i+1] == '{' || value[i+1] == '(') {
			return true
		}
	}
	if strings.Count(value, "%") >= 2 {
		return true
	}
	if strings.Contains(value, "{{") {
		return true
	}
	if len(value) > 2 && value[0] == '`' && value[len(value)-1] == '`' {
		return true
	}
	// HTML/XML content
	if strings.Contains(value, "</") || strings.Contains(value, "/>") {
		return true
	}
	// Well-known defaults
	if _, ok := wellKnownDefaults[value]; ok {
		return true
	}
	// Env-var references: $VAR, ${VAR}, $(cmd)
	if value[0] == '$' {
		return true
	}
	// Python/Go/Node env reads: os.environ[, os.getenv(, os.Getenv(, process.env.
	for _, fn := range []string{"os.environ", "os.getenv(", "os.Getenv(", "process.env.", "System.getenv("} {
		if strings.HasPrefix(value, fn) {
			return true
		}
	}
	// Pure identifier: all word-chars and underscores, no special chars,
	// and passes the identifier-shape check
	if looksLikeFullIdentifier(value) {
		return true
	}
	return false
}

// looksLikeFullIdentifier checks if an entire extracted value (not just a
// prefix remainder) looks like a variable/function name rather than a secret.
func looksLikeFullIdentifier(s string) bool {
	if len(s) < 8 {
		return false
	}
	underscores := 0
	hasLower := false
	hasUpper := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
			hasLower = true
		case c >= 'A' && c <= 'Z':
			hasUpper = true
		case c == '_':
			underscores++
		case c >= '0' && c <= '9':
			// ok
		default:
			return false
		}
	}
	// Require at least 2 underscores for a multi-word identifier
	// (single underscore could be a short prefix token like sk_live_xxx)
	if underscores >= 2 && !(hasLower && hasUpper) {
		return true
	}
	return false
}

// ============================================================================
// SCANNER
// ============================================================================

// FileDefinitelySafe returns true if a filename should always be skipped.
func FileDefinitelySafe(fname string) bool {
	fnameLower := strings.ToLower(fname)
	if _, ok := lockFiles[fnameLower]; ok {
		return true
	}
	ext := filepath.Ext(fnameLower)
	if _, ok := skipExtensions[ext]; ok {
		return true
	}
	if strings.HasSuffix(fname, ".min.js") || strings.HasSuffix(fname, ".min.css") || strings.HasSuffix(fname, ".d.ts") {
		return true
	}
	if strings.HasSuffix(fnameLower, ".generated.go") || strings.HasSuffix(fnameLower, ".generated.ts") {
		return true
	}
	if strings.HasSuffix(fnameLower, "_generated.go") || strings.HasSuffix(fnameLower, "_generated.rs") {
		return true
	}
	if strings.HasSuffix(fnameLower, ".pb.go") || strings.HasSuffix(fnameLower, "_pb2.py") {
		return true
	}
	return false
}

// ScanFile scans a single file and returns findings above the threshold.
func ScanFile(filepath string, threshold float64) []Finding {
	info, err := os.Stat(filepath)
	if err != nil {
		return nil
	}
	if info.Size() > 10_000_000 {
		return nil
	}
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil
	}

	content := string(data)
	tokens := ExtractTokens(filepath, content)
	tokens = append(tokens, AdvancedExtractTokens(filepath, content)...)
	var findings []Finding

	for _, token := range tokens {
		classification := ClassifyToken(token)

		// When the decision tree is uncertain, consult the ML classifier
		// to resolve gray-zone candidates with contextual understanding.
		if classification.Prov == ProvenanceUncertain {
			classification = refineWithML(token, content, classification)
		}

		if classification.Prov != ProvenanceAuthCredential && classification.Prov != ProvenanceUncertain {
			continue
		}
		if classification.Conf < threshold {
			continue
		}

		v := token.Value
		var redacted string
		if len(v) > 16 {
			redacted = v[:6] + "..." + v[len(v)-4:]
		} else if len(v) > 8 {
			redacted = v[:4] + "****"
		} else {
			redacted = "****"
		}

		sigs := make([]map[string]interface{}, len(classification.Signals))
		for i, s := range classification.Signals {
			sigs[i] = map[string]interface{}{
				"name":       s.Name,
				"value":      s.Value,
				"confidence": s.Confidence,
				"reasoning":  s.ReasonText,
			}
		}

		findings = append(findings, Finding{
			File:         filepath,
			Line:         token.Line,
			MatchedValue: redacted,
			Detector:     "synapse:" + strings.ToLower(string(classification.Prov)),
			Confidence:   classification.Conf,
			Provenance:   string(classification.Prov),
			Signals:      sigs,
			ReasoningStr: classification.Reasoning(),
		})
	}

	return findings
}

// ScanFileDeep scans a file with the decoder + handler pipeline.
// Regular files: decode content -> extract tokens -> classify
// Archives: extract inner files -> decode each -> extract tokens -> classify
func ScanFileDeep(fpath string, threshold float64) []Finding {
	chunks, err := HandleFile(fpath)
	if err != nil || len(chunks) == 0 {
		// Fallback to regular scan if handler fails.
		return ScanFile(fpath, threshold)
	}

	var allFindings []Finding

	for _, chunk := range chunks {
		// Run decoders on each chunk.
		decoded := DecodeContent(chunk.Content)

		for _, dc := range decoded {
			tokens := ExtractTokens(chunk.FilePath, dc.Content)
			for _, token := range tokens {
				classification := ClassifyToken(token)

				// ML refinement for UNCERTAIN tokens (same as ScanFile path).
				if classification.Prov == ProvenanceUncertain {
					classification = refineWithML(token, dc.Content, classification)
				}

				if classification.Prov != ProvenanceAuthCredential && classification.Prov != ProvenanceUncertain {
					continue
				}
				if classification.Conf < threshold {
					continue
				}

				allFindings = append(allFindings, buildFinding(token, classification))
			}
		}
	}

	return allFindings
}

// buildFinding creates a Finding from a classified token.
func buildFinding(token Token, classification Classification) Finding {
	v := token.Value
	var redacted string
	if len(v) > 16 {
		redacted = v[:6] + "..." + v[len(v)-4:]
	} else if len(v) > 8 {
		redacted = v[:4] + "****"
	} else {
		redacted = "****"
	}

	sigs := make([]map[string]interface{}, len(classification.Signals))
	for i, s := range classification.Signals {
		sigs[i] = map[string]interface{}{
			"name":       s.Name,
			"value":      s.Value,
			"confidence": s.Confidence,
			"reasoning":  s.ReasonText,
		}
	}

	return Finding{
		File:         token.FilePath,
		Line:         token.Line,
		MatchedValue: redacted,
		Detector:     "synapse:" + strings.ToLower(string(classification.Prov)),
		Confidence:   classification.Conf,
		Provenance:   string(classification.Prov),
		Signals:      sigs,
		ReasoningStr: classification.Reasoning(),
	}
}

// ScanDirectory scans a directory tree using a goroutine worker pool.
func ScanDirectory(root string, threshold float64, workers int) []Finding {
	if workers <= 0 {
		workers = runtime.NumCPU()
	}

	filePaths := collectFilePaths(root)
	if len(filePaths) == 0 {
		return nil
	}

	// Single-threaded for small jobs
	if len(filePaths) < 50 {
		var allFindings []Finding
		for _, fp := range filePaths {
			allFindings = append(allFindings, ScanFile(fp, threshold)...)
		}
		return allFindings
	}

	// Goroutine worker pool
	bufSize := workers * 4
	if bufSize > len(filePaths) {
		bufSize = len(filePaths)
	}
	pathCh := make(chan string, bufSize)
	resultCh := make(chan []Finding, bufSize)

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for fp := range pathCh {
				findings := ScanFile(fp, threshold)
				if len(findings) > 0 {
					resultCh <- findings
				}
			}
		}()
	}

	for _, fp := range filePaths {
		pathCh <- fp
	}
	close(pathCh)

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	var allFindings []Finding
	for findings := range resultCh {
		allFindings = append(allFindings, findings...)
	}

	return allFindings
}

func collectFilePaths(root string) []string {
	var paths []string

	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		if d.IsDir() {
			name := d.Name()
			if _, skip := skipDirs[name]; skip || (strings.HasPrefix(name, ".") && name != ".") {
				return filepath.SkipDir
			}
			return nil
		}

		fname := d.Name()
		// Allow archive files through even if their extension is in skipExtensions.
		if FileDefinitelySafe(fname) && !IsArchiveFile(path) {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return nil
		}
		size := info.Size()
		// Archives can be up to 10MB; regular files up to 1MB.
		maxSize := int64(1_000_000)
		if IsArchiveFile(path) {
			maxSize = int64(maxTotalExtractSize)
		}
		if size == 0 || size > maxSize {
			return nil
		}

		fileCat, _, _ := ClassifyFileProvenance(path)
		if fileCat == "build_artifact" {
			return nil
		}

		paths = append(paths, path)
		return nil
	})

	return paths
}

// ============================================================================
// OUTPUT
// ============================================================================

type jsonOutput struct {
	Tool          string        `json:"tool"`
	Version       string        `json:"version"`
	Engine        string        `json:"engine"`
	TotalFindings int           `json:"total_findings"`
	Findings      []jsonFinding `json:"findings"`
}

type jsonFinding struct {
	File         string                   `json:"file"`
	Line         int                      `json:"line"`
	Detector     string                   `json:"detector"`
	Description  string                   `json:"description"`
	MatchedValue string                   `json:"matched_value"`
	Confidence   float64                  `json:"confidence"`
	Provenance   string                   `json:"provenance"`
	Signals      []map[string]interface{} `json:"signals"`
}

// refineWithML consults the ML classifier for UNCERTAIN tokens.
// When the 14-rule decision tree cannot resolve a candidate (Provenance == UNCERTAIN),
// this function builds a ±10-line context window and asks the ContextClassifier
// for a verdict. The ML model either promotes the finding to AUTH_CREDENTIAL,
// suppresses it to DOC_EXAMPLE, or leaves it as UNCERTAIN with adjusted confidence.
func refineWithML(token Token, fileContent string, cls Classification) Classification {
	classifier := GetClassifier()
	if !classifier.IsLoaded() {
		return cls
	}

	contextWindow := BuildContextWindow(fileContent, token.Line, 10)
	if contextWindow == "" {
		return cls
	}

	prediction := classifier.Predict(contextWindow)

	mlSignal := SignalResult{
		Name:       "ml_classifier",
		Value:      prediction.LabelName,
		Confidence: prediction.Confidence,
		ReasonText: fmt.Sprintf("ML model predicted %s with %.1f%% confidence (%.1fms)",
			prediction.LabelName, prediction.Confidence*100, prediction.LatencyMs),
	}

	cls.Signals = append(cls.Signals, mlSignal)

	switch {
	case prediction.Label == 1 && prediction.Confidence >= 0.70:
		// ML says SECRET with high confidence — promote to AUTH_CREDENTIAL.
		cls.Prov = ProvenanceAuthCredential
		// Blend: take the max of the decision-tree confidence and ML confidence,
		// but cap at 0.85 since ML alone shouldn't produce "verified" certainty.
		mlConf := prediction.Confidence * 0.85
		if mlConf > cls.Conf {
			cls.Conf = mlConf
		}

	case prediction.Label == 0 && prediction.Confidence >= 0.80:
		// ML says NOT_SECRET with very high confidence — suppress.
		cls.Prov = ProvenanceDocExample
		cls.Conf = 1.0 - prediction.Confidence

	case prediction.Label == 1 && prediction.Confidence >= 0.55:
		// ML leans SECRET but not decisive — boost confidence, keep UNCERTAIN.
		boost := (prediction.Confidence - 0.5) * 0.4
		cls.Conf = clamp64(cls.Conf+boost, 0.0, 0.95)

	case prediction.Label == 0 && prediction.Confidence >= 0.60:
		// ML leans NOT_SECRET — reduce confidence, keep UNCERTAIN.
		reduction := (prediction.Confidence - 0.5) * 0.3
		cls.Conf = clamp64(cls.Conf-reduction, 0.05, 1.0)

	default:
		// ML inconclusive — leave classification unchanged.
	}

	return cls
}

// RefineWithML is the exported entry point for ML refinement.
// Use this from external packages (e.g., the AEGIS integration layer)
// to run the ML classifier on UNCERTAIN tokens.
func RefineWithML(token Token, fileContent string, cls Classification) Classification {
	return refineWithML(token, fileContent, cls)
}

// clamp64 restricts v to [lo, hi].
func clamp64(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// OutputJSON produces JSON output matching the Python version's format.
func OutputJSON(findings []Finding) (string, error) {
	out := jsonOutput{
		Tool:          "aegis",
		Version:       "2.0.0-synapse-v2",
		Engine:        "SYNAPSE v2 (Algorithmically Reinvented)",
		TotalFindings: len(findings),
		Findings:      make([]jsonFinding, len(findings)),
	}

	for i, f := range findings {
		out.Findings[i] = jsonFinding{
			File:         f.File,
			Line:         f.Line,
			Detector:     f.Detector,
			Description:  f.ReasoningStr,
			MatchedValue: f.MatchedValue,
			Confidence:   f.Confidence,
			Provenance:   f.Provenance,
			Signals:      f.Signals,
		}
	}

	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// IsEngineFalsePositive is the exported version for use by the orchestrator.
func IsEngineFalsePositive(token Token) bool {
	return valueIsNotSecret(token.Value)
}
