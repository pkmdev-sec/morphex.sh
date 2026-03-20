package engine

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// AdvancedExtractionEnabled controls whether the advanced extraction
// pipeline runs. It adds ~2x overhead on large repos but catches secrets
// hidden by string concatenation, encoding, and obfuscation. Enabled via
// the --deep CLI flag.
var AdvancedExtractionEnabled = false
// AdvancedExtractTokens applies heuristic transforms to content before
// extraction, catching secrets hidden by:
//   - String concatenation: "AK" + "IA" + "Z3" → "AKIAZ3..."
//   - Variable interpolation: prefix="sk_live_"; key=f"{prefix}xxx"
//   - Reversed strings: reversed_key = "XappC..." → "...CppaX"
//   - XML credential tags: <password>secret</password>
//   - Hex/bytes literals: b'\x41\x4b\x49\x41' → "AKIA"
//   - ROT13 encoded: fx_yvir → sk_live
//
// Returns additional tokens found by these transforms. The caller should
// merge these with the standard ExtractTokens results.
func AdvancedExtractTokens(filepath string, content string) []Token {
	if !AdvancedExtractionEnabled {
		return nil
	}
	var extra []Token
	lines := strings.Split(content, "\n")

	extra = append(extra, extractConcatenated(filepath, lines)...)
	extra = append(extra, extractVariableInterpolation(filepath, lines, content)...)
	extra = append(extra, extractReversed(filepath, lines)...)
	extra = append(extra, extractXMLCredentials(filepath, content)...)
	extra = append(extra, extractHexByteLiterals(filepath, lines)...)
	extra = append(extra, extractROT13(filepath, lines)...)

	extra = append(extra, extractYAMLBlockScalar(filepath, lines)...)
	extra = append(extra, extractMySQLInlinePassword(filepath, lines)...)
	extra = append(extra, extractSingleQuotedCredentials(filepath, lines)...)

	// P0 extractors: close benchmark gaps
	vars := buildVarMap(lines)
	extra = append(extra, extractCrossVarConcat(filepath, lines, vars)...)
	extra = append(extra, extractBase64DecodeCalls(filepath, lines, vars)...)
	extra = append(extra, extractMultiLineJoin(filepath, lines, content)...)
	extra = append(extra, extractPythonSliceReverse(filepath, lines)...)
	extra = append(extra, extractBearerTokensInStrings(filepath, lines)...)
	extra = append(extra, extractCodecsROT13(filepath, lines)...)
	extra = append(extra, extractBytesArrayLiterals(filepath, lines)...)
	extra = append(extra, extractINICredentials(filepath, lines)...)
	extra = append(extra, extractURLDecodedConnStrings(filepath, lines)...)

	return extra
}

// =========================================================================
// 1. String Concatenation Reconstruction
// Catches: key = "AK" + "IA" + "Z3" + "ME"
// =========================================================================

var concatRE = regexp.MustCompile(
	`([A-Za-z_]\w*)\s*=\s*` +
		`"([^"]*?)"\s*\+\s*"([^"]*?)"` +
		`(?:\s*\+\s*"([^"]*?)")?` +
		`(?:\s*\+\s*"([^"]*?)")?` +
		`(?:\s*\+\s*"([^"]*?)")?` +
		`(?:\s*\+\s*"([^"]*?)")?`)

var concatSingleRE = regexp.MustCompile(
	`([A-Za-z_]\w*)\s*=\s*'([^']*?)'\s*\+\s*'([^']*?)'` +
		`(?:\s*\+\s*'([^']*?)')?` +
		`(?:\s*\+\s*'([^']*?)')?`)

func extractConcatenated(filepath string, lines []string) []Token {
	var tokens []Token
	for lineNum, line := range lines {
		for _, re := range []*regexp.Regexp{concatRE, concatSingleRE} {
			m := re.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			varName := m[1]
			var parts []string
			for _, p := range m[2:] {
				if p != "" {
					parts = append(parts, p)
				}
			}
			joined := strings.Join(parts, "")
			if len(joined) >= 8 {
				tokens = append(tokens, Token{
					Value: joined, VarName: varName,
					Line: lineNum + 1, LineContent: line, FilePath: filepath,
				})
			}
		}
	}
	return tokens
}

// =========================================================================
// 2. Variable Interpolation / Two-Line Assignment
// Catches: prefix = "sk_live_"; suffix = "xxx"; key = f"{prefix}{suffix}"
// Also: template = "sk_live_%s"; key = template % "xxx"
// =========================================================================

var simpleAssignRE = regexp.MustCompile(`^[^#/]*?([A-Za-z_]\w*)\s*=\s*["']([^"']{4,})["']`)

func extractVariableInterpolation(filepath string, lines []string, content string) []Token {
	var tokens []Token

	// Build a simple variable→value map from single-line assignments.
	vars := make(map[string]string)
	for _, line := range lines {
		m := simpleAssignRE.FindStringSubmatch(line)
		if m != nil {
			vars[m[1]] = m[2]
		}
	}

	// Look for f-string / format patterns referencing known variables.
	fstringRE := regexp.MustCompile(`([A-Za-z_]\w*)\s*=\s*f["'](.+?)["']`)
	fmtRE := regexp.MustCompile(`([A-Za-z_]\w*)\s*=\s*(\w+)\s*%\s*["']([^"']+)["']`)
	joinRE := regexp.MustCompile(`([A-Za-z_]\w*)\s*=\s*["']?["']?\.join\(\[(.+?)\]\)`)

	for lineNum, line := range lines {
		// f-string: key = f"{prefix}{suffix}"
		if m := fstringRE.FindStringSubmatch(line); m != nil {
			varName := m[1]
			template := m[2]
			resolved := resolveVars(template, vars)
			if resolved != template && len(resolved) >= 8 {
				tokens = append(tokens, Token{
					Value: resolved, VarName: varName,
					Line: lineNum + 1, LineContent: line, FilePath: filepath,
				})
			}
		}

		// format: key = template % "value"
		if m := fmtRE.FindStringSubmatch(line); m != nil {
			varName := m[1]
			templateVar := m[2]
			arg := m[3]
			if tmpl, ok := vars[templateVar]; ok {
				resolved := strings.Replace(tmpl, "%s", arg, 1)
				if len(resolved) >= 8 {
					tokens = append(tokens, Token{
						Value: resolved, VarName: varName,
						Line: lineNum + 1, LineContent: line, FilePath: filepath,
					})
				}
			}
		}

		// join: key = "".join(["a", "b", "c"])
		if m := joinRE.FindStringSubmatch(line); m != nil {
			varName := m[1]
			inner := m[2]
			var parts []string
			for _, p := range regexp.MustCompile(`["']([^"']+)["']`).FindAllStringSubmatch(inner, -1) {
				parts = append(parts, p[1])
			}
			joined := strings.Join(parts, "")
			if len(joined) >= 8 {
				tokens = append(tokens, Token{
					Value: joined, VarName: varName,
					Line: lineNum + 1, LineContent: line, FilePath: filepath,
				})
			}
		}
	}

	return tokens
}

// resolveVars replaces {varname} placeholders with known values.
func resolveVars(template string, vars map[string]string) string {
	result := template
	for name, val := range vars {
		result = strings.ReplaceAll(result, "{"+name+"}", val)
	}
	return result
}

// =========================================================================
// 3. Reversed String Detection
// Catches: reversed_key = "XappC...phg" (reverse of ghp_...CppaX)
// Strategy: if a high-entropy string, when reversed, matches a known prefix,
// it's a reversed credential.
// =========================================================================

func extractReversed(filepath string, lines []string) []Token {
	var tokens []Token
	assignRE := regexp.MustCompile(`([A-Za-z_]\w*)\s*=\s*["']([A-Za-z0-9_+/=\-.]{16,})["']`)

	for lineNum, line := range lines {
		m := assignRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		varName := m[1]
		value := m[2]

		// Only check if variable name hints at reversal
		lv := strings.ToLower(varName)
		if !strings.Contains(lv, "reverse") && !strings.Contains(lv, "backward") &&
			!strings.Contains(lv, "encoded") && !strings.Contains(lv, "obfus") {
			continue
		}

		reversed := reverseString(value)
		if _, _, found := MatchKnownPrefixTrie(reversed); found {
			tokens = append(tokens, Token{
				Value: reversed, VarName: varName + "_reversed",
				Line: lineNum + 1, LineContent: line, FilePath: filepath,
			})
		}
	}
	return tokens
}

func reverseString(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

// =========================================================================
// 4. XML Credential Tag Extraction
// Catches: <password>secret</password>, <apiKey>xxx</apiKey>
// Works on: Maven settings.xml, Spring configs, Tomcat configs, etc.
// =========================================================================

var xmlCredTagRE = regexp.MustCompile(
	`<(password|secret|token|apiKey|api_key|secretKey|secret_key|` +
		`accessKey|access_key|privateKey|private_key|` +
		`connectionString|connection_string|auth_token|authToken|` +
		`credentials|passphrase|signing_key|signingKey|` +
		`client_secret|clientSecret|webhook_secret|webhookSecret)>` +
		`([^<]{4,})</`)

func extractXMLCredentials(filepath string, content string) []Token {
	// Only apply to XML-like files
	ext := strings.ToLower(filepath)
	if !strings.HasSuffix(ext, ".xml") && !strings.HasSuffix(ext, ".config") &&
		!strings.HasSuffix(ext, ".pom") && !strings.HasSuffix(ext, ".csproj") &&
		!strings.HasSuffix(ext, ".props") && !strings.Contains(content, "<?xml") {
		return nil
	}

	var tokens []Token
	lines := strings.Split(content, "\n")

	for lineNum, line := range lines {
		// Tag-based: <password>value</password>
		for _, m := range xmlCredTagRE.FindAllStringSubmatch(line, -1) {
			tagName := m[1]
			value := strings.TrimSpace(m[2])
			// Skip template references
			if strings.Contains(value, "${") || strings.Contains(value, "#{") {
				continue
			}
			if len(value) >= 4 {
				tokens = append(tokens, Token{
					Value: value, VarName: tagName,
					Line: lineNum + 1, LineContent: line, FilePath: filepath,
				})
			}
		}
	}

	return tokens
}

// =========================================================================
// 5. Hex / Bytes Literal Extraction
// Catches: b'\x41\x4b\x49\x41' → "AKIA"
//          hex_str = "736b5f6c697665" → decode to "sk_live"
// =========================================================================

var bytesLiteralRE = regexp.MustCompile(`([A-Za-z_]\w*)\s*=\s*b'((?:\\x[0-9a-fA-F]{2})+)'`)
var bytesLiteralDQRE = regexp.MustCompile(`([A-Za-z_]\w*)\s*=\s*b"((?:\\x[0-9a-fA-F]{2})+)"`)

func extractHexByteLiterals(filepath string, lines []string) []Token {
	var tokens []Token

	for lineNum, line := range lines {
		for _, re := range []*regexp.Regexp{bytesLiteralRE, bytesLiteralDQRE} {
			m := re.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			varName := m[1]
			hexParts := m[2]

			// Parse \xNN sequences
			var decoded []byte
			for i := 0; i+3 < len(hexParts); i += 4 {
				if hexParts[i] == '\\' && hexParts[i+1] == 'x' {
					b, err := hex.DecodeString(hexParts[i+2 : i+4])
					if err == nil {
						decoded = append(decoded, b...)
					}
				}
			}

			if len(decoded) >= 8 && utf8.Valid(decoded) {
				decodedStr := string(decoded)
				tokens = append(tokens, Token{
					Value: decodedStr, VarName: varName,
					Line: lineNum + 1, LineContent: line, FilePath: filepath,
				})
			}
		}
	}

	return tokens
}

// =========================================================================
// 6. ROT13 Detection
// Catches: encoded_secret = "fx_yvir_..." → ROT13 → "sk_live_..."
// Strategy: only apply ROT13 when the variable name hints at encoding,
// and the decoded result matches a known prefix.
// =========================================================================

func extractROT13(filepath string, lines []string) []Token {
	var tokens []Token
	assignRE := regexp.MustCompile(`([A-Za-z_]\w*)\s*=\s*["']([A-Za-z0-9_+/=\-.]{8,})["']`)

	for lineNum, line := range lines {
		m := assignRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		varName := m[1]
		value := m[2]

		// Only try ROT13 when variable name hints at encoding/obfuscation
		lv := strings.ToLower(varName)
		if !strings.Contains(lv, "encoded") && !strings.Contains(lv, "encrypt") &&
			!strings.Contains(lv, "obfus") && !strings.Contains(lv, "cipher") &&
			!strings.Contains(lv, "rot") && !strings.Contains(lv, "hidden") &&
			!strings.Contains(lv, "masked") {
			continue
		}

		decoded := rot13(value)
		if _, _, found := MatchKnownPrefixTrie(decoded); found {
			tokens = append(tokens, Token{
				Value: decoded, VarName: varName + "_rot13",
				Line: lineNum + 1, LineContent: line, FilePath: filepath,
			})
		}
	}

	return tokens
}

func rot13(s string) string {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
			result[i] = (c-'a'+13)%26 + 'a'
		case c >= 'A' && c <= 'Z':
			result[i] = (c-'A'+13)%26 + 'A'
		default:
			result[i] = c
		}
	}
	return string(result)
}

// =========================================================================
// 7. YAML Block Scalar Extraction
// Catches:
//   password: |
//     Kx9vT3mNw7pLcR2jQ5xHv8
// The key is on one line, the value is on the next line(s) indented.
// =========================================================================

var yamlBlockKeyRE = regexp.MustCompile(
	`^\s*(password|secret|token|api_key|apikey|secret_key|private_key|` +
		`access_key|auth_token|connection_string|db_password|database_url|` +
		`client_secret|webhook_secret|signing_key|passphrase|credentials)` +
		`\s*:\s*[|>]\s*$`)

func extractYAMLBlockScalar(filepath string, lines []string) []Token {
	var tokens []Token
	for i, line := range lines {
		m := yamlBlockKeyRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		keyName := m[1]
		// The value is on the next non-empty indented line(s)
		if i+1 < len(lines) {
			nextLine := strings.TrimSpace(lines[i+1])
			if len(nextLine) >= 8 {
				// Skip template references
				if strings.Contains(nextLine, "${") || strings.Contains(nextLine, "{{") {
					continue
				}
				tokens = append(tokens, Token{
					Value:       nextLine,
					VarName:     keyName,
					Line:        i + 2,
					LineContent: lines[i+1],
					FilePath:    filepath,
				})
			}
		}
	}
	return tokens
}

// =========================================================================
// 8. MySQL -p Inline Password
// Catches: mysql -u root -pMyPassword hostname
// MySQL convention: -p has NO space before the password.
// =========================================================================

var mysqlPwRE = regexp.MustCompile(`-p([^ 	"']{6,})`)

func extractMySQLInlinePassword(filepath string, lines []string) []Token {
	var tokens []Token
	for i, line := range lines {
		lower := strings.ToLower(line)
		if !strings.Contains(lower, "mysql") && !strings.Contains(lower, "mysqldump") &&
			!strings.Contains(lower, "mariadb") {
			continue
		}
		m := mysqlPwRE.FindStringSubmatch(line)
		if m != nil {
			pw := m[1]
			// Skip common flags like -port, -protocol
			if strings.HasPrefix(strings.ToLower(pw), "ort") ||
				strings.HasPrefix(strings.ToLower(pw), "rotocol") {
				continue
			}
			tokens = append(tokens, Token{
				Value:       pw,
				VarName:     "mysql_password",
				Line:        i + 1,
				LineContent: line,
				FilePath:    filepath,
			})
		}
	}
	return tokens
}

// =========================================================================
// 9. Single-Quoted Credential Extraction
// Catches: 'api_key': 'ghp_SV2ceN59...' (Python dict, Ruby hash, etc.)
// The standard extractor only handles double-quoted JSON or assignment
// patterns. This catches single-quoted key-value pairs common in
// Python dicts, Ruby hashes, and YAML.
// =========================================================================

var singleQuoteCredRE = regexp.MustCompile(
	`'(password|secret|token|api_key|apikey|secret_key|private_key|` +
		`access_key|auth_token|db_password|client_secret|webhook_secret|` +
		`signing_key|credentials|api_secret|stripe_key|github_token|` +
		`slack_token|aws_secret)'\s*:\s*'([^']{8,})'`)

func extractSingleQuotedCredentials(filepath string, lines []string) []Token {
	var tokens []Token
	for i, line := range lines {
		for _, m := range singleQuoteCredRE.FindAllStringSubmatch(line, -1) {
			keyName := m[1]
			value := m[2]
			// Skip placeholders
			lower := strings.ToLower(value)
			if strings.Contains(lower, "your") || strings.Contains(lower, "replace") ||
				strings.Contains(lower, "change") || strings.Contains(lower, "example") ||
				strings.Contains(lower, "xxx") {
				continue
			}
			tokens = append(tokens, Token{
				Value:       value,
				VarName:     keyName,
				Line:        i + 1,
				LineContent: line,
				FilePath:    filepath,
			})
		}
	}
	return tokens
}

// =========================================================================
// SHARED: Build a single-file variable → literal-value map.
// Used by cross-var concat, base64 decode, and other resolvers.
// =========================================================================

func buildVarMap(lines []string) map[string]string {
	vars := make(map[string]string)
	re := regexp.MustCompile(`^[^#/]*?([A-Za-z_]\w*)\s*=\s*["']([^"']{1,512})["']`)
	for _, line := range lines {
		m := re.FindStringSubmatch(line)
		if m != nil {
			vars[m[1]] = m[2]
		}
	}
	return vars
}

// =========================================================================
// P0-1: Cross-Variable Concatenation
// Catches: _p = "sk_live_"; _s = "4eC39..."; key = _p + _s
// =========================================================================

var varConcatRE = regexp.MustCompile(
	`([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\s*\+\s*([A-Za-z_]\w*|"[^"]*"|'[^']*')`)

func extractCrossVarConcat(filepath string, lines []string, vars map[string]string) []Token {
	var tokens []Token
	for lineNum, line := range lines {
		m := varConcatRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		target := m[1]
		leftVal := resolveOperand(m[2], vars)
		rightVal := resolveOperand(m[3], vars)
		if leftVal == "" || rightVal == "" {
			continue
		}
		joined := leftVal + rightVal
		if len(joined) >= 8 {
			if _, _, found := MatchKnownPrefix(joined); found {
				tokens = append(tokens, Token{
					Value: joined, VarName: target,
					Line: lineNum + 1, LineContent: line, FilePath: filepath,
				})
			}
		}
	}
	return tokens
}

func resolveOperand(op string, vars map[string]string) string {
	if len(op) >= 2 && (op[0] == '"' || op[0] == '\'') {
		return op[1 : len(op)-1]
	}
	if val, ok := vars[op]; ok {
		return val
	}
	return ""
}

// =========================================================================
// P0-2: Base64 Decode Call Tracing
// Catches: encoded = "c2tfbGl2ZV8..."; key = base64.b64decode(encoded)
// =========================================================================

var b64DecodeCallRE = regexp.MustCompile(
	`(?:base64\.b64decode|base64\.decodebytes|atob|` +
		`Base64\.decode64|base64\.StdEncoding\.DecodeString|` +
		`Buffer\.from)\s*\(\s*([A-Za-z_]\w*)`)

func extractBase64DecodeCalls(filepath string, lines []string, vars map[string]string) []Token {
	var tokens []Token
	for lineNum, line := range lines {
		m := b64DecodeCallRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		sourceVar := m[1]
		encoded, ok := vars[sourceVar]
		if !ok {
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			decoded, err = base64.RawStdEncoding.DecodeString(encoded)
		}
		if err != nil || len(decoded) < 8 || !utf8.Valid(decoded) {
			continue
		}
		tokens = append(tokens, Token{
			Value: string(decoded), VarName: sourceVar + "_b64decoded",
			Line: lineNum + 1, LineContent: line, FilePath: filepath,
		})
	}
	return tokens
}

// =========================================================================
// P0-3: Multi-Line Array Join
// Catches: parts = ["sk_", "live_", ...]\n api_key = "".join(parts)
// =========================================================================

var listStartRE = regexp.MustCompile(`^[^#]*?([A-Za-z_]\w*)\s*=\s*\[`)
var listItemRE = regexp.MustCompile(`["']([^"']+)["']`)
var joinCallRE = regexp.MustCompile(`([A-Za-z_]\w*)\s*=\s*["'][^"']*["']\.join\(\s*([A-Za-z_]\w*)\s*\)`)

func extractMultiLineJoin(filepath string, lines []string, content string) []Token {
	var tokens []Token
	listVars := make(map[string][]string)
	var currentList string
	var collecting bool

	for _, line := range lines {
		if collecting {
			for _, m := range listItemRE.FindAllStringSubmatch(line, -1) {
				listVars[currentList] = append(listVars[currentList], m[1])
			}
			if strings.Contains(line, "]") {
				collecting = false
			}
			continue
		}
		m := listStartRE.FindStringSubmatch(line)
		if m != nil {
			currentList = m[1]
			collecting = true
			listVars[currentList] = nil
			for _, im := range listItemRE.FindAllStringSubmatch(line, -1) {
				listVars[currentList] = append(listVars[currentList], im[1])
			}
			if strings.Contains(line, "]") {
				collecting = false
			}
		}
	}

	for lineNum, line := range lines {
		m := joinCallRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		target := m[1]
		parts, ok := listVars[m[2]]
		if !ok || len(parts) == 0 {
			continue
		}
		joined := strings.Join(parts, "")
		if len(joined) >= 8 {
			tokens = append(tokens, Token{
				Value: joined, VarName: target,
				Line: lineNum + 1, LineContent: line, FilePath: filepath,
			})
		}
	}
	return tokens
}

// =========================================================================
// P0-4: Python Slice Reversal [::-1]
// Catches: secret = "cd7pdz1T...evil_ks"[::-1]
// =========================================================================

var sliceReverseRE = regexp.MustCompile(
	`([A-Za-z_]\w*)\s*=\s*["']([^"']{8,})["']\s*\[::\s*-1\s*\]`)

func extractPythonSliceReverse(filepath string, lines []string) []Token {
	var tokens []Token
	for lineNum, line := range lines {
		m := sliceReverseRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		reversed := reverseString(m[2])
		if len(reversed) >= 8 {
			tokens = append(tokens, Token{
				Value: reversed, VarName: m[1],
				Line: lineNum + 1, LineContent: line, FilePath: filepath,
			})
		}
	}
	return tokens
}

// =========================================================================
// P0-5: Bearer/Auth Tokens Embedded in String Literals
// Catches: curl -H 'Authorization: Bearer ghp_R3aL...' https://...
// =========================================================================

var bearerInStringRE = regexp.MustCompile(
	`(?i)Authorization\s*:\s*Bearer\s+([A-Za-z0-9_\-.]{20,})`)

func extractBearerTokensInStrings(filepath string, lines []string) []Token {
	var tokens []Token
	for lineNum, line := range lines {
		if m := bearerInStringRE.FindStringSubmatch(line); m != nil {
			tokens = append(tokens, Token{
				Value: m[1], VarName: "bearer_token",
				Line: lineNum + 1, LineContent: line, FilePath: filepath,
			})
		}
	}
	return tokens
}

// =========================================================================
// P1-1: codecs.decode(..., "rot_13") Function Call Detection
// =========================================================================

var codecsROT13RE = regexp.MustCompile(
	`([A-Za-z_]\w*)\s*=\s*codecs\.decode\(\s*["']([^"']{8,})["']\s*,\s*["']rot.?13["']\s*\)`)

func extractCodecsROT13(filepath string, lines []string) []Token {
	var tokens []Token
	for lineNum, line := range lines {
		m := codecsROT13RE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		decoded := rot13(m[2])
		if len(decoded) >= 8 {
			tokens = append(tokens, Token{
				Value: decoded, VarName: m[1],
				Line: lineNum + 1, LineContent: line, FilePath: filepath,
			})
		}
	}
	return tokens
}

// =========================================================================
// P2-1: bytes([0x73, 0x6b, ...]) Array Literal
// =========================================================================

var bytesArrayRE = regexp.MustCompile(
	`([A-Za-z_]\w*)\s*=\s*(?:bytes|bytearray)\s*\(\s*\[([^\]]+)\]`)

func extractBytesArrayLiterals(filepath string, lines []string) []Token {
	var tokens []Token
	content := strings.Join(lines, "\n")

	for _, m := range bytesArrayRE.FindAllStringSubmatch(content, -1) {
		varName := m[1]
		inner := m[2]
		var decoded []byte
		for _, numStr := range regexp.MustCompile(`0[xX]([0-9a-fA-F]{2})`).FindAllStringSubmatch(inner, -1) {
			b, err := hex.DecodeString(numStr[1])
			if err == nil {
				decoded = append(decoded, b...)
			}
		}
		if len(decoded) == 0 {
			for _, numStr := range regexp.MustCompile(`\b(\d{1,3})\b`).FindAllStringSubmatch(inner, -1) {
				val, err := strconv.Atoi(numStr[1])
				if err == nil && val >= 0 && val <= 255 {
					decoded = append(decoded, byte(val))
				}
			}
		}
		if len(decoded) >= 8 && utf8.Valid(decoded) {
			lineNum := strings.Count(content[:strings.Index(content, m[0])], "\n") + 1
			tokens = append(tokens, Token{
				Value: string(decoded), VarName: varName,
				Line: lineNum, LineContent: m[0], FilePath: filepath,
			})
		}
	}
	return tokens
}

// =========================================================================
// INI-Style Credential Extraction (AWS credentials, .cfg, .ini, .conf)
// Catches: aws_secret_access_key = AwsCredF1leS3cr3t+K3y/...
// The main extractor's combinedExtractRE requires uppercase-start vars.
// AWS credential files use lowercase keys with unquoted values.
// =========================================================================

var iniCredRE = regexp.MustCompile(
	`^(?:\s*)` +
		`(aws_access_key_id|aws_secret_access_key|` +
		`aws_session_token|password|secret|token|api_key|` +
		`secret_key|access_key|private_key|auth_token|` +
		`client_secret|client_id)` +
		`\s*=\s*([^\s#]{8,})`)

func extractINICredentials(filepath string, lines []string) []Token {
	var tokens []Token
	for lineNum, line := range lines {
		m := iniCredRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		varName := m[1]
		value := strings.TrimRight(m[2], `"'`)
		if len(value) >= 8 {
			tokens = append(tokens, Token{
				Value: value, VarName: varName,
				Line: lineNum + 1, LineContent: line, FilePath: filepath,
			})
		}
	}
	return tokens
}

// =========================================================================
// URL-Decoded Connection Strings
// Catches: postgresql://user:S3cur3%40P%21ss@host (where %40=@, %21=!)
// The main connection string regex can fail on URL-encoded special chars
// because the password boundary parser looks for literal @.
// This extractor URL-decodes the password portion before classification.
// =========================================================================

var urlEncodedConnRE = regexp.MustCompile(
	`((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|mssql)://[^\s"']+%[0-9a-fA-F]{2}[^\s"']*)`)

func extractURLDecodedConnStrings(filepath string, lines []string) []Token {
	var tokens []Token
	for lineNum, line := range lines {
		m := urlEncodedConnRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		raw := m[1]
		decoded, err := url.QueryUnescape(raw)
		if err != nil {
			continue
		}
		if decoded != raw && len(decoded) >= 16 {
			tokens = append(tokens, Token{
				Value: decoded, VarName: "connection_string",
				Line: lineNum + 1, LineContent: line, FilePath: filepath,
			})
		}
	}
	return tokens
}
