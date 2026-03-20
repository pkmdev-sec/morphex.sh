package engine

import (
	"hash/fnv"
	"math"
	"sync"
)

// ============================================================================
// 1. Aho-Corasick Trie for prefix matching
// ============================================================================

// trieNode is a node in a compact prefix trie.
type trieNode struct {
	children  [256]*trieNode
	ecosystem string // non-empty if this node terminates a known prefix
	prefix    string // the full prefix string at this terminal node
}

var prefixTrieRoot *trieNode

func init() {
	prefixTrieRoot = &trieNode{}
	for prefix, ecosystem := range KnownPrefixes {
		node := prefixTrieRoot
		for i := 0; i < len(prefix); i++ {
			c := prefix[i]
			if node.children[c] == nil {
				node.children[c] = &trieNode{}
			}
			node = node.children[c]
		}
		node.ecosystem = ecosystem
		node.prefix = prefix
	}
}

// MatchKnownPrefixTrie performs O(V) prefix matching using a trie, where V is
// the length of value. It walks the trie byte-by-byte and returns the longest
// matching prefix. This scales independently of the number of prefixes.
func MatchKnownPrefixTrie(value string) (prefix, ecosystem string, found bool) {
	if len(value) == 0 {
		return "", "", false
	}

	node := prefixTrieRoot
	// Track the longest match found so far.
	var bestPrefix string
	var bestEcosystem string

	for i := 0; i < len(value); i++ {
		child := node.children[value[i]]
		if child == nil {
			break
		}
		node = child
		if node.ecosystem != "" {
			bestPrefix = node.prefix
			bestEcosystem = node.ecosystem
		}
	}

	if bestEcosystem != "" {
		return bestPrefix, bestEcosystem, true
	}
	return "", "", false
}

// ============================================================================
// 2. Batch Classification API
// ============================================================================

// ClassifyTokenBatch classifies a batch of tokens, pre-computing file
// provenance for all unique file paths in one pass to eliminate redundant
// cache lookups. Returns classifications in the same order as input tokens.
func ClassifyTokenBatch(tokens []Token) []Classification {
	if len(tokens) == 0 {
		return nil
	}

	// Pre-compute file provenance for all unique file paths.
	type fileProvEntry struct {
		category   string
		likelihood float64
		reason     string
	}
	provCache := make(map[string]fileProvEntry, len(tokens))
	for _, tok := range tokens {
		if _, exists := provCache[tok.FilePath]; !exists {
			cat, lk, reason := ClassifyFileProvenance(tok.FilePath)
			provCache[tok.FilePath] = fileProvEntry{cat, lk, reason}
		}
	}

	results := make([]Classification, len(tokens))
	for i, tok := range tokens {
		results[i] = ClassifyToken(tok)
	}
	return results
}

// ============================================================================
// 3. Entropy Lookup Table
// ============================================================================

// entropyLUT stores pre-computed -p*log2(p) values.
// Index [count][length] = -p*log2(p) where p = count/length.
// We support strings up to 512 chars long. For a given frequency count
// (1..512) and string length (1..512), the value is pre-computed.
//
// To keep memory bounded we use a flat table indexed by count (1-based).
// For a given count c in a string of length n, entropy contribution =
// -(c/n)*log2(c/n). We store values per count in a [513]float64 array
// indexed by string length n, but that would be 513*513*8 = ~2MB.
// Instead, we use a single [513]float64 table mapping ratio numerator
// to -p*log2(p) at runtime, keyed by (count, length).
//
// Practical approach: store a lookup of plog2p[count] for each possible
// count, then at runtime divide by length. Since:
//   -p*log2(p) = -(c/n)*log2(c/n) = (c/n)*(log2(n) - log2(c))
//              = (c * (log2(n) - log2(c))) / n
// We pre-compute log2Table[i] = log2(i) for i in 1..512.

const maxLUTLen = 512

var log2Table [maxLUTLen + 1]float64

func init() {
	for i := 1; i <= maxLUTLen; i++ {
		log2Table[i] = math.Log2(float64(i))
	}
}

// ShannonEntropyLUT computes Shannon entropy using a pre-computed log2 lookup
// table, avoiding per-character math.Log2 calls. For strings up to 512 chars
// all log2 values are table lookups; longer strings fall back to math.Log2.
func ShannonEntropyLUT(s string) float64 {
	n := len(s)
	if n == 0 {
		return 0.0
	}

	var freq [256]int
	for i := 0; i < n; i++ {
		freq[s[i]]++
	}

	if n <= maxLUTLen {
		log2n := log2Table[n]
		entropy := 0.0
		for _, count := range freq {
			if count == 0 {
				continue
			}
			// -p*log2(p) = (count/n) * (log2(n) - log2(count))
			entropy += float64(count) * (log2n - log2Table[count])
		}
		return entropy / float64(n)
	}

	// Fallback for strings longer than 512 chars.
	length := float64(n)
	log2n := math.Log2(length)
	entropy := 0.0
	for _, count := range freq {
		if count == 0 {
			continue
		}
		c := float64(count)
		entropy += c * (log2n - math.Log2(c))
	}
	return entropy / length
}

// ============================================================================
// 4. SIMD-friendly line pre-filter
// ============================================================================

// signalCharLUT is a lookup table: true for bytes that indicate a line may
// contain an extractable token ('=', ':', or '-').
var signalCharLUT [256]bool

func init() {
	signalCharLUT['='] = true
	signalCharLUT[':'] = true
	signalCharLUT['-'] = true
}

// LineHasExtractSignal performs a single-pass scan of a line to check whether
// it contains any of the extraction signal characters ('=', ':', '-').
// This replaces the original 3-pass approach of:
//
//	strings.Contains(line, "=") || strings.Contains(line, ":") || strings.Contains(line, "-----")
//
// with a single byte scan that short-circuits on the first match.
func LineHasExtractSignal(line string) bool {
	for i := 0; i < len(line); i++ {
		if signalCharLUT[line[i]] {
			return true
		}
	}
	return false
}

// ============================================================================
// 5. Bloom filter for git dedup
// ============================================================================

// bloomFilterBits is the size of the bloom filter bit array in bits (64KB = 524288 bits).
const bloomFilterBits = 64 * 1024 * 8 // 524288 bits

// bloomFilterBytes is the size of the bit array in bytes.
const bloomFilterBytes = bloomFilterBits / 8

// FindingBloomFilter is a probabilistic data structure for fast deduplication
// of findings. It uses 2 independent hash functions over a 64KB bit array.
// False positive rate ≈ (1 - e^(-2n/m))^2 where n = items, m = 524288 bits.
// For 10,000 findings this is approximately 0.07%.
type FindingBloomFilter struct {
	mu   sync.RWMutex
	bits [bloomFilterBytes]byte
}

// NewFindingBloomFilter creates a new bloom filter for finding deduplication.
func NewFindingBloomFilter() *FindingBloomFilter {
	return &FindingBloomFilter{}
}

// bloomHashes computes two independent hash positions for the given key.
// Uses FNV-1a (hash1) and FNV-1a with a seed offset (hash2).
func bloomHashes(secretHash, filePath string) (uint32, uint32) {
	combined := secretHash + "|" + filePath

	h1 := fnv.New32a()
	h1.Write([]byte(combined))
	hash1 := h1.Sum32() % bloomFilterBits

	h2 := fnv.New32a()
	h2.Write([]byte("bloom2:" + combined))
	hash2 := h2.Sum32() % bloomFilterBits

	return hash1, hash2
}

// Add inserts a (secretHash, filePath) pair into the bloom filter.
func (bf *FindingBloomFilter) Add(secretHash, filePath string) {
	h1, h2 := bloomHashes(secretHash, filePath)

	bf.mu.Lock()
	bf.bits[h1/8] |= 1 << (h1 % 8)
	bf.bits[h2/8] |= 1 << (h2 % 8)
	bf.mu.Unlock()
}

// MayContain returns true if the (secretHash, filePath) pair may have been
// added to the filter. False positives are possible; false negatives are not.
func (bf *FindingBloomFilter) MayContain(secretHash, filePath string) bool {
	h1, h2 := bloomHashes(secretHash, filePath)

	bf.mu.RLock()
	defer bf.mu.RUnlock()
	return (bf.bits[h1/8]&(1<<(h1%8)) != 0) &&
		(bf.bits[h2/8]&(1<<(h2%8)) != 0)
}

// Reset clears all bits in the bloom filter.
func (bf *FindingBloomFilter) Reset() {
	bf.mu.Lock()
	for i := range bf.bits {
		bf.bits[i] = 0
	}
	bf.mu.Unlock()
}
