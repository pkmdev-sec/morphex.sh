package engine

import (
	"crypto/sha256"
	"encoding/hex"
)

// DefaultMaxDecodeDepth is the default maximum decode depth, matching
// TruffleHog's --max-decode-depth default.
const DefaultMaxDecodeDepth = 5

// contentHash returns a hex-encoded SHA-256 hash of s, used to deduplicate
// decoded content across decode passes.
func contentHash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// DecodeChain applies all decoders iteratively up to maxDepth.
// Each decoder's output is fed back through all decoders.
// Depth 1 = single pass (current behavior), 2+ = chained decoding.
//
// The algorithm starts with DecodeContent(content) as depth 1. For each
// decoded fragment at depth N it runs DecodeContent(fragment.Content) again,
// collecting new unique variants. It deduplicates by content hash to avoid
// infinite loops and stops at maxDepth or when no new content is discovered.
//
// All unique decoded variants found across all depths are returned. The first
// element is always the raw input itself (as returned by DecodeContent).
func DecodeChain(content string, maxDepth int) []DecodedContent {
	if maxDepth <= 0 {
		maxDepth = DefaultMaxDecodeDepth
	}

	// seen tracks content hashes we have already recorded to avoid duplicates.
	seen := make(map[string]bool)

	// results accumulates every unique DecodedContent across all depths.
	var results []DecodedContent

	// addUnique appends dc to results if its content hasn't been seen before.
	// Returns true when the content was new.
	addUnique := func(dc DecodedContent) bool {
		h := contentHash(dc.Content)
		if seen[h] {
			return false
		}
		seen[h] = true
		results = append(results, dc)
		return true
	}

	// Depth 1: run the standard single-pass decoder.
	firstPass := DecodeContent(content)
	for _, dc := range firstPass {
		addUnique(dc)
	}

	// frontier holds content strings discovered at the current depth that
	// should be decoded again at the next depth.
	frontier := make([]string, 0, len(firstPass))
	for _, dc := range firstPass {
		// Only chain non-raw fragments (raw is the original input; decoding
		// it again at depth 2 would just repeat depth 1). We do include raw
		// in the frontier for depth 1 since firstPass already handled it.
		if dc.Encoding != "raw" {
			frontier = append(frontier, dc.Content)
		}
	}

	// Iterative deepening: depths 2 through maxDepth.
	for depth := 2; depth <= maxDepth; depth++ {
		if len(frontier) == 0 {
			break
		}

		var nextFrontier []string

		for _, fragment := range frontier {
			decoded := DecodeContent(fragment)
			for _, dc := range decoded {
				if dc.Encoding == "raw" {
					// The raw echo of a fragment we already recorded — skip.
					continue
				}
				if addUnique(dc) {
					nextFrontier = append(nextFrontier, dc.Content)
				}
			}
		}

		frontier = nextFrontier
	}

	return results
}
