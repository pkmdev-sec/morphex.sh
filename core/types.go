package synapse

import "time"

// Chunk represents a piece of content to be scanned for secrets.
// This mirrors the MORPHEX SDK Chunk type for local use without a direct
// SDK import dependency.
type Chunk struct {
	Data     []byte
	Metadata ChunkMetadata
}

// ChunkMetadata contains source information about a chunk.
type ChunkMetadata struct {
	Source    string
	SourceID int64
	File     string
	Line     int
	Commit   string
	Email    string
	Timestamp time.Time
	Link     string
}

// Result represents a detected secret finding, mirroring the MORPHEX SDK Result.
type Result struct {
	DetectorName string
	Raw          string
	Redacted     string
	Verified     bool
	SourceFile   string
	SourceLine   int
	Link         string
	ExtraData    map[string]string
}
