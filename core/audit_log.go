// audit_log.go -- Tier 3: Security Audit Logging
//
// Records all security-relevant actions for compliance and forensics.
// Thread-safe, supports JSON and CSV export.
package synapse

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"
)

// AuditLogger records all security-relevant actions.
type AuditLogger struct {
	entries []AuditEntry
	mu      sync.Mutex
	output  io.Writer // file or stdout
}

// AuditEntry represents a single audit log entry.
type AuditEntry struct {
	Timestamp time.Time         `json:"timestamp"`
	Action    string            `json:"action"`    // "scan_started", "secret_found", "secret_verified", "secret_remediated", "config_changed"
	Actor     string            `json:"actor"`     // scanner ID or user
	Resource  string            `json:"resource"`  // file path, repo URL, etc.
	Details   map[string]string `json:"details"`
	Outcome   string            `json:"outcome"`   // "success", "failure", "skipped"
}

// NewAuditLogger creates a new audit logger writing to the given output.
func NewAuditLogger(output io.Writer) *AuditLogger {
	return &AuditLogger{
		output: output,
	}
}

// Log records a new audit entry.
func (al *AuditLogger) Log(action, actor, resource, outcome string, details map[string]string) {
	entry := AuditEntry{
		Timestamp: time.Now(),
		Action:    action,
		Actor:     actor,
		Resource:  resource,
		Details:   details,
		Outcome:   outcome,
	}

	al.mu.Lock()
	al.entries = append(al.entries, entry)
	al.mu.Unlock()

	// Write to output if configured
	if al.output != nil {
		line := fmt.Sprintf("[%s] action=%s actor=%s resource=%s outcome=%s\n",
			entry.Timestamp.Format(time.RFC3339),
			action, actor, resource, outcome)
		// Best-effort write; do not block on output errors
		al.mu.Lock()
		_, _ = io.WriteString(al.output, line)
		al.mu.Unlock()
	}
}

// GetEntries returns all entries since the given time.
func (al *AuditLogger) GetEntries(since time.Time) []AuditEntry {
	al.mu.Lock()
	defer al.mu.Unlock()

	var result []AuditEntry
	for _, e := range al.entries {
		if !e.Timestamp.Before(since) {
			result = append(result, e)
		}
	}
	return result
}

// Export exports all entries in the given format ("json" or "csv").
func (al *AuditLogger) Export(format string) ([]byte, error) {
	al.mu.Lock()
	entries := make([]AuditEntry, len(al.entries))
	copy(entries, al.entries)
	al.mu.Unlock()

	// Sort by timestamp
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Timestamp.Before(entries[j].Timestamp)
	})

	switch strings.ToLower(format) {
	case "json":
		return json.MarshalIndent(entries, "", "  ")
	case "csv":
		return exportCSV(entries)
	default:
		return nil, fmt.Errorf("unsupported export format: %s (use 'json' or 'csv')", format)
	}
}

func exportCSV(entries []AuditEntry) ([]byte, error) {
	var buf strings.Builder
	w := csv.NewWriter(&buf)

	// Header
	if err := w.Write([]string{"timestamp", "action", "actor", "resource", "outcome", "details"}); err != nil {
		return nil, err
	}

	for _, e := range entries {
		detailParts := make([]string, 0, len(e.Details))
		for k, v := range e.Details {
			detailParts = append(detailParts, k+"="+v)
		}
		detailStr := strings.Join(detailParts, "; ")

		if err := w.Write([]string{
			e.Timestamp.Format(time.RFC3339),
			e.Action,
			e.Actor,
			e.Resource,
			e.Outcome,
			detailStr,
		}); err != nil {
			return nil, err
		}
	}

	w.Flush()
	if err := w.Error(); err != nil {
		return nil, err
	}
	return []byte(buf.String()), nil
}
