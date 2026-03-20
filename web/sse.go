package web

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
)

// SSEEvent is a typed event published to SSE subscribers.
type SSEEvent struct {
	Type   string      `json:"type"`
	ScanID string      `json:"scan_id"`
	Data   interface{} `json:"data"`
}

// ScanProgress carries real-time progress information for a running scan.
type ScanProgress struct {
	FilesScanned   int     `json:"files_scanned"`
	FilesTotal     int     `json:"files_total"`
	FindingsSoFar  int     `json:"findings_so_far"`
	CurrentFile    string  `json:"current_file"`
	ElapsedSeconds float64 `json:"elapsed_seconds"`
	Percentage     float64 `json:"percentage"`
}

// SSEHub manages per-scan SSE subscriber channels.
type SSEHub struct {
	mu      sync.RWMutex
	clients map[string][]chan SSEEvent
}

// NewSSEHub creates an empty SSEHub.
func NewSSEHub() *SSEHub {
	return &SSEHub{
		clients: make(map[string][]chan SSEEvent),
	}
}

// Subscribe registers a new listener for the given scan ID. It returns a
// read-only channel that will receive events and an unsubscribe function
// that must be called when the client disconnects.
func (h *SSEHub) Subscribe(scanID string) (<-chan SSEEvent, func()) {
	ch := make(chan SSEEvent, 64)

	h.mu.Lock()
	h.clients[scanID] = append(h.clients[scanID], ch)
	h.mu.Unlock()

	unsubscribe := func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		subs := h.clients[scanID]
		for i, c := range subs {
			if c == ch {
				h.clients[scanID] = append(subs[:i], subs[i+1:]...)
				close(ch)
				break
			}
		}
		if len(h.clients[scanID]) == 0 {
			delete(h.clients, scanID)
		}
	}

	return ch, unsubscribe
}

// Publish sends an event to all subscribers of the given scan ID.
func (h *SSEHub) Publish(event SSEEvent) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	subs := h.clients[event.ScanID]
	for _, ch := range subs {
		select {
		case ch <- event:
		default:
			log.Printf("[SSE] dropping event for slow client on scan %s", event.ScanID)
		}
	}
}

// ServeHTTP handles SSE stream requests. The scan_id is extracted from the
// URL path which should be /api/v1/stream/{scan_id}.
func (h *SSEHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	scanID := extractScanIDFromPath(r.URL.Path)
	if scanID == "" {
		http.Error(w, "missing scan_id", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	ch, unsub := h.Subscribe(scanID)
	defer unsub()

	ctx := r.Context()

	for {
		select {
		case <-ctx.Done():
			return
		case evt, ok := <-ch:
			if !ok {
				return
			}
			data, err := json.Marshal(evt)
			if err != nil {
				log.Printf("[SSE] marshal error: %v", err)
				continue
			}
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", evt.Type, data)
			flusher.Flush()

			if evt.Type == "complete" || evt.Type == "error" {
				return
			}
		}
	}
}

// extractScanIDFromPath pulls the last path segment from a URL like
// /api/v1/stream/{scan_id}.
func extractScanIDFromPath(path string) string {
	path = strings.TrimSuffix(path, "/")
	parts := strings.Split(path, "/")
	if len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1]
}
