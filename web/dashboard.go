package web

import (
	"encoding/json"
	"net/http"
)

// DashboardStats is the aggregate statistics response.
type DashboardStats struct {
	TotalScans           int            `json:"total_scans"`
	TotalFindings        int            `json:"total_findings"`
	AvgScanTime          string         `json:"avg_scan_time"`
	FindingsByProvenance map[string]int `json:"findings_by_provenance"`
	FindingsBySeverity   map[string]int `json:"findings_by_severity"`
	RecentScans          []ScanRecord   `json:"recent_scans"`
	TopFiles             []FileHotspot  `json:"top_files"`
	TrendDaily           []DailyTrend   `json:"trend_daily"`
	DetectorBreakdown    map[string]int `json:"detector_breakdown"`
	ScansByType          map[string]int `json:"scans_by_type"`
}

// FileHotspot identifies a file with many findings.
type FileHotspot struct {
	File   string `json:"file"`
	Count  int    `json:"count"`
	MaxSev string `json:"max_severity"`
}

// DailyTrend captures per-day scan and finding counts.
type DailyTrend struct {
	Date     string `json:"date"`
	Scans    int    `json:"scans"`
	Findings int    `json:"findings"`
}

// handleDashboardStats returns GET /api/v1/dashboard/stats.
func handleDashboardStats(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		stats := store.GetStats()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(stats)
	}
}

// handleDashboardTrends returns GET /api/v1/dashboard/trends.
func handleDashboardTrends(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		stats := store.GetStats()
		resp := struct {
			TrendDaily []DailyTrend `json:"trend_daily"`
		}{
			TrendDaily: stats.TrendDaily,
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// writeJSONError writes a JSON error response.
func writeJSONError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}
