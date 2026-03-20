package web

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// ScanRecord represents a persisted scan execution.
type ScanRecord struct {
	ID            string    `json:"id"`
	StartedAt     time.Time `json:"started_at"`
	CompletedAt   time.Time `json:"completed_at"`
	Status        string    `json:"status"`
	Target        string    `json:"target"`
	ScanType      string    `json:"scan_type"`
	TotalFindings int       `json:"total_findings"`
	FilesScanned  int       `json:"files_scanned"`
	Duration      string    `json:"duration"`
	Threshold     float64   `json:"threshold"`
	Deep          bool      `json:"deep"`
	Error         string    `json:"error,omitempty"`
}

// FindingRecord represents a persisted finding from a scan.
type FindingRecord struct {
	ScanID      string    `json:"scan_id"`
	File        string    `json:"file"`
	Line        int       `json:"line"`
	Detector    string    `json:"detector"`
	Confidence  float64   `json:"confidence"`
	Provenance  string    `json:"provenance"`
	Severity    string    `json:"severity"`
	Fingerprint string    `json:"fingerprint"`
	CreatedAt   time.Time `json:"created_at"`
}

// storeData is the on-disk JSON structure.
type storeData struct {
	Scans    []ScanRecord    `json:"scans"`
	Findings []FindingRecord `json:"findings"`
}

// Store persists scan history to disk as JSON.
type Store struct {
	mu       sync.RWMutex
	dataDir  string
	scans    []ScanRecord
	findings []FindingRecord
}

// NewStore creates a new Store that reads/writes to dataDir.
func NewStore(dataDir string) *Store {
	s := &Store{
		dataDir:  dataDir,
		scans:    make([]ScanRecord, 0),
		findings: make([]FindingRecord, 0),
	}
	_ = os.MkdirAll(dataDir, 0o755)
	_ = s.load()
	return s
}

func (s *Store) filePath() string {
	return filepath.Join(s.dataDir, "morphex_store.json")
}

// load reads persisted data from disk.
func (s *Store) load() error {
	data, err := os.ReadFile(s.filePath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("store load: %w", err)
	}
	var sd storeData
	if err := json.Unmarshal(data, &sd); err != nil {
		return fmt.Errorf("store unmarshal: %w", err)
	}
	s.scans = sd.Scans
	s.findings = sd.Findings
	if s.scans == nil {
		s.scans = make([]ScanRecord, 0)
	}
	if s.findings == nil {
		s.findings = make([]FindingRecord, 0)
	}
	return nil
}

// persist writes the in-memory data to disk.
func (s *Store) persist() error {
	sd := storeData{
		Scans:    s.scans,
		Findings: s.findings,
	}
	data, err := json.MarshalIndent(sd, "", "  ")
	if err != nil {
		return fmt.Errorf("store marshal: %w", err)
	}
	return os.WriteFile(s.filePath(), data, 0o644)
}

// SaveScan persists a scan record. If a scan with the same ID exists it is updated.
func (s *Store) SaveScan(scan ScanRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	updated := false
	for i, existing := range s.scans {
		if existing.ID == scan.ID {
			s.scans[i] = scan
			updated = true
			break
		}
	}
	if !updated {
		s.scans = append(s.scans, scan)
	}
	return s.persist()
}

// SaveFindings appends findings for a given scan.
func (s *Store) SaveFindings(scanID string, findings []FindingRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range findings {
		findings[i].ScanID = scanID
		if findings[i].CreatedAt.IsZero() {
			findings[i].CreatedAt = time.Now()
		}
	}
	s.findings = append(s.findings, findings...)
	return s.persist()
}

// GetScans returns the most recent scans up to limit (0 = all).
func (s *Store) GetScans(limit int) ([]ScanRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]ScanRecord, len(s.scans))
	copy(result, s.scans)

	sort.Slice(result, func(i, j int) bool {
		return result[i].StartedAt.After(result[j].StartedAt)
	})

	if limit > 0 && limit < len(result) {
		result = result[:limit]
	}
	return result, nil
}

// GetScan returns a single scan by ID.
func (s *Store) GetScan(id string) (*ScanRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, scan := range s.scans {
		if scan.ID == id {
			cp := scan
			return &cp, nil
		}
	}
	return nil, fmt.Errorf("scan %s not found", id)
}

// GetFindings returns all findings for a given scan ID.
func (s *Store) GetFindings(scanID string) ([]FindingRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]FindingRecord, 0)
	for _, f := range s.findings {
		if f.ScanID == scanID {
			result = append(result, f)
		}
	}
	return result, nil
}

// DeleteScan removes a scan and all its findings from the store.
func (s *Store) DeleteScan(scanID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	found := false
	newScans := make([]ScanRecord, 0, len(s.scans))
	for _, sc := range s.scans {
		if sc.ID == scanID {
			found = true
			continue
		}
		newScans = append(newScans, sc)
	}
	if !found {
		return fmt.Errorf("scan %s not found", scanID)
	}
	s.scans = newScans
	newFindings := make([]FindingRecord, 0, len(s.findings))
	for _, f := range s.findings {
		if f.ScanID != scanID {
			newFindings = append(newFindings, f)
		}
	}
	s.findings = newFindings
	return s.persist()
}

// GetStats computes dashboard statistics from the in-memory data.
func (s *Store) GetStats() DashboardStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := DashboardStats{
		FindingsByProvenance: make(map[string]int),
		FindingsBySeverity:   make(map[string]int),
		DetectorBreakdown:    make(map[string]int),
		ScansByType:          make(map[string]int),
	}

	stats.TotalScans = len(s.scans)
	stats.TotalFindings = len(s.findings)

	var totalDuration time.Duration
	completedScans := 0
	for _, scan := range s.scans {
		stats.ScansByType[scan.ScanType]++
		if scan.Status == "completed" {
			d, err := time.ParseDuration(scan.Duration)
			if err == nil {
				totalDuration += d
				completedScans++
			}
		}
	}
	if completedScans > 0 {
		avg := totalDuration / time.Duration(completedScans)
		stats.AvgScanTime = avg.String()
	} else {
		stats.AvgScanTime = "0s"
	}

	for _, f := range s.findings {
		stats.FindingsByProvenance[f.Provenance]++
		stats.FindingsBySeverity[f.Severity]++
		stats.DetectorBreakdown[f.Detector]++
	}

	recentScans := make([]ScanRecord, len(s.scans))
	copy(recentScans, s.scans)
	sort.Slice(recentScans, func(i, j int) bool {
		return recentScans[i].StartedAt.After(recentScans[j].StartedAt)
	})
	if len(recentScans) > 10 {
		recentScans = recentScans[:10]
	}
	stats.RecentScans = recentScans

	stats.TopFiles = s.computeTopFiles(10)
	stats.TrendDaily = s.computeDailyTrends(30)

	return stats
}

// computeTopFiles returns the files with the most findings.
func (s *Store) computeTopFiles(limit int) []FileHotspot {
	fileCounts := make(map[string]int)
	fileMaxSev := make(map[string]string)

	sevRank := map[string]int{
		"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4,
	}

	for _, f := range s.findings {
		fileCounts[f.File]++
		cur := fileMaxSev[f.File]
		if sevRank[f.Severity] > sevRank[cur] {
			fileMaxSev[f.File] = f.Severity
		}
	}

	hotspots := make([]FileHotspot, 0, len(fileCounts))
	for file, count := range fileCounts {
		hotspots = append(hotspots, FileHotspot{
			File:   file,
			Count:  count,
			MaxSev: fileMaxSev[file],
		})
	}

	sort.Slice(hotspots, func(i, j int) bool {
		return hotspots[i].Count > hotspots[j].Count
	})

	if limit > 0 && limit < len(hotspots) {
		hotspots = hotspots[:limit]
	}
	return hotspots
}

// computeDailyTrends builds daily scan/finding counts for the last n days.
func (s *Store) computeDailyTrends(days int) []DailyTrend {
	now := time.Now()
	trendMap := make(map[string]*DailyTrend, days)
	ordered := make([]string, 0, days)

	for i := days - 1; i >= 0; i-- {
		d := now.AddDate(0, 0, -i).Format("2006-01-02")
		trendMap[d] = &DailyTrend{Date: d}
		ordered = append(ordered, d)
	}

	for _, scan := range s.scans {
		d := scan.StartedAt.Format("2006-01-02")
		if t, ok := trendMap[d]; ok {
			t.Scans++
		}
	}

	for _, f := range s.findings {
		d := f.CreatedAt.Format("2006-01-02")
		if t, ok := trendMap[d]; ok {
			t.Findings++
		}
	}

	result := make([]DailyTrend, 0, len(ordered))
	for _, d := range ordered {
		result = append(result, *trendMap[d])
	}
	return result
}
