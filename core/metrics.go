package synapse

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ScanMetrics holds aggregated metrics for a scan run.
type ScanMetrics struct {
	FilesScanned            int
	FilesSkipped            int
	TokensExtracted         int
	FindingsTotal           int
	FindingsByProvenance    map[string]int
	FindingsBySeverity      map[string]int
	ScanDuration            time.Duration
	TokenExtractionDuration time.Duration
	ClassificationDuration  time.Duration
	MLRefinementDuration    time.Duration
	BytesProcessed          int64
	ErrorCount              int
}

// MetricsCollector is a thread-safe collector for scan metrics.
type MetricsCollector struct {
	mu sync.RWMutex

	filesScanned    atomic.Int64
	filesSkipped    atomic.Int64
	tokensExtracted atomic.Int64
	findingsTotal   atomic.Int64
	bytesProcessed  atomic.Int64
	errorCount      atomic.Int64

	findingsByProvenance map[string]int
	findingsBySeverity   map[string]int

	scanStart               time.Time
	scanEnd                 time.Time
	tokenExtractionDuration atomic.Int64
	classificationDuration  atomic.Int64
	mlRefinementDuration    atomic.Int64
}

// NewMetricsCollector creates a new thread-safe metrics collector.
func NewMetricsCollector() *MetricsCollector {
	return &MetricsCollector{
		findingsByProvenance: make(map[string]int),
		findingsBySeverity:   make(map[string]int),
		scanStart:            time.Now(),
	}
}

// RecordFileScanned increments the files-scanned counter.
func (m *MetricsCollector) RecordFileScanned() {
	m.filesScanned.Add(1)
}

// RecordFileSkipped increments the files-skipped counter.
func (m *MetricsCollector) RecordFileSkipped() {
	m.filesSkipped.Add(1)
}

// RecordTokensExtracted adds to the token count.
func (m *MetricsCollector) RecordTokensExtracted(count int) {
	m.tokensExtracted.Add(int64(count))
}

// RecordFinding records a finding with its provenance and severity.
func (m *MetricsCollector) RecordFinding(provenance, severity string) {
	m.findingsTotal.Add(1)
	m.mu.Lock()
	m.findingsByProvenance[provenance]++
	m.findingsBySeverity[severity]++
	m.mu.Unlock()
}

// RecordBytesProcessed adds to the total bytes processed.
func (m *MetricsCollector) RecordBytesProcessed(n int64) {
	m.bytesProcessed.Add(n)
}

// RecordError increments the error counter.
func (m *MetricsCollector) RecordError() {
	m.errorCount.Add(1)
}

// RecordTokenExtractionDuration adds to the cumulative token extraction time.
func (m *MetricsCollector) RecordTokenExtractionDuration(d time.Duration) {
	m.tokenExtractionDuration.Add(int64(d))
}

// RecordClassificationDuration adds to the cumulative classification time.
func (m *MetricsCollector) RecordClassificationDuration(d time.Duration) {
	m.classificationDuration.Add(int64(d))
}

// RecordMLRefinementDuration adds to the cumulative ML refinement time.
func (m *MetricsCollector) RecordMLRefinementDuration(d time.Duration) {
	m.mlRefinementDuration.Add(int64(d))
}

// FinishScan marks the scan end time.
func (m *MetricsCollector) FinishScan() {
	m.mu.Lock()
	m.scanEnd = time.Now()
	m.mu.Unlock()
}

// Snapshot returns a point-in-time copy of the collected metrics.
func (m *MetricsCollector) Snapshot() ScanMetrics {
	m.mu.RLock()
	defer m.mu.RUnlock()

	provCopy := make(map[string]int, len(m.findingsByProvenance))
	for k, v := range m.findingsByProvenance {
		provCopy[k] = v
	}

	sevCopy := make(map[string]int, len(m.findingsBySeverity))
	for k, v := range m.findingsBySeverity {
		sevCopy[k] = v
	}

	var scanDur time.Duration
	if !m.scanEnd.IsZero() {
		scanDur = m.scanEnd.Sub(m.scanStart)
	} else {
		scanDur = time.Since(m.scanStart)
	}

	return ScanMetrics{
		FilesScanned:            int(m.filesScanned.Load()),
		FilesSkipped:            int(m.filesSkipped.Load()),
		TokensExtracted:         int(m.tokensExtracted.Load()),
		FindingsTotal:           int(m.findingsTotal.Load()),
		FindingsByProvenance:    provCopy,
		FindingsBySeverity:      sevCopy,
		ScanDuration:            scanDur,
		TokenExtractionDuration: time.Duration(m.tokenExtractionDuration.Load()),
		ClassificationDuration:  time.Duration(m.classificationDuration.Load()),
		MLRefinementDuration:    time.Duration(m.mlRefinementDuration.Load()),
		BytesProcessed:          m.bytesProcessed.Load(),
		ErrorCount:              int(m.errorCount.Load()),
	}
}

// Reset clears all collected metrics and restarts the scan timer.
func (m *MetricsCollector) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.filesScanned.Store(0)
	m.filesSkipped.Store(0)
	m.tokensExtracted.Store(0)
	m.findingsTotal.Store(0)
	m.bytesProcessed.Store(0)
	m.errorCount.Store(0)
	m.tokenExtractionDuration.Store(0)
	m.classificationDuration.Store(0)
	m.mlRefinementDuration.Store(0)

	m.findingsByProvenance = make(map[string]int)
	m.findingsBySeverity = make(map[string]int)
	m.scanStart = time.Now()
	m.scanEnd = time.Time{}
}

// PrometheusExport returns all metrics in the Prometheus text exposition format.
func (m *MetricsCollector) PrometheusExport() string {
	snap := m.Snapshot()
	var b strings.Builder

	writeGauge := func(name, help string, value interface{}) {
		fmt.Fprintf(&b, "# HELP %s %s\n", name, help)
		fmt.Fprintf(&b, "# TYPE %s gauge\n", name)
		fmt.Fprintf(&b, "%s %v\n", name, value)
	}

	writeGauge("morphex_scan_files_scanned_total", "Total files scanned", snap.FilesScanned)
	writeGauge("morphex_scan_files_skipped_total", "Total files skipped", snap.FilesSkipped)
	writeGauge("morphex_scan_tokens_extracted_total", "Total tokens extracted", snap.TokensExtracted)
	writeGauge("morphex_scan_findings_total", "Total findings", snap.FindingsTotal)
	writeGauge("morphex_scan_bytes_processed_total", "Total bytes processed", snap.BytesProcessed)
	writeGauge("morphex_scan_errors_total", "Total errors encountered", snap.ErrorCount)
	writeGauge("morphex_scan_duration_seconds", "Total scan duration in seconds", snap.ScanDuration.Seconds())
	writeGauge("morphex_scan_token_extraction_seconds", "Cumulative token extraction time in seconds", snap.TokenExtractionDuration.Seconds())
	writeGauge("morphex_scan_classification_seconds", "Cumulative classification time in seconds", snap.ClassificationDuration.Seconds())
	writeGauge("morphex_scan_ml_refinement_seconds", "Cumulative ML refinement time in seconds", snap.MLRefinementDuration.Seconds())

	fmt.Fprintf(&b, "# HELP morphex_scan_findings_by_provenance Findings by provenance\n")
	fmt.Fprintf(&b, "# TYPE morphex_scan_findings_by_provenance gauge\n")
	for prov, count := range snap.FindingsByProvenance {
		fmt.Fprintf(&b, "morphex_scan_findings_by_provenance{provenance=%q} %d\n", prov, count)
	}

	fmt.Fprintf(&b, "# HELP morphex_scan_findings_by_severity Findings by severity\n")
	fmt.Fprintf(&b, "# TYPE morphex_scan_findings_by_severity gauge\n")
	for sev, count := range snap.FindingsBySeverity {
		fmt.Fprintf(&b, "morphex_scan_findings_by_severity{severity=%q} %d\n", sev, count)
	}

	return b.String()
}
