package synapse

import (
	"encoding/json"
	"net/http"
	"os"
	"runtime"
	"sync"
	"time"

	engine "github.com/synapse/engine"
)

// HealthStatus represents the overall health of the service.
type HealthStatus struct {
	Status  string                 `json:"status"`
	Version string                 `json:"version"`
	Uptime  time.Duration          `json:"uptime_ns"`
	Checks  map[string]CheckResult `json:"checks"`
}

// CheckResult represents the result of a single health check.
type CheckResult struct {
	Status   string        `json:"status"`
	Message  string        `json:"message"`
	Duration time.Duration `json:"duration_ns"`
}

// HealthCheckFunc is the signature for a health check function.
type HealthCheckFunc func() CheckResult

// HealthChecker manages health and readiness checks.
type HealthChecker struct {
	mu      sync.RWMutex
	version string
	started time.Time
	checks  map[string]HealthCheckFunc
}

// NewHealthChecker creates a new health checker with the given version.
func NewHealthChecker(version string) *HealthChecker {
	hc := &HealthChecker{
		version: version,
		started: time.Now(),
		checks:  make(map[string]HealthCheckFunc),
	}
	hc.registerBuiltinChecks()
	return hc
}

// RegisterCheck adds a named health check function.
func (h *HealthChecker) RegisterCheck(name string, fn HealthCheckFunc) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.checks[name] = fn
}

// RunChecks executes all registered checks and returns the aggregate status.
func (h *HealthChecker) RunChecks() HealthStatus {
	h.mu.RLock()
	checks := make(map[string]HealthCheckFunc, len(h.checks))
	for k, v := range h.checks {
		checks[k] = v
	}
	h.mu.RUnlock()

	results := make(map[string]CheckResult, len(checks))
	overall := "healthy"

	for name, fn := range checks {
		result := fn()
		results[name] = result
		if result.Status != "healthy" {
			overall = "degraded"
		}
	}

	return HealthStatus{
		Status:  overall,
		Version: h.version,
		Uptime:  time.Since(h.started),
		Checks:  results,
	}
}

// ServeHTTP implements http.Handler, serving /healthz and /readyz.
func (h *HealthChecker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/healthz":
		h.serveHealth(w, r)
	case "/readyz":
		h.serveReady(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *HealthChecker) serveHealth(w http.ResponseWriter, _ *http.Request) {
	status := h.RunChecks()
	w.Header().Set("Content-Type", "application/json")
	if status.Status != "healthy" {
		w.WriteHeader(http.StatusServiceUnavailable)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	json.NewEncoder(w).Encode(status)
}

func (h *HealthChecker) serveReady(w http.ResponseWriter, _ *http.Request) {
	status := h.RunChecks()
	w.Header().Set("Content-Type", "application/json")

	allHealthy := true
	for _, cr := range status.Checks {
		if cr.Status != "healthy" {
			allHealthy = false
			break
		}
	}

	if !allHealthy {
		w.WriteHeader(http.StatusServiceUnavailable)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	json.NewEncoder(w).Encode(status)
}

// registerBuiltinChecks adds the default health checks.
func (h *HealthChecker) registerBuiltinChecks() {
	h.checks["ml_classifier"] = checkMLClassifier
	h.checks["disk_space"] = checkDiskSpace
	h.checks["goroutines"] = checkGoroutines
}

// checkMLClassifier verifies the ML model is loaded and functional.
func checkMLClassifier() CheckResult {
	start := time.Now()
	classifier := engine.GetClassifier()
	loaded := classifier.IsLoaded()

	status := "healthy"
	msg := "ML classifier loaded"
	if !loaded {
		status = "degraded"
		msg = "ML classifier not loaded; classification will fall back to decision tree only"
	}

	return CheckResult{
		Status:   status,
		Message:  msg,
		Duration: time.Since(start),
	}
}

// checkDiskSpace verifies temp directory has available space.
func checkDiskSpace() CheckResult {
	start := time.Now()
	tmpDir := os.TempDir()

	f, err := os.CreateTemp(tmpDir, "morphex-health-*")
	if err != nil {
		return CheckResult{
			Status:   "unhealthy",
			Message:  "cannot write to temp directory: " + err.Error(),
			Duration: time.Since(start),
		}
	}
	name := f.Name()
	f.Close()
	os.Remove(name)

	return CheckResult{
		Status:   "healthy",
		Message:  "temp directory writable: " + tmpDir,
		Duration: time.Since(start),
	}
}

// goroutineLimit is the threshold above which we consider goroutines leaking.
const goroutineLimit = 10000

// checkGoroutines verifies the goroutine count is within healthy bounds.
func checkGoroutines() CheckResult {
	start := time.Now()
	count := runtime.NumGoroutine()

	status := "healthy"
	msg := "goroutine count nominal"
	if count > goroutineLimit {
		status = "unhealthy"
		msg = "goroutine count exceeds limit"
	}

	return CheckResult{
		Status:   status,
		Message:  msg + ": " + itoa(count),
		Duration: time.Since(start),
	}
}

// itoa is a simple int-to-string helper to avoid importing strconv.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	buf := [20]byte{}
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
