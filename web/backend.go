package web

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"strconv"
	"strings"
	"time"

	"github.com/morphex/api"
	engine "github.com/synapse/engine"
	synapse "github.com/morphex/integrations/synapse"
)

// WebConfig holds configuration for the web backend.
type WebConfig struct {
	Address   string
	APIKeys   []string
	DataDir   string
	StaticDir string
	RateLimit int
}

// WebServer extends the MORPHEX API server with persistence, SSE, and a
// dashboard for the frontend SPA.
type WebServer struct {
	apiServer    *api.Server
	store        *Store
	sseHub       *SSEHub
	config       WebConfig
	mux          *http.ServeMux
	httpSrv      *http.Server
	orchestrator *synapse.Orchestrator
	startTime    time.Time
}

// NewWebServer creates a fully wired WebServer.
func NewWebServer(config WebConfig) *WebServer {
	if config.Address == "" {
		config.Address = ":9090"
	}
	if config.DataDir == "" {
		config.DataDir = "data"
	}
	if config.StaticDir == "" {
		// Try common locations for the frontend files
		candidates := []string{
			"static",
			"web/static",
			"../web/static",
		}
		for _, c := range candidates {
			if _, err := os.Stat(filepath.Join(c, "css", "morphex.css")); err == nil {
				config.StaticDir = c
				break
			}
		}
		if config.StaticDir == "" {
			config.StaticDir = "static"
		}
	}
	log.Printf("[MORPHEX-WEB] Static dir: %s", config.StaticDir)

	apiCfg := api.DefaultServerConfig()
	apiCfg.Address = config.Address
	apiCfg.APIKeys = config.APIKeys
	apiCfg.RateLimit = config.RateLimit
	apiSrv := api.NewServer(apiCfg)

	store := NewStore(config.DataDir)
	sseHub := NewSSEHub()

	orch := synapse.NewOrchestrator(synapse.OrchestratorConfig{
		MaxConcurrentTeams: runtime.NumCPU(),
		ContextTimeout:     30 * time.Second,
		VerifyTimeout:      25 * time.Second,
		AlertThreshold:     0.3,
		EnableVerification: true,
	})

	ws := &WebServer{
		apiServer:    apiSrv,
		store:        store,
		sseHub:       sseHub,
		config:       config,
		mux:          http.NewServeMux(),
		orchestrator: orch,
		startTime:    time.Now(),
	}

	ws.registerRoutes()

	ws.httpSrv = &http.Server{
		Addr:         config.Address,
		Handler:      ws.buildMiddleware(ws.mux),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 120 * time.Second,
	}

	return ws
}

// registerRoutes wires all web backend routes onto the mux.
func (ws *WebServer) registerRoutes() {
	mux := ws.mux

	// Scan endpoints (proxied via the same handler logic as the API server)
	mux.HandleFunc("/api/v1/scan/content", ws.requirePOST(ws.handleScanContent))
	mux.HandleFunc("/api/v1/scan/file", ws.requirePOST(ws.handleScanFile))
	mux.HandleFunc("/api/v1/scan/directory", ws.requirePOST(ws.handleScanDirectory))
	mux.HandleFunc("/api/v1/scan/git", ws.requirePOST(ws.handleScanGit))

	// Async scan
	mux.HandleFunc("/api/v1/scan/async", ws.requirePOST(ws.handleAsyncScan))

	// Scan history
	mux.HandleFunc("/api/v1/scans", ws.requireGET(ws.handleListScans))
	mux.HandleFunc("/api/v1/scans/", ws.handleScanByID)

	// Dashboard
	mux.HandleFunc("/api/v1/dashboard/stats", handleDashboardStats(ws.store))
	mux.HandleFunc("/api/v1/dashboard/trends", handleDashboardTrends(ws.store))

	// SSE stream
	mux.HandleFunc("/api/v1/stream/", ws.sseHub.ServeHTTP)

	// Health
	mux.HandleFunc("/api/v1/health", ws.requireGET(ws.handleHealth))

	// Proxied API routes (called by JS but not in the base web routes)
	mux.HandleFunc("/api/v1/version", ws.requireGET(ws.handleVersion))
	mux.HandleFunc("/api/v1/analyze/classify", ws.requirePOST(ws.handleClassify))
	mux.HandleFunc("/api/v1/classify", ws.requirePOST(ws.handleClassify))
	mux.HandleFunc("/api/v1/metrics", ws.requireGET(ws.handleMetrics))

	// Static files
	staticFS := http.FileServer(http.Dir(ws.config.StaticDir))
	mux.Handle("/static/", http.StripPrefix("/static/", staticFS))

	// SPA fallback: serve templates/index.html for root and unknown routes
	mux.HandleFunc("/", ws.handleSPAFallback)
}

// buildMiddleware wraps the mux with the standard middleware chain.
func (ws *WebServer) buildMiddleware(handler http.Handler) http.Handler {
	h := handler

	h = api.MaxBodyMiddleware(10 << 20)(h)

	if ws.config.RateLimit > 0 {
		h = api.RateLimitMiddleware(ws.config.RateLimit)(h)
	}

	// Auth only for API routes — frontend (/, /static/*) is public.
	noAuthHandler := h
	authHandler := api.AuthMiddleware(ws.config.APIKeys)(h)
	h = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		publicAPIPaths := map[string]bool{
			"/api/v1/health":  true,
			"/api/v1/version": true,
			"/api/v1/metrics": true,
		}
		if strings.HasPrefix(r.URL.Path, "/api/") && !publicAPIPaths[r.URL.Path] {
			authHandler.ServeHTTP(w, r)
		} else {
			noAuthHandler.ServeHTTP(w, r)
		}
	})
	h = api.CORSMiddleware(h)
	h = api.LoggingMiddleware(h)
	h = api.RequestIDMiddleware(h)
	h = api.RecoverMiddleware(h)

	return h
}

// Start begins serving HTTP requests. It blocks until shutdown.
func (ws *WebServer) Start() error {
	log.Printf("[MORPHEX-WEB] Server starting on %s", ws.config.Address)
	return ws.httpSrv.ListenAndServe()
}

// Shutdown gracefully stops the server.
func (ws *WebServer) Shutdown(ctx context.Context) error {
	log.Printf("[MORPHEX-WEB] Server shutting down")
	return ws.httpSrv.Shutdown(ctx)
}

// =========================================================================
// Helper middleware
// =========================================================================

func (ws *WebServer) requirePOST(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		fn(w, r)
	}
}

func (ws *WebServer) requireGET(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		fn(w, r)
	}
}

// =========================================================================
// Scan handlers (with persistence)
// =========================================================================

func (ws *WebServer) handleScanContent(w http.ResponseWriter, r *http.Request) {
	var req api.ScanContentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	if req.Content == "" {
		writeJSONError(w, http.StatusBadRequest, "content is required")
		return
	}

	threshold := defaultThresh(req.Threshold)
	scanID := generateWebScanID()
	start := time.Now()

	record := ScanRecord{
		ID:        scanID,
		StartedAt: start,
		Status:    "running",
		Target:    req.FileName,
		ScanType:  "content",
		Threshold: threshold,
		Deep:      req.Deep,
	}
	_ = ws.store.SaveScan(record)

	tmpFile, err := os.CreateTemp("", "morphex-web-*.txt")
	if err != nil {
		ws.completeScanError(record, "failed to create temp file")
		writeJSONError(w, http.StatusInternalServerError, "failed to create temp file")
		return
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)
	_, _ = tmpFile.WriteString(req.Content)
	tmpFile.Close()

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()

	var findings []api.Finding

	// Zero-FP pipeline: always route through orchestrator for verification.
	results, err := ws.orchestrator.ScanFile(ctx, tmpPath)
	if err != nil {
		ws.completeScanError(record, err.Error())
		writeJSONError(w, http.StatusInternalServerError, "scan failed: "+err.Error())
		return
	}
	findings = orchestratorToAPIFindings(results)

	elapsed := time.Since(start)
	record.Status = "completed"
	record.CompletedAt = time.Now()
	record.Duration = elapsed.String()
	record.TotalFindings = len(findings)
	record.FilesScanned = 1
	_ = ws.store.SaveScan(record)
	_ = ws.store.SaveFindings(scanID, apiToFindingRecords(findings))

	resp := api.ScanResponse{
		Tool:          "morphex",
		Version:       "2.0.0-synapse-v2",
		ScanID:        scanID,
		Status:        "completed",
		TotalFindings: len(findings),
		ScanTime:      elapsed.String(),
		Findings:      findings,
	}
	writeJSONResp(w, http.StatusOK, resp)
}

func (ws *WebServer) handleScanFile(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid multipart form: "+err.Error())
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "missing file field: "+err.Error())
		return
	}
	defer file.Close()

	ext := filepath.Ext(header.Filename)
	tmpFile, err := os.CreateTemp("", "morphex-web-*"+ext)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to create temp file")
		return
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	buf := make([]byte, 32*1024)
	for {
		n, readErr := file.Read(buf)
		if n > 0 {
			tmpFile.Write(buf[:n])
		}
		if readErr != nil {
			break
		}
	}
	tmpFile.Close()

	threshold := 0.7
	if ts := r.FormValue("threshold"); ts != "" {
		if v, err := strconv.ParseFloat(ts, 64); err == nil {
			threshold = v
		}
	}
	deep := r.FormValue("deep") == "true"

	scanID := generateWebScanID()
	start := time.Now()
	record := ScanRecord{
		ID:        scanID,
		StartedAt: start,
		Status:    "running",
		Target:    header.Filename,
		ScanType:  "file",
		Threshold: threshold,
		Deep:      deep,
	}
	_ = ws.store.SaveScan(record)

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()

	var findings []api.Finding

	// Zero-FP pipeline: always route through orchestrator.
	{
		results, err := ws.orchestrator.ScanFile(ctx, tmpPath)
		if err != nil {
			ws.completeScanError(record, err.Error())
			writeJSONError(w, http.StatusInternalServerError, "scan failed: "+err.Error())
			return
		}
		findings = orchestratorToAPIFindings(results)
	}

	elapsed := time.Since(start)
	record.Status = "completed"
	record.CompletedAt = time.Now()
	record.Duration = elapsed.String()
	record.TotalFindings = len(findings)
	record.FilesScanned = 1
	_ = ws.store.SaveScan(record)
	_ = ws.store.SaveFindings(scanID, apiToFindingRecords(findings))

	resp := api.ScanResponse{
		Tool:          "morphex",
		Version:       "2.0.0-synapse-v2",
		ScanID:        scanID,
		Status:        "completed",
		TotalFindings: len(findings),
		ScanTime:      elapsed.String(),
		Findings:      findings,
	}
	writeJSONResp(w, http.StatusOK, resp)
}

func (ws *WebServer) handleScanDirectory(w http.ResponseWriter, r *http.Request) {
	var req api.ScanDirectoryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	if req.Path == "" {
		writeJSONError(w, http.StatusBadRequest, "path is required")
		return
	}

	info, err := os.Stat(req.Path)
	if err != nil || !info.IsDir() {
		writeJSONError(w, http.StatusBadRequest, "path is not a valid directory")
		return
	}

	threshold := defaultThresh(req.Threshold)
	workers := req.Workers
	if workers <= 0 {
		workers = runtime.NumCPU()
	}

	scanID := generateWebScanID()
	start := time.Now()
	filesCount := countFiles(req.Path)

	record := ScanRecord{
		ID:           scanID,
		StartedAt:    start,
		Status:       "running",
		Target:       req.Path,
		ScanType:     "directory",
		Threshold:    threshold,
		Deep:         req.Deep,
		FilesScanned: filesCount,
	}
	_ = ws.store.SaveScan(record)

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()

	var findings []api.Finding

	// Zero-FP pipeline: always route through orchestrator.
		results, err := ws.orchestrator.ScanDirectory(ctx, req.Path, workers)
		if err != nil {
			ws.completeScanError(record, err.Error())
			writeJSONError(w, http.StatusInternalServerError, "scan failed: "+err.Error())
			return
		}
		findings = orchestratorToAPIFindings(results)

	elapsed := time.Since(start)
	record.Status = "completed"
	record.CompletedAt = time.Now()
	record.Duration = elapsed.String()
	record.TotalFindings = len(findings)
	_ = ws.store.SaveScan(record)
	_ = ws.store.SaveFindings(scanID, apiToFindingRecords(findings))

	resp := api.ScanResponse{
		Tool:          "morphex",
		Version:       "2.0.0-synapse-v2",
		ScanID:        scanID,
		Status:        "completed",
		TotalFindings: len(findings),
		ScanTime:      elapsed.String(),
		Findings:      findings,
	}
	writeJSONResp(w, http.StatusOK, resp)
}

func (ws *WebServer) handleScanGit(w http.ResponseWriter, r *http.Request) {
	var req api.ScanGitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	if req.RepoPath == "" {
		writeJSONError(w, http.StatusBadRequest, "repo_path is required")
		return
	}

	threshold := defaultThresh(req.Threshold)
	workers := req.Workers
	if workers <= 0 {
		workers = runtime.NumCPU()
	}

	scanID := generateWebScanID()
	start := time.Now()

	record := ScanRecord{
		ID:        scanID,
		StartedAt: start,
		Status:    "running",
		Target:    req.RepoPath,
		ScanType:  "git",
		Threshold: threshold,
	}
	_ = ws.store.SaveScan(record)

	opts := engine.GitScanOptions{
		MaxCommits: req.MaxCommits,
		Since:      req.Since,
		Branch:     req.Branch,
		Workers:    workers,
	}

	gitFindings, err := engine.ScanGitRepo(req.RepoPath, threshold, opts)
	if err != nil {
		ws.completeScanError(record, err.Error())
		writeJSONError(w, http.StatusInternalServerError, "git scan failed: "+err.Error())
		return
	}

	findings := make([]api.Finding, 0, len(gitFindings))
	for _, gf := range gitFindings {
		findings = append(findings, engineFindingToAPIFinding(gf.Finding))
	}

	elapsed := time.Since(start)
	record.Status = "completed"
	record.CompletedAt = time.Now()
	record.Duration = elapsed.String()
	record.TotalFindings = len(findings)
	_ = ws.store.SaveScan(record)
	_ = ws.store.SaveFindings(scanID, apiToFindingRecords(findings))

	resp := api.ScanResponse{
		Tool:          "morphex",
		Version:       "2.0.0-synapse-v2",
		ScanID:        scanID,
		Status:        "completed",
		TotalFindings: len(findings),
		ScanTime:      elapsed.String(),
		Findings:      findings,
	}
	writeJSONResp(w, http.StatusOK, resp)
}

// =========================================================================
// Async scan handler
// =========================================================================

// asyncScanRequest is the request body for POST /api/v1/scan/async.
type asyncScanRequest struct {
	ScanType  string  `json:"scan_type"`
	Path      string  `json:"path"`
	Content   string  `json:"content,omitempty"`
	FileName  string  `json:"file_name,omitempty"`
	Threshold float64 `json:"threshold,omitempty"`
	Deep      bool    `json:"deep,omitempty"`
	Workers   int     `json:"workers,omitempty"`
	Branch    string  `json:"branch,omitempty"`
	Since     string  `json:"since,omitempty"`
	MaxCommits int    `json:"max_commits,omitempty"`
}

func (ws *WebServer) handleAsyncScan(w http.ResponseWriter, r *http.Request) {
	var req asyncScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}

	scanType := req.ScanType
	if scanType == "" {
		scanType = "directory"
	}

	scanID := generateWebScanID()
	threshold := defaultThresh(req.Threshold)
	workers := req.Workers
	if workers <= 0 {
		workers = runtime.NumCPU()
	}

	target := req.Path
	if target == "" {
		target = req.FileName
	}

	record := ScanRecord{
		ID:        scanID,
		StartedAt: time.Now(),
		Status:    "running",
		Target:    target,
		ScanType:  scanType,
		Threshold: threshold,
		Deep:      req.Deep,
	}
	_ = ws.store.SaveScan(record)

	writeJSONResp(w, http.StatusAccepted, map[string]string{
		"scan_id": scanID,
		"status":  "running",
		"stream":  fmt.Sprintf("/api/v1/stream/%s", scanID),
	})

	go ws.runAsyncScan(scanID, req, record, threshold, workers)
}

func (ws *WebServer) runAsyncScan(scanID string, req asyncScanRequest, record ScanRecord, threshold float64, workers int) {
	start := time.Now()

	publishProgress := func(scanned, total, findingsSoFar int, currentFile string) {
		elapsed := time.Since(start).Seconds()
		pct := 0.0
		if total > 0 {
			pct = float64(scanned) / float64(total) * 100.0
		}
		ws.sseHub.Publish(SSEEvent{
			Type:   "progress",
			ScanID: scanID,
			Data: ScanProgress{
				FilesScanned:   scanned,
				FilesTotal:     total,
				FindingsSoFar:  findingsSoFar,
				CurrentFile:    currentFile,
				ElapsedSeconds: elapsed,
				Percentage:     pct,
			},
		})
	}

	var findings []api.Finding
	var scanErr error

	switch req.ScanType {
	case "content":
		tmpFile, err := os.CreateTemp("", "morphex-async-*.txt")
		if err != nil {
			scanErr = err
			break
		}
		tmpPath := tmpFile.Name()
		defer os.Remove(tmpPath)
		_, _ = tmpFile.WriteString(req.Content)
		tmpFile.Close()

		publishProgress(0, 1, 0, req.FileName)

		// Zero-FP pipeline: always route through orchestrator.
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			results, err := ws.orchestrator.ScanFile(ctx, tmpPath)
			if err != nil {
				scanErr = err
				break
			}
			findings = orchestratorToAPIFindings(results)
		publishProgress(1, 1, len(findings), req.FileName)

	case "directory":
		if req.Path == "" {
			scanErr = fmt.Errorf("path is required for directory scan")
			break
		}
		filePaths := collectFilePaths(req.Path)
		totalFiles := len(filePaths)
		record.FilesScanned = totalFiles

		// Parallel file processing with bounded worker pool
		fileWorkers := runtime.NumCPU()
		if fileWorkers > 8 {
			fileWorkers = 8
		}
		if !req.Deep && fileWorkers < 4 {
			fileWorkers = 4
		}

		var mu sync.Mutex
		var filesProcessed int64

		fileCh := make(chan int, len(filePaths))
		for i := range filePaths {
			fileCh <- i
		}
		close(fileCh)

		var wg sync.WaitGroup
		for w := 0; w < fileWorkers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for idx := range fileCh {
					fp := filePaths[idx]
					n := atomic.AddInt64(&filesProcessed, 1)
					publishProgress(int(n), totalFiles, len(findings), fp)

					var batch []api.Finding
					// Zero-FP pipeline: always route through orchestrator.
						ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
						results, err := ws.orchestrator.ScanFile(ctx, fp)
						cancel()
						if err == nil {
							batch = orchestratorToAPIFindings(results)
						}

					if len(batch) > 0 {
						mu.Lock()
						findings = append(findings, batch...)
						mu.Unlock()
						for _, f := range batch {
							ws.sseHub.Publish(SSEEvent{
								Type:   "finding",
								ScanID: scanID,
								Data:   f,
							})
						}
					}
				}
			}()
		}
		wg.Wait()
		publishProgress(totalFiles, totalFiles, len(findings), "")

	case "git":
		if req.Path == "" {
			scanErr = fmt.Errorf("path is required for git scan")
			break
		}
		publishProgress(0, 0, 0, req.Path)

		opts := engine.GitScanOptions{
			MaxCommits: req.MaxCommits,
			Since:      req.Since,
			Branch:     req.Branch,
			Workers:    workers,
		}
		gitFindings, err := engine.ScanGitRepo(req.Path, threshold, opts)
		if err != nil {
			scanErr = err
			break
		}
		for _, gf := range gitFindings {
			f := engineFindingToAPIFinding(gf.Finding)
			findings = append(findings, f)
			ws.sseHub.Publish(SSEEvent{
				Type:   "finding",
				ScanID: scanID,
				Data:   f,
			})
		}
		publishProgress(1, 1, len(findings), "")

	default:
		scanErr = fmt.Errorf("unsupported scan_type: %s", req.ScanType)
	}

	elapsed := time.Since(start)

	if scanErr != nil {
		record.Status = "error"
		record.Error = scanErr.Error()
		record.CompletedAt = time.Now()
		record.Duration = elapsed.String()
		_ = ws.store.SaveScan(record)

		ws.sseHub.Publish(SSEEvent{
			Type:   "error",
			ScanID: scanID,
			Data:   map[string]string{"error": scanErr.Error()},
		})
		return
	}

	record.Status = "completed"
	record.CompletedAt = time.Now()
	record.Duration = elapsed.String()
	record.TotalFindings = len(findings)
	_ = ws.store.SaveScan(record)
	_ = ws.store.SaveFindings(scanID, apiToFindingRecords(findings))

	ws.sseHub.Publish(SSEEvent{
		Type:   "complete",
		ScanID: scanID,
		Data: map[string]interface{}{
			"total_findings": len(findings),
			"scan_time":      elapsed.String(),
		},
	})
}

// =========================================================================
// Scan history handlers
// =========================================================================

func (ws *WebServer) handleListScans(w http.ResponseWriter, r *http.Request) {
	limitStr := r.URL.Query().Get("limit")
	limit := 50
	if limitStr != "" {
		if v, err := strconv.Atoi(limitStr); err == nil && v > 0 {
			limit = v
		}
	}

	scans, err := ws.store.GetScans(limit)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSONResp(w, http.StatusOK, scans)
}

func (ws *WebServer) handleScanByID(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/scans/")
	parts := strings.SplitN(path, "/", 2)
	scanID := parts[0]

	if scanID == "" {
		writeJSONError(w, http.StatusBadRequest, "missing scan id")
		return
	}

	if r.Method == http.MethodDelete {
		if err := ws.store.DeleteScan(scanID); err != nil {
			writeJSONError(w, http.StatusNotFound, err.Error())
			return
		}
		writeJSONResp(w, http.StatusOK, map[string]string{"status": "deleted", "id": scanID})
		return
	}

	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if len(parts) == 2 && parts[1] == "findings" {
		findings, err := ws.store.GetFindings(scanID)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSONResp(w, http.StatusOK, findings)
		return
	}

	scan, err := ws.store.GetScan(scanID)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSONResp(w, http.StatusOK, scan)
}

// =========================================================================
// Health handler
// =========================================================================

func (ws *WebServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	resp := map[string]interface{}{
		"status":  "ok",
		"version": "2.0.0-synapse-v2",
		"uptime":  time.Since(ws.startTime).String(),
		"store": map[string]interface{}{
			"data_dir": ws.config.DataDir,
		},
	}
	writeJSONResp(w, http.StatusOK, resp)
}

func (ws *WebServer) handleVersion(w http.ResponseWriter, r *http.Request) {
	resp := map[string]interface{}{
		"tool":       "morphex",
		"version":    "2.0.0-synapse-v2",
		"engine":     "SYNAPSE v2 (Algorithmically Reinvented)",
		"go_version": runtime.Version(),
		"features":   []string{"synapse_v2", "avat_context_agent", "git_history_scan", "sarif_output"},
	}
	writeJSONResp(w, http.StatusOK, resp)
}

func (ws *WebServer) handleClassify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Value   string `json:"value"`
		VarName string `json:"var_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request: "+err.Error())
		return
	}
	if req.Value == "" {
		writeJSONError(w, http.StatusBadRequest, "value is required")
		return
	}
	tok := engine.Token{Value: req.Value, VarName: req.VarName}
	cls := engine.ClassifyToken(tok)
	signals := make([]map[string]interface{}, 0, len(cls.Signals))
	for _, s := range cls.Signals {
		signals = append(signals, map[string]interface{}{
			"name": s.Name, "value": s.Value, "confidence": s.Confidence, "reasoning": s.ReasonText,
		})
	}
	writeJSONResp(w, http.StatusOK, map[string]interface{}{
		"provenance": string(cls.Prov), "confidence": cls.Conf, "signals": signals, "reasoning": cls.Reasoning(),
	})
}

func (ws *WebServer) handleMetrics(w http.ResponseWriter, r *http.Request) {
	mc := synapse.NewMetricsCollector()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, mc.PrometheusExport())
}

// =========================================================================
// SPA fallback
// =========================================================================

func (ws *WebServer) handleSPAFallback(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" && !strings.HasPrefix(r.URL.Path, "/api/") && !strings.HasPrefix(r.URL.Path, "/static/") {
		indexPath := filepath.Join(ws.config.StaticDir, "..", "templates", "index.html")
		if _, err := os.Stat(indexPath); err == nil {
			http.ServeFile(w, r, indexPath)
			return
		}
	}

	if r.URL.Path == "/" {
		indexPath := filepath.Join(ws.config.StaticDir, "..", "templates", "index.html")
		if _, err := os.Stat(indexPath); err == nil {
			http.ServeFile(w, r, indexPath)
			return
		}
	}

	writeJSONError(w, http.StatusNotFound, "not found")
}

// =========================================================================
// Conversion helpers
// =========================================================================

func engineFindingToAPIFinding(ef engine.Finding) api.Finding {
	sev := severityFor(ef.Confidence)
	return api.Finding{
		File:         ef.File,
		Line:         ef.Line,
		Detector:     ef.Detector,
		Confidence:   ef.Confidence,
		Provenance:   ef.Provenance,
		MatchedValue: redactVal(ef.MatchedValue),
		Description:  ef.ReasoningStr,
		Severity:     sev,
		Fingerprint:  synapse.Fingerprint(ef.File, ef.Line, ef.Detector, ef.MatchedValue),
	}
}

func engineToAPIFindings(engineFindings []engine.Finding) []api.Finding {
	findings := make([]api.Finding, 0, len(engineFindings))
	for _, ef := range engineFindings {
		findings = append(findings, engineFindingToAPIFinding(ef))
	}
	return findings
}

func orchestratorToAPIFindings(results []synapse.AgentTeamResult) []api.Finding {
	findings := make([]api.Finding, 0, len(results))
	for _, r := range results {
		det := "synapse:" + strings.ToLower(r.Finding.Provenance)
		f := api.Finding{
			File:         r.File,
			Line:         r.Line,
			Detector:     det,
			Confidence:   r.Finding.FinalConfidence,
			Provenance:   r.Finding.Provenance,
			MatchedValue: redactVal(r.RawSecret),
			Description:  evidenceDescription(r.Finding.Evidence),
			Severity:     severityFor(r.Finding.FinalConfidence),
			Fingerprint:  synapse.Fingerprint(r.File, r.Line, det, redactVal(r.RawSecret)),
		}
		findings = append(findings, f)
	}
	return findings
}

func apiToFindingRecords(findings []api.Finding) []FindingRecord {
	records := make([]FindingRecord, 0, len(findings))
	now := time.Now()
	for _, f := range findings {
		records = append(records, FindingRecord{
			File:        f.File,
			Line:        f.Line,
			Detector:    f.Detector,
			Confidence:  f.Confidence,
			Provenance:  f.Provenance,
			Severity:    f.Severity,
			Fingerprint: f.Fingerprint,
			CreatedAt:   now,
		})
	}
	return records
}

func evidenceDescription(evidence []synapse.EvidenceItem) string {
	parts := make([]string, 0, len(evidence))
	for _, e := range evidence {
		parts = append(parts, e.Description)
	}
	return strings.Join(parts, " | ")
}

func severityFor(conf float64) string {
	switch {
	case conf >= 0.9:
		return "critical"
	case conf >= 0.7:
		return "high"
	case conf >= 0.5:
		return "medium"
	case conf >= 0.3:
		return "low"
	default:
		return "info"
	}
}

func redactVal(v string) string {
	if len(v) > 16 {
		return v[:6] + "..." + v[len(v)-4:]
	}
	if len(v) > 8 {
		return v[:4] + "****"
	}
	return "****"
}

func defaultThresh(t float64) float64 {
	if t <= 0 {
		return 0.7
	}
	return t
}

func generateWebScanID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b[:4]) + "-" +
		hex.EncodeToString(b[4:6]) + "-" +
		hex.EncodeToString(b[6:8]) + "-" +
		hex.EncodeToString(b[8:10]) + "-" +
		hex.EncodeToString(b[10:16])
}

func (ws *WebServer) completeScanError(record ScanRecord, errMsg string) {
	record.Status = "error"
	record.Error = errMsg
	record.CompletedAt = time.Now()
	_ = ws.store.SaveScan(record)
}

// collectFilePaths walks a directory and returns all regular file paths.
func collectFilePaths(root string) []string {
	var paths []string
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == "node_modules" || name == "__pycache__" || name == ".venv" {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type().IsRegular() {
			paths = append(paths, path)
		}
		return nil
	})
	return paths
}

// countFiles returns the number of regular files in a directory tree.
func countFiles(root string) int {
	count := 0
	_ = filepath.WalkDir(root, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == "node_modules" || name == "__pycache__" || name == ".venv" {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type().IsRegular() {
			count++
		}
		return nil
	})
	return count
}

// writeJSONResp writes a JSON response.
func writeJSONResp(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
