package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// newTestWebServer creates a WebServer backed by a temp data directory
// and no API key requirement (public access).
func newTestWebServer(t *testing.T) *WebServer {
	t.Helper()
	dataDir := t.TempDir()

	staticDir := t.TempDir()
	cssDir := filepath.Join(staticDir, "css")
	if err := os.MkdirAll(cssDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cssDir, "morphex.css"), []byte("body{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	templatesDir := filepath.Join(staticDir, "..", "templates")
	if err := os.MkdirAll(templatesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	indexHTML := `<!DOCTYPE html><html><body>Morphex SPA</body></html>`
	if err := os.WriteFile(filepath.Join(templatesDir, "index.html"), []byte(indexHTML), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := WebConfig{
		Address:   ":0",
		DataDir:   dataDir,
		StaticDir: staticDir,
	}
	return NewWebServer(cfg)
}

// --------------------------------------------------------------------------
// Health
// --------------------------------------------------------------------------

func TestWebHealth(t *testing.T) {
	ws := newTestWebServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	rec := httptest.NewRecorder()

	ws.httpSrv.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var body map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}
	if _, ok := body["status"]; !ok {
		t.Error("response JSON missing key: status")
	}
}

// --------------------------------------------------------------------------
// Dashboard stats
// --------------------------------------------------------------------------

func TestWebDashboardStats(t *testing.T) {
	ws := newTestWebServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/stats", nil)
	rec := httptest.NewRecorder()

	ws.httpSrv.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var body map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}
	if _, ok := body["total_scans"]; !ok {
		t.Error("response JSON missing key: total_scans")
	}
}

// --------------------------------------------------------------------------
// List scans
// --------------------------------------------------------------------------

func TestWebListScans(t *testing.T) {
	ws := newTestWebServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans", nil)
	rec := httptest.NewRecorder()

	ws.httpSrv.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var body []interface{}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode JSON array: %v", err)
	}
}

// --------------------------------------------------------------------------
// SPA fallback (root path)
// --------------------------------------------------------------------------

func TestWebStaticFallback(t *testing.T) {
	ws := newTestWebServer(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	ws.httpSrv.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}
}
