package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newTestServer returns an http.Handler wired through the full middleware
// chain. When apiKeys is non-empty the auth middleware is active.
func newTestServer(apiKeys []string) http.Handler {
	cfg := DefaultServerConfig()
	cfg.APIKeys = apiKeys
	srv := NewServer(cfg)
	return srv.httpSrv.Handler
}

// --------------------------------------------------------------------------
// Health / Version / Metrics - no auth required (APIKeys left empty)
// --------------------------------------------------------------------------

func TestHealth(t *testing.T) {
	handler := newTestServer(nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

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

func TestVersion(t *testing.T) {
	handler := newTestServer(nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/version", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var body map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}
	if _, ok := body["version"]; !ok {
		t.Error("response JSON missing key: version")
	}
}

func TestMetrics(t *testing.T) {
	handler := newTestServer(nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/plain") {
		t.Errorf("expected text/plain Content-Type, got %q", ct)
	}
}

// --------------------------------------------------------------------------
// Scan content - no auth (APIKeys empty)
// --------------------------------------------------------------------------

func TestScanContent(t *testing.T) {
	handler := newTestServer(nil)

	body := `{"content": "aws_key = AKIAIOSFODNN7EXAMPLE"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scan/content", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}
	if _, ok := resp["findings"]; !ok {
		t.Error("response JSON missing key: findings")
	}
}

func TestScanContentEmpty(t *testing.T) {
	handler := newTestServer(nil)

	body := `{"content": ""}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scan/content", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK && rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 200 or 400, got %d", rec.Code)
	}
}

// --------------------------------------------------------------------------
// Auth enforcement - APIKeys set but request omits key
// --------------------------------------------------------------------------

func TestAuthRequired(t *testing.T) {
	handler := newTestServer([]string{"test-secret-key"})

	body := `{"content": "aws_key = AKIAIOSFODNN7EXAMPLE"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scan/content", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// --------------------------------------------------------------------------
// Table-driven: method enforcement on operations endpoints
// --------------------------------------------------------------------------

func TestOperationsMethodEnforcement(t *testing.T) {
	handler := newTestServer(nil)

	tests := []struct {
		name       string
		method     string
		path       string
		wantStatus int
	}{
		{"health POST rejected", http.MethodPost, "/api/v1/health", http.StatusMethodNotAllowed},
		{"version POST rejected", http.MethodPost, "/api/v1/version", http.StatusMethodNotAllowed},
		{"metrics POST rejected", http.MethodPost, "/api/v1/metrics", http.StatusMethodNotAllowed},
		{"scan/content GET rejected", http.MethodGet, "/api/v1/scan/content", http.StatusMethodNotAllowed},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Errorf("expected %d, got %d", tc.wantStatus, rec.Code)
			}
		})
	}
}
