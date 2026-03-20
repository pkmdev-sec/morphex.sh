package api

import "net/http"

// NewRouter builds the API route tree. It does NOT apply middleware;
// that is the responsibility of NewServer which wraps the router.
func NewRouter(h *Handlers) http.Handler {
	mux := http.NewServeMux()

	// Scan endpoints
	mux.HandleFunc("/api/v1/scan/content", h.requirePOST(h.ScanContent))
	mux.HandleFunc("/api/v1/scan/file", h.requirePOST(h.ScanFile))
	mux.HandleFunc("/api/v1/scan/directory", h.requirePOST(h.ScanDirectory))
	mux.HandleFunc("/api/v1/scan/git", h.requirePOST(h.ScanGit))

	// Analysis endpoints
	mux.HandleFunc("/api/v1/analyze/classify", h.requirePOST(h.AnalyzeClassify))
	mux.HandleFunc("/api/v1/analyze/extract", h.requirePOST(h.AnalyzeExtract))
	mux.HandleFunc("/api/v1/analyze/verify", h.requirePOST(h.AnalyzeVerify))

	// Short-path aliases (SDK compatibility — sdk/go and sdk/python use these paths)
	mux.HandleFunc("/api/v1/classify", h.requirePOST(h.AnalyzeClassify))
	mux.HandleFunc("/api/v1/extract", h.requirePOST(h.AnalyzeExtract))

	// Policy endpoints
	mux.HandleFunc("/api/v1/policy/validate", h.requirePOST(h.PolicyValidate))
	mux.HandleFunc("/api/v1/policy/apply", h.requirePOST(h.PolicyApply))

	// Baseline endpoints
	mux.HandleFunc("/api/v1/baseline/create", h.requirePOST(h.BaselineCreate))
	mux.HandleFunc("/api/v1/baseline", h.requirePOST(h.BaselineCreate))
	mux.HandleFunc("/api/v1/baseline/apply", h.requirePOST(h.BaselineApply))
	mux.HandleFunc("/api/v1/baseline/diff", h.requirePOST(h.BaselineDiff))

	// Operations
	mux.HandleFunc("/api/v1/health", h.requireGET(h.Health))
	mux.HandleFunc("/api/v1/metrics", h.requireGET(h.Metrics))
	mux.HandleFunc("/api/v1/version", h.requireGET(h.Version))

	// Catch-all
	mux.HandleFunc("/", notFound)

	return mux
}

// requirePOST wraps a handler to enforce POST method.
func (h *Handlers) requirePOST(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			methodNotAllowed(w, r)
			return
		}
		fn(w, r)
	}
}

// requireGET wraps a handler to enforce GET method.
func (h *Handlers) requireGET(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			methodNotAllowed(w, r)
			return
		}
		fn(w, r)
	}
}
