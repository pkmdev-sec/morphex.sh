package api

import (
	"context"
	"crypto/tls"
	"log"
	"net/http"
	"time"
)

// ServerConfig holds all tunable parameters for the MORPHEX API server.
type ServerConfig struct {
	Address       string
	APIKeys       []string
	RateLimit     int
	ReadTimeout   time.Duration
	WriteTimeout  time.Duration
	MaxBodySize   int64
	EnableMetrics bool
	EnableCORS    bool
	TLSCert       string
	TLSKey        string
}

// DefaultServerConfig returns a ServerConfig with sensible defaults.
func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		Address:       ":8080",
		RateLimit:     0,
		ReadTimeout:   30 * time.Second,
		WriteTimeout:  120 * time.Second,
		MaxBodySize:   10 << 20, // 10 MB
		EnableMetrics: true,
		EnableCORS:    true,
	}
}

// Server is the MORPHEX REST API server.
type Server struct {
	config   ServerConfig
	httpSrv  *http.Server
	handlers *Handlers
}

// NewServer creates a new Server ready to be started.
func NewServer(config ServerConfig) *Server {
	if config.Address == "" {
		config.Address = ":8080"
	}
	if config.ReadTimeout == 0 {
		config.ReadTimeout = 30 * time.Second
	}
	if config.WriteTimeout == 0 {
		config.WriteTimeout = 120 * time.Second
	}
	if config.MaxBodySize == 0 {
		config.MaxBodySize = 10 << 20
	}

	h := NewHandlers()
	router := NewRouter(h)

	// Build the middleware chain (outermost first).
	var handler http.Handler = router

	// Body size limit
	handler = MaxBodyMiddleware(config.MaxBodySize)(handler)

	// Rate limiting (per API key)
	handler = RateLimitMiddleware(config.RateLimit)(handler)

	// Auth
	handler = AuthMiddleware(config.APIKeys)(handler)

	// CORS
	if config.EnableCORS {
		handler = CORSMiddleware(handler)
	}

	// Logging
	handler = LoggingMiddleware(handler)

	// Request ID
	handler = RequestIDMiddleware(handler)

	// Panic recovery (outermost)
	handler = RecoverMiddleware(handler)

	srv := &http.Server{
		Addr:         config.Address,
		Handler:      handler,
		ReadTimeout:  config.ReadTimeout,
		WriteTimeout: config.WriteTimeout,
	}

	return &Server{
		config:   config,
		httpSrv:  srv,
		handlers: h,
	}
}

// Start begins listening for HTTP (or HTTPS) requests. It blocks until
// the server is shut down or an error occurs.
func (s *Server) Start() error {
	log.Printf("[MORPHEX] API server starting on %s", s.config.Address)

	if s.config.TLSCert != "" && s.config.TLSKey != "" {
		s.httpSrv.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
		return s.httpSrv.ListenAndServeTLS(s.config.TLSCert, s.config.TLSKey)
	}

	return s.httpSrv.ListenAndServe()
}

// Shutdown gracefully shuts down the server without interrupting active
// connections. It waits for in-flight requests to complete within the
// provided context deadline.
func (s *Server) Shutdown(ctx context.Context) error {
	log.Printf("[MORPHEX] API server shutting down")
	return s.httpSrv.Shutdown(ctx)
}
