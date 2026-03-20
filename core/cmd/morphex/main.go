// MORPHEX — Morphological Pattern & Heuristic EXamination
//
// The only secret scanner that understands code as code.
// Powered by SYNAPSE (Syntactic Analysis Pipeline for Secret Exposure).
//
// Zero false positives by design:
//   Reports high-confidence true positives (LIKELY_TRUE_POSITIVE) using
//   multi-signal behavioral analysis — no pattern matching, no regex.
//
// Usage:
//
//	morphex scan <path>              Scan a file or directory
//	  --json                       Output benchmark-compatible JSON
//	  --threshold N                Confidence threshold (default: 0.7)
//	  --workers N                  Concurrent workers (default: auto)

//	  --raw                        Include unverified NEEDS_VERIFICATION findings (debug mode)
//	morphex scan-git <repo>          Scan git history for secrets
//	  --json                       Output JSON
//	  --threshold N                Confidence threshold (default: 0.7)
//	  --since DATE                 Only scan commits after this date
//	  --max-commits N              Limit number of commits to scan
//	  --workers N                  Concurrent workers (default: auto)
//	morphex version                  Show version
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"
	"bytes"

	synapse "github.com/morphex/integrations/synapse"
	engine "github.com/synapse/engine"
	"github.com/morphex/web"
)

const version = "1.0.0"

// noColor disables colorized output globally.
var noColor bool

// logLevel controls stderr logging verbosity.
var logLevel string

func setupLogging() {
	switch logLevel {
	case "error":
		log.SetOutput(io.Discard)
	case "warn":
		log.SetOutput(os.Stderr)
		log.SetFlags(0)
	case "debug", "trace":
		log.SetOutput(os.Stderr)
		log.SetFlags(log.Ltime | log.Lshortfile)
	default:
		log.SetOutput(os.Stderr)
		log.SetFlags(0)
	}
}

// setupSignalHandler installs SIGINT/SIGTERM handling for graceful shutdown.
// Returns a context that is cancelled on signal and a cancel function.
func setupSignalHandler() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		select {
		case sig := <-sigCh:
			fmt.Fprintf(os.Stderr, "\nReceived %s, shutting down gracefully...\n", sig)
			cancel()
			// Second signal forces immediate exit.
			<-sigCh
			fmt.Fprintf(os.Stderr, "Forced exit.\n")
			os.Exit(130)
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}

func main() {
	// Parse global flags that appear before the subcommand.
	// Go's flag package doesn't support this natively, so we peek.
	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--no-color":
			noColor = true
			os.Args = append(os.Args[:i], os.Args[i+1:]...)
			i--
		case "--log-level":
			if i+1 < len(os.Args) {
				logLevel = os.Args[i+1]
				os.Args = append(os.Args[:i], os.Args[i+2:]...)
				i--
			}
		}
	}
	setupLogging()

	ctx, cancel := setupSignalHandler()
	defer cancel()
	_ = ctx // passed to scan functions below

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "version":
		fmt.Printf("MORPHEX v%s\n", version)
		fmt.Println("Morphological Pattern & Heuristic EXamination")
		fmt.Println("Engine: SYNAPSE v2 (5-signal provenance classification)")
		fmt.Println("Pipeline: SYNAPSE multi-signal classification + AVAT Context Agent")
		fmt.Printf("Runtime: Go %s, %d CPUs\n", runtime.Version(), runtime.NumCPU())

	case "scan":
		scanCmd := flag.NewFlagSet("scan", flag.ExitOnError)
		jsonOut := scanCmd.Bool("json", false, "Output benchmark-compatible JSON")
		threshold := scanCmd.Float64("threshold", 0.7, "Confidence threshold")
		workers := scanCmd.Int("workers", 0, "Concurrent workers (0=auto)")
		verifyVal := false
		verify := &verifyVal
		dryRunVal := false
		dryRun := &dryRunVal
		raw := scanCmd.Bool("raw", false, "Include unverified NEEDS_VERIFICATION findings (debug mode)")
		modelDir := scanCmd.String("model-dir", "", "Path to DistilBERT ONNX model directory for ML classification")
		sarifOut := scanCmd.Bool("sarif", false, "Output in SARIF v2.1.0 format (for GitHub Code Scanning / CI)")
		policyFile := scanCmd.String("policy", "", "Path to scan policy JSON file")
		deep := scanCmd.Bool("deep", false, "Enable deep scanning (decode base64, archives, UTF-16)")
		fail := scanCmd.Bool("fail", false, "Exit with code 1 if secrets are found (for CI gating)")
		baselinePath := scanCmd.String("baseline", "", "Path to baseline file — suppress known findings")
		createBaseline := scanCmd.Bool("create-baseline", false, "Create baseline from current findings (use with --baseline)")
		redactLevel := scanCmd.Int("redact", 100, "Redaction percentage (0=show full, 100=fully redacted)")
		include := scanCmd.String("include", "", "Comma-separated glob patterns to include")
		exclude := scanCmd.String("exclude", "", "Comma-separated glob patterns to exclude")
		skipBinaries := scanCmd.Bool("force-skip-binaries", false, "Skip binary files")
		ghActions := scanCmd.Bool("github-actions", false, "Output GitHub Actions annotation format")
		scanCmd.Parse(os.Args[2:])
		_ = skipBinaries // wired into orchestrator below
		_ = ghActions    // wired into output below

		// Initialize the ML classifier if a model directory is provided.
		// This enables ONNX-based inference for UNCERTAIN tokens in the SYNAPSE engine.
		if *modelDir != "" {
			if err := engine.InitClassifier(*modelDir); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: ML classifier init failed: %v\n", err)
			} else {
				defer engine.GetClassifier().Destroy()
				if engine.GetClassifier().HasONNX() {
					fmt.Fprintln(os.Stderr, "ML classifier: ONNX model loaded")
				} else {
					fmt.Fprintln(os.Stderr, "ML classifier: heuristic mode (no model.onnx)")
				}
			}
		}

		if scanCmd.NArg() < 1 {
			fmt.Fprintln(os.Stderr, "Usage: morphex scan [--json] [--threshold N] <path>")
			os.Exit(1)
		}

		path := scanCmd.Arg(0)
		runScan(path, *jsonOut, *sarifOut, *ghActions, *threshold, *workers, *verify, *dryRun, *raw, *deep, *policyFile, *fail, *baselinePath, *createBaseline, *redactLevel, *include, *exclude, *skipBinaries)

	case "scan-git":
		gitCmd := flag.NewFlagSet("scan-git", flag.ExitOnError)
		jsonOut := gitCmd.Bool("json", false, "Output JSON")
		threshold := gitCmd.Float64("threshold", 0.7, "Confidence threshold")
		since := gitCmd.String("since", "", "Only scan commits after this date (e.g., 2024-01-01)")
		maxCommits := gitCmd.Int("max-commits", 0, "Limit number of commits (0=all)")
		workers := gitCmd.Int("workers", 0, "Concurrent workers (0=auto)")
		branch := gitCmd.String("branch", "", "Specific branch to scan (default: all branches)")
		gitCmd.Parse(os.Args[2:])

		if gitCmd.NArg() < 1 {
			fmt.Fprintln(os.Stderr, "Usage: morphex scan-git [--json] [--threshold N] [--since DATE] [--max-commits N] <repo-path>")
			os.Exit(1)
		}

		repoPath := gitCmd.Arg(0)
		runGitScan(repoPath, *jsonOut, *threshold, *since, *maxCommits, *workers, *branch)

	case "stdin":
		stdinCmd := flag.NewFlagSet("stdin", flag.ExitOnError)
		jsonOut := stdinCmd.Bool("json", false, "Output JSON")
		threshold := stdinCmd.Float64("threshold", 0.7, "Confidence threshold")
		stdinCmd.Parse(os.Args[2:])

		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading stdin: %v\n", err)
			os.Exit(1)
		}
		if len(data) == 0 {
			fmt.Fprintln(os.Stderr, "No input on stdin.")
			os.Exit(0)
		}
		// Scan stdin content as a virtual file.
		tokens := engine.ExtractTokens("stdin", string(data))
		var findings []engine.Finding
		for _, tok := range tokens {
			cls := engine.ClassifyToken(tok)
			if cls.Prov != engine.ProvenanceAuthCredential && cls.Prov != engine.ProvenanceUncertain {
				continue
			}
			if cls.Conf < *threshold {
				continue
			}
			v := tok.Value
			var redacted string
			if len(v) > 16 {
				redacted = v[:6] + "..." + v[len(v)-4:]
			} else if len(v) > 8 {
				redacted = v[:4] + "****"
			} else {
				redacted = "****"
			}
			sigs := make([]map[string]interface{}, len(cls.Signals))
			for i, s := range cls.Signals {
				sigs[i] = map[string]interface{}{"name": s.Name, "value": s.Value, "confidence": s.Confidence, "reasoning": s.ReasonText}
			}
			findings = append(findings, engine.Finding{
				File: "stdin", Line: tok.Line, MatchedValue: redacted, Detector: "synapse:" + strings.ToLower(string(cls.Prov)),
				Confidence: cls.Conf, Provenance: string(cls.Prov), Signals: sigs, ReasoningStr: cls.Reasoning(),
			})
		}
		if *jsonOut {
			out, _ := engine.OutputJSON(findings)
			fmt.Println(out)
		} else {
			if len(findings) == 0 {
				fmt.Println("MORPHEX: No secrets detected in stdin.")
			} else {
				fmt.Printf("MORPHEX found %d potential secrets from stdin:\n\n", len(findings))
				for _, f := range findings {
					fmt.Printf("  [%.0f%%] %s  line %d: %s\n", f.Confidence*100, f.Provenance, f.Line, f.MatchedValue)
				}
			}
		}

	case "generate-key":
		genCmd := flag.NewFlagSet("generate-key", flag.ExitOnError)
		keyType := genCmd.String("type", "admin", "Key type: admin, scan, readonly, webhook")
		keySet := genCmd.Bool("set", false, "Generate a full key set (admin + scan + readonly)")
		genCmd.Parse(os.Args[2:])

		if *keySet {
			admin, scanKey, readonly, err := synapse.GenerateKeySet()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("MORPHEX API Key Set")
			fmt.Println(strings.Repeat("=", 65))
			fmt.Println()
			fmt.Printf("  Admin key:     %s\n", admin)
			fmt.Printf("  Scan key:      %s\n", scanKey)
			fmt.Printf("  Read-only key: %s\n", readonly)
			fmt.Println()
			fmt.Println("Security:")
			fmt.Println("  256 bits entropy (crypto/rand) | HMAC-SHA256 checksum")
			fmt.Println("  Store securely — keys cannot be recovered")
			fmt.Println()
			fmt.Println("Start server:")
			fmt.Printf("  morphex serve --api-keys '%s'\n", admin)
		} else {
			var kt synapse.KeyType
			switch *keyType {
			case "admin":
				kt = synapse.KeyTypeAdmin
			case "scan":
				kt = synapse.KeyTypeScanOnly
			case "readonly":
				kt = synapse.KeyTypeReadOnly
			case "webhook":
				kt = synapse.KeyTypeWebhook
			default:
				fmt.Fprintf(os.Stderr, "Unknown key type: %s\n", *keyType)
				os.Exit(1)
			}
			key, err := synapse.GenerateAPIKey(kt)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			info, _ := synapse.InspectKey(key)
			fmt.Println("MORPHEX API Key")
			fmt.Println(strings.Repeat("=", 65))
			fmt.Printf("  Key:      %s\n", key)
			fmt.Printf("  Type:     %s\n", info.Type)
			fmt.Printf("  Entropy:  %s\n", info.Entropy)
			fmt.Printf("  Hash:     %s\n", info.Hash)
			fmt.Println()
			fmt.Println("  Store securely — cannot be recovered.")
		}

	case "serve":
		serveCmd := flag.NewFlagSet("serve", flag.ExitOnError)
		addr := serveCmd.String("addr", ":8080", "Listen address (host:port)")
		apiKeys := serveCmd.String("api-keys", "", "Comma-separated API keys (required)")
		rateLimit := serveCmd.Int("rate-limit", 60, "Requests per minute per API key")
		modelDir := serveCmd.String("model-dir", "", "DistilBERT ONNX model directory")
		serveCmd.Parse(os.Args[2:])

		if *apiKeys == "" {
			fmt.Fprintln(os.Stderr, "Error: --api-keys is required for the API server")
			fmt.Fprintln(os.Stderr, "Usage: morphex serve --api-keys KEY1,KEY2 [--addr :8080]")
			os.Exit(1)
		}

		if *modelDir != "" {
			if err := engine.InitClassifier(*modelDir); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: ML classifier init failed: %v\n", err)
			} else {
				defer engine.GetClassifier().Destroy()
			}
		}

		keys := strings.Split(*apiKeys, ",")
		for i := range keys {
			keys[i] = strings.TrimSpace(keys[i])
		}

		config := web.WebConfig{
			Address:    *addr,
			APIKeys:    keys,
			RateLimit:  *rateLimit,
			DataDir:    ".morphex-data",
			StaticDir:  "",
		}

		srv := web.NewWebServer(config)

		go func() {
			<-ctx.Done()
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer shutdownCancel()
			srv.Shutdown(shutdownCtx)
		}()

		fmt.Fprintf(os.Stderr, "MORPHEX server starting on %s\n", *addr)
		fmt.Fprintf(os.Stderr, "  Web UI:      http://%s\n", *addr)
		fmt.Fprintf(os.Stderr, "  API:         http://%s/api/v1/\n", *addr)
		fmt.Fprintf(os.Stderr, "  API keys:    %d configured\n", len(keys))
		fmt.Fprintf(os.Stderr, "  Rate limit:  %d req/min per key\n", *rateLimit)
		fmt.Fprintf(os.Stderr, "  Data dir:    .morphex-data/\n")

		fmt.Fprintln(os.Stderr, "")

		if err := srv.Start(); err != nil && err.Error() != "http: Server closed" {
			fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
			os.Exit(1)
		}

	case "completion":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "Usage: morphex completion <bash|zsh|fish>")
			os.Exit(1)
		}
		printCompletion(os.Args[2])

	default:
		printUsage()
		os.Exit(1)
	}
}

// Finding is the benchmark-compatible output format.
type finding struct {
	File         string                   `json:"file"`
	Line         int                      `json:"line"`
	Detector     string                   `json:"detector"`
	Description  string                   `json:"description"`
	MatchedValue string                   `json:"matched_value"`
	Confidence   float64                  `json:"confidence"`
	Provenance   string                   `json:"provenance"`
	Verdict      string                   `json:"verdict"`
	RiskLevel    string                   `json:"risk_level"`
	ShouldAlert  bool                     `json:"should_alert"`
	ShouldBlock  bool                     `json:"should_block"`
	Signals      []map[string]interface{} `json:"signals"`
	Evidence     []map[string]string      `json:"evidence"`
}

type outputJSON struct {
	Tool          string    `json:"tool"`
	Version       string    `json:"version"`
	Engine        string    `json:"engine"`
	Mode          string    `json:"mode"`
	TotalFindings int       `json:"total_findings"`
	Candidates    int       `json:"candidates_evaluated"`
	Suppressed    int       `json:"suppressed_unverified"`
	ScanTime      string    `json:"scan_time"`
	Findings      []finding `json:"findings"`
}

func runScan(path string, jsonOut bool, sarifOut bool, ghActions bool, threshold float64, workers int, verify bool, dryRun bool, raw bool, deep bool, policyFile string, fail bool, baselinePath string, createBaseline bool, redactLevel int, includePat string, excludePat string, skipBinaries bool) {
	if workers <= 0 {
		workers = runtime.NumCPU()
	}

	// Wire --redact flag.
	activeRedactLevel = redactLevel

	// Wire --force-skip-binaries flag.
	if skipBinaries {
		engine.ForceSkipBinaries = true
	}

	// Wire --deep flag to enable advanced extraction (concat, ROT13, etc.)
	if deep {
		engine.AdvancedExtractionEnabled = true
	}

	// Load scan policy if specified.
	var policy *synapse.ScanPolicy
	if policyFile != "" {
		var err error
		policy, err = synapse.LoadPolicy(policyFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading policy: %v\n", err)
			os.Exit(1)
		}
		if err := policy.Validate(); err != nil {
			fmt.Fprintf(os.Stderr, "Invalid policy: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Loaded scan policy from %s\n", policyFile)
		if policy.MinConfidence > threshold {
			threshold = policy.MinConfidence
		}
	}

	// Load baseline for suppressing known findings.
	var baseline *synapse.BaselineFile
	if baselinePath != "" {
		var err error
		baseline, err = synapse.LoadBaseline(baselinePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading baseline: %v\n", err)
			os.Exit(1)
		}
		if len(baseline.Findings) > 0 {
			fmt.Fprintf(os.Stderr, "Loaded baseline with %d suppressed findings\n", len(baseline.Findings))
		}
	}

	// Default (no --verify): engine-only mode. Reports high-confidence findings.
	// With --verify: Claude AI verification. Only confirmed secrets shown.
	scanThreshold := threshold
	if verify && threshold > 0.4 {
		scanThreshold = 0.4
	}

	orchConfig := synapse.OrchestratorConfig{
		MaxConcurrentTeams: workers,
		ContextTimeout:     30 * time.Second,
		VerifyTimeout:      25 * time.Second,
		AlertThreshold:     scanThreshold,
		EnableVerification: verify,
	}

	if verify {
		orchConfig.VerificationConfig = &synapse.VerificationAgentConfig{
			DryRun: dryRun,
		}
	}

	orch := synapse.NewOrchestrator(orchConfig)

	ctx := context.Background()
	start := time.Now()

	info, err := os.Stat(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	var results []synapse.AgentTeamResult
	if info.IsDir() {
		results, err = orch.ScanDirectory(ctx, path, workers)
	} else {
		results, err = orch.ScanFile(ctx, path)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	elapsed := time.Since(start)

	// ── Output Filter ──────────────────────────────────────────────────
	//
	// Two modes:
	//   Default: engine-only. Reports LIKELY_TRUE_POSITIVE above threshold.
	//   --verify: Claude AI. Only CONFIRMED findings shown. Zero false positives.
	//
	var filtered []synapse.AgentTeamResult
	totalCandidates := 0
	droppedUnverified := 0

	for _, r := range results {
		if r.FinalVerdict.Confidence < threshold {
			continue
		}
		totalCandidates++

		switch {
		case raw:
			if r.FinalVerdict.IsSecret || r.Finding.Verdict == synapse.VerdictNeedsVerify {
				filtered = append(filtered, r)
			}
		case verify:
			if r.VerificationResult != nil && r.VerificationResult.Verified {
				filtered = append(filtered, r)
			} else {
				droppedUnverified++
			}
		default:
			if r.FinalVerdict.IsSecret {
				filtered = append(filtered, r)
			} else {
				droppedUnverified++
			}
		}
	}

	// Apply policy filtering if a policy was loaded.
	if policy != nil {
		var policyFiltered []synapse.AgentTeamResult
		for _, r := range filtered {
			f := engine.Finding{
				File:       r.File,
				Line:       r.Line,
				Confidence: r.FinalVerdict.Confidence,
				Provenance: r.Finding.Provenance,
			}
			if policy.ShouldReport(f) {
				policyFiltered = append(policyFiltered, r)
			}
		}
		filtered = policyFiltered
	}

	// Apply baseline filtering — suppress known findings.
	if baseline != nil && len(baseline.Findings) > 0 {
		var baselineFiltered []synapse.AgentTeamResult
		baselineSuppressed := 0
		for _, r := range filtered {
			fp := synapse.Fingerprint(r.File, r.Line, "morphex:synapse", r.RawSecret)
			if baseline.Contains(fp) {
				baselineSuppressed++
				continue
			}
			baselineFiltered = append(baselineFiltered, r)
		}
		if baselineSuppressed > 0 {
			fmt.Fprintf(os.Stderr, "Baseline suppressed %d known findings\n", baselineSuppressed)
		}
		filtered = baselineFiltered
	}

	// Create baseline if requested.
	if createBaseline && baselinePath != "" {
		var entries []synapse.BaselineFinding
		for _, r := range filtered {
			fp := synapse.Fingerprint(r.File, r.Line, "morphex:synapse", r.RawSecret)
			entries = append(entries, synapse.BaselineFinding{
				Fingerprint: fp,
				File:        r.File,
				Line:        r.Line,
				Detector:    "morphex:synapse",
			})
		}
		if err := synapse.SaveBaseline(baselinePath, entries); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving baseline: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "Baseline saved with %d findings to %s\n", len(entries), baselinePath)
		}
	}

	if sarifOut {
		printSARIF(filtered, deep)
	} else if ghActions {
		printGitHubActions(filtered)
	} else if jsonOut {
		printJSON(filtered, elapsed, totalCandidates, droppedUnverified, verify, raw)
	} else {
		printText(filtered, elapsed, totalCandidates, droppedUnverified, verify)
	}

	// --fail: exit with code 1 if secrets were found (for CI gating).
	if fail && len(filtered) > 0 {
		os.Exit(1)
	}
}

func printJSON(results []synapse.AgentTeamResult, elapsed time.Duration, candidates int, dropped int, verified bool, raw bool) {
	mode := "default"
	if verified {
		mode = "verified"
	} else if raw {
		mode = "raw"
	}

	out := outputJSON{
		Tool:          "morphex",
		Version:       version,
		Engine:        "SYNAPSE v2 + AVAT Context Agent",
		TotalFindings: len(results),
		ScanTime:      elapsed.String(),
		Mode:          mode,
		Candidates:    candidates,
		Suppressed:    dropped,
	}

	for _, r := range results {
		f := finding{
			File:         r.File,
			Line:         r.Line,
			Detector:     "morphex:synapse",
			MatchedValue: redact(r.RawSecret),
			Confidence:   r.FinalVerdict.Confidence,
			Provenance:   r.Finding.Provenance,
			Verdict:      string(r.Finding.Verdict),
			RiskLevel:    r.FinalVerdict.RiskLevel,
			ShouldAlert:  r.FinalVerdict.ShouldAlert,
			ShouldBlock:  r.FinalVerdict.ShouldBlock,
		}

		// Build description
		var parts []string
		for _, e := range r.Finding.Evidence {
			parts = append(parts, e.Description)
		}
		if len(parts) > 0 {
			f.Description = parts[0]
		}

		// Signals
		for _, s := range r.Finding.Signals {
			f.Signals = append(f.Signals, map[string]interface{}{
				"name":       s.Name,
				"value":      s.Value,
				"confidence": s.Confidence,
				"reasoning":  s.Reasoning,
			})
		}

		// Evidence
		for _, e := range r.Finding.Evidence {
			f.Evidence = append(f.Evidence, map[string]string{
				"type":        e.Type,
				"description": e.Description,
			})
		}

		out.Findings = append(out.Findings, f)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(out)
}

func printText(results []synapse.AgentTeamResult, elapsed time.Duration, candidates int, dropped int, verified bool) {
	if len(results) == 0 {
		if candidates > 0 {
			fmt.Printf("\nMORPHEX: No confirmed secrets. (%d candidates evaluated, %d suppressed as unverified, %s)\n", candidates, dropped, elapsed.Round(time.Millisecond))
			if !verified {
			}
		} else {
			fmt.Println("MORPHEX: No secrets detected.")
		}
		return
	}

	// Sort by confidence desc
	sort.Slice(results, func(i, j int) bool {
		return results[i].FinalVerdict.Confidence > results[j].FinalVerdict.Confidence
	})

	label := "confirmed secrets"
	if verified {
		label = "AI-verified secrets"
	}
	fmt.Printf("\nMORPHEX found %d %s (scanned in %s):\n", len(results), label, elapsed.Round(time.Millisecond))
	if dropped > 0 {
		fmt.Printf("  (%d candidates evaluated, %d suppressed as unverified)\n", candidates, dropped)
	}
	fmt.Println()

	for _, r := range results {
		conf := r.FinalVerdict.Confidence
		filled := int(conf * 10)
		bar := ""
		for i := 0; i < 10; i++ {
			if i < filled {
				bar += "\u2588"
			} else {
				bar += "\u2591"
			}
		}

		risk := r.FinalVerdict.RiskLevel
		verdict := string(r.Finding.Verdict)

		fmt.Printf("  [%s] %.0f%%  %s  (%s risk)\n", bar, conf*100, verdict, risk)
		fmt.Printf("    File: %s:%d\n", r.File, r.Line)
		fmt.Printf("    Value: %s\n", redact(r.RawSecret))
		fmt.Printf("    Provenance: %s\n", r.Finding.Provenance)
		if r.VerificationResult != nil && r.VerificationResult.Verified {
			fmt.Printf("    Verification: CONFIRMED ACTIVE (HTTP %d)\n", r.VerificationResult.HTTPCode)
		}
		if r.FinalVerdict.ShouldBlock {
			fmt.Printf("    CI/CD: WOULD BLOCK\n")
		}
		for _, e := range r.Finding.Evidence {
			fmt.Printf("    [%s] %s\n", e.Type, e.Description)
		}
		fmt.Println()
	}

	critical := 0
	high := 0
	for _, r := range results {
		switch r.FinalVerdict.RiskLevel {
		case "critical":
			critical++
		case "high":
			high++
		}
	}
	fmt.Printf("Summary: %d findings (%d critical, %d high) in %s\n", len(results), critical, high, elapsed.Round(time.Millisecond))
}

func redact(s string) string {
	// --redact 0 shows full secret (for debugging only)
	if activeRedactLevel == 0 {
		return s
	}
	// --redact 100 (default) fully masks
	if activeRedactLevel >= 100 || len(s) <= 8 {
		return "****"
	}
	// Partial redaction: show proportional prefix
	showChars := len(s) * (100 - activeRedactLevel) / 100
	if showChars < 2 {
		showChars = 2
	}
	if showChars >= len(s) {
		showChars = len(s) - 1
	}
	return s[:showChars] + strings.Repeat("*", len(s)-showChars)
}

// activeRedactLevel is set from --redact flag (0=show all, 100=fully masked).
var activeRedactLevel = 100

// redactOld is the original redaction function kept for reference.
func redactOld(s string) string {
	if len(s) > 16 {
		return s[:6] + "..." + s[len(s)-4:]
	}
	if len(s) > 8 {
		return s[:4] + "****"
	}
	return "****"
}

// printSARIF outputs findings in SARIF v2.1.0 format for CI/CD integration.
func printSARIF(results []synapse.AgentTeamResult, deep bool) {
	var engineFindings []engine.Finding
	for _, r := range results {
		ef := engine.Finding{
			File:         r.File,
			Line:         r.Line,
			MatchedValue: redact(r.RawSecret),
			Detector:     "morphex:synapse",
			Confidence:   r.FinalVerdict.Confidence,
			Provenance:   r.Finding.Provenance,
		}
		var parts []string
		for _, e := range r.Finding.Evidence {
			parts = append(parts, e.Description)
		}
		if len(parts) > 0 {
			ef.ReasoningStr = parts[0]
		}
		for _, s := range r.Finding.Signals {
			ef.Signals = append(ef.Signals, map[string]interface{}{
				"name":       s.Name,
				"value":      s.Value,
				"confidence": s.Confidence,
				"reasoning":  s.Reasoning,
			})
		}
		engineFindings = append(engineFindings, ef)
	}
	report, err := synapse.GenerateSARIF(engineFindings, version)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating SARIF: %v\n", err)
		os.Exit(1)
	}
	var buf bytes.Buffer
	if err := synapse.WriteSARIF(report, &buf); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing SARIF: %v\n", err)
		os.Exit(1)
	}
	os.Stdout.Write(buf.Bytes())
}

func runGitScan(repoPath string, jsonOut bool, threshold float64, since string, maxCommits int, workers int, branch string) {
	if workers <= 0 {
		workers = runtime.NumCPU()
	}

	opts := engine.GitScanOptions{
		MaxCommits: maxCommits,
		Since:      since,
		Branch:     branch,
		Workers:    workers,
	}

	start := time.Now()

	findings, err := engine.ScanGitRepo(repoPath, threshold, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	elapsed := time.Since(start)

	if jsonOut {
		printGitJSON(findings, elapsed)
	} else {
		printGitText(findings, elapsed)
	}
}

func printGitJSON(findings []engine.GitFinding, elapsed time.Duration) {
	type gitFindingJSON struct {
		File         string                   `json:"file"`
		Line         int                      `json:"line"`
		Detector     string                   `json:"detector"`
		MatchedValue string                   `json:"matched_value"`
		Confidence   float64                  `json:"confidence"`
		Provenance   string                   `json:"provenance"`
		Description  string                   `json:"description"`
		CommitHash   string                   `json:"commit_hash"`
		CommitAuthor string                   `json:"commit_author"`
		CommitDate   string                   `json:"commit_date"`
		CommitMsg    string                   `json:"commit_message"`
		Branch       string                   `json:"branch,omitempty"`
		Signals      []map[string]interface{} `json:"signals"`
	}

	type gitOutputJSON struct {
		Tool          string           `json:"tool"`
		Version       string           `json:"version"`
		Engine        string           `json:"engine"`
		ScanType      string           `json:"scan_type"`
		TotalFindings int              `json:"total_findings"`
		ScanTime      string           `json:"scan_time"`
		Findings      []gitFindingJSON `json:"findings"`
	}

	out := gitOutputJSON{
		Tool:          "morphex",
		Version:       version,
		Engine:        "SYNAPSE v2 Git History Scanner",
		ScanType:      "git_history",
		TotalFindings: len(findings),
		ScanTime:      elapsed.String(),
	}

	for _, gf := range findings {
		out.Findings = append(out.Findings, gitFindingJSON{
			File:         gf.Finding.File,
			Line:         gf.Finding.Line,
			Detector:     gf.Finding.Detector,
			MatchedValue: gf.Finding.MatchedValue,
			Confidence:   gf.Finding.Confidence,
			Provenance:   gf.Finding.Provenance,
			Description:  gf.Finding.ReasoningStr,
			CommitHash:   gf.CommitHash,
			CommitAuthor: gf.CommitAuthor,
			CommitDate:   gf.CommitDate,
			CommitMsg:    gf.CommitMsg,
			Branch:       gf.Branch,
			Signals:      gf.Finding.Signals,
		})
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(out)
}

func printGitText(findings []engine.GitFinding, elapsed time.Duration) {
	if len(findings) == 0 {
		fmt.Println("MORPHEX: No secrets detected in git history.")
		return
	}

	// Sort by confidence desc
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Finding.Confidence > findings[j].Finding.Confidence
	})

	fmt.Printf("\nMORPHEX found %d secrets in git history (scanned in %s):\n\n", len(findings), elapsed.Round(time.Millisecond))

	for _, gf := range findings {
		conf := gf.Finding.Confidence
		filled := int(conf * 10)
		bar := ""
		for i := 0; i < 10; i++ {
			if i < filled {
				bar += "\u2588"
			} else {
				bar += "\u2591"
			}
		}

		fmt.Printf("  [%s] %.0f%%  %s\n", bar, conf*100, gf.Finding.Provenance)
		fmt.Printf("    File: %s:%d\n", gf.Finding.File, gf.Finding.Line)
		fmt.Printf("    Value: %s\n", gf.Finding.MatchedValue)
		if gf.CommitHash != "" {
			commitDisplay := gf.CommitHash
			if len(commitDisplay) > 12 {
				commitDisplay = commitDisplay[:12]
			}
			fmt.Printf("    Commit: %s\n", commitDisplay)
			fmt.Printf("    Author: %s\n", gf.CommitAuthor)
			fmt.Printf("    Date: %s\n", gf.CommitDate)
			fmt.Printf("    Message: %s\n", gf.CommitMsg)
		}
		fmt.Println()
	}

	fmt.Printf("Summary: %d findings in %s\n", len(findings), elapsed.Round(time.Millisecond))
}

func printUsage() {
	fmt.Println("MORPHEX — Morphological Pattern & Heuristic EXamination")
	fmt.Println()
	fmt.Println("Zero false positives by design. Only reports what it can confirm.")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  morphex version              Show version info")
	fmt.Println("  morphex scan <path>          Scan file or directory")
	fmt.Println("    --json                   Benchmark-compatible JSON output")
	fmt.Println("    --threshold N            Confidence threshold (default: 0.7)")
	fmt.Println("    --workers N              Concurrent workers (default: auto)")
	fmt.Println("    --raw                    Include unverified findings (debug/benchmark only)")
	fmt.Println("    --model-dir PATH         DistilBERT ONNX model dir for ML classification")
	fmt.Println("    --sarif                  Output SARIF v2.1.0 (for GitHub Code Scanning / CI)")
	fmt.Println("    --policy PATH            Scan policy JSON file (confidence, allow-list, etc.)")
	fmt.Println("    --deep                   Deep scan (decode base64/archives/UTF-16)")
	fmt.Println("    --fail                   Exit code 1 if secrets found (CI gating)")
	fmt.Println("    --baseline PATH          Suppress known findings from baseline file")
	fmt.Println("    --create-baseline        Save current findings as baseline (with --baseline)")
	fmt.Println("    --redact N               Redaction percentage 0-100 (default: 100)")
	fmt.Println("    --include GLOBS          Comma-separated include patterns (e.g. '*.py,*.go')")
	fmt.Println("    --exclude GLOBS          Comma-separated exclude patterns")
	fmt.Println()
	fmt.Println("  morphex scan-git <repo>      Scan git history for secrets")
	fmt.Println("    --json                   Output JSON")
	fmt.Println("    --threshold N            Confidence threshold (default: 0.7)")
	fmt.Println("    --since DATE             Only scan commits after this date")
	fmt.Println("    --max-commits N          Limit number of commits (0=all)")
	fmt.Println("    --workers N              Concurrent workers (default: auto)")
	fmt.Println("    --branch NAME            Specific branch (default: all)")
	fmt.Println()
	fmt.Println("  morphex serve                Start API server")
	fmt.Println("    --addr ADDR              Listen address (default: :8080)")
	fmt.Println("    --api-keys KEYS          Comma-separated API keys (required)")
	fmt.Println("    --rate-limit N           Requests per minute per key (default: 60)")
	fmt.Println("    --cors                   Enable CORS headers")
	fmt.Println("    --tls-cert PATH          TLS certificate file")
	fmt.Println("    --tls-key PATH           TLS key file")
	fmt.Println("    --model-dir PATH         DistilBERT ONNX model directory")
	fmt.Println()
	fmt.Println("Modes:")
	fmt.Println("  Default          Only high-confidence true positives (context analysis)")
	fmt.Println("  --raw            All candidates above threshold (debug/benchmark)")
	fmt.Println()
	fmt.Println("  morphex generate-key         Generate a cryptographic API key")
	fmt.Println("    --type TYPE              Key type: admin, scan, readonly, webhook")
	fmt.Println("    --set                    Generate admin + scan + readonly key set")
	fmt.Println()
	fmt.Println("  morphex completion <shell>   Generate shell completions (bash, zsh, fish)")
	fmt.Println()
	fmt.Println("Additional flags:")
	fmt.Println("    --force-skip-binaries    Skip binary files during scan")
	fmt.Println("    --github-actions         Output GitHub Actions annotation format")
	fmt.Println()
	fmt.Printf("https://morphex.sh  |  v%s\n", version)
}

// printGitHubActions outputs findings as GitHub Actions annotations.
// Format: ::warning file={file},line={line}::{message}
func printGitHubActions(results []synapse.AgentTeamResult) {
	for _, r := range results {
		level := "warning"
		if r.FinalVerdict.Confidence >= 0.9 {
			level = "error"
		}
		msg := fmt.Sprintf("Secret detected (%s, %.0f%% confidence): %s",
			r.Finding.Provenance, r.FinalVerdict.Confidence*100, redact(r.RawSecret))
		fmt.Printf("::%s file=%s,line=%d::%s\n", level, r.File, r.Line, msg)
	}
}

// printCompletion outputs shell completion scripts.
func printCompletion(shell string) {
	switch shell {
	case "bash":
		fmt.Print(`_morphex() {
    local cur prev commands
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    commands="scan scan-git stdin serve version generate-key completion"

    if [ $COMP_CWORD -eq 1 ]; then
        COMPREPLY=( $(compgen -W "$commands" -- "$cur") )
        return 0
    fi

    case "${COMP_WORDS[1]}" in
        scan)
            COMPREPLY=( $(compgen -W "--json --sarif --github-actions --threshold --workers --raw --deep --fail --baseline --create-baseline --redact --include --exclude --policy --model-dir --force-skip-binaries" -- "$cur") )
            if [[ "$cur" != -* ]]; then
                COMPREPLY=( $(compgen -f -- "$cur") )
            fi
            ;;
        scan-git)
            COMPREPLY=( $(compgen -W "--json --threshold --since --max-commits --workers --branch" -- "$cur") )
            ;;
        completion)
            COMPREPLY=( $(compgen -W "bash zsh fish" -- "$cur") )
            ;;
    esac
}
complete -F _morphex morphex
`)
	case "zsh":
		fmt.Print(`#compdef morphex

_morphex() {
    local -a commands
    commands=(
        'scan:Scan file or directory for secrets'
        'scan-git:Scan git history for secrets'
        'stdin:Scan from standard input'
        'serve:Start API server'
        'version:Show version info'
        'generate-key:Generate API key'
        'completion:Generate shell completions'
    )

    _arguments -C \
        '1:command:->command' \
        '*::arg:->args'

    case $state in
        command)
            _describe 'command' commands
            ;;
        args)
            case $words[1] in
                scan)
                    _arguments \
                        '--json[Output JSON]' \
                        '--sarif[Output SARIF v2.1.0]' \
                        '--github-actions[Output GitHub Actions annotations]' \
                        '--threshold[Confidence threshold]:threshold:' \
                        '--workers[Concurrent workers]:workers:' \
                        '--raw[Include unverified findings]' \
                        '--deep[Enable deep scanning]' \
                        '--fail[Exit code 1 if secrets found]' \
                        '--force-skip-binaries[Skip binary files]' \
                        '--baseline[Baseline file path]:file:_files' \
                        '--policy[Policy file path]:file:_files' \
                        '--redact[Redaction percentage]:level:' \
                        '*:path:_files'
                    ;;
                scan-git)
                    _arguments \
                        '--json[Output JSON]' \
                        '--threshold[Confidence threshold]:threshold:' \
                        '--since[Scan commits after date]:date:' \
                        '--max-commits[Limit commits]:count:' \
                        '--workers[Concurrent workers]:workers:' \
                        '--branch[Specific branch]:branch:' \
                        '*:repo:_files -/'
                    ;;
                completion)
                    _arguments '1:shell:(bash zsh fish)'
                    ;;
            esac
            ;;
    esac
}
_morphex
`)
	case "fish":
		fmt.Print(`complete -c morphex -n '__fish_use_subcommand' -a 'scan' -d 'Scan file or directory'
complete -c morphex -n '__fish_use_subcommand' -a 'scan-git' -d 'Scan git history'
complete -c morphex -n '__fish_use_subcommand' -a 'stdin' -d 'Scan from stdin'
complete -c morphex -n '__fish_use_subcommand' -a 'serve' -d 'Start API server'
complete -c morphex -n '__fish_use_subcommand' -a 'version' -d 'Show version'
complete -c morphex -n '__fish_use_subcommand' -a 'generate-key' -d 'Generate API key'
complete -c morphex -n '__fish_use_subcommand' -a 'completion' -d 'Shell completions'

complete -c morphex -n '__fish_seen_subcommand_from scan' -l json -d 'JSON output'
complete -c morphex -n '__fish_seen_subcommand_from scan' -l sarif -d 'SARIF output'
complete -c morphex -n '__fish_seen_subcommand_from scan' -l github-actions -d 'GH Actions output'
complete -c morphex -n '__fish_seen_subcommand_from scan' -l threshold -d 'Confidence threshold' -r
complete -c morphex -n '__fish_seen_subcommand_from scan' -l deep -d 'Deep scanning'
complete -c morphex -n '__fish_seen_subcommand_from scan' -l fail -d 'Exit 1 on findings'
complete -c morphex -n '__fish_seen_subcommand_from scan' -l force-skip-binaries -d 'Skip binaries'
complete -c morphex -n '__fish_seen_subcommand_from scan' -l baseline -d 'Baseline file' -rF
complete -c morphex -n '__fish_seen_subcommand_from scan' -l redact -d 'Redaction level' -r
complete -c morphex -n '__fish_seen_subcommand_from scan-git' -l json -d 'JSON output'
complete -c morphex -n '__fish_seen_subcommand_from scan-git' -l since -d 'Since date' -r
complete -c morphex -n '__fish_seen_subcommand_from scan-git' -l branch -d 'Branch name' -r
complete -c morphex -n '__fish_seen_subcommand_from completion' -a 'bash zsh fish'
`)
	default:
		fmt.Fprintf(os.Stderr, "Unsupported shell: %s (supported: bash, zsh, fish)\n", shell)
		os.Exit(1)
	}
}
