package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"sort"

	engine "github.com/synapse/engine"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "version":
		fmt.Println("SYNAPSE v2.0.0-go")
		fmt.Println("Algorithmically Reinvented Secret Scanner [Go]")
		fmt.Printf("Known prefixes: %d (first-char indexed)\n", len(engine.KnownPrefixes))
		fmt.Printf("Runtime: Go %s, %d CPUs\n", runtime.Version(), runtime.NumCPU())

	case "scan":
		scanCmd := flag.NewFlagSet("scan", flag.ExitOnError)
		jsonOutput := scanCmd.Bool("json", false, "Output in JSON format")
		threshold := scanCmd.Float64("threshold", 0.3, "Alert confidence threshold")
		workers := scanCmd.Int("workers", 0, "Number of concurrent workers (0 = auto)")
		scanCmd.Parse(os.Args[2:])

		if scanCmd.NArg() < 1 {
			fmt.Fprintln(os.Stderr, "Usage: synapse scan [--json] [--threshold N] [--workers N] <path>")
			os.Exit(1)
		}

		path := scanCmd.Arg(0)
		var findings []engine.Finding

		info, err := os.Stat(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if info.IsDir() {
			findings = engine.ScanDirectory(path, *threshold, *workers)
		} else {
			findings = engine.ScanFile(path, *threshold)
		}

		if *jsonOutput {
			output, err := engine.OutputJSON(findings)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			fmt.Println(output)
		} else {
			if len(findings) == 0 {
				fmt.Println("SYNAPSE: No secrets detected.")
				return
			}

			sort.Slice(findings, func(i, j int) bool {
				return findings[i].Confidence > findings[j].Confidence
			})

			fmt.Printf("\nSYNAPSE found %d potential secrets:\n\n", len(findings))

			for _, f := range findings {
				filled := int(f.Confidence * 10)
				bar := ""
				for i := 0; i < 10; i++ {
					if i < filled {
						bar += "\u2588"
					} else {
						bar += "\u2591"
					}
				}
				fmt.Printf("  [%s] %.0f%%  %s\n", bar, f.Confidence*100, f.Provenance)
				fmt.Printf("    File: %s:%d\n", f.File, f.Line)
				fmt.Printf("    Value: %s\n", f.MatchedValue)
				for _, sig := range f.Signals {
					name, _ := sig["name"].(string)
					value, _ := sig["value"]
					reasoning, _ := sig["reasoning"].(string)
					fmt.Printf("    %s: %v -- %s\n", name, value, reasoning)
				}
				fmt.Println()
			}

			auth := 0
			unc := 0
			for _, f := range findings {
				if f.Provenance == string(engine.ProvenanceAuthCredential) {
					auth++
				}
				if f.Provenance == string(engine.ProvenanceUncertain) {
					unc++
				}
			}
			fmt.Printf("Total: %d (%d AUTH_CREDENTIAL, %d UNCERTAIN)\n", len(findings), auth, unc)
		}

	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("SYNAPSE — Syntactic Analysis Pipeline for Secret Exposure [Go]")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  synapse version              Show version information")
	fmt.Println("  synapse scan <path>          Scan a file or directory")
	fmt.Println("    --json                     Output in JSON format")
	fmt.Println("    --threshold N              Alert confidence threshold (default: 0.3)")
	fmt.Println("    --workers N                Concurrent workers (default: auto)")
}

// OutputJSON wraps the engine output for the CLI.
func outputJSON(findings []engine.Finding) {
	type Output struct {
		Tool          string           `json:"tool"`
		Version       string           `json:"version"`
		Engine        string           `json:"engine"`
		TotalFindings int              `json:"total_findings"`
		Findings      []engine.Finding `json:"findings"`
	}

	out := Output{
		Tool:          "morphex",
		Version:       "2.0.0-synapse-go",
		Engine:        "SYNAPSE v2 Go (Algorithmically Reinvented)",
		TotalFindings: len(findings),
		Findings:      findings,
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(out)
}
