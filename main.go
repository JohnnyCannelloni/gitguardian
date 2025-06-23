package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/JohnnyCannelloni/gitguardian/internal/config"
	"github.com/JohnnyCannelloni/gitguardian/internal/hooks"
	"github.com/JohnnyCannelloni/gitguardian/internal/scanner"
)

func main() {
	var (
		scanPath     = flag.String("path", ".", "Path to scan")
		installHooks = flag.Bool("install-hooks", false, "Install Git hooks")
		configFile   = flag.String("config", "", "Configuration file path")
		verbose      = flag.Bool("verbose", false, "Verbose output")
		onlySecrets  = flag.Bool("secrets-only", false, "Only scan for secrets")
		onlyDeps     = flag.Bool("deps-only", false, "Only scan dependencies")
		format       = flag.String("format", "text", "Output format (text, json)")
	)
	flag.Parse()

	// Load configuration
	cfg, err := config.Load(*configFile)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	if *verbose {
		cfg.Verbose = true
	}

	// Install Git hooks if requested
	if *installHooks {
		if err := hooks.Install(*scanPath); err != nil {
			log.Fatalf("Failed to install hooks: %v", err)
		}
		fmt.Println("Git hooks installed successfully!")
		return
	}

	// Initialize scanner
	s := scanner.New(cfg)

	// Determine scan type
	scanType := scanner.ScanTypeAll
	if *onlySecrets {
		scanType = scanner.ScanTypeSecrets
	} else if *onlyDeps {
		scanType = scanner.ScanTypeDependencies
	}

	// Run scan
	results, err := s.ScanPath(*scanPath, scanType)
	if err != nil {
		log.Fatalf("Scan failed: %v", err)
	}

	// Output results
	if err := outputResults(results, *format); err != nil {
		log.Fatalf("Failed to output results: %v", err)
	}

	// Exit with error code if issues found
	if results.HasIssues() {
		os.Exit(1)
	}
}

func outputResults(results *scanner.Results, format string) error {
	switch format {
	case "json":
		return results.OutputJSON(os.Stdout)
	case "text":
		return results.OutputText(os.Stdout)
	default:
		return fmt.Errorf("unsupported output format: %s", format)
	}
}
