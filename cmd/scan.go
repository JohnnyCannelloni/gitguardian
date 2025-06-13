// cmd/scan.go
package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/JohnnyCannelloni/gitguardian/config"
	"github.com/JohnnyCannelloni/gitguardian/scanner"
	"github.com/spf13/cobra"
)

// scanCmd represents the "scan" subcommand.
var scanCmd = &cobra.Command{
	Use:   "scan [paths...]",
	Short: "Scan files or directories for secrets",
	Long: `Recursively scan each given path (file or directory) for secrets using regex patterns.
If no paths are provided, scans the current directory.`,
	Args: cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		// 1) Determine the working directory (to load .gitguardian.yml)
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("failed to get working directory: %w", err)
		}

		// 2) Load config from .gitguardian.yml
		cfg, err := config.LoadConfig(cwd)
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		// 3) Determine target paths to scan
		targets := args
		if len(targets) == 0 {
			targets = []string{"."}
		}

		// 4) Collect all findings from each target
		var allFindings []scanner.Finding
		for _, t := range targets {
			absPath, err := filepath.Abs(t)
			if err != nil {
				return fmt.Errorf("failed to get absolute path of %s: %w", t, err)
			}
			findings, err := scanner.ScanPath(absPath, cfg)
			if err != nil {
				return fmt.Errorf("error scanning %s: %w", t, err)
			}
			allFindings = append(allFindings, findings...)
		}

		// ── Social‐engineering scan: latest commit message ─────────────────────
		commitFnds, err := scanner.ScanLastCommitMessage()
		if err == nil && len(commitFnds) > 0 {
			allFindings = append(allFindings, commitFnds...)
		}

		// 5) Print each finding
		for _, f := range allFindings {
			fmt.Printf("%s:%d: [%s] %s\n", f.File, f.Line, f.Rule, f.Content)
		}

		// 6) Exit with code 1 if any findings, else 0
		if len(allFindings) > 0 {
			os.Exit(1)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
}
