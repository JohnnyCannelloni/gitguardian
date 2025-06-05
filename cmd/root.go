// cmd/root.go
package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

// rootCmd is the base command for the CLI.
var rootCmd = &cobra.Command{
	Use:   "gitguardian",
	Short: "GitGuardian CLI scans for secrets and vulnerable dependencies",
	Long: `gitguardian is a tool to catch accidental commits of secrets (API keys, tokens, etc.)
and flag vulnerable dependencies before push or on CI.`,
}

// Execute executes the root command. This should be called by main().
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// We’ll add subcommands (scan, install-hook, deps-scan, etc.) in later steps.
func init() {
	// If you want global flags (e.g. a --config flag), you can define them here:
	// rootCmd.PersistentFlags().StringP("config", "c", "", "config file (default is .gitguardian.yml)")
}
