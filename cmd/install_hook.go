// cmd/install_hook.go
package cmd

import (
	"fmt"

	"github.com/JohnnyCannelloni/gitguardian/hooks"
	"github.com/spf13/cobra"
)

// installHookCmd runs hooks.InstallPreCommit()
var installHookCmd = &cobra.Command{
	Use:   "install-hook",
	Short: "Install Git pre-commit hook to run gitguardian scan",
	Long:  "Writes an executable pre-commit hook into .git/hooks/pre-commit so that every commit is scanned for secrets.",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := hooks.InstallPreCommit(); err != nil {
			return fmt.Errorf("failed to install pre-commit hook: %w", err)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(installHookCmd)
}
