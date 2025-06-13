// cmd/deps_scan.go
package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/JohnnyCannelloni/gitguardian/deps"
	"github.com/spf13/cobra"
)

var depsScanCmd = &cobra.Command{
	Use:   "deps-scan [path]",
	Short: "Scan dependencies for known vulnerabilities",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		root := "."
		if len(args) == 1 {
			root = args[0]
		}
		abs, _ := filepath.Abs(root)
		findings, err := deps.CombinedScan(abs)
		if err != nil {
			return err
		}
		for _, f := range findings {
			fmt.Printf("%s [%s] %s\n", f.File, f.Rule, f.Content)
		}
		if len(findings) > 0 {
			os.Exit(1)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(depsScanCmd)
}
