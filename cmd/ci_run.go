// cmd/ci_run.go
package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/JohnnyCannelloni/gitguardian/config"
	"github.com/JohnnyCannelloni/gitguardian/deps"
	"github.com/JohnnyCannelloni/gitguardian/scanner"
	"github.com/spf13/cobra"
)

var ciRunCmd = &cobra.Command{
	Use:   "ci-run [path]",
	Short: "Run both secrets+deps scans and output JSON",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		root := "."
		if len(args) == 1 {
			root = args[0]
		}
		abs, _ := filepath.Abs(root)

		cfg, err := config.LoadConfig(abs)
		if err != nil {
			return err
		}

		sec, _ := scanner.ScanPath(abs, cfg)
		dep, _ := deps.CombinedScan(abs)
		all := append(sec, dep...)

		out, err := json.MarshalIndent(all, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(out))

		if len(all) > 0 {
			os.Exit(1)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(ciRunCmd)
}
