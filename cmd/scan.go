package cmd

import (
	"fmt"

	"github.com/JohnnyCannelloni/gitguardian/scanner"
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "Scan files (or a directory) for secrets",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		path := "."
		if len(args) == 1 {
			path = args[0]
		}
		findings, err := scanner.ScanPath(path)
		if err != nil {
			return err
		}
		for _, f := range findings {
			fmt.Println(f)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
}
