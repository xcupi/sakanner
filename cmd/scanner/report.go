package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"sakanner/internal/reporting"
)

func newReportCmd(a *app) *cobra.Command {
	var scanID, format, output string
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Generate a report for a scan (JSON or Markdown)",
		Long: `Generate a full report for one scan job: assets, hosts, DNS
records, services, HTTP services, technologies, endpoints, inputs,
findings, and chains -- everything "scanner status"/"findings"/
"chains" show piecemeal, assembled into one document.`,
		Example: `  scanner report --scan <scan-id>
  scanner report --scan <scan-id> --format json
  scanner report --scan <scan-id> --format json --output report.json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if scanID == "" {
				return requiredFlagError(cmd, "--scan", "scanner report --scan <scan-id>")
			}

			rep, err := reporting.Build(cmd.Context(), a.store, scanID)
			if err != nil {
				return err
			}

			var content []byte
			switch format {
			case "json":
				content, err = rep.JSON()
				if err != nil {
					return err
				}
			case "markdown", "md":
				content = []byte(rep.Markdown())
			default:
				return fmt.Errorf("unknown --format %q (want json or markdown)", format)
			}

			if output == "" {
				_, err := cmd.OutOrStdout().Write(content)
				return err
			}
			return os.WriteFile(output, content, 0o644)
		},
	}
	cmd.Flags().StringVar(&scanID, "scan", "", "scan job ID")
	cmd.Flags().StringVar(&format, "format", "markdown", "output format: json or markdown")
	_ = cmd.RegisterFlagCompletionFunc("format", staticChoiceCompletion("json", "markdown"))
	cmd.Flags().StringVar(&output, "output", "", "output file path (default: stdout)")
	return cmd
}
