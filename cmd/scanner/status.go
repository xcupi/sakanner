package main

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"sakanner/internal/reporting"
)

func newStatusCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "status <scan-id>",
		Short: "Show a scan job's status and result counts",
		Long: `Show one scan job's status (running/completed/failed/cancelled)
and a count of everything it produced -- assets, hosts, DNS records,
services, HTTP services, technologies, endpoints, findings.

Get <scan-id> from "scanner scan"'s own output ("Scan ID: ...").`,
		Example: `  scanner status <scan-id>`,
		Args: singleRequiredArg("a scan ID",
			"scanner scan example.com --profile web   # prints \"Scan ID: ...\"",
			"scanner status <scan-id>"),
		RunE: func(cmd *cobra.Command, args []string) error {
			rep, err := reporting.Build(cmd.Context(), a.store, args[0])
			if err != nil {
				return err
			}
			job := rep.Job

			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "id: %s\n", job.ID)
			fmt.Fprintf(out, "status: %s\n", job.Status)
			fmt.Fprintf(out, "started: %s\n", job.StartedAt.Format(time.RFC3339))
			if job.FinishedAt != nil {
				fmt.Fprintf(out, "finished: %s\n", job.FinishedAt.Format(time.RFC3339))
			}
			if job.Error != "" {
				fmt.Fprintf(out, "error: %s\n", job.Error)
			}
			fmt.Fprintf(out, "assets: %d\n", len(rep.Assets))
			fmt.Fprintf(out, "hosts: %d\n", len(rep.Hosts))
			fmt.Fprintf(out, "dns_records: %d\n", len(rep.DNSRecords))
			fmt.Fprintf(out, "services: %d\n", len(rep.Services))
			fmt.Fprintf(out, "http_services: %d\n", len(rep.HTTPServices))
			fmt.Fprintf(out, "technologies: %d\n", len(rep.Technologies))
			fmt.Fprintf(out, "endpoints: %d\n", len(rep.Endpoints))
			fmt.Fprintf(out, "findings: %d\n", len(rep.Findings))
			return nil
		},
	}
}
