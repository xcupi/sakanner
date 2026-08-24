package main

import (
	"fmt"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"sakanner/internal/detection"
	"sakanner/pkg/models"
)

func newFindingsCmd(a *app) *cobra.Command {
	var scanID, detectorID, severity string
	cmd := &cobra.Command{
		Use:   "findings",
		Short: "List findings discovered by a scan",
		Long: `List the vulnerabilities a scan's detectors found.

Only meaningful for a scan run with vulnerability detection enabled
("scanner scan <target> --profile web" or "--profile deep") -- a
"recon" profile scan (the default) never produces findings. Run
"scanner detectors list" to see which detectors are registered and
enabled in this build.

Use "scanner findings show <finding-id>" for one finding's full
detail (evidence, identity, chain membership), or add "--curl" to
that command for a sanitized, informational reproduction command.`,
		Example: `  scanner findings --scan <scan-id>
  scanner findings --scan <scan-id> --severity high
  scanner findings --scan <scan-id> --detector sqli-active`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if scanID == "" {
				return requiredFlagError(cmd, "--scan", "scanner findings --scan <scan-id>")
			}
			findings, err := a.store.Findings().ListByScanJob(cmd.Context(), scanID)
			if err != nil {
				return err
			}
			if detectorID != "" {
				findings = detection.FilterByDetector(findings, detectorID)
			}
			if severity != "" {
				findings = detection.FilterBySeverity(findings, models.Severity(severity))
			}
			if len(findings) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "no findings")
				return nil
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tSEVERITY\tDETECTOR\tTITLE\tENDPOINT\tSTATUS")
			for _, f := range findings {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", f.ID, f.Severity, f.DetectorID, sanitizeForTerminal(f.Title), sanitizeForTerminal(f.AffectedEndpoint), f.ValidationStatus)
			}
			return w.Flush()
		},
	}
	cmd.Flags().StringVar(&scanID, "scan", "", "scan job ID")
	cmd.Flags().StringVar(&detectorID, "detector", "", "filter to findings from this detector ID")
	cmd.Flags().StringVar(&severity, "severity", "", "filter to findings at this severity (info, low, medium, high, critical)")
	_ = cmd.RegisterFlagCompletionFunc("detector", detectorIDCompletion)
	_ = cmd.RegisterFlagCompletionFunc("severity", staticChoiceCompletion("info", "low", "medium", "high", "critical"))
	cmd.AddCommand(newFindingsShowCmd(a))
	return cmd
}

func newFindingsShowCmd(a *app) *cobra.Command {
	var curl bool
	cmd := &cobra.Command{
		Use:   "show <finding-id>",
		Short: "Show one finding's full detail, including evidence, identity, and chain membership",
		Example: `  scanner findings --scan <scan-id>        # find a finding ID first
  scanner findings show <finding-id>
  scanner findings show <finding-id> --curl`,
		Args: singleRequiredArg("a finding ID",
			"scanner findings --scan <scan-id>   # to find a finding ID first",
			"scanner findings show <finding-id>"),
		RunE: func(cmd *cobra.Command, args []string) error {
			f, err := a.store.Findings().Get(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()

			if curl {
				// --curl prints ONLY the reproduction command (plus its
				// own explanatory notes) -- a script-friendly, single-
				// purpose view, never mixed with the full detail dump
				// below. See docs/phase-3-32-operator-workflow.md
				// section 4: this is INFORMATION ONLY, never executed by
				// sakanner itself.
				repro, notes := buildCurlReproduction(f)
				if repro != "" {
					fmt.Fprintln(out, sanitizeForTerminal(repro))
				}
				for _, n := range notes {
					fmt.Fprintf(out, "# %s\n", sanitizeForTerminal(n))
				}
				return nil
			}

			s := sanitizeForTerminal
			fmt.Fprintf(out, "ID:          %s\n", s(f.ID))
			fmt.Fprintf(out, "Scan:        %s\n", s(f.ScanID))
			fmt.Fprintf(out, "Detector:    %s\n", s(f.DetectorID))
			fmt.Fprintf(out, "Type:        %s\n", s(f.VulnerabilityType))
			fmt.Fprintf(out, "Title:       %s\n", s(f.Title))
			fmt.Fprintf(out, "Severity:    %s\n", s(string(f.Severity)))
			fmt.Fprintf(out, "Confidence:  %.0f%%\n", f.Confidence*100)
			fmt.Fprintf(out, "Host:        %s\n", s(f.Host))
			fmt.Fprintf(out, "Port:        %d\n", f.Port)
			fmt.Fprintf(out, "URL:         %s\n", s(f.URL))
			fmt.Fprintf(out, "Method:      %s\n", s(f.Method))
			fmt.Fprintf(out, "Endpoint:    %s\n", s(f.AffectedEndpoint))
			fmt.Fprintf(out, "Parameter:   %s\n", s(f.AffectedParameter))
			fmt.Fprintf(out, "Status:      %s\n", s(string(f.ValidationStatus)))
			fmt.Fprintf(out, "Source:      %s\n", s(f.Source))
			identity := f.IdentityContext
			if identity == "" {
				identity = "(unauthenticated)"
			}
			fmt.Fprintf(out, "Identity:    %s\n", s(identity))
			if f.Description != "" {
				fmt.Fprintf(out, "Description: %s\n", s(f.Description))
			}
			if f.Remediation != "" {
				fmt.Fprintf(out, "Remediation: %s\n", s(f.Remediation))
			}
			if len(f.Evidence) == 0 {
				fmt.Fprintln(out, "Evidence:    (none)")
			} else {
				fmt.Fprintf(out, "Evidence (%d):\n", len(f.Evidence))
				for i, e := range f.Evidence {
					fmt.Fprintf(out, "  [%d] kind=%s\n      %s\n", i+1, s(string(e.Kind)), s(e.Content))
				}
			}

			if f.ScanID != "" {
				candidates, err := a.store.Chains().Candidates(cmd.Context(), f.ScanID)
				if err == nil {
					var member []string
					for _, c := range candidates {
						for _, fid := range c.FindingIDs {
							if fid == f.ID {
								member = append(member, fmt.Sprintf("%s (%s)", c.ID, c.Status))
								break
							}
						}
					}
					if len(member) == 0 {
						fmt.Fprintln(out, "Chain membership: not part of any chain candidate")
					} else {
						fmt.Fprintf(out, "Chain membership (%d):\n", len(member))
						for _, m := range member {
							fmt.Fprintf(out, "  - %s\n", s(m))
						}
					}
				}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&curl, "curl", false, "print a sanitized, informational curl-like reproduction command instead of the full detail view (never executed by sakanner)")
	return cmd
}
