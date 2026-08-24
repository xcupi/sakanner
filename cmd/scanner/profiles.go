package main

import (
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"sakanner/internal/policy"
)

// newProfilesCmd implements Phase 3.12's `scanner profiles` command --
// task's "scanner profiles list" / "scanner profiles show <name>."
func newProfilesCmd(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "profiles",
		Short: "Inspect sakanner's built-in scan profiles",
		Long: `Inspect sakanner's built-in scan profiles.

A profile is a named, fixed bundle of crawler/detection/resource
settings, selected with "scanner scan <target> --profile <name>".
Profiles never grant authorization: scope rules remain the sole
authority over what may actually be scanned, entirely independent of
which profile is active -- see docs/phase-3-12-scan-profiles.md
"Scope semantics."

Subcommands:
  list  show every profile in one table
  show  show one profile's full detail`,
	}
	cmd.AddCommand(newProfilesListCmd(), newProfilesShowCmd())
	return cmd
}

func newProfilesListCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Short:   "List every built-in scan profile",
		Example: `  scanner profiles list`,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tDESCRIPTION\tCRAWLER\tDETECTION\tVERIFICATION\tRESOURCE CLASS")
			for _, p := range policy.DefaultRegistry().List() {
				name := p.Name
				if name == policy.DefaultProfileName {
					name += " (default)"
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
					name, p.Description, crawlerColumn(p), enabledColumn(p.DetectionEnabled),
					enabledColumn(p.VerificationEnabled), p.ResourceClass)
			}
			return w.Flush()
		},
	}
}

func newProfilesShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <name>",
		Short: "Show one scan profile's full detail",
		Example: `  scanner profiles list         # see every profile name first
  scanner profiles show web`,
		Args: singleRequiredArg("a scan profile name",
			"scanner profiles list   # to see every profile name first",
			"scanner profiles show web"),
		ValidArgsFunction: profileNameCompletion,
		RunE: func(cmd *cobra.Command, args []string) error {
			reg := policy.DefaultRegistry()
			p, ok := reg.Get(args[0])
			if !ok {
				return &exitCodeErr{code: exitGenericError, err: &policy.UnknownProfileError{Name: args[0], Available: reg.Names()}}
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Name:        %s", p.Name)
			if p.Name == policy.DefaultProfileName {
				fmt.Fprint(out, " (default)")
			}
			fmt.Fprintln(out)
			fmt.Fprintf(out, "Description: %s\n", p.Description)
			fmt.Fprintln(out, "\nCrawler:")
			fmt.Fprintf(out, "  Enabled:   %v\n", p.CrawlEnabled)
			if p.CrawlEnabled {
				fmt.Fprintf(out, "  Max depth: %d\n", p.CrawlMaxDepth)
				fmt.Fprintf(out, "  Max pages: %d\n", p.CrawlMaxPages)
			}
			fmt.Fprintln(out, "\nDetection:")
			fmt.Fprintf(out, "  Enabled: %v\n", p.DetectionEnabled)
			fmt.Fprintln(out, "\nVerification:")
			fmt.Fprintf(out, "  Enabled: %v\n", p.VerificationEnabled)
			fmt.Fprintln(out, "\nEvidence collection:")
			fmt.Fprintf(out, "  Enabled: %v\n", p.EvidenceEnabled)
			fmt.Fprintln(out, "\nResource limits:")
			fmt.Fprintf(out, "  Resource class:        %s\n", p.ResourceClass)
			fmt.Fprintf(out, "  Detection concurrency: %d\n", p.DetectionConcurrency)
			fmt.Fprintf(out, "  Scan timeout:          %s\n", p.ScanTimeout)
			fmt.Fprintf(out, "  Stage timeout:         %s\n", p.StageTimeout)
			fmt.Fprintln(out, "\nNote: profiles never grant authorization. Scope rules remain")
			fmt.Fprintln(out, "authoritative regardless of which profile is active.")
			return nil
		},
	}
}

func crawlerColumn(p policy.Profile) string {
	if !p.CrawlEnabled {
		return "disabled"
	}
	return fmt.Sprintf("enabled (depth=%d, pages=%d)", p.CrawlMaxDepth, p.CrawlMaxPages)
}

func enabledColumn(enabled bool) string {
	if enabled {
		return "enabled"
	}
	return "disabled"
}

// profileNameCompletion completes a profile name argument/flag value
// -- registered on both `scan --profile` and `profiles show`. This is
// the one deliberate, safe exception to Phase 3.11.1's "completion is
// pure static CLI metadata, no ValidArgsFunction/RegisterFlagCompletionFunc
// anywhere" finding (docs/phase-3-11-1-cli-ux.md "Shell completion"):
// unlike scope rule IDs (which would require opening the database at
// completion time -- the reason that phase deliberately did NOT
// dynamically complete them), profile names are policy.DefaultRegistry's
// own fixed, in-memory, zero-I/O literal list. Completing them performs
// no database access, no network call, and no scan -- it does not
// weaken that phase's side-effect-free guarantee, only extends what
// "static CLI metadata" includes.
func profileNameCompletion(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	names := policy.DefaultRegistry().Names()
	var out []string
	for _, n := range names {
		if strings.HasPrefix(n, toComplete) {
			out = append(out, n)
		}
	}
	return out, cobra.ShellCompDirectiveNoFileComp
}
