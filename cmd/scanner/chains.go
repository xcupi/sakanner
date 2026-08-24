package main

import (
	"fmt"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"sakanner/internal/chains"
)

// newChainsCmd mirrors newFindingsCmd's exact structure (Phase 3.1) --
// a read-only, --scan-scoped listing command with a "show" subcommand
// for full detail. Phase 3.31's own addition: chains persisted by
// internal/orchestrator's own chain-correlation step
// (internal/chains.Correlate, Phase 3.30) via storage.ChainRepository.
// Never destructive -- no delete/modify verb exists on this command
// tree, only read paths.
func newChainsCmd(a *app) *cobra.Command {
	var scanID, status string
	cmd := &cobra.Command{
		Use:   "chains",
		Short: "List candidate vulnerability chains for a scan",
		Long: `List candidate vulnerability chains -- sakanner's own evidence
that two or more findings from the same scan are related (e.g. an
authentication weakness combined with an IDOR). Status is one of
POTENTIAL, SUPPORTED, or CONFIRMED.

Use "scanner chains show <chain-candidate-id> --scan <scan-id>" for
one chain's full detail: participating findings, relations, and
evidence.`,
		Example: `  scanner chains --scan <scan-id>
  scanner chains --scan <scan-id> --status SUPPORTED`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if scanID == "" {
				return requiredFlagError(cmd, "--scan", "scanner chains --scan <scan-id>")
			}
			candidates, err := a.store.Chains().Candidates(cmd.Context(), scanID)
			if err != nil {
				return err
			}
			if status != "" {
				filtered := candidates[:0]
				for _, c := range candidates {
					if string(c.Status) == status {
						filtered = append(filtered, c)
					}
				}
				candidates = filtered
			}
			if len(candidates) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "no chain candidates")
				return nil
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tSTATUS\tIDENTITY\tFINDINGS\tCONFIDENCE\tREASON")
			for _, c := range candidates {
				identity := c.IdentityContext
				if identity == "" {
					identity = "(unauthenticated)"
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%.0f%%\t%s\n", c.ID, c.Status, sanitizeForTerminal(identity), len(c.FindingIDs), c.Confidence*100, sanitizeForTerminal(c.Reason))
			}
			return w.Flush()
		},
	}
	cmd.Flags().StringVar(&scanID, "scan", "", "scan job ID")
	cmd.Flags().StringVar(&status, "status", "", "filter to chains at this status (POTENTIAL, SUPPORTED, CONFIRMED)")
	_ = cmd.RegisterFlagCompletionFunc("status", staticChoiceCompletion("POTENTIAL", "SUPPORTED", "CONFIRMED"))
	cmd.AddCommand(newChainsShowCmd(a))
	return cmd
}

// newChainsShowCmd shows one chain candidate's full detail: every
// participating finding (with ITS OWN, unmodified severity -- a chain
// never overwrites or hides an individual finding's own assessment),
// every relation connecting them (with its own evidence), and the
// chain's own status/confidence/impact/missing-evidence -- everything
// the task's own "CLI/REPORTING" section lists, and nothing else
// (never a credential, session cookie, or authorization header --
// internal/chains itself never stores one; see
// docs/phase-3-31-chain-integration.md).
func newChainsShowCmd(a *app) *cobra.Command {
	var scanID string
	cmd := &cobra.Command{
		Use:   "show <chain-candidate-id>",
		Short: "Show one chain candidate's full detail: participating findings, relations, and evidence",
		Example: `  scanner chains --scan <scan-id>                              # find a chain ID first
  scanner chains show <chain-candidate-id> --scan <scan-id>`,
		Args: singleRequiredArg("a chain candidate ID",
			"scanner chains --scan <scan-id>   # to find a chain candidate ID first",
			"scanner chains show <chain-candidate-id> --scan <scan-id>"),
		RunE: func(cmd *cobra.Command, args []string) error {
			candidateID := args[0]
			// Candidates() has no single-ID lookup (Phase 3.31 keeps the
			// read surface minimal); a --scan-scoped list plus a local
			// match is simplest since chain IDs are already
			// content-derived and effectively unique per scan.
			if scanID == "" {
				return requiredFlagError(cmd, "--scan", "scanner chains show <chain-candidate-id> --scan <scan-id>")
			}
			candidates, err := a.store.Chains().Candidates(cmd.Context(), scanID)
			if err != nil {
				return err
			}
			var candidate chains.ChainCandidate
			found := false
			for _, c := range candidates {
				if c.ID == candidateID {
					candidate, found = c, true
					break
				}
			}
			if !found {
				return fmt.Errorf("chain candidate %q not found in scan %q", candidateID, scanID)
			}

			relations, err := a.store.Chains().Relations(cmd.Context(), scanID)
			if err != nil {
				return err
			}
			relByID := make(map[string]chains.FindingRelation, len(relations))
			for _, r := range relations {
				relByID[r.ID] = r
			}

			s := sanitizeForTerminal
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "ID:               %s\n", candidate.ID)
			fmt.Fprintf(out, "Scan:             %s\n", s(candidate.ScanJobID))
			identity := candidate.IdentityContext
			if identity == "" {
				identity = "(unauthenticated)"
			}
			fmt.Fprintf(out, "Identity:         %s\n", s(identity))
			fmt.Fprintf(out, "Status:           %s\n", candidate.Status)
			fmt.Fprintf(out, "Confidence:       %.0f%%\n", candidate.Confidence*100)
			fmt.Fprintf(out, "Impact:           %s\n", s(candidate.ImpactEstimate))
			fmt.Fprintf(out, "Reason:           %s\n", s(candidate.Reason))
			if len(candidate.Endpoints) > 0 {
				fmt.Fprintf(out, "Endpoints:        %v\n", sanitizeSlice(candidate.Endpoints))
			}
			if len(candidate.MissingEvidence) > 0 {
				fmt.Fprintf(out, "Missing evidence: %v\n", sanitizeSlice(candidate.MissingEvidence))
			}

			fmt.Fprintf(out, "\nParticipating findings (%d):\n", len(candidate.FindingIDs))
			for _, fid := range candidate.FindingIDs {
				f, getErr := a.store.Findings().Get(cmd.Context(), fid)
				if getErr != nil {
					fmt.Fprintf(out, "  [%s] (could not load: %v)\n", fid, getErr)
					continue
				}
				fmt.Fprintf(out, "  [%s] %s severity=%s endpoint=%s parameter=%s\n", f.ID, s(f.VulnerabilityType), s(string(f.Severity)), s(f.AffectedEndpoint), s(f.AffectedParameter))
			}

			fmt.Fprintf(out, "\nRelations (%d):\n", len(candidate.RelationIDs))
			for _, rid := range candidate.RelationIDs {
				r, ok := relByID[rid]
				if !ok {
					fmt.Fprintf(out, "  [%s] (not found)\n", rid)
					continue
				}
				fmt.Fprintf(out, "  [%s] %s: %s <-> %s (confidence %.0f%%)\n", r.ID, r.Type, r.FindingAID, r.FindingBID, r.Confidence*100)
				fmt.Fprintf(out, "      reason: %s\n", s(r.Reason))
				for _, ev := range r.Evidence {
					fmt.Fprintf(out, "      evidence: kind=%s detail=%q -- %s\n", ev.Kind, s(ev.Detail), s(ev.Description))
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&scanID, "scan", "", "scan job ID")
	return cmd
}
