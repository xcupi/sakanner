package main

import (
	"fmt"
	"text/tabwriter"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"sakanner/internal/target"
	"sakanner/pkg/models"
)

func newTargetCmd(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "target",
		Short: "Manage registered targets (legacy recon-only scan path)",
		Long: `Manage registered scan targets.

A registered target is only needed for the LEGACY recon-only path,
"scanner scan --target <id>" -- discovery (hosts, ports, HTTP
services, technologies) with no crawling, detection, correlation,
risk scoring, or evidence collection.

For the normal, full-pipeline scan (recommended), you do NOT need
this command at all -- pass the host/domain/IP directly:

  scanner scan example.com --profile web

An "allow" scope rule is still required before either path may touch
anything -- see "scanner scope --help".

Subcommands:
  add     register a domain, hostname, IP, or CIDR as a target
  list    show every registered target, including its ID`,
	}
	cmd.AddCommand(newTargetAddCmd(a), newTargetListCmd(a))
	return cmd
}

func newTargetAddCmd(a *app) *cobra.Command {
	var note string
	cmd := &cobra.Command{
		Use:   "add <value>",
		Short: "Register a scan target (domain, hostname, IP, or CIDR)",
		Long: `Register a scan target for the legacy recon-only path
("scanner scan --target <id>", see "scanner target --help"). Not
needed for a normal full-pipeline scan -- "scanner scan <value>"
accepts the same value directly.`,
		Example: `  scanner target add example.com
  scanner target add 203.0.113.10 --note "bug bounty scope"`,
		Args: singleRequiredArg("a value (domain, hostname, IP, or CIDR)",
			"scanner target add example.com", "scanner target add 203.0.113.10"),
		RunE: func(cmd *cobra.Command, args []string) error {
			value, typ, err := target.Parse(args[0])
			if err != nil {
				return err
			}
			t := models.Target{ID: uuid.NewString(), Value: value, Type: typ, Note: note, CreatedAt: time.Now().UTC()}
			if err := a.store.Targets().Create(cmd.Context(), t); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "added target %s (%s) id=%s\n", t.Value, t.Type, t.ID)
			return nil
		},
	}
	cmd.Flags().StringVar(&note, "note", "", "optional note")
	return cmd
}

func newTargetListCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Short:   "List registered scan targets",
		Example: `  scanner target list`,
		RunE: func(cmd *cobra.Command, args []string) error {
			targets, err := a.store.Targets().List(cmd.Context())
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tVALUE\tTYPE\tNOTE\tCREATED")
			for _, t := range targets {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", t.ID, t.Value, t.Type, t.Note, t.CreatedAt.Format(time.RFC3339))
			}
			return w.Flush()
		},
	}
}
