package main

import (
	"fmt"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

// newInputsCmd implements Phase 3.13's `scanner inputs <scan-id>` --
// task's "CLI" section, listing every discovered application input
// (query parameters, form fields, ...) for one scan job. Mirrors
// `scanner findings`'s own list-then-inspect style; a dedicated `show`
// subcommand isn't added since a Parameter has no deeper detail beyond
// what one table row already shows (unlike a Finding, which carries
// evidence) -- task's own "do not add unnecessary commands if the
// existing reporting model already provides the information" applies
// here: `scanner report` already includes the full Inputs section
// (docs/phase-3-13-parameter-discovery.md) for anyone wanting more.
func newInputsCmd(a *app) *cobra.Command {
	var location string
	var provenance string
	cmd := &cobra.Command{
		Use:   "inputs <scan-id>",
		Short: "List discovered application inputs for a scan",
		Long: `List Phase 3.13's discovered application inputs for one scan job.

Values are already redacted at discovery time when a field's name looks
sensitive (password, token, secret, ...) -- see
docs/phase-3-13-parameter-discovery.md "Secret redaction."

Phase 3.18 adds two columns: PROVENANCE distinguishes an input actually
observed being accepted by the application (REQUEST_INPUT -- a query
string, a rendered form) from a field only ever observed IN A RESPONSE
BODY (RESPONSE_FIELD -- an API returned it, which proves nothing about
whether the application accepts it back; see
docs/phase-3-18-api-json-discovery.md section 2). API indicates whether
this input's own endpoint was classified as an API candidate (evidence-
based, never from the path alone -- see that same document's section
4); "-" means no evidence was available (the endpoint discovering this
input was not itself fetched by this scan).`,
		Example: `  scanner inputs <scan-id>
  scanner inputs <scan-id> --location form
  scanner inputs <scan-id> --provenance REQUEST_INPUT`,
		Args: singleRequiredArg("a scan ID",
			"scanner scan example.com --profile web   # prints \"Scan ID: ...\"",
			"scanner inputs <scan-id>"),
		RunE: func(cmd *cobra.Command, args []string) error {
			scanJobID := args[0]
			inputsList, err := a.store.Parameters().ListByScanJob(cmd.Context(), scanJobID)
			if err != nil {
				return err
			}
			if location != "" {
				filtered := inputsList[:0]
				for _, p := range inputsList {
					if p.Location == location {
						filtered = append(filtered, p)
					}
				}
				inputsList = filtered
			}
			if provenance != "" {
				filtered := inputsList[:0]
				for _, p := range inputsList {
					if p.Provenance == provenance {
						filtered = append(filtered, p)
					}
				}
				inputsList = filtered
			}
			out := cmd.OutOrStdout()
			if len(inputsList) == 0 {
				fmt.Fprintln(out, "no inputs discovered")
				return nil
			}

			// One batch fetch, not one per row -- API-candidate status
			// lives on the Endpoint, not the Parameter (task's "do not
			// change the meaning of the existing Endpoint model" means
			// this stays a join, not a duplicated column).
			endpointsList, err := a.store.Endpoints().ListByScanJob(cmd.Context(), scanJobID)
			if err != nil {
				return err
			}
			apiByEndpointID := make(map[string]bool, len(endpointsList))
			for _, e := range endpointsList {
				apiByEndpointID[e.ID] = e.APICandidate
			}

			w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tENDPOINT ID\tMETHOD\tNAME\tLOCATION\tCLASSIFICATION\tPROVENANCE\tAPI\tIDENTITY\tVALUE")
			for _, p := range inputsList {
				api := "-"
				if candidate, known := apiByEndpointID[p.EndpointID]; known {
					api = fmt.Sprintf("%v", candidate)
				}
				prov := p.Provenance
				if prov == "" {
					prov = "REQUEST_INPUT"
				}
				identity := p.IdentityContext
				if identity == "" {
					identity = "-"
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", p.ID, p.EndpointID, p.Method, p.Name, p.Location, p.Classification, prov, api, identity, p.Value)
			}
			return w.Flush()
		},
	}
	cmd.Flags().StringVar(&location, "location", "", "filter to inputs at this location (query, path, form, json, header, cookie)")
	cmd.Flags().StringVar(&provenance, "provenance", "", "filter to inputs with this provenance (REQUEST_INPUT, RESPONSE_FIELD)")
	_ = cmd.RegisterFlagCompletionFunc("location", staticChoiceCompletion("query", "path", "form", "json", "header", "cookie"))
	_ = cmd.RegisterFlagCompletionFunc("provenance", staticChoiceCompletion("REQUEST_INPUT", "RESPONSE_FIELD"))
	return cmd
}
