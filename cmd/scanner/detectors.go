package main

import (
	"fmt"
	"log/slog"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"sakanner/internal/detection"
	"sakanner/internal/detectors/cmdinjection"
	"sakanner/internal/detectors/cmdinjectionactive"
	"sakanner/internal/detectors/idor"
	"sakanner/internal/detectors/idoractive"
	"sakanner/internal/detectors/openredirectactive"
	"sakanner/internal/detectors/sqli"
	"sakanner/internal/detectors/sqliactive"
	"sakanner/internal/detectors/ssrf"
	"sakanner/internal/detectors/ssrfactive"
	"sakanner/internal/detectors/sstiactive"
	"sakanner/internal/detectors/traversal"
	"sakanner/internal/detectors/traversalactive"
	"sakanner/internal/detectors/xssactive"
	"sakanner/internal/detectors/xssreflected"
)

// productionRegistry returns the detection.Registry sakanner's CLI runs
// against. As of Phase 3.7 it registers six real detectors:
// xss-reflected (internal/detectors/xssreflected), sqli
// (internal/detectors/sqli), and command-injection
// (internal/detectors/cmdinjection) are fully enabled; ssrf
// (internal/detectors/ssrf), idor (internal/detectors/idor), and
// path-traversal (internal/detectors/traversal) are registered but
// DISABLED -- each of those three requires operator-configured
// infrastructure this build does not ship (an out-of-band callback
// service for ssrf; at least 2 pre-authenticated AuthContext values
// plus resource-ownership ground truth for idor; at least 1 known
// TraversalCase for path-traversal), so each is constructed with a
// nil/empty dependency (safe: Detect returns OutcomeSkipped rather
// than panicking) purely so `scanner detectors list` honestly shows it
// exists and why it's off, exactly mirroring how Phase 3.1 documented
// DetectionConfig as built-but-not-yet-wired.
//
// command-injection is a deliberate exception to that disabled-by-
// default pattern: unlike ssrf/idor/traversal, its correlation
// mechanism (a freshly generated, unpredictable per-probe token) is
// entirely self-contained -- it needs no operator-supplied production
// knowledge at all (cmdinjection.New() takes no arguments), so there is
// nothing missing to justify disabling it. See
// docs/phase-3-7-command-injection.md "Why this detector needs no
// external configuration."
//
// Every future detector registers itself here the same way, and
// nowhere else in this file (or internal/detection) needs to change to
// add one. See "How to implement a new detector" in
// docs/phase-3-1-detection-engine.md.
//
// Phase 3.19 adds xss-reflected-active (internal/detectors/xssactive)
// -- a SECOND, independent reflected-XSS detector built on
// internal/mutation's canonical Request/Mutate/Execute model, enabled
// by default alongside xss-reflected (Phase 3.3). Both may run in the
// same scan; each has its own stable ID and its own findings. See
// docs/phase-3-19-active-detection.md.
//
// Phase 3.20 adds sqli-active (internal/detectors/sqliactive) --
// the SAME coexistence pattern, for SQL injection: a second,
// independent detector built on internal/mutation, enabled by default
// alongside sqli (Phase 3.3). See docs/phase-3-20-sqli.md.
//
// Phase 3.24 adds idor-active (internal/detectors/idoractive) --
// registered here disabled, with a nil compare executor, exactly like
// ssrf/idor/traversal: `scanner detectors list` honestly shows it
// exists and why it's off. Unlike those three, idor-active's missing
// dependency (a second, independently-authenticated identity) is
// scan-specific, not a static build-time configuration -- see
// productionRegistryWithAuthz below, which cmd/scanner/scan.go calls
// INSTEAD of this function whenever --authz-identity was supplied.
// See docs/phase-3-24-authorization.md section 6.
//
// Phase 3.25 adds ssrf-active (internal/detectors/ssrfactive) --
// registered here disabled, with a nil CallbackClient, exactly like
// ssrf itself: no production-reachable callback service ships with
// this build (the SAME honest, pre-existing gap ssrf.New(nil) already
// documents), so `scanner detectors list` shows it registered but off.
// Proven end to end exclusively through the lab's real
// lab.SSRFCallbackServer. See docs/phase-3-25-ssrf-active-detection.md
// section 16.
//
// Phase 3.26 adds command-injection-active
// (internal/detectors/cmdinjectionactive) -- the SAME "no external
// dependency needed" exception command-injection itself already is:
// its correlation mechanism is entirely self-contained
// (cmdinjectionactive.New() takes no arguments), so it is enabled by
// default alongside command-injection, mirroring xss-reflected-active/
// sqli-active's own precedent, not idor-active/ssrf-active's disabled-
// by-default one. See docs/phase-3-26-command-injection-active.md
// section 15.
//
// Phase 3.27 adds path-traversal-active
// (internal/detectors/traversalactive) -- registered here disabled,
// with a nil/empty TraversalCase slice, exactly like path-traversal
// itself: no operator-configured known-traversal-path/marker pair
// ships with this build (the SAME honest, pre-existing gap
// traversal.New(nil) already documents), so `scanner detectors list`
// shows it registered but off. Proven end to end exclusively through
// the lab's own known TraversalCase configuration. See
// docs/phase-3-27-path-traversal-active.md section 1.4.
//
// Phase 3.28 adds open-redirect-active
// (internal/detectors/openredirectactive) -- registered here disabled,
// with an empty destination string, mirroring ssrfactive/
// traversalactive exactly: no operator-configured, known, out-of-scope
// canary destination ships with this build, so `scanner detectors
// list` shows it registered but off. There is no pre-existing
// "open-redirect"/passive detector to mirror the disabled-by-default
// reasoning against -- this is the first detector for this
// vulnerability class at all. Proven end to end exclusively through
// the lab's own known destination configuration. See
// docs/phase-3-28-open-redirect-active.md section 1.4.
//
// Phase 3.29 adds ssti-active (internal/detectors/sstiactive) --
// enabled by default, mirroring cmdinjectionactive/xssactive/
// sqliactive's own precedent, not ssrfactive/traversalactive/
// openredirectactive's disabled-by-default one: its correlation
// mechanism (a freshly generated, unpredictable per-probe arithmetic
// product) is entirely self-contained, needing no operator-supplied
// external configuration at all (sstiactive.New() takes no
// arguments). There is no pre-existing "ssti"/passive detector to
// coexist with -- this is the first detector for this vulnerability
// class, selected after Phase 3.29's own architecture/coverage review
// found it the only candidate requiring zero new foundation work. See
// docs/phase-3-29-active-detection-coverage-review.md.
func productionRegistry() *detection.Registry {
	return buildProductionRegistry(idoractive.New(nil, ""), false)
}

// productionRegistryWithAuthz is productionRegistry, but constructed
// with idor-active's REAL compare-identity executor from the start
// (and enabled) rather than the nil/disabled placeholder --
// detection.Registry has no way to replace an already-registered
// detector, so the base detector set is built once, by
// buildProductionRegistry, parameterized by which idor-active instance
// to register -- never two independently-drifting detector lists.
// Called by runFullScan exactly when --authz-identity was supplied
// (task section 18's "enable/disable authorization testing" minimal
// CLI surface: the flag's mere presence is the enable signal -- see
// docs/phase-3-24-authorization.md section 6). compareExecutor/
// compareIdentity are never nil/empty when this is called -- scan.go
// resolves and authenticates the compare identity strictly before
// building this registry, mirroring how the primary --identity is
// already resolved before productionRegistry() itself is ever needed.
func productionRegistryWithAuthz(compareExecutor *detection.Executor, compareIdentity string) *detection.Registry {
	return buildProductionRegistry(idoractive.New(compareExecutor, compareIdentity), true)
}

// buildProductionRegistry registers every real detector once,
// disabling the ones that need operator/scan-specific configuration
// this build/invocation may not have. idorActive/idorActiveEnabled let
// the two callers above share this ONE registration list instead of
// maintaining two.
func buildProductionRegistry(idorActive *idoractive.Detector, idorActiveEnabled bool) *detection.Registry {
	r := detection.NewRegistry()
	for _, d := range []detection.Detector{xssreflected.New(), xssactive.New(), sqli.New(), sqliactive.New(), cmdinjection.New(), cmdinjectionactive.New(), ssrf.New(nil), ssrfactive.New(nil, "", ""), idor.New(nil), traversal.New(nil), traversalactive.New(nil), openredirectactive.New(""), sstiactive.New(), idorActive} {
		if err := r.Register(d); err != nil {
			// Only reachable if a future detector's ID collides with an
			// existing one -- a programming error caught immediately at
			// startup, not a runtime condition to recover from.
			slog.Default().Error("failed to register detector", slog.String("error", err.Error()))
		}
	}
	for _, id := range []string{ssrf.ID, ssrfactive.ID, idor.ID, traversal.ID, traversalactive.ID, openredirectactive.ID} {
		if err := r.SetEnabled(id, false); err != nil {
			slog.Default().Error("failed to disable detector", slog.String("detector_id", id), slog.String("error", err.Error()))
		}
	}
	if err := r.SetEnabled(idoractive.ID, idorActiveEnabled); err != nil {
		slog.Default().Error("failed to set idor-active enablement", slog.String("detector_id", idoractive.ID), slog.String("error", err.Error()))
	}
	return r
}

func newDetectorsCmd(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "detectors",
		Short: "Inspect the vulnerability detection framework's registry",
		Long: `Inspect sakanner's vulnerability detection framework.

Detectors only ever run during a scan with detection enabled --
"scanner scan <target> --profile web" or "--profile deep" -- and only
against endpoints/parameters the crawler actually discovered. A
"disabled" detector is registered but will not run: some are disabled
because this build ships no default configuration for them (e.g. an
out-of-band callback for ssrf-active), and idor-active is disabled
unless the scan is run with --authz-identity.

Run "scanner detectors list" for the exact, current list -- this
help text intentionally does not enumerate detector IDs, since new
ones are added over time and only the registry itself is
authoritative.`,
	}
	cmd.AddCommand(newDetectorsListCmd(a))
	return cmd
}

func newDetectorsListCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Short:   "List every registered detector and whether it's enabled",
		Example: `  scanner detectors list`,
		RunE: func(cmd *cobra.Command, args []string) error {
			entries := productionRegistry().List()
			out := cmd.OutOrStdout()
			if len(entries) == 0 {
				fmt.Fprintln(out, "no detectors registered")
				return nil
			}
			w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tSTATUS\tCATEGORY\tNAME")
			for _, e := range entries {
				status := "disabled"
				if e.Enabled {
					status = "enabled"
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", e.Metadata.ID, status, e.Metadata.Category, e.Metadata.Name)
			}
			return w.Flush()
		},
	}
}
