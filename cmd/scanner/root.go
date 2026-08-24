package main

import (
	"log/slog"

	"github.com/spf13/cobra"

	"sakanner/internal/config"
	"sakanner/internal/logging"
	"sakanner/internal/storage"
	"sakanner/internal/storage/sqlite"
)

// app holds the shared state every subcommand needs, populated by the
// root command's PersistentPreRunE once config and storage are ready.
type app struct {
	cfg    *config.Config
	store  storage.Store
	logger *slog.Logger
}

func newRootCmd() *cobra.Command {
	a := &app{}
	var configPath string

	root := &cobra.Command{
		Use:   "scanner",
		Short: "sakanner: modular, deterministic web security assessment platform",
		Long: `sakanner: modular, deterministic web security assessment platform.

Typical workflow:
  1. scanner scope add <target>      authorize a target (required --
                                      default-deny, see "scope --help")
  2. scanner scan <target>           run a scan (recon-only by default;
                                      --profile web/deep also crawls and
                                      runs vulnerability detection)
  3. scanner findings --scan <id>    inspect what was found
  4. scanner chains --scan <id>      inspect related-finding chains
  5. scanner report --scan <id>      export everything as one document

Command groups:
  target, scope       define what's authorized to scan
  scan, profiles      run scans and inspect the built-in scan profiles
  auth, identities    inspect authentication profiles/identities
                       (config-file only -- see "auth --help")
  status, findings,
  chains, inputs,
  report              inspect what a scan discovered/found
  detectors, tools    inspect the detection framework and optional
                       external tools

Every command is read-only except "target add", "scope add/remove",
and "scan" itself -- nothing else mutates state or touches the
network. Run "scanner <command> --help" for any command's full detail
and examples.`,
		// Both usage and Cobra's own automatic "Error: ..." print are
		// silenced here: main.go already prints every returned error
		// itself ("error: ..."), so leaving SilenceErrors false (the
		// pre-3.11.1 default) printed every error TWICE -- once from
		// Cobra, once from main.go -- which was barely noticeable for a
		// short one-line error but became a jarring duplicated block
		// once Phase 3.11.1 introduced longer, multi-line usage/example
		// error text (task section 15, "error message quality"). A
		// command that wants Cobra's own usage block on a specific
		// error can still print it explicitly (see missingScopeRuleIDError).
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(configPath)
			if err != nil {
				return err
			}
			a.cfg = cfg
			a.logger = logging.New(logging.Options{Level: cfg.Logging.Level, Format: cfg.Logging.Format})

			store, err := sqlite.New(cmd.Context(), cfg.Storage.DSN)
			if err != nil {
				return err
			}
			a.store = store
			return nil
		},
		PersistentPostRunE: func(cmd *cobra.Command, args []string) error {
			if a.store != nil {
				return a.store.Close()
			}
			return nil
		},
	}

	root.PersistentFlags().StringVar(&configPath, "config", "", "path to config file (YAML)")

	root.AddCommand(
		newTargetCmd(a),
		newScopeCmd(a),
		newScanCmd(a),
		newStatusCmd(a),
		newFindingsCmd(a),
		newChainsCmd(a),
		newReportCmd(a),
		newToolsCmd(a),
		newDetectorsCmd(a),
		newProfilesCmd(a),
		newInputsCmd(a),
		newAuthCmd(a),
		newIdentitiesCmd(a),
	)
	return root
}
