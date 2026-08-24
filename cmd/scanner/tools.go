package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"sakanner/pkg/plugins"
)

func newToolsCmd(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tools",
		Short: "Inspect pluggable external tool integrations",
		Long: `Inspect sakanner's optional external recon tool integrations
(subfinder, dnsx, naabu, httpx, katana).

Each stage's backend is configured under "tools.<name>" in your
config file: "auto" (default -- use the tool if found on PATH, else
sakanner's own native implementation), "native" (always use
sakanner's own implementation), or the tool's own name (require it,
fail if not found). Every stage runs correctly with no external tools
installed at all -- these are optional accelerators, never a
requirement.`,
	}
	cmd.AddCommand(newToolsStatusCmd(a))
	return cmd
}

func newToolsStatusCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:     "status",
		Short:   "Show detection status and configured backend for each pluggable external tool",
		Example: `  scanner tools status`,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			backendByTool := map[string]string{
				plugins.Subfinder.Name: a.cfg.Tools.Subfinder,
				plugins.Dnsx.Name:      a.cfg.Tools.Dnsx,
				plugins.Naabu.Name:     a.cfg.Tools.Naabu,
				plugins.Httpx.Name:     a.cfg.Tools.Httpx,
				plugins.Katana.Name:    a.cfg.Tools.Katana,
			}

			for _, tool := range plugins.AllTools() {
				backend := backendByTool[tool.Name]
				if backend == "" {
					backend = "native"
				}
				path, found := plugins.Detect(tool.BinaryName)
				if found {
					fmt.Fprintf(out, "%-10s backend=%-10s detected=%s\n", tool.Name, backend, path)
					continue
				}
				fmt.Fprintf(out, "%-10s backend=%-10s detected=not found\n", tool.Name, backend)
				if backend == tool.Name {
					fmt.Fprintf(out, "%-10s WARNING: backend explicitly set to %q but the binary was not found -- scans using this stage will fail\n", "", tool.Name)
				}
				fmt.Fprintf(out, "%-10s %s\n", "", tool.InstallHint)
			}
			return nil
		},
	}
}
