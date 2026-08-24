package main

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"sakanner/internal/auth"
	"sakanner/internal/config"
)

// authProfileConfigs translates every configured
// config.AuthProfileConfig into internal/auth's own ProfileConfig shape
// -- field-by-field, mirroring exactly how cmd/scanner already
// translates internal/policy.ConfigView for --profile (see scan.go's
// runFullScan). internal/config never imports internal/auth's
// ProfileConfig type itself (see config.go's own doc comment on why),
// so this translation lives here instead.
func authProfileConfigs(cfg *config.Config) []auth.ProfileConfig {
	out := make([]auth.ProfileConfig, 0, len(cfg.Authentication.Profiles))
	for _, pc := range cfg.Authentication.Profiles {
		out = append(out, auth.ProfileConfig{
			Name: pc.Name, Type: auth.Type(pc.Type),
			LoginURL: pc.LoginURL, UsernameEnv: pc.UsernameEnv, PasswordEnv: pc.PasswordEnv,
			UsernameField: pc.UsernameField, PasswordField: pc.PasswordField, ExtraFields: pc.ExtraFields,
			SuccessURLContains: pc.SuccessURLContains, SuccessTextContains: pc.SuccessTextContains, FailureTextContains: pc.FailureTextContains,
			CookieEnv: pc.CookieEnv, TokenEnv: pc.TokenEnv,
			HeaderName: pc.HeaderName, HeaderValueEnv: pc.HeaderValueEnv,
			ScopeHost: pc.ScopeHost, Timeout: pc.Timeout, MaxRedirects: pc.MaxRedirects,
		})
	}
	return out
}

// newAuthCmd implements Phase 3.14's `scanner auth` command family --
// task section 12's "scanner auth profiles list" / "scanner auth
// profiles show <name>."
func newAuthCmd(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Inspect configured authentication profiles",
		Long: `Inspect sakanner's configured authentication profiles.

An authentication profile describes how to establish an authenticated
session against a target -- form-based login, a pre-obtained session
cookie, a bearer/API token, or a custom header -- configured under
"authentication.profiles" in your config file (see
docs/phase-3-14-authentication.md). Credentials themselves are never
stored in configuration: each profile REFERENCES an environment
variable (e.g. "username_env: SAKANNER_LAB_USERNAME") that must be set
in the environment before the profile can actually be used.

Subcommands:
  profiles list          show every configured profile in one table
  profiles show <name>   show one profile's full (secret-free) detail

Use "scanner scan <target> --auth-profile <name>" to authenticate
before scanning.`,
	}
	cmd.AddCommand(newAuthProfilesCmd(a))
	return cmd
}

func newAuthProfilesCmd(a *app) *cobra.Command {
	cmd := &cobra.Command{Use: "profiles", Short: "Inspect configured authentication profiles"}
	cmd.AddCommand(newAuthProfilesListCmd(a), newAuthProfilesShowCmd(a))
	return cmd
}

func newAuthProfilesListCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List every configured authentication profile",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			profiles := authProfileConfigs(a.cfg)
			if len(profiles) == 0 {
				fmt.Fprintln(out, "no authentication profiles configured -- see \"authentication.profiles\" in your config file")
				return nil
			}
			w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tTYPE\tHOST\tSTATUS")
			for _, pc := range profiles {
				host := pc.ScopeHost
				status := "ready"
				resolved, err := auth.ResolveProfile(pc)
				if err != nil {
					status = fmt.Sprintf("INVALID (see \"auth profiles show %s\")", pc.Name)
				} else if host == "" {
					host = resolved.Host
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", pc.Name, pc.Type, host, status)
			}
			return w.Flush()
		},
	}
}

func newAuthProfilesShowCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "show <name>",
		Short: "Show one authentication profile's full (secret-free) detail",
		Example: `  scanner auth profiles list         # find a profile name first
  scanner auth profiles show <name>`,
		Args: singleRequiredArg("an authentication profile name",
			"scanner auth profiles list   # to find a profile name first",
			"scanner auth profiles show <name>"),
		RunE: func(cmd *cobra.Command, args []string) error {
			pc, err := auth.FindProfileConfig(authProfileConfigs(a.cfg), args[0])
			if err != nil {
				return &exitCodeErr{code: exitGenericError, err: err}
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Name: %s\n", pc.Name)
			fmt.Fprintf(out, "Type: %s\n", pc.Type)

			profile, resolveErr := auth.ResolveProfile(pc)
			if resolveErr != nil {
				fmt.Fprintf(out, "Status: INVALID -- %v\n", resolveErr)
				return nil
			}
			summary := profile.Redacted()
			fmt.Fprintln(out, "Status: ready")
			fmt.Fprintf(out, "Host: %s\n", summary.Host)
			if summary.LoginURL != "" {
				fmt.Fprintf(out, "Login URL: %s\n", summary.LoginURL)
				fmt.Fprintf(out, "Username field: %s\n", summary.UsernameField)
				fmt.Fprintf(out, "Password field: %s\n", summary.PasswordField)
			}
			fmt.Fprintln(out, "\nCredentials (values never shown):")
			printSecretStatus(out, "Username", summary.HasUsername)
			printSecretStatus(out, "Password", summary.HasPassword)
			printSecretStatus(out, "Token", summary.HasToken)
			printSecretStatus(out, "Cookie", summary.HasCookie)
			if summary.HeaderName != "" {
				printSecretStatus(out, "Header ("+summary.HeaderName+")", summary.HasHeaderValue)
			}
			fmt.Fprintf(out, "\nTimeout: %s\n", summary.Timeout)
			fmt.Fprintf(out, "Max redirects: %d\n", summary.MaxRedirects)
			return nil
		},
	}
}

func printSecretStatus(out io.Writer, label string, has bool) {
	value := "(not configured)"
	if has {
		value = auth.RedactedPlaceholder
	}
	fmt.Fprintf(out, "  %s: %s\n", label, value)
}

// Dynamic completion of a profile NAME (as opposed to the --auth-profile
// FLAG's own name, which cobra completes structurally for free) is
// deliberately NOT implemented here: it would require loading
// config.yaml at completion time, and cobra's `__complete` machinery
// does not run the root command's PersistentPreRunE (which is what
// populates a.cfg) before invoking a ValidArgsFunction/flag completion
// callback -- confirmed empirically, not merely assumed. This mirrors
// Phase 3.11.1's own established precedent of NOT dynamically
// completing scope rule IDs for the analogous reason (would require
// opening the database at completion time); see
// docs/phase-3-11-1-cli-ux.md "Shell completion" and
// docs/phase-3-14-authentication.md "Shell completion" for both.
