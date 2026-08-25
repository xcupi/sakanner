package main

import (
	"fmt"
	"io"
	"net/url"
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
			LoginURL: pc.LoginURL, StartURL: pc.StartURL, UsernameEnv: pc.UsernameEnv, PasswordEnv: pc.PasswordEnv,
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

A "form_login_auto" profile skips login_url/username_field/password_field
entirely: give it a start_url (any reachable same-origin page, not
necessarily the login page) plus credentials, and sakanner discovers
the actual login page/form/field names itself -- see "scanner auth
discover --help" to preview what discovery finds before configuring
anything.

Subcommands:
  discover <start-url>   preview (or perform) automatic login-form discovery
  profiles list           show every configured profile in one table
  profiles show <name>    show one profile's full (secret-free) detail

Use "scanner scan <target> --auth-profile <name>" to authenticate
before scanning.`,
	}
	cmd.AddCommand(newAuthDiscoverCmd(a), newAuthProfilesCmd(a))
	return cmd
}

// newAuthDiscoverCmd implements Phase 3.36's `scanner auth discover
// <start-url>` -- a standalone way to preview (or, with credentials,
// actually perform) automatic login-form discovery without first
// writing a form_login_auto profile into config. Strictly read-only
// with respect to sakanner's OWN persistent state: it never creates a
// scan job, never writes to storage, and (in preview mode, the
// default) never submits a credential anywhere -- it only ever reads
// the currently-configured scope rules (to scope-check the target,
// exactly like any other authentication attempt) and performs the
// same bounded, same-origin HTTP fetches internal/auth.DiscoverOnly
// itself is documented to make.
func newAuthDiscoverCmd(a *app) *cobra.Command {
	var usernameEnv, passwordEnv string
	cmd := &cobra.Command{
		Use:   "discover <start-url>",
		Short: "Preview (or perform) automatic login-form discovery against a target",
		Long: `Preview -- or, with credentials, actually perform -- sakanner's
automatic login-form discovery (the same mechanism a "form_login_auto"
authentication profile uses at scan time).

<start-url> is any reachable, same-origin page on the target
application (an absolute http(s) URL) -- not necessarily the exact
login page; discovery looks there first, then follows a bounded
number of same-origin "login-like" links if the start page itself has
no password field.

With no --username-env/--password-env, this command ONLY discovers
and reports what it found -- no credential is read, no form is ever
submitted, nothing is authenticated. This is the safe way to check
what discovery would find before writing a form_login_auto profile,
or against an application you're not yet sure has a conventional
login form at all.

With BOTH --username-env and --password-env given, this command also
attempts one real login using the discovered form -- exactly what a
"scan --identity <name>" would do for a form_login_auto profile
pointed at the same start_url -- and reports whether it succeeded.
Never prints credential values.

An "allow" scope rule for the target is still required -- see
"scanner scope --help".`,
		Example: `  scanner auth discover http://203.0.113.10/                          # preview only
  export SAKANNER_USERNAME=myuser
  export SAKANNER_PASSWORD=mypassword
  scanner auth discover http://203.0.113.10/ --username-env SAKANNER_USERNAME --password-env SAKANNER_PASSWORD`,
		Args: singleRequiredArg("a start URL",
			"scanner auth discover http://203.0.113.10/"),
		RunE: func(cmd *cobra.Command, args []string) error {
			if (usernameEnv == "") != (passwordEnv == "") {
				return &exitCodeErr{code: exitGenericError, err: fmt.Errorf("--username-env and --password-env must both be given, or neither (for a discovery-only preview)")}
			}
			startURL, err := url.Parse(args[0])
			if err != nil || startURL.Scheme == "" || startURL.Host == "" || (startURL.Scheme != "http" && startURL.Scheme != "https") {
				return &exitCodeErr{code: exitGenericError, err: fmt.Errorf("%q is not a valid absolute http(s) URL", args[0])}
			}
			deps, err := buildAuthDependencies(cmd, a)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()

			if usernameEnv == "" {
				fmt.Fprintf(out, "Discovering a login form starting from %s (preview only -- no credentials submitted)...\n", startURL)
				result, discErr := auth.DiscoverOnly(cmd.Context(), deps, startURL, 0, 0)
				if discErr != nil {
					return &exitCodeErr{code: exitAuthFailed, err: fmt.Errorf("discovery failed: %w", discErr)}
				}
				printDiscoveryResult(out, result)
				return nil
			}

			pc := auth.ProfileConfig{Name: "auth-discover", Type: auth.TypeFormLoginAuto, StartURL: startURL.String(), UsernameEnv: usernameEnv, PasswordEnv: passwordEnv}
			profile, resolveErr := auth.ResolveProfile(pc)
			if resolveErr != nil {
				return &exitCodeErr{code: exitAuthFailed, err: resolveErr}
			}
			provider, err := auth.NewProvider(profile)
			if err != nil {
				return &exitCodeErr{code: exitAuthFailed, err: err}
			}
			fmt.Fprintf(out, "Discovering a login form and authenticating, starting from %s...\n", startURL)
			sess, authErr := provider.Authenticate(cmd.Context(), deps)
			if authErr != nil {
				fmt.Fprintf(out, "Authentication FAILED: %v\n", authErr)
				return &exitCodeErr{code: exitAuthFailed, err: authErr}
			}
			fmt.Fprintln(out, "Authentication succeeded.")
			if sess.LoginURL != nil {
				fmt.Fprintf(out, "Discovered login URL: %s\n", sess.LoginURL)
			}
			summary := sess.Redacted()
			fmt.Fprintf(out, "Session cookies established: %d\n", summary.CookieCount)
			return nil
		},
	}
	cmd.Flags().StringVar(&usernameEnv, "username-env", "", "environment variable holding the username -- with --password-env, also attempts a real login; omit both for a discovery-only preview")
	cmd.Flags().StringVar(&passwordEnv, "password-env", "", "environment variable holding the password (see --username-env)")
	return cmd
}

func printDiscoveryResult(out io.Writer, result auth.DiscoveryResult) {
	fmt.Fprintln(out, "Login form discovered:")
	fmt.Fprintf(out, "  Login URL:      %s\n", result.LoginURL)
	fmt.Fprintf(out, "  Method:         %s\n", result.Method)
	fmt.Fprintf(out, "  Username field: %s\n", result.UsernameField)
	fmt.Fprintf(out, "  Password field: %s\n", result.PasswordField)
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
			if summary.StartURL != "" {
				fmt.Fprintf(out, "Start URL (discovery): %s\n", summary.StartURL)
				fmt.Fprintln(out, "Login page/form/fields: discovered automatically at authenticate time -- see \"scanner auth discover\" to preview this without authenticating")
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
