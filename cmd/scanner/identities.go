package main

import (
	"fmt"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"sakanner/internal/auth"
	"sakanner/internal/config"
)

// identityConfigs translates every configured config.IdentityConfig
// into internal/auth's own IdentityConfig shape -- field-by-field,
// mirroring authProfileConfigs' exact translation pattern (auth.go).
func identityConfigs(cfg *config.Config) []auth.IdentityConfig {
	out := make([]auth.IdentityConfig, 0, len(cfg.Identities.Identities))
	for _, ic := range cfg.Identities.Identities {
		out = append(out, auth.IdentityConfig{
			Name: ic.Name, AuthProfile: ic.AuthProfile, Disabled: ic.Disabled,
			UsernameEnv: ic.UsernameEnv, PasswordEnv: ic.PasswordEnv, TokenEnv: ic.TokenEnv,
			CookieEnv: ic.CookieEnv, HeaderValueEnv: ic.HeaderValueEnv,
		})
	}
	return out
}

// findIdentityConfig looks up name among the configured identities,
// returning an *auth.UnknownIdentityError (with every configured name,
// sorted) if not found -- mirrors auth.FindProfileConfig's own
// established pattern and error shape.
func findIdentityConfig(cfg *config.Config, name string) (auth.IdentityConfig, error) {
	reg, err := auth.NewIdentityRegistry(identityConfigs(cfg))
	if err != nil {
		// Structurally malformed config (duplicate/empty names) --
		// config.Validate() already prevents this from ever loading in
		// the first place, so this is unreachable via the normal CLI
		// path; guarded defensively rather than assumed.
		return auth.IdentityConfig{}, err
	}
	if ic, ok := reg.Get(name); ok {
		return ic, nil
	}
	return auth.IdentityConfig{}, &auth.UnknownIdentityError{Name: name, Available: reg.Names()}
}

// newIdentitiesCmd implements Phase 3.16's `scanner identities` command
// family -- task section 4's "scanner identities list" / "scanner
// identities show <name>."
func newIdentitiesCmd(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "identities",
		Short: "Inspect configured multi-identity accounts",
		Long: `Inspect sakanner's configured identities.

An Identity is a security principal (e.g. "account-a") that
authenticates using a named authentication profile -- see "scanner
auth profiles list". Two identities may reference the SAME auth
profile (sharing its login mechanism -- URL, field names, success
indicators) while authenticating with completely independent
credentials, by each overriding the profile's own credential
environment variables. See docs/phase-3-16-multi-identity.md "Auth
Profile vs. Identity" for the full model.

Configured under "identities" in your config file. Credentials
themselves are never stored in configuration or shown by this command
-- only which environment variables are referenced.

Subcommands:
  list          show every configured identity in one table
  show <name>   show one identity's full (secret-free) detail

Use "scanner scan <target> --identity <name>" to authenticate as that
identity before scanning.`,
	}
	cmd.AddCommand(newIdentitiesListCmd(a), newIdentitiesShowCmd(a))
	return cmd
}

func newIdentitiesListCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List every configured identity",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			identities := identityConfigs(a.cfg)
			if len(identities) == 0 {
				fmt.Fprintln(out, "no identities configured -- see \"identities\" in your config file")
				return nil
			}
			w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tAUTH PROFILE\tSTATE")
			for _, ic := range identities {
				id := auth.NewIdentity(ic)
				state := string(id.State)
				if id.State == auth.IdentityConfigured {
					if _, err := auth.ResolveIdentityProfile(ic, authProfileConfigs(a.cfg)); err != nil {
						state = fmt.Sprintf("INVALID (see \"identities show %s\")", ic.Name)
					}
				}
				fmt.Fprintf(w, "%s\t%s\t%s\n", ic.Name, ic.AuthProfile, state)
			}
			return w.Flush()
		},
	}
}

func newIdentitiesShowCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "show <name>",
		Short: "Show one identity's full (secret-free) detail",
		Example: `  scanner identities list         # find an identity name first
  scanner identities show <name>`,
		Args: singleRequiredArg("an identity name",
			"scanner identities list   # to find an identity name first",
			"scanner identities show <name>"),
		RunE: func(cmd *cobra.Command, args []string) error {
			ic, err := findIdentityConfig(a.cfg, args[0])
			if err != nil {
				return &exitCodeErr{code: exitGenericError, err: err}
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Name: %s\n", ic.Name)
			fmt.Fprintf(out, "Auth profile: %s\n", ic.AuthProfile)

			id := auth.NewIdentity(ic)
			if id.State == auth.IdentityDisabled {
				fmt.Fprintln(out, "State: IDENTITY_DISABLED")
				return nil
			}

			profile, resolveErr := auth.ResolveIdentityProfile(ic, authProfileConfigs(a.cfg))
			if resolveErr != nil {
				fmt.Fprintf(out, "State: INVALID -- %v\n", resolveErr)
				return nil
			}
			summary := profile.Redacted()
			fmt.Fprintln(out, "State: IDENTITY_CONFIGURED (not yet authenticated)")
			fmt.Fprintf(out, "Host: %s\n", summary.Host)
			if summary.LoginURL != "" {
				fmt.Fprintf(out, "Login URL: %s\n", summary.LoginURL)
			}
			if summary.StartURL != "" {
				fmt.Fprintf(out, "Start URL (discovery): %s\n", summary.StartURL)
			}
			fmt.Fprintln(out, "\nCredentials (values never shown):")
			printSecretStatus(out, "Username", summary.HasUsername)
			printSecretStatus(out, "Password", summary.HasPassword)
			printSecretStatus(out, "Token", summary.HasToken)
			printSecretStatus(out, "Cookie", summary.HasCookie)
			if summary.HeaderName != "" {
				printSecretStatus(out, "Header ("+summary.HeaderName+")", summary.HasHeaderValue)
			}
			return nil
		},
	}
}

// Dynamic completion of an identity NAME is deliberately not
// implemented here, for the exact same reason established for auth
// profile names (auth.go's own doc comment) -- confirmed empirically
// that cobra's __complete does not run the config-loading
// PersistentPreRunE before a completion callback.
