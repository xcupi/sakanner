package main

import (
	"bufio"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"sakanner/internal/storage"
	"sakanner/internal/target"
	"sakanner/pkg/models"
)

func newScopeCmd(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scope",
		Short: "Manage authorized scope rules",
		Long: `Manage the scope rules that authorize (or explicitly exclude) targets for active scanning.

sakanner is DEFAULT-DENY: a target must match an "allow" scope rule before
any active request (port scan, HTTP probe, detection) is permitted against
it. A "deny" rule always overrides a matching "allow" rule for the same
target, and an unmatched target is denied by default -- there is no way to
scan something with no matching allow rule.

Rule types (inferred automatically from the value you add, or --exact):
  exact_host     matches one literal host or IP exactly
  domain_suffix  matches a domain and every subdomain of it (the default
                 for a bare domain like example.com; use --exact for
                 exact_host instead)
  cidr           matches every address in an IP range

Subcommands:
  add     authorize (or exclude) a domain, host, IP, or CIDR
  list    show every configured rule, including its ID
  remove  delete a rule by ID, by --value, or interactively`,
	}
	cmd.AddCommand(newScopeAddCmd(a), newScopeListCmd(a), newScopeRemoveCmd(a))
	return cmd
}

func newScopeAddCmd(a *app) *cobra.Command {
	var action, note string
	var exact bool

	cmd := &cobra.Command{
		Use:   "add <value>",
		Short: "Add a scope rule authorizing (or excluding) a domain, host, IP, or CIDR",
		Long: `Add a scope rule.

A domain like example.com defaults to matching itself and all subdomains
(domain_suffix); pass --exact to match only that literal host. IPs are
matched exactly; CIDR ranges (e.g. 203.0.113.0/24) match every address in
the range.

An "allow" rule is required before sakanner will make any active request
against a target -- this is DEFAULT-DENY (see "scanner scope --help"). A
"deny" rule always overrides a matching "allow" rule for the same target,
regardless of which was added first.

Adding a rule identical to one that already exists is allowed: each gets
its own ID and its own independent lifecycle (see
"scanner scope remove --help" for how this affects removal).`,
		Example: `  scanner scope add example.com                          # allow example.com and its subdomains
  scanner scope add --exact example.com                  # allow only example.com itself
  scanner scope add --action deny internal.example.com   # explicitly exclude a subdomain
  scanner scope add 127.0.0.1                             # allow a single IP
  scanner scope add 203.0.113.0/24                        # allow a CIDR range`,
		Args: singleRequiredArg("a value (domain, host, IP, or CIDR)",
			"scanner scope add example.com", "scanner scope add 203.0.113.10"),
		RunE: func(cmd *cobra.Command, args []string) error {
			scopeAction := models.ScopeAction(action)
			if scopeAction != models.ScopeActionAllow && scopeAction != models.ScopeActionDeny {
				return fmt.Errorf("--action must be %q or %q", models.ScopeActionAllow, models.ScopeActionDeny)
			}

			value, targetType, err := target.Parse(args[0])
			if err != nil {
				return err
			}

			var ruleType models.ScopeRuleType
			switch targetType {
			case models.TargetTypeCIDR:
				ruleType = models.ScopeRuleCIDR
			case models.TargetTypeIP:
				ruleType = models.ScopeRuleExactHost
			default: // domain or host
				if exact {
					ruleType = models.ScopeRuleExactHost
				} else {
					ruleType = models.ScopeRuleDomainSuffix
				}
			}

			rule := models.ScopeRule{ID: uuid.NewString(), Value: value, Type: ruleType, Action: scopeAction, Note: note, CreatedAt: time.Now().UTC()}
			if err := a.store.ScopeRules().Create(cmd.Context(), rule); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "added scope rule: %s %s %s id=%s\n", rule.Action, rule.Type, rule.Value, rule.ID)
			return nil
		},
	}
	cmd.Flags().StringVar(&action, "action", string(models.ScopeActionAllow), "allow or deny")
	_ = cmd.RegisterFlagCompletionFunc("action", staticChoiceCompletion(string(models.ScopeActionAllow), string(models.ScopeActionDeny)))
	cmd.Flags().BoolVar(&exact, "exact", false, "match only the literal host, not its subdomains")
	cmd.Flags().StringVar(&note, "note", "", "optional note")
	return cmd
}

func newScopeListCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List scope rules",
		Long: `List every configured scope rule, in the order they were added.

The ID column is the full, unshortened rule ID -- this is what
"scanner scope remove <rule-id>" expects. Deny rules always override a
matching allow rule; an unmatched target is denied by default.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			rules, err := a.store.ScopeRules().List(cmd.Context())
			if err != nil {
				return err
			}
			if len(rules) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "no scope rules configured (default-deny: no target is authorized)")
				return nil
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tACTION\tTYPE\tVALUE\tNOTE")
			for _, r := range rules {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", r.ID, r.Action, r.Type, r.Value, r.Note)
			}
			return w.Flush()
		},
	}
}

func newScopeRemoveCmd(a *app) *cobra.Command {
	var value string

	cmd := &cobra.Command{
		Use:   "remove [rule-id]",
		Short: "Remove a scope rule by ID, by --value, or interactively",
		Long: `Remove exactly one scope rule. Three ways to select which one:

  scanner scope remove <rule-id>     remove the rule with this exact ID
  scanner scope remove --value <v>   remove the rule whose value exactly
                                      matches <v> -- only if exactly one
                                      rule has that value
  scanner scope remove               interactively choose from a numbered
                                      list (only when input is available;
                                      see "Non-interactive use" below)

--value matching is an EXACT match against the value shown in
"scope list"'s VALUE column -- never a partial or pattern match. If more
than one rule shares that value (e.g. an "allow" and a "deny" rule for the
same host), nothing is removed: the matching rules are listed and you must
supply one of their IDs explicitly instead.

Non-interactive use: if no <rule-id> and no --value are given, and no
input is available on stdin (e.g. it's redirected from /dev/null, or a
script piped nothing to it), this command fails immediately with a clear
error instead of hanging.`,
		Example: `  scanner scope remove 1fe4cb6e-1364-48f9-ae1f-9fe3788e4551
  scanner scope remove --value 127.0.0.1
  scanner scope remove`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			switch {
			case len(args) == 1:
				return removeScopeRuleByID(a, cmd, args[0])
			case value != "":
				return removeScopeRuleByValue(a, cmd, value)
			default:
				return removeScopeRuleInteractive(a, cmd)
			}
		},
	}
	cmd.Flags().StringVar(&value, "value", "", "remove the rule whose value exactly matches this (must be unambiguous)")
	return cmd
}

// removeScopeRuleByID is the canonical, unchanged remove path -- task
// section 2. On a nonexistent ID it now returns a clear, distinctly
// exit-coded error instead of the pre-3.11.1 bug where
// scopeRuleRepo.Delete silently succeeded against zero matching rows
// (see internal/storage/sqlite/repos.go and the scope_rules_test.go
// regression test).
func removeScopeRuleByID(a *app, cmd *cobra.Command, id string) error {
	if err := a.store.ScopeRules().Delete(cmd.Context(), id); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return &exitCodeErr{code: exitNotFound, err: fmt.Errorf("scope rule %q not found", id)}
		}
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "removed scope rule %s\n", id)
	return nil
}

// removeScopeRuleByValue implements task section 3: exact matching
// only, never partial/pattern matching. Zero matches is an error;
// exactly one match removes it; more than one match removes NOTHING
// and instead lists every matching rule so the operator can supply an
// explicit ID (task section 11).
func removeScopeRuleByValue(a *app, cmd *cobra.Command, value string) error {
	rules, err := a.store.ScopeRules().List(cmd.Context())
	if err != nil {
		return err
	}
	var matches []models.ScopeRule
	for _, r := range rules {
		if r.Value == value {
			matches = append(matches, r)
		}
	}
	switch len(matches) {
	case 0:
		return &exitCodeErr{code: exitNotFound, err: fmt.Errorf("no scope rule has value %q", value)}
	case 1:
		return removeScopeRuleByID(a, cmd, matches[0].ID)
	default:
		out := cmd.ErrOrStderr()
		fmt.Fprintf(out, "ambiguous: %d scope rules have value %q -- remove by explicit ID instead:\n", len(matches), value)
		w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "  ID\tACTION\tTYPE\tVALUE\tNOTE")
		for _, r := range matches {
			fmt.Fprintf(w, "  %s\t%s\t%s\t%s\t%s\n", r.ID, r.Action, r.Type, r.Value, r.Note)
		}
		w.Flush()
		return fmt.Errorf("ambiguous --value %q matches %d scope rules; run `scanner scope remove <rule-id>` with one of the IDs listed above", value, len(matches))
	}
}

// removeScopeRuleInteractive implements task section 4. It never
// defaults to a destructive choice: an empty line, "q"/"cancel"/"quit",
// or an out-of-range/non-numeric selection all leave every rule
// intact. If stdin has no input available at all (a non-interactive
// environment -- the common case for scripts/CI, where an unset
// exec.Cmd.Stdin reads as immediate EOF), this returns the exact same
// "scope rule ID is required" error as running with no rules to choose
// from, satisfying task section 6 without ever hanging.
func removeScopeRuleInteractive(a *app, cmd *cobra.Command) error {
	rules, err := a.store.ScopeRules().List(cmd.Context())
	if err != nil {
		return err
	}
	if len(rules) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "no scope rules configured")
		return nil
	}

	out := cmd.ErrOrStderr()
	fmt.Fprintln(out, "Select scope rule to remove:")
	for i, r := range rules {
		fmt.Fprintf(out, "  %d. %s %s %s\n", i+1, r.Action, r.Type, r.Value)
	}
	fmt.Fprint(out, "Enter a number (or press Enter/q to cancel): ")

	scanner := bufio.NewScanner(cmd.InOrStdin())
	if !scanner.Scan() {
		return missingScopeRuleIDError()
	}
	line := strings.TrimSpace(scanner.Text())
	if line == "" || strings.EqualFold(line, "q") || strings.EqualFold(line, "cancel") || strings.EqualFold(line, "quit") {
		fmt.Fprintln(out, "cancelled; no rule removed")
		return nil
	}
	n, convErr := strconv.Atoi(line)
	if convErr != nil || n < 1 || n > len(rules) {
		return fmt.Errorf("invalid selection %q; no rule removed", line)
	}
	return removeScopeRuleByID(a, cmd, rules[n-1].ID)
}

// missingScopeRuleIDError is task section 6's improved
// missing-argument message, also reused by the interactive path when
// no input is available at all (see removeScopeRuleInteractive).
func missingScopeRuleIDError() error {
	return fmt.Errorf(`scope rule ID is required

Usage:
  scanner scope remove <rule-id>

Examples:
  scanner scope remove <rule-id>
  scanner scope remove --value <value>`)
}
