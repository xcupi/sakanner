package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

// singleRequiredArg returns a cobra.PositionalArgs validator for a
// command that takes exactly one required positional argument. On a
// missing or extra argument it produces a clear, actionable error --
// what's missing, the command's own Usage line, at least one worked
// example, and a pointer to --help -- instead of Cobra's generic
// "accepts 1 arg(s), received 0". This generalizes the precedent
// scope.go's missingScopeRuleIDError set in Phase 3.11.1 to every other
// single-required-positional-argument command in this codebase (Phase
// 3.34, task section 3, "Missing-argument UX").
//
// subject names the missing thing the way an operator would ask for it
// ("a scan ID", "a finding ID", ...), not the bare flag/placeholder
// name. examples are full, ready-to-adapt command lines (no leading
// indentation, no trailing comment needed).
func singleRequiredArg(subject string, examples ...string) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		switch len(args) {
		case 1:
			return nil
		case 0:
			return missingArgError(cmd, subject, examples)
		default:
			return fmt.Errorf("%s accepts exactly one argument (%s), received %d\n\nUsage:\n  %s\n\nRun '%s --help' for more information.",
				cmd.CommandPath(), subject, len(args), cmd.UseLine(), cmd.CommandPath())
		}
	}
}

// missingArgError formats the standard "X is required" error shared by
// every missing-positional-argument and missing-required-flag case in
// this CLI -- Usage line, optional Examples, and a pointer to --help.
func missingArgError(cmd *cobra.Command, subject string, examples []string) error {
	var b strings.Builder
	fmt.Fprintf(&b, "%s is required\n\nUsage:\n  %s", subject, cmd.UseLine())
	if len(examples) > 0 {
		b.WriteString("\n\nExamples:\n")
		for _, e := range examples {
			fmt.Fprintf(&b, "  %s\n", e)
		}
		// Trim the trailing newline the loop above leaves, so the "Run
		// ... --help" line below is separated by exactly one blank line
		// like the Usage block above it, not two.
		trimmed := strings.TrimSuffix(b.String(), "\n")
		b.Reset()
		b.WriteString(trimmed)
	}
	fmt.Fprintf(&b, "\n\nRun '%s --help' for more information.", cmd.CommandPath())
	return fmt.Errorf("%s", b.String())
}

// requiredFlagError is missingArgError's counterpart for a missing
// required --flag (findings/chains/report all gate on --scan today).
// subject should name the flag the way an operator would ask for it,
// e.g. "--scan".
func requiredFlagError(cmd *cobra.Command, subject string, examples ...string) error {
	return missingArgError(cmd, subject, examples)
}

// staticChoiceCompletion returns a cobra completion func for a flag or
// positional argument whose valid values are a small, fixed, in-memory
// set known entirely at compile time (a severity name, a chain status,
// ...). Phase 3.11.1 established that dynamic completion of anything
// requiring config/database access is deliberately NOT implemented
// (cobra's __complete machinery never runs the root command's
// PersistentPreRunE first -- see auth.go's doc comment); this is the
// other, safe half of that same rule: a closed, static enum performs
// no I/O at all, so completing it weakens nothing. Never used for
// free-form or sensitive values (targets, URLs, secrets) -- see
// docs/phase-3-11-1-cli-ux.md "Shell completion".
func staticChoiceCompletion(choices ...string) func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	return func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		var out []string
		for _, c := range choices {
			if strings.HasPrefix(c, toComplete) {
				out = append(out, c)
			}
		}
		return out, cobra.ShellCompDirectiveNoFileComp
	}
}

// detectorIDCompletion completes a detector ID (e.g. --detector on
// "scanner findings") against the SAME static, zero-I/O
// productionRegistry() every "scanner detectors list" invocation
// builds -- no config or database access, exactly like
// profileNameCompletion's own precedent (profiles.go).
func detectorIDCompletion(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	entries := productionRegistry().List()
	ids := make([]string, 0, len(entries))
	for _, e := range entries {
		ids = append(ids, e.Metadata.ID)
	}
	return staticChoiceCompletion(ids...)(cmd, args, toComplete)
}
