package main

// Exit codes. Every command not explicitly listed below keeps
// main.go's original, unchanged behavior: any error exits 1. These
// codes are additive, not a redefinition of the existing convention --
// see docs/phase-3-11-1-cli-ux.md "Exit codes" for the full table.
//
//	0  success (a completed scan -- COMPLETED or COMPLETED_WITH_WARNINGS
//	   -- or any other command that finished without error)
//	1  invalid arguments / a generic, otherwise-uncategorized error
//	   (e.g. no target supplied at all, a storage/config error, a
//	   missing --value with no rules to select from interactively)
//	2  scope violation / scan failure (the scan reached a terminal
//	   FAILED status: invalid target, out-of-scope target, or an
//	   internal stage failure)
//	3  cancelled (operator interrupt, or a configured timeout elapsed)
//	4  not found (Phase 3.11.1: `scope remove <id>` / `--value <v>`
//	   found no matching scope rule -- distinct from a generic
//	   argument error so scripts can tell "nothing to remove" apart
//	   from "you used the command wrong")
//	5  authentication failed (Phase 3.14: `scan --auth-profile <name>`
//	   where the named profile is invalid/misconfigured, or a valid
//	   profile's login attempt did not succeed -- distinct from
//	   exitScanFailed because NO scan job is ever created for this
//	   case, task section 12's "fail before network activity, create
//	   no scan job")
const (
	exitOK            = 0
	exitGenericError  = 1
	exitScanFailed    = 2
	exitScanCancelled = 3
	exitNotFound      = 4
	exitAuthFailed    = 5
)

// exitCodeErr wraps an error with the specific process exit code
// main.go should use for it -- returned by newScanCmd's target-string
// path (exitScanFailed/exitScanCancelled/exitGenericError for an
// invalid --profile), newScopeRemoveCmd (exitNotFound), and
// newProfilesShowCmd (exitGenericError for an unknown profile name);
// every other command's plain errors keep main.go's original exit(1)
// behavior untouched.
type exitCodeErr struct {
	code int
	err  error
}

func (e *exitCodeErr) Error() string { return e.err.Error() }
func (e *exitCodeErr) Unwrap() error { return e.err }
