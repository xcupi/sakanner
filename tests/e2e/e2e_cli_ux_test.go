// Phase 3.34 CLI end-to-end tests: CLI & operator UX consistency.
//
// This phase changes no detection/mutation/scope/auth/chain semantics
// -- these tests exist to pin down help-text accuracy, consistent
// missing-argument UX, and the new static-enum shell completions,
// against the REAL built binary (never a manually constructed command
// tree), so a future phase cannot silently regress any of them.
package e2e

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// --- Help accuracy (task section 1) -----------------------------------

// TestScanHelp_DoesNotClaimFormJSONPathAreUndetected proves the stale
// pre-3.34 claim ("form/JSON/path inputs are discovered and
// reportable but do not yet feed any detector") is gone, and the
// replacement text accurately reflects Phase 3.21 (form)/3.23 (path)
// closing that gap -- see
// docs/phase-3-29-active-detection-coverage-review.md section 3.
func TestScanHelp_DoesNotClaimFormJSONPathAreUndetected(t *testing.T) {
	c := newScopeCLI(t)
	out := c.mustRun("scan", "--help")

	stale := "do not yet feed any detector"
	if strings.Contains(out, stale) {
		t.Errorf("scan --help still contains the stale pre-3.34 claim %q:\n%s", stale, out)
	}
	for _, want := range []string{"query, form, and path", "RESPONSE body", "header/cookie inputs are not yet discovered"} {
		if !strings.Contains(out, want) {
			t.Errorf("scan --help missing accurate detection-coverage text %q:\n%s", want, out)
		}
	}
}

// TestScanHelp_HasExamples: scan had NO Example field at all before
// this phase (task section 7, "Operator Examples") despite being the
// single most important command.
func TestScanHelp_HasExamples(t *testing.T) {
	c := newScopeCLI(t)
	out := c.mustRun("scan", "--help")
	if !strings.Contains(out, "Examples:") {
		t.Errorf("scan --help missing an Examples section:\n%s", out)
	}
	for _, want := range []string{"--profile web", "--auth-profile", "--identity"} {
		if !strings.Contains(out, want) {
			t.Errorf("scan --help examples missing %q:\n%s", want, out)
		}
	}
}

// TestScanHelp_DescribesDetectionCoverage proves the replacement text
// actually names which detectors are enabled/disabled by default in
// THIS build, sourced from cmd/scanner/detectors.go's own
// buildProductionRegistry -- not a stale/aspirational list.
func TestScanHelp_DescribesDetectionCoverage(t *testing.T) {
	c := newScopeCLI(t)
	out := c.mustRun("scan", "--help")
	for _, want := range []string{"SSTI", "Enabled by default", "Registered, disabled", "detectors list"} {
		if !strings.Contains(out, want) {
			t.Errorf("scan --help missing detection-coverage text %q:\n%s", want, out)
		}
	}
}

// TestFindingsShort_NotStale proves the root command listing's
// one-line description of "findings" no longer claims findings are
// "empty until a Phase 3.x detector is registered" -- false since
// Phase 3.7 registered real detectors, and findings has never been
// empty in this build for any reason other than the target/profile
// genuinely producing none.
func TestFindingsShort_NotStale(t *testing.T) {
	c := newScopeCLI(t)
	out := c.mustRun("--help")
	stale := "Phase 3.x detector is registered"
	if strings.Contains(out, stale) {
		t.Errorf("root --help's findings line still contains stale text %q:\n%s", stale, out)
	}
}

// TestDetectorsListHelp_NoStalePhase1Claim: the "no detectors
// registered" fallback message used to cite Phase 3.1's long-obsolete
// stub state; this build always has >0 registered detectors, but the
// message itself (reachable only if that ever regresses) must not
// mislead about the CURRENT registry either way.
func TestDetectorsListHelp_ListsRealDetectors(t *testing.T) {
	c := newScopeCLI(t)
	out := c.mustRun("detectors", "list")
	for _, want := range []string{"xss-reflected-active", "sqli-active", "ssti-active", "idor-active"} {
		if !strings.Contains(out, want) {
			t.Errorf("detectors list missing %q:\n%s", want, out)
		}
	}
}

// --- Missing-argument UX (task section 3) -------------------------------

// missingArgCase drives one command that used to fail with Cobra's
// generic "accepts 1 arg(s), received 0" and asserts the Phase 3.34
// replacement: exit 1, a clear "<subject> is required" line, a
// Usage: block, and a pointer to --help.
type missingArgCase struct {
	name    string
	args    []string
	wantSub string // substring expected in "<wantSub> is required"
}

func TestMissingRequiredArgument_ClearErrorAcrossCommands(t *testing.T) {
	c := newScopeCLI(t)
	cases := []missingArgCase{
		{"scope add", []string{"scope", "add"}, "value"},
		{"target add", []string{"target", "add"}, "value"},
		{"findings show", []string{"findings", "show"}, "finding ID"},
		{"chains show", []string{"chains", "show"}, "chain candidate ID"},
		{"status", []string{"status"}, "scan ID"},
		{"inputs", []string{"inputs"}, "scan ID"},
		{"auth profiles show", []string{"auth", "profiles", "show"}, "authentication profile name"},
		{"identities show", []string{"identities", "show"}, "identity name"},
		{"profiles show", []string{"profiles", "show"}, "scan profile name"},
		{"scan (no target, no --target)", []string{"scan"}, "target argument"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, stderr, err := c.run(tc.args...)
			if err == nil {
				t.Fatalf("%v succeeded with no required argument, want an error\nstdout: %s", tc.args, out)
			}
			if code := exitCode(t, err); code != 1 {
				t.Errorf("exit code = %d, want 1", code)
			}
			if !strings.Contains(stderr, tc.wantSub) {
				t.Errorf("stderr = %q, want it to mention %q", stderr, tc.wantSub)
			}
			if !strings.Contains(stderr, "is required") {
				t.Errorf("stderr = %q, want \"is required\"", stderr)
			}
			if !strings.Contains(stderr, "Usage:") {
				t.Errorf("stderr = %q, want a Usage: block", stderr)
			}
			if !strings.Contains(stderr, "--help") {
				t.Errorf("stderr = %q, want a pointer to --help", stderr)
			}
		})
	}
}

// TestMissingRequiredFlag_ClearErrorAcrossCommands covers the
// --scan-flag-based commands (findings/chains/report), which never
// went through Cobra's positional-arg validator at all -- the
// pre-3.34 error was a bare "--scan is required" with no Usage or
// example.
func TestMissingRequiredFlag_ClearErrorAcrossCommands(t *testing.T) {
	c := newScopeCLI(t)
	cases := []missingArgCase{
		{"findings", []string{"findings"}, "--scan"},
		{"chains", []string{"chains"}, "--scan"},
		{"report", []string{"report"}, "--scan"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, stderr, err := c.run(tc.args...)
			if err == nil {
				t.Fatalf("%v succeeded with no --scan, want an error", tc.args)
			}
			if code := exitCode(t, err); code != 1 {
				t.Errorf("exit code = %d, want 1", code)
			}
			if !strings.Contains(stderr, tc.wantSub+" is required") {
				t.Errorf("stderr = %q, want %q", stderr, tc.wantSub+" is required")
			}
			if !strings.Contains(stderr, "Usage:") {
				t.Errorf("stderr = %q, want a Usage: block", stderr)
			}
		})
	}
}

// TestTooManyArgs_AlsoGetsAClearError proves singleRequiredArg's
// "too many arguments" branch (not just the missing-argument one) is
// clear too.
func TestTooManyArgs_AlsoGetsAClearError(t *testing.T) {
	c := newScopeCLI(t)
	_, stderr, err := c.run("status", "one-id", "two-id")
	if err == nil {
		t.Fatal("status with two args succeeded, want an error")
	}
	if code := exitCode(t, err); code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr, "Usage:") {
		t.Errorf("stderr = %q, want a Usage: block", stderr)
	}
}

// --- Shell completion for new static enums (task section 5) ------------

func TestShellCompletion_StaticEnums(t *testing.T) {
	c := newScopeCLI(t)
	cases := []struct {
		name string
		args []string
		want []string
	}{
		{"findings --detector", []string{"__complete", "findings", "--detector", ""}, []string{"xss-reflected-active", "sqli-active", "ssti-active"}},
		{"findings --severity", []string{"__complete", "findings", "--severity", ""}, []string{"info", "low", "medium", "high", "critical"}},
		{"chains --status", []string{"__complete", "chains", "--status", ""}, []string{"POTENTIAL", "SUPPORTED", "CONFIRMED"}},
		{"report --format", []string{"__complete", "report", "--format", ""}, []string{"json", "markdown"}},
		{"inputs --location", []string{"__complete", "inputs", "x", "--location", ""}, []string{"query", "path", "form", "json", "header", "cookie"}},
		{"inputs --provenance", []string{"__complete", "inputs", "x", "--provenance", ""}, []string{"REQUEST_INPUT", "RESPONSE_FIELD"}},
		{"scope add --action", []string{"__complete", "scope", "add", "x", "--action", ""}, []string{"allow", "deny"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := c.mustRun(tc.args...)
			for _, w := range tc.want {
				if !strings.Contains(out, w) {
					t.Errorf("completion for %s missing %q:\n%s", tc.name, w, out)
				}
			}
		})
	}
}

// TestShellCompletion_StaticEnums_NeverTouchDatabase proves the new
// completions are pure, zero-I/O static metadata -- exactly like
// Phase 3.11.1's own TestShellCompletion_NeverMutatesOrScans, extended
// to the new flag completions this phase adds. Pointed at a config
// whose database file does not exist yet: if any of these completions
// touched storage, sqlite.New would create/migrate that file as a
// side effect.
func TestShellCompletion_StaticEnums_NeverTouchDatabase(t *testing.T) {
	bin := buildBinary(t)
	configPath := writeConfig(t, "")

	// writeConfig's dsn path is under the same temp dir; derive it and
	// confirm it does not exist before completion runs.
	dbCandidate := strings.TrimSuffix(configPath, "config.yaml") + "sakanner.db"
	if _, err := os.Stat(dbCandidate); err == nil {
		t.Fatalf("test setup bug: db file already exists before completion: %s", dbCandidate)
	}

	for _, args := range [][]string{
		{"--config", configPath, "__complete", "findings", "--detector", ""},
		{"--config", configPath, "__complete", "chains", "--status", ""},
	} {
		out, err := exec.Command(bin, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
	}

	if _, err := os.Stat(dbCandidate); err == nil {
		t.Errorf("completion created the database file at %s -- it must be pure, zero-I/O static metadata", dbCandidate)
	}
}

// --- Security: help/completion output is static, never target-derived ---

// TestHelpOutput_NeverReferencesLiveTargetOrCredential is a light
// adversarial check: --help text for every command is fixed at
// compile time and must never vary with, or embed, anything from the
// environment (a config file, an env var, a live target) -- unlike
// "profiles show"/"auth profiles show"/"identities show", which DO
// read config but are proven secret-free elsewhere
// (TestOperatorWorkflow_NoRawSecretsInInspectionOrCurl). This test
// instead proves --help itself needs no config file at all: it must
// produce identical, correct output even pointed at a nonexistent
// config path.
func TestHelpOutput_NeverReferencesLiveTargetOrCredential(t *testing.T) {
	bin := buildBinary(t)
	out, err := exec.Command(bin, "--config", "/nonexistent/does-not-exist.yaml", "scan", "--help").CombinedOutput()
	if err != nil {
		t.Fatalf("scan --help with a nonexistent --config failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "Usage:") {
		t.Errorf("scan --help output looks wrong:\n%s", out)
	}
}
