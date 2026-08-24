// Phase 3.11.1 CLI end-to-end test: drives the built scanner binary
// through the improved `scanner scope` commands -- remove by ID, by
// --value, interactively, help text, exit codes, persistence,
// concurrency, special characters, and the default-deny/allow/deny
// scope-enforcement regression suite (task sections 1-30).
package e2e

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// runWithStdin is like cli.run but feeds stdin -- used for the
// interactive `scope remove` path (task section 4).
func (c *cli) runWithStdin(stdin string, args ...string) (stdout, stderr string, err error) {
	c.t.Helper()
	fullArgs := append([]string{"--config", c.config}, args...)
	cmd := exec.Command(c.bin, fullArgs...)
	cmd.Stdin = strings.NewReader(stdin)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err = cmd.Run()
	return outBuf.String(), errBuf.String(), err
}

var ruleIDRe = regexp.MustCompile(`id=([0-9a-f-]{36})`)

func extractRuleID(t *testing.T, addOutput string) string {
	t.Helper()
	m := ruleIDRe.FindStringSubmatch(addOutput)
	if m == nil {
		t.Fatalf("could not find id= in scope add output: %q", addOutput)
	}
	return m[1]
}

func newScopeCLI(t *testing.T) *cli {
	t.Helper()
	bin := buildBinary(t)
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	dbPath := filepath.Join(dir, "sakanner.db")
	if err := os.WriteFile(configPath, []byte(fmt.Sprintf("storage:\n  dsn: %s\n", dbPath)), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return newCLI(t, bin, configPath)
}

// newScopeCLIAllowReserved is newScopeCLI plus
// scope.allow_reserved_ranges: true -- needed for any regression test
// that scans 127.0.0.1, since the built-in reserved-range deny-list
// (loopback/link-local/metadata/etc.) blocks it regardless of any
// explicit allow rule otherwise, unchanged from every prior phase's
// behavior (see internal/scope). This is a TEST fixture choice, never
// a product-level relaxation of default-deny.
func newScopeCLIAllowReserved(t *testing.T) *cli {
	t.Helper()
	bin := buildBinary(t)
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	dbPath := filepath.Join(dir, "sakanner.db")
	if err := os.WriteFile(configPath, []byte(fmt.Sprintf("storage:\n  dsn: %s\nscope:\n  allow_reserved_ranges: true\n", dbPath)), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return newCLI(t, bin, configPath)
}

// --- Remove by ID (task section 2, test matrix 1-4) -----------------------

func TestScopeRemove_ByID_Valid(t *testing.T) {
	c := newScopeCLI(t)
	id := extractRuleID(t, c.mustRun("scope", "add", "example.com"))

	out := c.mustRun("scope", "remove", id)
	if !strings.Contains(out, "removed scope rule "+id) {
		t.Errorf("output = %q, want confirmation mentioning %s", out, id)
	}
	list := c.mustRun("scope", "list")
	if strings.Contains(list, id) {
		t.Errorf("rule %s still present after removal:\n%s", id, list)
	}
}

func TestScopeRemove_ByID_Invalid(t *testing.T) {
	c := newScopeCLI(t)
	c.mustRun("scope", "add", "example.com") // one real rule, to prove it survives

	for _, id := range []string{
		"?", "missing-id", "00000000-0000-0000-0000-000000000000",
		"1fe4cb6e-1364-48f9-ae1f-9fe3788e4551", // a plausible-looking but never-added UUID
		"not-a-uuid-at-all",
	} {
		out, stderr, err := c.run("scope", "remove", id)
		if err == nil {
			t.Errorf("id %q: scope remove succeeded, want an error", id)
		}
		if code := exitCode(t, err); code != 4 {
			t.Errorf("id %q: exit code = %d, want 4 (not found)", id, code)
		}
		if strings.Contains(out, "removed scope rule") {
			t.Errorf("id %q: output claims removal despite no matching rule: %q", id, out)
		}
		if !strings.Contains(stderr, "not found") {
			t.Errorf("id %q: stderr = %q, want it to mention \"not found\"", id, stderr)
		}
	}

	// The one real rule must have survived every nonexistent-ID attempt.
	list := c.mustRun("scope", "list")
	if !strings.Contains(list, "example.com") {
		t.Errorf("real rule was lost after nonexistent-ID removal attempts:\n%s", list)
	}
}

func TestScopeRemove_ByID_MalformedUUID(t *testing.T) {
	c := newScopeCLI(t)
	_, _, err := c.run("scope", "remove", "not-even-uuid-shaped-!!!")
	if err == nil {
		t.Fatal("scope remove with a malformed ID succeeded, want an error")
	}
	if code := exitCode(t, err); code != 4 {
		t.Errorf("exit code = %d, want 4", code)
	}
}

func TestScopeRemove_ByID_EmptyStringArgument(t *testing.T) {
	// `scope remove ""` (an explicit empty-string arg) is 1 positional
	// arg, not 0 -- must be treated as "not found," never as the
	// missing-argument/interactive path.
	c := newScopeCLI(t)
	_, stderr, err := c.run("scope", "remove", "")
	if err == nil {
		t.Fatal("scope remove \"\" succeeded, want an error")
	}
	if code := exitCode(t, err); code != 4 {
		t.Errorf("exit code = %d, want 4", code)
	}
	if !strings.Contains(stderr, "not found") {
		t.Errorf("stderr = %q, want \"not found\"", stderr)
	}
}

// --- Missing argument UX (task section 6, test matrix 4) -------------------

func TestScopeRemove_MissingArgument_NonInteractive(t *testing.T) {
	c := newScopeCLI(t)
	c.mustRun("scope", "add", "example.com")

	// No id, no --value, and (via runWithStdin("")) stdin reads as
	// immediate EOF -- simulating a script/CI environment, never a real
	// terminal. Must fail clearly and immediately, never hang.
	out, stderr, err := c.runWithStdin("", "scope", "remove")
	if err == nil {
		t.Fatalf("scope remove with no id/--value/stdin succeeded, want an error\nstdout: %s", out)
	}
	if code := exitCode(t, err); code != 1 {
		t.Errorf("exit code = %d, want 1 (generic/invalid-arguments)", code)
	}
	if !strings.Contains(stderr, "scope rule ID is required") {
		t.Errorf("stderr = %q, want it to mention \"scope rule ID is required\"", stderr)
	}
	if !strings.Contains(stderr, "Usage:") {
		t.Errorf("stderr = %q, want a Usage: block", stderr)
	}

	// The rule must have survived.
	list := c.mustRun("scope", "list")
	if !strings.Contains(list, "example.com") {
		t.Errorf("rule lost after a missing-argument attempt:\n%s", list)
	}
}

func TestScopeRemove_NoRulesAtAll_NonInteractive(t *testing.T) {
	c := newScopeCLI(t)
	out, _, err := c.runWithStdin("", "scope", "remove")
	if err != nil {
		t.Fatalf("scope remove with zero rules configured should not itself be an error: %v\nstdout: %s", out, out)
	}
	if !strings.Contains(out, "no scope rules configured") {
		t.Errorf("output = %q, want it to say no scope rules are configured", out)
	}
}

// --- Remove by value (task section 3, test matrix 5-8) ---------------------

func TestScopeRemove_ByValue_NoMatch(t *testing.T) {
	c := newScopeCLI(t)
	c.mustRun("scope", "add", "example.com")

	_, stderr, err := c.run("scope", "remove", "--value", "nonexistent.example.test")
	if err == nil {
		t.Fatal("scope remove --value with no match succeeded, want an error")
	}
	if code := exitCode(t, err); code != 4 {
		t.Errorf("exit code = %d, want 4 (not found)", code)
	}
	if !strings.Contains(stderr, "no scope rule has value") {
		t.Errorf("stderr = %q", stderr)
	}
}

func TestScopeRemove_ByValue_SingleMatch(t *testing.T) {
	c := newScopeCLI(t)
	id := extractRuleID(t, c.mustRun("scope", "add", "127.0.0.1"))

	out := c.mustRun("scope", "remove", "--value", "127.0.0.1")
	if !strings.Contains(out, "removed scope rule "+id) {
		t.Errorf("output = %q, want confirmation for %s", out, id)
	}
	list := c.mustRun("scope", "list")
	if strings.Contains(list, "127.0.0.1") {
		t.Errorf("value still present after --value removal:\n%s", list)
	}
}

func TestScopeRemove_ByValue_MultipleMatches_Ambiguous(t *testing.T) {
	c := newScopeCLI(t)
	allowID := extractRuleID(t, c.mustRun("scope", "add", "example.com"))
	denyID := extractRuleID(t, c.mustRun("scope", "add", "--action", "deny", "example.com"))

	out, stderr, err := c.run("scope", "remove", "--value", "example.com")
	if err == nil {
		t.Fatalf("scope remove --value with 2 matches succeeded, want an error\nstdout: %s", out)
	}
	if code := exitCode(t, err); code != 1 {
		t.Errorf("exit code = %d, want 1 (ambiguous is a usage error, not a not-found)", code)
	}
	if !strings.Contains(stderr, "ambiguous") {
		t.Errorf("stderr = %q, want it to say \"ambiguous\"", stderr)
	}
	if !strings.Contains(stderr, allowID) || !strings.Contains(stderr, denyID) {
		t.Errorf("stderr = %q, want both matching rule IDs listed", stderr)
	}

	// Task section 11: NEITHER rule may be removed.
	list := c.mustRun("scope", "list")
	if !strings.Contains(list, allowID) || !strings.Contains(list, denyID) {
		t.Errorf("one or both ambiguous rules were removed:\n%s", list)
	}
}

// --- Interactive remove (task section 4, test matrix 9-10) -----------------

func TestScopeRemove_Interactive_ValidSelection(t *testing.T) {
	c := newScopeCLI(t)
	id1 := extractRuleID(t, c.mustRun("scope", "add", "example.com"))
	id2 := extractRuleID(t, c.mustRun("scope", "add", "other.example.test"))

	out, _, err := c.runWithStdin("1\n", "scope", "remove")
	if err != nil {
		t.Fatalf("interactive remove with a valid selection failed: %v\noutput: %s", err, out)
	}
	if !strings.Contains(out, "removed scope rule "+id1) {
		t.Errorf("output = %q, want confirmation for rule 1 (%s)", out, id1)
	}
	list := c.mustRun("scope", "list")
	if strings.Contains(list, id1) {
		t.Errorf("selected rule still present:\n%s", list)
	}
	if !strings.Contains(list, id2) {
		t.Errorf("unselected rule was removed too:\n%s", list)
	}
}

func TestScopeRemove_Interactive_CancelViaEmptyLine(t *testing.T) {
	c := newScopeCLI(t)
	id := extractRuleID(t, c.mustRun("scope", "add", "example.com"))

	out, stderr, err := c.runWithStdin("\n", "scope", "remove")
	if err != nil {
		t.Fatalf("cancelling interactively should not be an error: %v\noutput: %s", err, out)
	}
	// The prompt and cancellation message are UI chrome, not the
	// command's "result" -- deliberately written to stderr so stdout
	// stays clean for scripts/pipes (task section 16).
	if !strings.Contains(stderr, "cancelled") {
		t.Errorf("stderr = %q, want a cancellation message", stderr)
	}
	list := c.mustRun("scope", "list")
	if !strings.Contains(list, id) {
		t.Errorf("rule was removed despite cancellation:\n%s", list)
	}
}

func TestScopeRemove_Interactive_CancelViaQ(t *testing.T) {
	c := newScopeCLI(t)
	id := extractRuleID(t, c.mustRun("scope", "add", "example.com"))

	c.runWithStdin("q\n", "scope", "remove")
	list := c.mustRun("scope", "list")
	if !strings.Contains(list, id) {
		t.Errorf("rule was removed despite 'q' cancellation:\n%s", list)
	}
}

func TestScopeRemove_Interactive_InvalidSelection(t *testing.T) {
	c := newScopeCLI(t)
	id := extractRuleID(t, c.mustRun("scope", "add", "example.com"))

	_, stderr, err := c.runWithStdin("99\n", "scope", "remove")
	if err == nil {
		t.Fatal("interactive remove with an out-of-range selection succeeded, want an error")
	}
	if !strings.Contains(stderr, "invalid selection") {
		t.Errorf("stderr = %q, want \"invalid selection\"", stderr)
	}
	list := c.mustRun("scope", "list")
	if !strings.Contains(list, id) {
		t.Errorf("rule was removed despite an invalid selection:\n%s", list)
	}
}

func TestScopeRemove_Interactive_NonNumericSelection(t *testing.T) {
	c := newScopeCLI(t)
	id := extractRuleID(t, c.mustRun("scope", "add", "example.com"))

	_, _, err := c.runWithStdin("banana\n", "scope", "remove")
	if err == nil {
		t.Fatal("interactive remove with a non-numeric selection succeeded, want an error")
	}
	list := c.mustRun("scope", "list")
	if !strings.Contains(list, id) {
		t.Errorf("rule was removed despite a non-numeric selection:\n%s", list)
	}
}

// --- Duplicate rules (task section 9) ---------------------------------------

func TestScopeAdd_DuplicatesAllowed(t *testing.T) {
	c := newScopeCLI(t)
	id1 := extractRuleID(t, c.mustRun("scope", "add", "example.com"))
	id2 := extractRuleID(t, c.mustRun("scope", "add", "example.com"))
	if id1 == id2 {
		t.Fatal("two separate `scope add` calls produced the same ID")
	}
	list := c.mustRun("scope", "list")
	if !strings.Contains(list, id1) || !strings.Contains(list, id2) {
		t.Errorf("both duplicate rules must coexist:\n%s", list)
	}
}

// --- Remove safety (task section 10) ----------------------------------------

func TestScopeRemove_OnlyAffectsExactRule(t *testing.T) {
	c := newScopeCLI(t)
	idA := extractRuleID(t, c.mustRun("scope", "add", "--exact", "example.com"))
	idB := extractRuleID(t, c.mustRun("scope", "add", "--exact", "api.example.com"))

	c.mustRun("scope", "remove", idA)
	list := c.mustRun("scope", "list")
	if strings.Contains(list, idA) {
		t.Errorf("removed rule A still present:\n%s", list)
	}
	if !strings.Contains(list, idB) {
		t.Errorf("unrelated rule B was affected by removing A:\n%s", list)
	}
}

func TestScopeRemove_AllowDenySameValue_RemovingOneLeavesOther(t *testing.T) {
	c := newScopeCLI(t)
	allowID := extractRuleID(t, c.mustRun("scope", "add", "127.0.0.1"))
	denyID := extractRuleID(t, c.mustRun("scope", "add", "--action", "deny", "127.0.0.1"))

	c.mustRun("scope", "remove", allowID)
	list := c.mustRun("scope", "list")
	if strings.Contains(list, allowID) {
		t.Errorf("removed allow rule still present:\n%s", list)
	}
	if !strings.Contains(list, denyID) {
		t.Errorf("deny rule was removed alongside the allow rule:\n%s", list)
	}
}

// --- Help (task section 7) --------------------------------------------------

func TestScopeHelp_ExplainsDefaultDenyAndSubcommands(t *testing.T) {
	c := newScopeCLI(t)
	out := c.mustRun("scope", "--help")
	for _, want := range []string{"DEFAULT-DENY", "allow", "deny", "exact_host", "domain_suffix", "cidr", "add", "list", "remove"} {
		if !strings.Contains(out, want) {
			t.Errorf("scope --help missing %q:\n%s", want, out)
		}
	}
}

func TestScopeAddHelp_ShowsExamples(t *testing.T) {
	c := newScopeCLI(t)
	out := c.mustRun("scope", "add", "--help")
	if !strings.Contains(out, "Examples:") {
		t.Errorf("scope add --help missing an Examples section:\n%s", out)
	}
	if !strings.Contains(out, "--action") || !strings.Contains(out, "--exact") {
		t.Errorf("scope add --help missing flag docs:\n%s", out)
	}
}

func TestScopeRemoveHelp_ExplainsAllThreeModes(t *testing.T) {
	c := newScopeCLI(t)
	out := c.mustRun("scope", "remove", "--help")
	for _, want := range []string{"<rule-id>", "--value", "Non-interactive", "Examples:"} {
		if !strings.Contains(out, want) {
			t.Errorf("scope remove --help missing %q:\n%s", want, out)
		}
	}
}

func TestScopeListHelp(t *testing.T) {
	c := newScopeCLI(t)
	out := c.mustRun("scope", "list", "--help")
	if !strings.Contains(out, "scope rule") {
		t.Errorf("scope list --help = %q, want it to mention scope rules", out)
	}
}

// --- Persistence (task section 26) ------------------------------------------

func TestScopePersistence_AcrossProcesses(t *testing.T) {
	c := newScopeCLI(t)
	id := extractRuleID(t, c.mustRun("scope", "add", "persistent.example.com"))

	// Every c.run call is already a fresh process invocation -- this
	// directly proves persistence across process restarts.
	list1 := c.mustRun("scope", "list")
	if !strings.Contains(list1, id) {
		t.Fatalf("rule missing immediately after a fresh process listed it:\n%s", list1)
	}

	c.mustRun("scope", "remove", id)
	list2 := c.mustRun("scope", "list")
	if strings.Contains(list2, id) {
		t.Errorf("removed rule reappeared in a fresh process's listing:\n%s", list2)
	}
}

// --- Default-deny / allow / remove / deny-precedence regression ------------
// (task sections 19-22)

func TestDefaultDeny_Regression(t *testing.T) {
	c := newScopeCLI(t)
	_, _, err := c.run("scan", "example.com")
	if err == nil {
		t.Fatal("scan with no scope rule at all succeeded, want default-deny to block it")
	}
	if code := exitCode(t, err); code != 2 {
		t.Errorf("exit code = %d, want 2 (scope violation)", code)
	}
}

func TestAllowRule_Regression(t *testing.T) {
	c := newScopeCLIAllowReserved(t)
	c.mustRun("scope", "add", "--action", "allow", "127.0.0.1")
	out, _, err := c.run("scan", "127.0.0.1", "--ports", "1")
	if err != nil {
		t.Fatalf("scan with an allow rule failed scope validation: %v\noutput: %s", err, out)
	}
	if !strings.Contains(out, "Status:   COMPLETED") {
		t.Errorf("output = %q, want a COMPLETED status", out)
	}
}

func TestRemoveRule_Regression(t *testing.T) {
	c := newScopeCLIAllowReserved(t)
	id := extractRuleID(t, c.mustRun("scope", "add", "127.0.0.1"))

	if _, _, err := c.run("scan", "127.0.0.1", "--ports", "1"); err != nil {
		t.Fatalf("scan should pass scope with the allow rule present: %v", err)
	}

	c.mustRun("scope", "remove", id)

	_, _, err := c.run("scan", "127.0.0.1", "--ports", "1")
	if err == nil {
		t.Fatal("scan succeeded after its allow rule was removed, want scope validation to fail")
	}
	if code := exitCode(t, err); code != 2 {
		t.Errorf("exit code = %d, want 2 (scope violation)", code)
	}
}

func TestDenyRule_Regression_PrecedenceUnchanged(t *testing.T) {
	c := newScopeCLIAllowReserved(t)
	c.mustRun("scope", "add", "--action", "allow", "127.0.0.1")
	c.mustRun("scope", "add", "--action", "deny", "127.0.0.1")

	_, stderr, err := c.run("scan", "127.0.0.1", "--ports", "1")
	if err == nil {
		t.Fatal("scan succeeded despite a deny rule matching the same target as an allow rule")
	}
	if code := exitCode(t, err); code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr, "deny") {
		t.Errorf("stderr = %q, want it to mention the deny rule", stderr)
	}
}

// --- Special characters (task section 23) -----------------------------------

func TestScopeAdd_SpecialCharacterValues_NoCrashNoShellInterpretation(t *testing.T) {
	c := newScopeCLI(t)
	// Every one of these is invalid per internal/target.Parse's existing,
	// unchanged hostname validation -- the point of this test is that
	// each is REJECTED cleanly (a clear error, no crash, no shell
	// metacharacter ever reaching a shell -- this Go binary never
	// invokes one), never silently accepted or misinterpreted.
	for _, v := range []string{"?", "*", "a/b", "user@example.com", "has space.com", "weird:value"} {
		_, stderr, err := c.run("scope", "add", v)
		if err == nil {
			t.Errorf("value %q was accepted, want target.Parse to reject it", v)
			continue
		}
		if stderr == "" {
			t.Errorf("value %q: no error message produced", v)
		}
	}
	// Confirm nothing was accidentally added despite the rejections.
	list := c.mustRun("scope", "list")
	if !strings.Contains(list, "no scope rules configured") {
		t.Errorf("expected no rules to have been added:\n%s", list)
	}
}

// --- Security tests (task section 30) ---------------------------------------

func TestSecurity_ScopeRemove_SQLInjectionShapedID_NoBypassNoCrash(t *testing.T) {
	c := newScopeCLI(t)
	id := extractRuleID(t, c.mustRun("scope", "add", "example.com"))

	_, _, err := c.run("scope", "remove", "'; DROP TABLE scope_rules; --")
	if err == nil {
		t.Fatal("SQL-injection-shaped ID was accepted as a match, want not-found")
	}
	// The database must still be fully functional and the real rule intact.
	list := c.mustRun("scope", "list")
	if !strings.Contains(list, id) {
		t.Errorf("real rule lost or table corrupted after a SQL-injection-shaped remove attempt:\n%s", list)
	}
}

func TestSecurity_ScopeRemove_PathTraversalShapedID_NoBypass(t *testing.T) {
	c := newScopeCLI(t)
	id := extractRuleID(t, c.mustRun("scope", "add", "example.com"))

	for _, malicious := range []string{"../../etc/passwd", "$(whoami)", "`id`", "日本語"} {
		_, _, err := c.run("scope", "remove", malicious)
		if err == nil {
			t.Errorf("malicious ID %q unexpectedly matched a rule", malicious)
		}
	}
	list := c.mustRun("scope", "list")
	if !strings.Contains(list, id) {
		t.Errorf("real rule lost after malicious-ID remove attempts:\n%s", list)
	}
}

func TestSecurity_ScopeRemoveByValue_NoWildcardOrPartialMatch(t *testing.T) {
	c := newScopeCLI(t)
	fullID := extractRuleID(t, c.mustRun("scope", "add", "example.com"))

	// A partial/prefix value must NOT match the full "example.com" rule.
	_, _, err := c.run("scope", "remove", "--value", "example")
	if err == nil {
		t.Fatal("--value \"example\" (a partial match) unexpectedly removed the \"example.com\" rule")
	}
	list := c.mustRun("scope", "list")
	if !strings.Contains(list, fullID) {
		t.Errorf("rule was removed by a partial-value match:\n%s", list)
	}
}

// --- Concurrency (task section 25) ------------------------------------------

func TestConcurrency_ScopeAdd_FreshDatabase_NoCorruption(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	dbPath := filepath.Join(dir, "sakanner.db")
	if err := os.WriteFile(configPath, []byte(fmt.Sprintf("storage:\n  dsn: %s\n", dbPath)), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	c := newCLI(t, bin, configPath)

	const n = 10
	var wg sync.WaitGroup
	errs := make([]error, n)
	stderrs := make([]string, n)
	for i := 0; i < n; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, stderr, err := c.run("scope", "add", fmt.Sprintf("10.1.0.%d", i+1))
			errs[i] = err
			stderrs[i] = stderr
		}()
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("concurrent scope add %d failed: %v\nstderr: %s", i, err, stderrs[i])
		}
	}

	list := c.mustRun("scope", "list")
	count := strings.Count(list, "allow")
	if count != n {
		t.Errorf("scope list shows %d rules, want %d (possible corruption from concurrent migration)", count, n)
	}
}

// --- Shell completion (task sections 12-13) ---------------------------------

func TestShellCompletion_GeneratesValidScriptsForEveryShell(t *testing.T) {
	bin := buildBinary(t)
	for _, shell := range []string{"bash", "zsh", "fish", "powershell"} {
		cmd := exec.Command(bin, "completion", shell)
		out, err := cmd.Output()
		if err != nil {
			t.Errorf("completion %s failed: %v", shell, err)
			continue
		}
		if len(out) < 100 {
			t.Errorf("completion %s produced suspiciously little output (%d bytes)", shell, len(out))
		}
	}
}

func TestShellCompletion_TopLevelSubcommands(t *testing.T) {
	bin := buildBinary(t)
	cmd := exec.Command(bin, "__complete", "")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("__complete: %v", err)
	}
	for _, want := range []string{"scope", "scan", "target", "status", "findings", "report"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("completion output missing subcommand %q:\n%s", want, out)
		}
	}
}

func TestShellCompletion_ScopeSubcommands(t *testing.T) {
	bin := buildBinary(t)
	cmd := exec.Command(bin, "__complete", "scope", "")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("__complete: %v", err)
	}
	for _, want := range []string{"add", "list", "remove"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("completion output missing scope subcommand %q:\n%s", want, out)
		}
	}
}

func TestShellCompletion_ScanFlags(t *testing.T) {
	bin := buildBinary(t)
	cmd := exec.Command(bin, "__complete", "scan", "--")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("__complete: %v", err)
	}
	for _, want := range []string{"--target", "--ports", "--timeout", "--profile", "--auth-profile"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("completion output missing flag %q:\n%s", want, out)
		}
	}
}

// TestShellCompletion_AuthSubcommands covers `scanner auth <TAB>` and
// `scanner auth profiles <TAB>` -- structural subcommand-name
// completion, which cobra provides automatically with no
// ValidArgsFunction (dynamic completion of a profile NAME's actual
// VALUE is deliberately not implemented -- see auth.go's doc comment
// on why, and docs/phase-3-14-authentication.md "Shell completion").
func TestShellCompletion_AuthSubcommands(t *testing.T) {
	bin := buildBinary(t)
	configPath := writeConfig(t, "")

	cmd := exec.Command(bin, "--config", configPath, "__complete", "auth", "")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("__complete: %v", err)
	}
	if !strings.Contains(string(out), "profiles") {
		t.Errorf("completion output missing \"profiles\" subcommand:\n%s", out)
	}

	cmd2 := exec.Command(bin, "--config", configPath, "__complete", "auth", "profiles", "")
	out2, err := cmd2.Output()
	if err != nil {
		t.Fatalf("__complete: %v", err)
	}
	for _, want := range []string{"list", "show"} {
		if !strings.Contains(string(out2), want) {
			t.Errorf("completion output missing %q subcommand:\n%s", want, out2)
		}
	}
}

func TestShellCompletion_NeverMutatesOrScans(t *testing.T) {
	// Completion must be pure CLI metadata (task section 13): running
	// __complete against a fresh, empty database must never create a
	// scope rule, scan job, or any other row.
	bin := buildBinary(t)
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	dbPath := filepath.Join(dir, "sakanner.db")
	if err := os.WriteFile(configPath, []byte(fmt.Sprintf("storage:\n  dsn: %s\n", dbPath)), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	c := newCLI(t, bin, configPath)

	for _, args := range [][]string{
		{"__complete", ""},
		{"__complete", "scope", ""},
		{"__complete", "scope", "add", ""},
		{"__complete", "scope", "remove", ""},
		{"__complete", "scan", ""},
		{"__complete", "scan", "--"},
	} {
		if _, _, err := c.run(args...); err != nil {
			t.Errorf("%v: %v", args, err)
		}
	}

	list := c.mustRun("scope", "list")
	if !strings.Contains(list, "no scope rules configured") {
		t.Errorf("completion mutated scope state:\n%s", list)
	}
}
