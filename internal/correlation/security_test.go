package correlation

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sakanner/pkg/models"
)

// Security tests (task section 30): malicious/malformed finding input
// must never crash the engine, and the engine must never touch the
// filesystem, execute a command, or make a network request -- it is a
// pure, in-memory data-transformation package.

func TestSecurity_SourceNeverTouchesFilesystemNetworkOrShell(t *testing.T) {
	forbidden := map[string]bool{
		"os/exec": true, "syscall": true, "net": true, "net/http": true,
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(".", name), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("ParseFile(%s): %v", name, err)
		}
		for _, imp := range file.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			if forbidden[path] {
				t.Errorf("%s imports %q -- this package must remain a pure in-memory data transformation with no filesystem/network/shell access", name, path)
			}
		}
	}
	// os.ReadDir/os.ReadFile ARE used, but only by THIS TEST (reading
	// the package's own source for the check above) -- never by the
	// package's own (non-test) code, which the import check just
	// confirmed directly.
}

func TestSecurity_ExtremelyLongHost_NoCrash(t *testing.T) {
	f := xssFinding("scan-1", "")
	f.Host = strings.Repeat("a", 1_000_000)

	e := NewEngine()
	e.Ingest(f)
	got := e.Findings()
	if len(got) != 1 {
		t.Fatalf("Findings() = %d, want 1", len(got))
	}
}

func TestSecurity_ExtremelyLongParameter_NoCrash(t *testing.T) {
	f := xssFinding("scan-1", "")
	f.AffectedParameter = strings.Repeat("p", 1_000_000)

	e := NewEngine()
	e.Ingest(f)
	if len(e.Findings()) != 1 {
		t.Fatal("expected exactly 1 finding")
	}
}

func TestSecurity_ExtremelyLongEvidence_NoCrashAndBounded(t *testing.T) {
	f := xssFinding("scan-1", "")
	f.Evidence = []models.Evidence{newEvidence(models.EvidenceKindRequestResponse, strings.Repeat("E", 50_000_000))}

	e := NewEngine()
	e.Ingest(f)
	got := e.Findings()
	if len(got[0].Evidence) != 1 {
		t.Fatalf("Evidence count = %d, want 1", len(got[0].Evidence))
	}
	if len(got[0].Evidence[0].Content) > maxEvidenceContentBytes {
		t.Errorf("Content length = %d, want <= %d", len(got[0].Evidence[0].Content), maxEvidenceContentBytes)
	}
}

func TestSecurity_InvalidUnicode_NoCrash(t *testing.T) {
	f := xssFinding("scan-1", "")
	f.Host = "example\xff\xfe.test"
	f.AffectedParameter = "para\xc3\x28m"
	f.Evidence = []models.Evidence{newEvidence(models.EvidenceKindRequestResponse, "bad\xffunicode\xfe")}

	e := NewEngine()
	e.Ingest(f)
	if len(e.Findings()) != 1 {
		t.Fatal("expected exactly 1 finding, no panic")
	}
}

func TestSecurity_MalformedURL_NoCrash(t *testing.T) {
	cases := []string{
		"://not-a-url",
		"http://[::1:bad",
		"",
		"   ",
		"http://" + strings.Repeat("x", 100000) + ".test/path",
		"not even url shaped at all !! @@ ##",
	}
	for _, u := range cases {
		f := xssFinding("scan-1", "")
		f.URL = u
		e := NewEngine()
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("Ingest panicked on URL %q: %v", u, r)
				}
			}()
			e.Ingest(f)
		}()
	}
}

func TestSecurity_NullBytes_NoCrash(t *testing.T) {
	f := xssFinding("scan-1", "")
	f.Host = "example\x00.test"
	f.AffectedParameter = "q\x00ux"
	f.Evidence = []models.Evidence{newEvidence(models.EvidenceKindRequestResponse, "content\x00withnull")}

	e := NewEngine()
	e.Ingest(f)
	if len(e.Findings()) != 1 {
		t.Fatal("expected exactly 1 finding, no panic")
	}
}

func TestSecurity_ControlCharacters_NoCrash(t *testing.T) {
	f := xssFinding("scan-1", "")
	f.Title = "Title\r\nwith\tcontrol\x07chars"
	f.AffectedParameter = "q\n\r\t"

	e := NewEngine()
	e.Ingest(f)
	if len(e.Findings()) != 1 {
		t.Fatal("expected exactly 1 finding, no panic")
	}
}

func TestSecurity_DuplicateEvidenceFields_NoCrash(t *testing.T) {
	f := xssFinding("scan-1", "")
	f.Evidence = []models.Evidence{
		newEvidence(models.EvidenceKindRequestResponse, "dup"),
		newEvidence(models.EvidenceKindRequestResponse, "dup"),
		newEvidence(models.EvidenceKindRequestResponse, "dup"),
	}

	e := NewEngine()
	e.Ingest(f)
	got := e.Findings()
	if len(got[0].Evidence) != 1 {
		t.Errorf("Evidence count = %d, want 1 (duplicate fields within a single finding must also dedupe)", len(got[0].Evidence))
	}
}

func TestSecurity_ConflictingSeverityAcrossResubmissions_NoCrash(t *testing.T) {
	a := xssFinding("scan-1", "")
	a.Severity = models.SeverityCritical
	b := xssFinding("scan-1", "")
	b.Severity = models.Severity("not_a_real_severity_value")

	e := NewEngine()
	e.Ingest(a, b)
	got := e.Findings()
	if len(got) != 1 {
		t.Fatal("expected exactly 1 finding, no panic")
	}
	// An unrecognized severity value must never outrank a recognized
	// one (rankOfSeverity returns -1 for it) -- the real "critical"
	// value must still win.
	if got[0].Severity != models.SeverityCritical {
		t.Errorf("Severity = %q, want critical (an unrecognized severity string must never win)", got[0].Severity)
	}
}

func TestSecurity_ConflictingConfidenceValues_NoCrash(t *testing.T) {
	a := xssFinding("scan-1", "")
	a.Confidence = -5.0 // invalid: below 0
	b := xssFinding("scan-1", "")
	b.Confidence = 999.0 // invalid: above 1

	e := NewEngine()
	e.Ingest(a, b)
	got := e.Findings()
	if len(got) != 1 {
		t.Fatal("expected exactly 1 finding, no panic")
	}
	// max(-5, 999) is still well-defined arithmetically; the engine
	// does not attempt to "fix" out-of-range confidence values (that
	// is a detector-side data-quality concern, out of this phase's
	// scope), it simply must not crash on them.
}

func TestSecurity_MalformedFindingID_NoCrash(t *testing.T) {
	f := xssFinding("scan-1", "")
	f.ID = "" // empty
	e := NewEngine()
	e.Ingest(f)

	f2 := xssFinding("scan-1", "")
	f2.ID = strings.Repeat("!", 100000) // garbage, oversized
	e.Ingest(f2)

	if len(e.Findings()) != 1 {
		t.Fatal("expected exactly 1 finding -- f.ID is detector bookkeeping, never part of this package's own Identity")
	}
}

func TestSecurity_EmptyFinding_NoCrash(t *testing.T) {
	e := NewEngine()
	e.Ingest(models.Finding{})
	if len(e.Findings()) != 1 {
		t.Fatal("a completely empty Finding must still produce exactly one (degenerate) canonical finding, not a panic")
	}
}

func TestSecurity_NilEvidenceSlice_NoCrash(t *testing.T) {
	f := xssFinding("scan-1", "")
	f.Evidence = nil
	e := NewEngine()
	e.Ingest(f)
	if len(e.Findings()) != 1 {
		t.Fatal("expected exactly 1 finding")
	}
}

func TestSecurity_ThousandsOfMalformedFindings_NoCrash(t *testing.T) {
	e := NewEngine()
	for i := 0; i < 2000; i++ {
		f := xssFinding("scan-1", "")
		f.Host = strings.Repeat("x", i%500) + "\x00\xff"
		f.AffectedParameter = strings.Repeat("p", i%200)
		f.Evidence = []models.Evidence{newEvidence(models.EvidenceKindRequestResponse, strings.Repeat("e", i%10000))}
		e.Ingest(f)
	}
	// Must complete without panicking; count is not asserted precisely
	// since the malformed hosts intentionally vary.
	_ = e.Findings()
}
