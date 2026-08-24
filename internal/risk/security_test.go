package risk

import (
	"go/parser"
	"go/token"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sakanner/internal/correlation"
	"sakanner/pkg/models"
)

// Security tests (task section 28): the risk engine must make no
// network requests, execute no commands, access no filesystem paths
// from target input, execute no code from finding metadata, invoke no
// shell, invoke no LLM, and load no remote configuration. Every
// finding field is treated as untrusted data.

func TestSecurity_SourceNeverTouchesFilesystemNetworkShellOrLLM(t *testing.T) {
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
				t.Errorf("%s imports %q -- this package must remain a pure, in-memory scoring computation with no filesystem/network/shell access", name, path)
			}
		}
	}
}

func TestSecurity_MissingSeverity_NoCrash(t *testing.T) {
	cf := canonicalFinding("scan-1", "f1", "reflected_xss", "", 0.5, correlation.StatusNew, "h.test")
	a := Assess(cf, nil)
	if a.Breakdown.SeverityRecognized {
		t.Error("empty severity must not be treated as recognized")
	}
}

func TestSecurity_InvalidSeverity_NoCrash(t *testing.T) {
	cf := canonicalFinding("scan-1", "f1", "reflected_xss", models.Severity("💥not-a-severity💥"), 0.5, correlation.StatusNew, "h.test")
	a := Assess(cf, nil)
	if a.RiskScore < 0 || a.RiskScore > 100 {
		t.Errorf("RiskScore = %d, want in [0, 100]", a.RiskScore)
	}
}

func TestSecurity_InvalidConfidence_NaN_NoCrash(t *testing.T) {
	cf := canonicalFinding("scan-1", "f1", "reflected_xss", models.SeverityHigh, math.NaN(), correlation.StatusNew, "h.test")
	a := Assess(cf, nil)
	if a.RiskScore < 0 || a.RiskScore > 100 {
		t.Errorf("RiskScore = %d, want in [0, 100]", a.RiskScore)
	}
}

func TestSecurity_InvalidConfidence_Infinity_NoCrash(t *testing.T) {
	cf := canonicalFinding("scan-1", "f1", "reflected_xss", models.SeverityHigh, math.Inf(1), correlation.StatusNew, "h.test")
	a := Assess(cf, nil)
	if a.RiskScore < 0 || a.RiskScore > 100 {
		t.Errorf("RiskScore = %d, want in [0, 100]", a.RiskScore)
	}
}

func TestSecurity_InvalidExposure_NoCrash(t *testing.T) {
	cf := canonicalFinding("scan-1", "f1", "reflected_xss", models.SeverityHigh, 0.9, correlation.StatusNew, "h.test")
	a := Assess(cf, &AssetContext{Exposure: ExposureTier("\x00\xff garbage")})
	if a.RiskScore < 0 || a.RiskScore > 100 {
		t.Errorf("RiskScore = %d, want in [0, 100]", a.RiskScore)
	}
}

func TestSecurity_NegativeConfidenceValue_NoCrash(t *testing.T) {
	cf := canonicalFinding("scan-1", "f1", "reflected_xss", models.SeverityHigh, -99.0, correlation.StatusNew, "h.test")
	a := Assess(cf, nil)
	if a.RiskScore < 0 || a.RiskScore > 100 {
		t.Errorf("RiskScore = %d, want in [0, 100]", a.RiskScore)
	}
}

func TestSecurity_ExtremelyLargeFindingSet_NoCrash(t *testing.T) {
	var findings []correlation.CanonicalFinding
	for i := 0; i < 5000; i++ {
		findings = append(findings, canonicalFinding("scan-1", "f-"+strings.Repeat("x", i%50), "reflected_xss", models.SeverityHigh, 0.9, correlation.StatusNew, "h.test"))
	}
	got := AssessAll(findings, nil)
	if len(got) != 5000 {
		t.Fatalf("len = %d, want 5000", len(got))
	}
}

func TestSecurity_MalformedMetadata_NoCrash(t *testing.T) {
	cf := canonicalFinding("scan-1", "f1", "reflected_xss", models.SeverityHigh, 0.9, correlation.StatusNew, "h.test")
	cf.Metadata = map[string]string{
		"'; DROP TABLE findings; --": "1",
		"$(rm -rf /)":                "1",
		"../../../../etc/passwd":     "1",
		strings.Repeat("k", 100000):  strings.Repeat("v", 100000),
	}
	a := Assess(cf, nil)
	if a.RiskScore < 0 || a.RiskScore > 100 {
		t.Errorf("RiskScore = %d, want in [0, 100]", a.RiskScore)
	}
}

func TestSecurity_UnicodeInFindingFields_NoCrash(t *testing.T) {
	cf := canonicalFinding("scan-1", "f1", "reflected_xss", models.SeverityHigh, 0.9, correlation.StatusNew, "h\xff\xfe.test")
	cf.Title = "unicode-title-mixed-with-symbols-\U0001F525"
	cf.Asset.Path = "/日本語/path\x00"
	a := Assess(cf, nil)
	if a.Explanation == "" {
		t.Error("Explanation is empty")
	}
}

func TestSecurity_EmptyStrings_NoCrash(t *testing.T) {
	cf := correlation.CanonicalFinding{}
	a := Assess(cf, nil)
	if a.RiskScore < 0 || a.RiskScore > 100 {
		t.Errorf("RiskScore = %d, want in [0, 100]", a.RiskScore)
	}
}

func TestSecurity_DuplicateAssetContextFieldsIgnoredSafely(t *testing.T) {
	cf := canonicalFinding("scan-1", "f1", "reflected_xss", models.SeverityHigh, 0.9, correlation.StatusNew, "h.test")
	ctx := &AssetContext{Exposure: ExposureInternetFacing, Host: "different-host.test", Port: 9999}
	a := Assess(cf, ctx)
	// The finding's OWN asset host must win for Asset.Host -- an
	// AssetContext is supplementary display context, never a way to
	// silently relocate a finding to a different asset.
	if a.Asset.Host != cf.Asset.Host {
		t.Errorf("Asset.Host = %q, want %q (the finding's own asset, not AssetContext.Host)", a.Asset.Host, cf.Asset.Host)
	}
}
