package lab

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// VulnGroundTruth is the parsed contents of
// ground-truth-vulnerabilities.yaml -- the Phase 3 Security Test
// Laboratory's ground truth, kept separate from GroundTruth (Phase 2)
// so neither file grows unmanageably large and Phase 2's own ground
// truth is never touched by Phase 3 work.
type VulnGroundTruth struct {
	Host           string                 `yaml:"host"`
	InternalHost   string                 `yaml:"internal_host"`
	Findings       []VulnFinding          `yaml:"findings"`
	ScopeScenarios []ScopeScenario        `yaml:"scope_enforcement_scenarios"`
	AuthCoverage   AuthenticationCoverage `yaml:"authentication_coverage"`
}

// VulnFinding is one expected (positive) or explicitly-not-expected
// (negative) finding. Field names mirror pkg/models.Finding wherever a
// natural mapping exists (Type -> VulnerabilityType, Severity ->
// Severity, Endpoint -> AffectedEndpoint, Parameter ->
// AffectedParameter), so a future comparison against real
// detector-produced Finding rows needs no translation layer.
type VulnFinding struct {
	ID                      string           `yaml:"id"`
	Type                    string           `yaml:"type"`
	VulnerabilityClass      string           `yaml:"vulnerability_class"`
	Host                    string           `yaml:"host"`
	Endpoint                string           `yaml:"endpoint"`
	Method                  string           `yaml:"method"`
	Parameter               string           `yaml:"parameter"`
	Severity                string           `yaml:"severity"`
	SeverityRationale       string           `yaml:"severity_rationale"`
	AuthenticationRequired  bool             `yaml:"authentication_required"`
	AutomaticallyDetectable bool             `yaml:"automatically_detectable"`
	DetectorCategory        string           `yaml:"detector_category"`
	RequiresCapability      string           `yaml:"requires_capability"`
	ExpectedEvidence        ExpectedEvidence `yaml:"expected_evidence"`
	ExpectedBehavior        string           `yaml:"expected_behavior"`
	IsolationNote           string           `yaml:"isolation_note"`

	// Negative fixtures (the "safe" counterpart) set Negative=true and
	// ExpectedResult="no_vulnerability" instead of populating Severity/
	// ExpectedEvidence -- there is nothing to find, by design.
	Negative       bool   `yaml:"negative"`
	ExpectedResult string `yaml:"expected_result"`
}

// ExpectedEvidence documents what a future detector should be able to
// collect to substantiate a positive finding.
type ExpectedEvidence struct {
	ProbePayload               string   `yaml:"probe_payload"`
	ResponseContains           string   `yaml:"response_contains"`
	ResponseHeader             string   `yaml:"response_header"`
	ResponseHeaderMissingAttrs []string `yaml:"response_header_missing_attributes"`
	ResponseHeadersAbsent      []string `yaml:"response_headers_absent"`
	RedirectLocationContains   string   `yaml:"redirect_location_contains"`
	Description                string   `yaml:"description"`
}

// ScopeScenario documents one way a vulnerable fixture's own natural
// behavior (a link, a redirect, an SSRF parameter) references an
// out-of-scope-looking destination, and what sakanner must still do
// about it (nothing, i.e. never dial it) regardless.
type ScopeScenario struct {
	Description      string `yaml:"description"`
	Mechanism        string `yaml:"mechanism"`
	ReferenceHost    string `yaml:"reference_host"`
	Fixture          string `yaml:"fixture"`
	ExpectedBehavior string `yaml:"expected_behavior"`
}

// AuthenticationCoverage indexes which finding IDs above exercise each
// of the four authentication/authorization scenarios requested for
// Phase 3.
type AuthenticationCoverage struct {
	UnauthenticatedAccess               []string `yaml:"unauthenticated_access"`
	AuthenticatedAccessRequiredEnforced []string `yaml:"authenticated_access_required_and_enforced"`
	UnauthorizedAccessCorrectlyDenied   []string `yaml:"unauthorized_access_correctly_denied"`
	HorizontalAuthorizationFailure      []string `yaml:"horizontal_authorization_failure"`
}

// Positives returns only the findings that describe an actual
// vulnerability (Negative == false).
func (gt *VulnGroundTruth) Positives() []VulnFinding {
	var out []VulnFinding
	for _, f := range gt.Findings {
		if !f.Negative {
			out = append(out, f)
		}
	}
	return out
}

// Negatives returns only the findings that describe a safe counterpart
// (Negative == true) -- these exist to measure false positives, not to
// be found.
func (gt *VulnGroundTruth) Negatives() []VulnFinding {
	var out []VulnFinding
	for _, f := range gt.Findings {
		if f.Negative {
			out = append(out, f)
		}
	}
	return out
}

// vulnGroundTruthPath locates ground-truth-vulnerabilities.yaml relative
// to this source file, mirroring groundtruth.go's groundTruthPath for
// the same reason (working-directory independence).
func vulnGroundTruthPath() (string, error) {
	path, err := groundTruthPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(path), "ground-truth-vulnerabilities.yaml"), nil
}

// LoadVulnGroundTruth reads and parses ground-truth-vulnerabilities.yaml.
func LoadVulnGroundTruth() (*VulnGroundTruth, error) {
	path, err := vulnGroundTruthPath()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("lab: reading %s: %w", path, err)
	}
	var gt VulnGroundTruth
	if err := yaml.Unmarshal(b, &gt); err != nil {
		return nil, fmt.Errorf("lab: parsing %s: %w", path, err)
	}
	return &gt, nil
}
