// Package lab is sakanner's Phase 2 Test Laboratory: a Docker-free,
// deterministic local environment for exercising every Phase 2 recon
// capability (DNS/subdomain discovery, HTTP/HTTPS probing, TLS/redirect
// capture, fingerprinting, crawling, endpoint discovery, scope
// enforcement, timeout/failure handling) against known ground truth,
// without touching any real third-party host.
//
// GroundTruth (this file) is the single source of truth, loaded from
// ground-truth.yaml. Harness (harness.go) builds real local servers plus
// a dns.FakeResolver matching that same file, so the harness and the
// test assertions can never silently drift apart from each other -- both
// read the same YAML.
//
// See docs/phase-2-test-lab.md for the full narrative.
package lab

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"gopkg.in/yaml.v3"
)

// GroundTruth is the parsed contents of ground-truth.yaml.
type GroundTruth struct {
	Domain string              `yaml:"domain"`
	Scope  ScopeGroundTruth    `yaml:"scope"`
	DNS    map[string]DNSEntry `yaml:"dns"`
	// DockerPorts documents the Docker Compose profile's fixed host
	// ports. The Go-native harness this package builds uses OS-assigned
	// ports instead (see harness.go) and does not read this field.
	DockerPorts map[string]int       `yaml:"docker_ports"`
	Services    map[string]ServiceGT `yaml:"services"`
}

// ScopeGroundTruth lists which lab hostnames a correctly-behaving scan
// must treat as authorized versus must never actively touch.
type ScopeGroundTruth struct {
	InScope    []string `yaml:"in_scope"`
	OutOfScope []string `yaml:"out_of_scope"`
}

// DNSEntry is one hostname's expected DNS record: exactly one of A,
// AAAA, or CNAME is set, matching how the ground-truth.yaml file
// expresses it.
type DNSEntry struct {
	A     string `yaml:"a"`
	AAAA  string `yaml:"aaaa"`
	CNAME string `yaml:"cname"`
}

// EndpointGT is one endpoint a crawl of a service is expected to
// discover.
type EndpointGT struct {
	Path   string `yaml:"path"`
	Method string `yaml:"method"`
	Source string `yaml:"source"`
}

// JavaScriptGT is one script a service is expected to reference, along
// with the technology fingerprinting its fetched body should reveal.
type JavaScriptGT struct {
	URL        string       `yaml:"url"`
	Technology TechnologyGT `yaml:"technology"`
}

// TechnologyGT is an expected fingerprint.Fingerprinter result.
type TechnologyGT struct {
	Name     string `yaml:"name"`
	Version  string `yaml:"version"`
	Category string `yaml:"category"`
}

// RedirectGT is one redirect scenario a service is expected to exhibit.
type RedirectGT struct {
	Path              string `yaml:"path"`
	ExpectHops        int    `yaml:"expect_hops"`
	ExpectFinalScheme string `yaml:"expect_final_scheme"`
	ExpectFinalPath   string `yaml:"expect_final_path"`
	ExpectTruncated   bool   `yaml:"expect_truncated"`
	Description       string `yaml:"description"`
}

// StatusCodeGT is one plain (non-redirect) status-code scenario.
type StatusCodeGT struct {
	Path         string `yaml:"path"`
	ExpectStatus int    `yaml:"expect_status"`
}

// ServiceGT is everything a lab hostname's HTTP service is expected to
// exhibit.
type ServiceGT struct {
	Scheme             string         `yaml:"scheme"`
	ServerHeader       string         `yaml:"server_header"`
	ExpectedTechnology *TechnologyGT  `yaml:"expected_technology"`
	Endpoints          []EndpointGT   `yaml:"endpoints"`
	EndpointCount      int            `yaml:"endpoint_count"`
	JavaScript         []JavaScriptGT `yaml:"javascript"`
	LinksToOutOfScope  []string       `yaml:"links_to_out_of_scope"`
	Redirects          []RedirectGT   `yaml:"redirects"`
	StatusCodes        []StatusCodeGT `yaml:"status_codes"`
	Scenario           string         `yaml:"scenario"`
	InDefaultPortList  *bool          `yaml:"in_default_port_list"`
}

// groundTruthPath locates ground-truth.yaml relative to this source
// file, so callers can load it regardless of the working directory a
// test binary happens to run from (Go test binaries run with cwd set to
// the package directory, but tools/cmd invoking this package from
// elsewhere should not have to guess the path).
func groundTruthPath() (string, error) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("lab: could not determine source file location")
	}
	return filepath.Join(filepath.Dir(thisFile), "ground-truth.yaml"), nil
}

// LoadGroundTruth reads and parses ground-truth.yaml.
func LoadGroundTruth() (*GroundTruth, error) {
	path, err := groundTruthPath()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("lab: reading %s: %w", path, err)
	}
	var gt GroundTruth
	if err := yaml.Unmarshal(b, &gt); err != nil {
		return nil, fmt.Errorf("lab: parsing %s: %w", path, err)
	}
	return &gt, nil
}
