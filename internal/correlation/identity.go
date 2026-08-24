package correlation

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"strconv"
	"strings"

	"sakanner/pkg/models"
)

// Identity is a finding's deterministic identity key -- task section
// 2's "finding identity." Two models.Finding values with an identical
// Identity are the SAME vulnerability, merged into one
// CanonicalFinding; any difference produces a separate finding. See
// docs/phase-3-8-finding-correlation.md "Identity algorithm" for the
// full rationale behind each component.
type Identity struct {
	ScanID             string
	Scheme             string
	Host               string
	Port               int
	Path               string
	Method             string
	Parameter          string
	ParameterLocation  string
	VulnerabilityType  string
	ResourceIdentifier string
}

// computeIdentity derives f's Identity purely from fields
// models.Finding already carries -- this package makes NO change to
// pkg/models, internal/detection, or any detector (see model.go's
// package doc comment). Host/Port/Method/VulnerabilityType/Parameter
// are normalized (see normalize.go); ParameterLocation and
// ResourceIdentifier are DERIVED, not stored, from f.URL (see
// "Parameter normalization" and "Resource-aware identity" in
// docs/phase-3-8-finding-correlation.md).
func computeIdentity(f models.Finding) Identity {
	scheme := schemeOf(f)
	return Identity{
		ScanID:             strings.TrimSpace(f.ScanID),
		Scheme:             scheme,
		Host:               normalizeHost(f.Host),
		Port:               normalizePort(f.Port, scheme),
		Path:               normalizePath(pathOf(f)),
		Method:             normalizeMethod(f.Method),
		Parameter:          strings.TrimSpace(f.AffectedParameter),
		ParameterLocation:  parameterLocation(f),
		VulnerabilityType:  normalizeVulnerabilityType(f.VulnerabilityType),
		ResourceIdentifier: resourceIdentifier(f),
	}
}

// Key returns Identity's canonical string form -- every component
// joined by a byte (0x1F, ASCII Unit Separator) that can never appear
// in any component's own normalized value, so no combination of
// component values can ever collide into the same Key by concatenation
// alone (the same separator choice internal/detection's own dedupKey
// already established, for the identical reason).
func (id Identity) Key() string {
	return strings.Join([]string{
		id.ScanID, id.Scheme, id.Host, strconv.Itoa(id.Port), id.Path, id.Method,
		id.Parameter, id.ParameterLocation, id.VulnerabilityType, id.ResourceIdentifier,
	}, "\x1f")
}

// FindingID returns a stable, deterministic finding ID derived from
// Key() -- task section 21's "stable finding ID." The SAME identity
// observed any number of times (within or across process runs)
// produces the IDENTICAL FindingID; this is a content hash, never a
// random UUID, so it needs no shared counter or database sequence to
// stay consistent. 128 bits (32 hex characters) of SHA-256 is used --
// far more collision-resistant than this system will ever need, at a
// fixed, small, predictable size.
func (id Identity) FindingID() string {
	sum := sha256.Sum256([]byte(id.Key()))
	return hex.EncodeToString(sum[:16])
}

// normalizeHost lowercases and strips a single trailing "." (the DNS
// root-zone dot, e.g. "example.com." == "example.com") -- task section
// 17. Deliberately does NOT strip subdomain structure or attempt IDN
// normalization beyond case-folding; "example.com" and
// "evil-example.com" must never collide, and never do here since
// nothing beyond case and a trailing dot is touched.
func normalizeHost(host string) string {
	h := strings.ToLower(strings.TrimSpace(host))
	h = strings.TrimSuffix(h, ".")
	return h
}

// normalizeMethod uppercases the HTTP method -- "get" and "GET" are
// obviously the same method.
func normalizeMethod(method string) string {
	return strings.ToUpper(strings.TrimSpace(method))
}

// normalizeVulnerabilityType lowercases and trims -- every detector in
// this project already emits a consistent lowercase snake_case value
// ("reflected_xss", "sql_injection", "ssrf", "idor", "path_traversal",
// "command_injection"); normalizing defensively costs nothing and
// guards against a future detector using different casing for the
// identical type.
func normalizeVulnerabilityType(t string) string {
	return strings.ToLower(strings.TrimSpace(t))
}

// defaultPortForScheme returns the well-known default port for scheme,
// or 0 if scheme isn't one this project's detectors ever probe (they
// only ever speak HTTP/HTTPS -- see docs/phase-3-1-detection-engine.md).
func defaultPortForScheme(scheme string) int {
	switch strings.ToLower(scheme) {
	case "http":
		return 80
	case "https":
		return 443
	default:
		return 0
	}
}

// normalizePort returns port unchanged -- it exists as a named,
// documented step (not a no-op left implicit) because task section 3's
// "https://example.com and https://example.com:443 should normally
// resolve to the same normalized target" requirement is ALREADY
// satisfied structurally in this system: every models.Finding's Port
// is the concrete, already-resolved TCP port Phase 2's HTTP probing
// dialed (internal/detection.Target.Port, copied verbatim by
// normalizeFinding), never an "omitted, assume default" placeholder --
// there is no ":443 vs omitted" ambiguity left to resolve by the time a
// Finding exists. schemeOf is accepted (and defaultPortForScheme kept
// as a documented, tested helper) so the equivalence this task section
// asks for is explicit and verifiable, not merely assumed.
func normalizePort(port int, scheme string) int {
	if port == 0 {
		return defaultPortForScheme(scheme)
	}
	return port
}

// schemeOf extracts f.URL's scheme, defaulting to "http" -- every
// Finding in this system carries a full URL (set by
// internal/detection's normalizeFinding), so this only ever falls back
// on a malformed/adversarial URL (handled without panicking; see
// security_test.go).
func schemeOf(f models.Finding) string {
	u, err := url.Parse(f.URL)
	if err != nil || u.Scheme == "" {
		return "http"
	}
	return strings.ToLower(u.Scheme)
}

// pathOf returns f's path -- AffectedEndpoint if set (the convention
// every detector and the Phase 3 ground truth already key on), else
// f.URL's path component.
func pathOf(f models.Finding) string {
	if f.AffectedEndpoint != "" {
		return f.AffectedEndpoint
	}
	u, err := url.Parse(f.URL)
	if err != nil {
		return ""
	}
	return u.Path
}

// normalizePath strips exactly one trailing "/" from a path longer
// than "/" -- task section 3's "trailing slash where appropriate."
// "/api/search" and "/api/search/" become identical; "/api/search" and
// "/api/searchable" are untouched by this rule (neither ends in a
// slash-only difference) and remain distinct, and the root path "/"
// is never stripped down to "".
func normalizePath(path string) string {
	if len(path) > 1 && strings.HasSuffix(path, "/") {
		return strings.TrimSuffix(path, "/")
	}
	return path
}

// parameterLocation derives WHERE f.AffectedParameter appears --
// "query" if it's present in f.URL's query string (true for every
// finding any detector in this project produces today; see
// docs/phase-3-8-finding-correlation.md "Parameter normalization" for
// why this is derived rather than stored), "unspecified" otherwise
// (reserved for a future body/path/header/cookie-testing detector this
// project does not yet have).
func parameterLocation(f models.Finding) string {
	if f.AffectedParameter == "" {
		return ""
	}
	u, err := url.Parse(f.URL)
	if err != nil {
		return "unspecified"
	}
	if _, ok := u.Query()[f.AffectedParameter]; ok {
		return "query"
	}
	return "unspecified"
}

// resourceIdentifier extracts the resource-level identity component --
// task section 19's "resource-aware identity" -- populated ONLY for
// "idor" findings, where task section 19 explicitly requires
// "User A -> Resource B" and "User A -> Resource C" to remain distinct
// findings. For every other vulnerability type, section 19 explicitly
// requires the OPPOSITE (traversal: "do not make every traversal
// payload a separate finding"; SSRF: "do not create one finding per
// callback token") -- so this deliberately returns "" for anything
// that isn't "idor", keeping probe-specific values OUT of identity for
// every other detector.
func resourceIdentifier(f models.Finding) string {
	if normalizeVulnerabilityType(f.VulnerabilityType) != "idor" {
		return ""
	}
	if f.AffectedParameter == "" {
		return ""
	}
	u, err := url.Parse(f.URL)
	if err != nil {
		return ""
	}
	return u.Query().Get(f.AffectedParameter)
}
