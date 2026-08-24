package correlation

import (
	"testing"

	"sakanner/pkg/models"
)

func TestNormalizeHost_LowercasesAndStripsTrailingDot(t *testing.T) {
	cases := map[string]string{
		"Example.Test":    "example.test",
		"EXAMPLE.TEST.":   "example.test",
		"example.test":    "example.test",
		"  example.test ": "example.test",
	}
	for in, want := range cases {
		if got := normalizeHost(in); got != want {
			t.Errorf("normalizeHost(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizeHost_NeverMergesDifferentHosts(t *testing.T) {
	if normalizeHost("example.com") == normalizeHost("evil-example.com") {
		t.Error("normalizeHost must never make different hosts equal")
	}
}

func TestNormalizeMethod_Uppercases(t *testing.T) {
	if normalizeMethod("get") != "GET" {
		t.Errorf("normalizeMethod(get) = %q, want GET", normalizeMethod("get"))
	}
}

func TestNormalizePath_StripsSingleTrailingSlash(t *testing.T) {
	if got := normalizePath("/api/search/"); got != "/api/search" {
		t.Errorf("normalizePath(/api/search/) = %q, want /api/search", got)
	}
}

func TestNormalizePath_RootStaysRoot(t *testing.T) {
	if got := normalizePath("/"); got != "/" {
		t.Errorf("normalizePath(/) = %q, want /", got)
	}
}

func TestNormalizePath_NeverMergesDifferentPaths(t *testing.T) {
	if normalizePath("/api/user") == normalizePath("/api/admin") {
		t.Error("normalizePath must never merge genuinely different paths")
	}
	if normalizePath("/api/search") == normalizePath("/api/searchable") {
		t.Error("normalizePath must not merge a path with one that merely shares a prefix")
	}
}

func TestNormalizePort_DefaultsFromScheme(t *testing.T) {
	if got := normalizePort(0, "https"); got != 443 {
		t.Errorf("normalizePort(0, https) = %d, want 443", got)
	}
	if got := normalizePort(0, "http"); got != 80 {
		t.Errorf("normalizePort(0, http) = %d, want 80", got)
	}
}

func TestNormalizePort_ExplicitPortPreserved(t *testing.T) {
	if got := normalizePort(8443, "https"); got != 8443 {
		t.Errorf("normalizePort(8443, https) = %d, want 8443", got)
	}
}

func TestNormalizePort_NeverMergesDifferentSecurityRelevantPorts(t *testing.T) {
	if normalizePort(8080, "http") == normalizePort(9090, "http") {
		t.Error("normalizePort must never merge genuinely different explicit ports")
	}
}

func TestComputeIdentity_SchemeEquivalence(t *testing.T) {
	// https://example.com and https://example.com:443 normalize to the
	// same asset (task section 3's exact example).
	a := sqliFinding("scan-1", "")
	a.URL = "https://example.test/products?id=1"
	a.Host = "example.test"
	a.Port = 443

	b := sqliFinding("scan-1", "")
	b.URL = "https://example.test:443/products?id=1"
	b.Host = "example.test"
	b.Port = 443

	idA, idB := computeIdentity(a), computeIdentity(b)
	if idA.Key() != idB.Key() {
		t.Errorf("identity keys differ for scheme/explicit-default-port equivalent findings:\n%q\n%q", idA.Key(), idB.Key())
	}
}

func TestComputeIdentity_HostnameCaseEquivalence(t *testing.T) {
	a := xssFinding("scan-1", "")
	a.Host = "Example.Test"
	b := xssFinding("scan-1", "")
	b.Host = "example.test"

	if computeIdentity(a).FindingID() != computeIdentity(b).FindingID() {
		t.Error("hostname case difference must not produce a different FindingID")
	}
}

func TestComputeIdentity_TrailingSlashEquivalence(t *testing.T) {
	a := xssFinding("scan-1", "")
	a.AffectedEndpoint = "/search"
	b := xssFinding("scan-1", "")
	b.AffectedEndpoint = "/search/"

	if computeIdentity(a).FindingID() != computeIdentity(b).FindingID() {
		t.Error("a single trailing slash difference must not produce a different FindingID")
	}
}

func TestComputeIdentity_DistinguishesVulnerabilityTypes(t *testing.T) {
	// Every OTHER identity component (scan/scheme/host/port/path/
	// method/parameter/parameter-location/resource) is held identical
	// -- including the URL's query key, which parameterLocation()
	// reads, so this test isolates the vulnerability-type dimension
	// precisely rather than accidentally also varying location.
	xss := xssFinding("scan-1", "")
	xss.URL = "http://example.test/search?q=1"
	xss.AffectedEndpoint = "/search"
	xss.AffectedParameter = "q"
	sqli := sqliFinding("scan-1", "")
	sqli.URL = "http://example.test/search?q=1"
	sqli.AffectedEndpoint = "/search"
	sqli.AffectedParameter = "q"
	sqli.Host = xss.Host

	idXSS, idSQLi := computeIdentity(xss), computeIdentity(sqli)
	if idXSS.ParameterLocation != idSQLi.ParameterLocation {
		t.Fatalf("test setup bug: ParameterLocation differs (%q vs %q) -- this test must isolate ONLY vulnerability type", idXSS.ParameterLocation, idSQLi.ParameterLocation)
	}
	if idXSS.FindingID() == idSQLi.FindingID() {
		t.Error("XSS and SQLi on the identical endpoint/parameter must never share a FindingID")
	}
}

func TestComputeIdentity_DistinguishesEndpoints(t *testing.T) {
	a := xssFinding("scan-1", "")
	a.AffectedEndpoint = "/user"
	b := xssFinding("scan-1", "")
	b.AffectedEndpoint = "/admin"

	if computeIdentity(a).FindingID() == computeIdentity(b).FindingID() {
		t.Error("different endpoints must never share a FindingID")
	}
}

func TestComputeIdentity_DistinguishesParameters(t *testing.T) {
	a := xssFinding("scan-1", "")
	a.AffectedParameter = "q"
	b := xssFinding("scan-1", "")
	b.AffectedParameter = "search"

	if computeIdentity(a).FindingID() == computeIdentity(b).FindingID() {
		t.Error("different parameters must never share a FindingID")
	}
}

func TestComputeIdentity_DistinguishesScanIDs(t *testing.T) {
	a := xssFinding("scan-A", "")
	b := xssFinding("scan-B", "")

	if computeIdentity(a).FindingID() == computeIdentity(b).FindingID() {
		t.Error("different scan IDs must never share a FindingID -- scan isolation")
	}
}

func TestComputeIdentity_ResourceAwareForIDOR(t *testing.T) {
	a := idorFinding("scan-1", "resource-b")
	c := idorFinding("scan-1", "resource-c")

	if computeIdentity(a).FindingID() == computeIdentity(c).FindingID() {
		t.Error("IDOR findings against different resource IDs must remain distinct (section 19)")
	}
}

func TestComputeIdentity_ProbeVariantsCollapseForTraversal(t *testing.T) {
	// Different traversal representations of the SAME underlying probe
	// must NOT create separate findings (section 19: "do not make
	// every traversal payload a separate finding").
	a := traversalFinding("scan-1", "..%2Fprotected%2Fsecret.txt")
	b := traversalFinding("scan-1", "../protected/secret.txt")
	// AffectedParameter/AffectedEndpoint are identical; only the URL's
	// query VALUE differs, which is never part of non-IDOR identity.

	if computeIdentity(a).FindingID() != computeIdentity(b).FindingID() {
		t.Error("different traversal payload representations for the same parameter must collapse to one identity")
	}
}

func TestComputeIdentity_CallbackTokensCollapseForSSRF(t *testing.T) {
	a := ssrfFinding("scan-1", "token-aaaa")
	b := ssrfFinding("scan-1", "token-bbbb")

	if computeIdentity(a).FindingID() != computeIdentity(b).FindingID() {
		t.Error("different SSRF callback tokens for the same parameter must collapse to one identity (section 19)")
	}
}

func TestComputeIdentity_CorrelationTokensCollapseForCommandInjection(t *testing.T) {
	a := cmdInjectionFinding("scan-1", "token-aaaa")
	b := cmdInjectionFinding("scan-1", "token-bbbb")

	if computeIdentity(a).FindingID() != computeIdentity(b).FindingID() {
		t.Error("different command-injection correlation tokens for the same parameter must collapse to one identity")
	}
}

func TestFindingID_StableAcrossRepeatedComputation(t *testing.T) {
	f := xssFinding("scan-1", "")
	id1 := computeIdentity(f).FindingID()
	id2 := computeIdentity(f).FindingID()
	if id1 != id2 {
		t.Errorf("FindingID changed across repeated computation: %q vs %q", id1, id2)
	}
}

func TestFindingID_LooksLikeAContentHashNotARandomUUID(t *testing.T) {
	f := xssFinding("scan-1", "")
	id := computeIdentity(f).FindingID()
	if len(id) != 32 {
		t.Errorf("FindingID length = %d, want 32 (16 bytes of SHA-256 hex-encoded)", len(id))
	}
	for _, r := range id {
		if !(r >= '0' && r <= '9') && !(r >= 'a' && r <= 'f') {
			t.Errorf("FindingID %q contains non-hex character %q -- a UUID would have dashes; this must be a plain hex hash", id, r)
			break
		}
	}
}

func TestParameterLocation_QueryDetectedFromURL(t *testing.T) {
	f := xssFinding("scan-1", "")
	loc := parameterLocation(f)
	if loc != "query" {
		t.Errorf("parameterLocation = %q, want query", loc)
	}
}

func TestParameterLocation_UnspecifiedWhenNotInQuery(t *testing.T) {
	f := xssFinding("scan-1", "")
	f.AffectedParameter = "not_in_url"
	loc := parameterLocation(f)
	if loc != "unspecified" {
		t.Errorf("parameterLocation = %q, want unspecified", loc)
	}
}

func TestResourceIdentifier_EmptyForNonIDORTypes(t *testing.T) {
	for _, f := range []models.Finding{
		xssFinding("scan-1", ""), sqliFinding("scan-1", ""), ssrfFinding("scan-1", "tok"),
		traversalFinding("scan-1", "x"), cmdInjectionFinding("scan-1", "tok"),
	} {
		if got := resourceIdentifier(f); got != "" {
			t.Errorf("resourceIdentifier(%s) = %q, want empty for a non-idor type", f.VulnerabilityType, got)
		}
	}
}
