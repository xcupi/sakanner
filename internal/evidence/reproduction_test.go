package evidence

import (
	"testing"

	"sakanner/internal/correlation"
	"sakanner/pkg/models"
)

// --- Reproducibility classification (task section 34) ---------------------

func TestReproducibility_FullWhenNothingRedactedOrTruncated(t *testing.T) {
	cf := fixtureXSS()
	limits := DefaultLimits()
	items := BuildEvidence(cf, limits)
	info := buildReproductionInfo(cf, items, limits)

	if info.Level != ReproducibilityFull {
		t.Errorf("Level = %q, want FULL: %+v", info.Level, info)
	}
	if info.Method != "GET" {
		t.Errorf("Method = %q, want GET", info.Method)
	}
	if info.SafeTestValue != "sakannerXSSPROBE123" {
		t.Errorf("SafeTestValue = %q, want the probe's own reflected value", info.SafeTestValue)
	}
}

func TestReproducibility_LimitedWhenNoVerificationEvidenceAvailable(t *testing.T) {
	cf := findingWith("reflected_xss", "h.test", "/p", "q", models.SeverityHigh, 0.9, rawRequestResponseEvidence{})
	// Replace the structured evidence with content that fails to parse as
	// the detection.RequestResponseEvidence JSON contract at all -- the
	// only real-world way BuildEvidence can end up with no Method/URL.
	cf.Evidence = []correlation.EvidenceItem{{Kind: models.EvidenceKindRequestResponse, Content: "not json evidence at all"}}

	limits := DefaultLimits()
	items := BuildEvidence(cf, limits)
	info := buildReproductionInfo(cf, items, limits)

	if info.Level != ReproducibilityLimited {
		t.Errorf("Level = %q, want LIMITED when Method/URL are unavailable: %+v", info.Level, info)
	}
	if len(info.Notes) == 0 {
		t.Error("Notes must explain why reproduction is limited (task section 32's honesty requirement)")
	}
}

func TestReproducibility_PartialWhenParameterValueNotInURL(t *testing.T) {
	raw := rawRequestResponseEvidence{Request: "GET http://h.test/p", Response: "HTTP 200", StatusCode: 200, ResponseFragment: "ok", Parameter: "q", Payload: "x"}
	cf := findingWith("reflected_xss", "h.test", "/p", "q", models.SeverityHigh, 0.9, raw)

	limits := DefaultLimits()
	items := BuildEvidence(cf, limits)
	info := buildReproductionInfo(cf, items, limits)

	if info.Level != ReproducibilityPartial {
		t.Errorf("Level = %q, want PARTIAL when the parameter has no corresponding value in the URL: %+v", info.Level, info)
	}
}

func TestReproducibility_PartialWhenTruncated(t *testing.T) {
	cf := fixtureXSS()
	limits := DefaultLimits()
	limits.MaxReproductionBytes = 1

	items := BuildEvidence(cf, limits)
	info := buildReproductionInfo(cf, items, limits)

	if info.Level != ReproducibilityPartial {
		t.Errorf("Level = %q, want PARTIAL when SafeTestValue had to be truncated: %+v", info.Level, info)
	}
}

func TestReproducibility_PartialWhenRedactionAppliedToTheReproducedValue(t *testing.T) {
	raw := rawRequestResponseEvidence{Request: "GET http://h.test/p?token=abc123", Response: "HTTP 200", StatusCode: 200, ResponseFragment: "ok", Parameter: "token", Payload: "abc123"}
	cf := findingWith("reflected_xss", "h.test", "/p", "token", models.SeverityHigh, 0.9, raw)

	limits := DefaultLimits()
	items := BuildEvidence(cf, limits)
	info := buildReproductionInfo(cf, items, limits)

	if info.Level != ReproducibilityPartial {
		t.Errorf("Level = %q, want PARTIAL: reproducing this finding requires a value this engine redacted, so FULL would be a false claim: %+v", info.Level, info)
	}
	if containsRedactedPlaceholder(info.SafeTestValue) == false {
		t.Errorf("SafeTestValue = %q, want it to carry the redaction placeholder (never the real secret)", info.SafeTestValue)
	}
}

func TestReproducibility_NeverClaimsFullWhenSecretsWereRedacted(t *testing.T) {
	// Section 34's explicit prohibition, checked directly across every
	// sensitive field name, not just "token".
	for _, param := range []string{"password", "api_key", "secret", "session"} {
		raw := rawRequestResponseEvidence{Request: "GET http://h.test/p?" + param + "=verysecretvalue", Response: "HTTP 200", StatusCode: 200, ResponseFragment: "ok", Parameter: param, Payload: "verysecretvalue"}
		cf := findingWith("reflected_xss", "h.test", "/p", param, models.SeverityHigh, 0.9, raw)

		limits := DefaultLimits()
		items := BuildEvidence(cf, limits)
		info := buildReproductionInfo(cf, items, limits)

		if info.Level == ReproducibilityFull {
			t.Errorf("param %q: Level = FULL, want PARTIAL or LIMITED whenever the reproduced value was redacted", param)
		}
	}
}

// --- safeTestValueFromURL / containsRedactedPlaceholder --------------------

func TestSafeTestValueFromURL_ExtractsExactParameterValue(t *testing.T) {
	got := safeTestValueFromURL("http://h.test/p?a=1&q=probe-value&z=2", "q")
	if got != "probe-value" {
		t.Errorf("got %q, want %q", got, "probe-value")
	}
}

func TestSafeTestValueFromURL_EmptyParameterName(t *testing.T) {
	if got := safeTestValueFromURL("http://h.test/p?q=1", ""); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestSafeTestValueFromURL_MalformedURL(t *testing.T) {
	if got := safeTestValueFromURL("http://%zz", "q"); got != "" {
		t.Errorf("got %q, want empty for an unparseable URL", got)
	}
}

func TestContainsRedactedPlaceholder(t *testing.T) {
	if !containsRedactedPlaceholder("token=<REDACTED>") {
		t.Error("want true when the placeholder is present")
	}
	if containsRedactedPlaceholder("token=abc123") {
		t.Error("want false when the placeholder is absent")
	}
}

// --- Reproduction evidence item (task section 3's REPRODUCTION type) -------

func TestBuildReproductionEvidence_NilWhenNoMethodOrURLAvailable(t *testing.T) {
	cf := findingWith("reflected_xss", "h.test", "/p", "q", models.SeverityHigh, 0.9, rawRequestResponseEvidence{})
	cf.Evidence = []correlation.EvidenceItem{{Kind: models.EvidenceKindRequestResponse, Content: "not json"}}

	limits := DefaultLimits()
	items := BuildEvidence(cf, limits)
	items = dedupeCanonicalEvidence(items)

	for _, it := range items {
		if it.Type == EvidenceTypeReproduction {
			t.Error("a REPRODUCTION item must not be synthesized when no Method/URL is available")
		}
	}
}

func TestBuildReproductionEvidence_PresentForEveryRealFixture(t *testing.T) {
	for name, cf := range allSixFixtures() {
		items := BuildEvidence(cf, DefaultLimits())
		found := false
		for _, it := range items {
			if it.Type == EvidenceTypeReproduction {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: no REPRODUCTION evidence item produced", name)
		}
	}
}
