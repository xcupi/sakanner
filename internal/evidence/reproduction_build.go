package evidence

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"sakanner/internal/correlation"
)

// buildReproductionInfo assembles task section 12's structured
// reproduction data from the VERIFICATION-typed CanonicalEvidence
// already built (never from raw, unsanitized detector output again --
// this reuses what BuildEvidence already sanitized and bounded).
func buildReproductionInfo(cf correlation.CanonicalFinding, items []CanonicalEvidence, limits Limits) ReproductionInfo {
	var verification *CanonicalEvidence
	for i := range items {
		if items[i].Type == EvidenceTypeVerification {
			verification = &items[i]
			break
		}
	}

	info := ReproductionInfo{
		Parameter:        cf.HTTP.Parameter,
		ExpectedBehavior: "input is treated as data, never interpreted or executed",
		Level:            ReproducibilityLimited,
	}
	if verification == nil {
		info.Notes = append(info.Notes, "no verification evidence available to derive reproduction steps from")
		return info
	}

	info.Method = verification.Request.Method
	info.URL = verification.Request.URL
	info.ObservedBehavior = verification.Verification
	if info.ObservedBehavior == "" {
		info.ObservedBehavior = verification.Observation
	}

	// SafeTestValue is the parameter value ALREADY present in the
	// sanitized URL -- never a newly-generated payload (task section
	// 13/14: reproduction proves the finding, it never invents a fresh
	// exploit). Extracted generically from the URL's own query string.
	info.SafeTestValue = safeTestValueFromURL(info.URL, info.Parameter)

	value, truncated := truncate(info.SafeTestValue, limits.MaxReproductionBytes)
	info.SafeTestValue = value

	info.Level = reproducibilityLevelOf(info, verification, truncated)
	if info.Level == ReproducibilityLimited && info.Method == "" && info.URL == "" {
		// The only item found was itself the "raw evidence didn't parse"
		// fallback (see buildFromRawItem) -- structurally indistinguishable
		// from "no verification evidence" for reproduction purposes, so it
		// gets the same explanatory note (task section 32).
		info.Notes = append(info.Notes, "no verification evidence available to derive reproduction steps from")
	}
	return info
}

// buildReproductionEvidence wraps the SAME reproduction data as one
// more CanonicalEvidence item, type REPRODUCTION -- task section 3's
// type enum lists REPRODUCTION as one of the 5 evidence kinds, so it
// is represented both as its own typed evidence item (here) and as the
// separate, more structured top-level ReproductionInfo field (task
// section 29's FindingPackage.Reproduction) -- two views of the same
// underlying, already-sanitized data, never two independently-derived
// (and therefore possibly inconsistent) sources of truth.
func buildReproductionEvidence(cf correlation.CanonicalFinding, items []CanonicalEvidence, limits Limits, now time.Time) *CanonicalEvidence {
	info := buildReproductionInfo(cf, items, limits)
	if info.Method == "" && info.URL == "" {
		return nil
	}

	req := RequestEvidence{Method: info.Method, URL: info.URL, Parameter: info.Parameter, Location: cf.HTTP.Location}
	obs := fmt.Sprintf("expected=%s observed=%s", info.ExpectedBehavior, info.ObservedBehavior)
	obs, truncated := truncate(obs, limits.MaxMetadataBytes)
	resp := ResponseEvidence{Truncated: truncated}

	ce := finishCanonicalEvidence(cf, EvidenceTypeReproduction, req, resp, obs, "", nil, "", now)
	return &ce
}

// safeTestValueFromURL extracts parameter's own value from URL's query
// string -- generic string/URL parsing only, never detector-specific
// knowledge of what the value "means."
func safeTestValueFromURL(rawURL, parameter string) string {
	if parameter == "" {
		return ""
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Query().Get(parameter)
}

// reproducibilityLevelOf classifies task section 34's FULL/PARTIAL/
// LIMITED from structural facts: FULL requires every required field
// present AND nothing redacted or truncated along the way; PARTIAL
// means some of that is missing; LIMITED means essentially nothing
// usable survived.
func reproducibilityLevelOf(info ReproductionInfo, verification *CanonicalEvidence, truncated bool) ReproducibilityLevel {
	if info.Method == "" || info.URL == "" {
		return ReproducibilityLimited
	}
	if info.Parameter == "" || info.SafeTestValue == "" {
		return ReproducibilityPartial
	}
	if truncated || verification.Request.Truncated || verification.Response.Truncated {
		return ReproducibilityPartial
	}
	if containsRedactedPlaceholder(info.URL) || containsRedactedPlaceholder(info.SafeTestValue) {
		return ReproducibilityPartial
	}
	return ReproducibilityFull
}

func containsRedactedPlaceholder(s string) bool {
	return strings.Contains(s, redactedPlaceholder)
}
