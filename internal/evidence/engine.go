package evidence

import (
	"sort"
	"strings"
	"time"

	"sakanner/internal/correlation"
	"sakanner/internal/risk"
	"sakanner/pkg/models"
)

// evidenceTypeForKind maps a raw correlation.EvidenceItem.Kind (which
// mirrors pkg/models.EvidenceKind, the kind every detector sets when it
// builds a models.Evidence record) onto this package's own EvidenceType
// vocabulary -- task section 3's 5 types. Phase 3.11 taught 5 of the 6
// real detectors to record a genuine EvidenceKindBaseline/EvidenceKindProbe
// item alongside their existing EvidenceKindRequestResponse item (see
// docs/phase-3-11-scan-orchestrator.md "Real evidence integration");
// this is the ONE place that distinction crosses into this package,
// kept generic (switches on the kind value, never a detector ID or
// vulnerability type) so it stays detector-independent. Anything this
// package doesn't recognize (including the pre-3.11
// EvidenceKindRequestResponse default, and EvidenceKindText) is
// classified VERIFICATION, unchanged from Phase 3.10's original,
// honest default: "the evidence supporting this conclusion," which is
// still an accurate description of what that single combined item is.
func evidenceTypeForKind(kind models.EvidenceKind) EvidenceType {
	switch kind {
	case models.EvidenceKindBaseline:
		return EvidenceTypeBaseline
	case models.EvidenceKindProbe:
		return EvidenceTypeProbe
	default:
		return EvidenceTypeVerification
	}
}

// BuildEvidence produces the normalized, sanitized, bounded evidence
// set for one CanonicalFinding -- task section 2's model, applied to
// every item in cf.Evidence (Phase 3.8's own already-deduplicated,
// already-bounded union). Output is always sorted deterministically
// (task section 19) and never exceeds limits.MaxEvidenceItemsPerFinding
// (task section 20).
func BuildEvidence(cf correlation.CanonicalFinding, limits Limits) []CanonicalEvidence {
	now := time.Now().UTC()
	var items []CanonicalEvidence

	for _, raw := range cf.Evidence {
		items = append(items, buildFromRawItem(cf, raw, limits, now))
	}

	if repro := buildReproductionEvidence(cf, items, limits, now); repro != nil {
		items = append(items, *repro)
	}

	items = dedupeCanonicalEvidence(items)
	sortCanonicalEvidence(items)

	if len(items) > limits.MaxEvidenceItemsPerFinding {
		items = items[:limits.MaxEvidenceItemsPerFinding]
	}
	return items
}

// buildFromRawItem converts one Phase 3.8 EvidenceItem into a
// CanonicalEvidence -- task section 2. Every field is sanitized (see
// redact.go/redact_body.go) BEFORE the integrity hash is computed, so
// the hash never encodes a secret (task section 15's implicit
// guarantee, made explicit here).
func buildFromRawItem(cf correlation.CanonicalFinding, item correlation.EvidenceItem, limits Limits, now time.Time) CanonicalEvidence {
	evType := evidenceTypeForKind(item.Kind)

	raw, ok := parseRawEvidence(item.Content)
	if !ok {
		// Plain-text fallback (task section 2's model still applies --
		// see parse.go's parseRawEvidence doc comment): bound BEFORE
		// sanitizing (see buildResponseEvidence's doc comment for why),
		// then treat the whole content as a sanitized Observation.
		bounded, truncated := truncate(item.Content, limits.MaxMetadataBytes)
		obs := redactText(bounded)
		return finishCanonicalEvidence(cf, evType, RequestEvidence{}, ResponseEvidence{Truncated: truncated}, obs, "", nil, "", now)
	}

	method, reqURL := parseMethodAndPath(raw.Request)
	if method == "" {
		method = cf.HTTP.Method
	}
	reqURL, urlTruncated := truncate(reqURL, limits.MaxRequestBytes)
	reqURL = redactURL(reqURL)

	reqEv := RequestEvidence{
		Method:    method,
		URL:       reqURL,
		Parameter: raw.Parameter,
		Location:  cf.HTTP.Location,
		Headers:   truncateHeaderMap(redactHeaders(raw.Headers), limits.MaxHeaderBytes),
		Truncated: urlTruncated,
	}

	respEv := buildResponseEvidence(raw, limits)

	obsBounded, obsTruncated := truncate(raw.Observation, limits.MaxMetadataBytes)
	obs := redactText(obsBounded)
	if obsTruncated {
		respEv.Truncated = true
	}
	reasonBounded, _ := truncate(raw.Reason, limits.MaxMetadataBytes)
	verification := redactText(reasonBounded)

	// DetectorFields are parsed from the ALREADY-BOUNDED Observation
	// (obsBounded, not raw.Observation) -- same reasoning as above, and
	// harmless: a detector's real Observation string is always far
	// smaller than MaxMetadataBytes in practice (see each Phase 3.x
	// detector's own evidenceFragmentRadius bound), so truncation here
	// only ever matters for adversarial/oversized input.
	detectorFields := parseDetectorFields(obsBounded)
	for k, v := range detectorFields {
		if isSensitiveFieldName(k) {
			detectorFields[k] = redactedPlaceholder
		} else {
			detectorFields[k] = redactText(v)
		}
	}

	return finishCanonicalEvidence(cf, evType, reqEv, respEv, obs, verification, detectorFields, authContextOf(raw.Headers), now)
}

// buildResponseEvidence bounds raw.ResponseFragment to
// limits.MaxResponseExcerptBytes BEFORE running any regex-based
// sanitization over it -- task section 21's "no memory explosion"
// extended to CPU cost, not just stored size: sanitization work always
// scales with the CONFIGURED LIMIT, never with however large a
// response a target happened to send. A secret whose value straddles
// the truncation boundary is still safe: if the cut lands inside the
// VALUE, whatever fragment of it remains is still recognized and
// redacted (the pattern only requires seeing a key, a separator, and
// SOME following value text); if the cut lands inside the KEY name
// itself, the fragment matches nothing and is left as harmless partial
// text, never a real secret.
//
// Binary detection (looksBinary) still runs on the FULL fragment,
// never the truncated one -- it's a simple linear byte scan (no
// regex), and truncating first could clip away the very bytes that
// would have identified genuinely binary content as such.
func buildResponseEvidence(raw rawRequestResponseEvidence, limits Limits) ResponseEvidence {
	contentType := raw.Headers["Content-Type"]
	if contentType == "" {
		contentType = raw.Headers["content-type"]
	}

	if isBinaryContentType(contentType) || looksBinary(raw.ResponseFragment) {
		return ResponseEvidence{
			StatusCode:  raw.StatusCode,
			ContentType: contentType,
			Headers:     truncateHeaderMap(redactHeaders(raw.Headers), limits.MaxHeaderBytes),
			Binary:      buildBinarySummary(contentType, raw.ResponseFragment),
		}
	}

	bounded, truncated := truncate(raw.ResponseFragment, limits.MaxResponseExcerptBytes)
	excerpt := redactBody(contentType, bounded)
	if contentType == "" {
		excerpt = redactText(bounded)
	}

	return ResponseEvidence{
		StatusCode:  raw.StatusCode,
		ContentType: contentType,
		Headers:     truncateHeaderMap(redactHeaders(raw.Headers), limits.MaxHeaderBytes),
		Excerpt:     excerpt,
		Truncated:   truncated,
	}
}

func truncateHeaderMap(headers map[string]string, maxTotal int) map[string]string {
	if headers == nil {
		return nil
	}
	out := make(map[string]string, len(headers))
	budget := maxTotal
	for k, v := range headers {
		if budget <= 0 {
			break
		}
		val, _ := truncate(v, budget)
		out[k] = val
		budget -= len(val)
	}
	return out
}

// authContextOf reports safe, non-secret authentication metadata only
// -- task section 33. Never the header's own value.
func authContextOf(headers map[string]string) string {
	for k := range headers {
		lk := strings.ToLower(k)
		if strings.Contains(lk, "auth") || lk == "cookie" {
			return "authenticated"
		}
	}
	return ""
}

func finishCanonicalEvidence(cf correlation.CanonicalFinding, t EvidenceType, req RequestEvidence, resp ResponseEvidence, observation, verification string, detectorFields map[string]string, authCtx string, now time.Time) CanonicalEvidence {
	input := canonicalHashInput{
		FindingID:      cf.FindingID,
		Type:           t,
		Request:        req,
		Response:       resp,
		Observation:    observation,
		Verification:   verification,
		Confidence:     cf.Confidence,
		DetectorFields: detectorFields,
	}
	return CanonicalEvidence{
		EvidenceID:            evidenceID(input),
		FindingID:             cf.FindingID,
		Type:                  t,
		Request:               req,
		Response:              resp,
		Observation:           observation,
		Verification:          verification,
		Confidence:            cf.Confidence,
		DetectorFields:        detectorFields,
		AuthenticationContext: authCtx,
		IntegrityHash:         integrityHash(input),
		CollectedAt:           now,
	}
}

// dedupeCanonicalEvidence collapses items sharing the SAME EvidenceID
// (derived from canonical, identity-bearing content -- task sections
// 17-18) into one, keeping the first occurrence.
func dedupeCanonicalEvidence(items []CanonicalEvidence) []CanonicalEvidence {
	seen := make(map[string]bool, len(items))
	out := make([]CanonicalEvidence, 0, len(items))
	for _, it := range items {
		if seen[it.EvidenceID] {
			continue
		}
		seen[it.EvidenceID] = true
		out = append(out, it)
	}
	return out
}

// sortCanonicalEvidence orders items by Type (task section 19's
// BASELINE/PROBE/OBSERVATION/VERIFICATION/REPRODUCTION order), then by
// EvidenceID -- both fields excluded from timestamp/randomness, so
// repeated runs against identical input always produce the identical
// order.
func sortCanonicalEvidence(items []CanonicalEvidence) {
	sort.SliceStable(items, func(i, j int) bool {
		if typeRank[items[i].Type] != typeRank[items[j].Type] {
			return typeRank[items[i].Type] < typeRank[items[j].Type]
		}
		return items[i].EvidenceID < items[j].EvidenceID
	})
}

// BuildPackage assembles task section 29's FindingPackage: the
// CanonicalFinding and risk.Assessment passed through unchanged (this
// package never modifies either -- see docs/phase-3-10-evidence-reproducibility.md
// "Detector independence"), plus this phase's own evidence,
// reproduction, summary, explanation, and limitations.
func BuildPackage(cf correlation.CanonicalFinding, assessment risk.Assessment, limits Limits) FindingPackage {
	items := BuildEvidence(cf, limits)
	repro := buildReproductionInfo(cf, items, limits)

	var verificationText, reasonText string
	for _, it := range items {
		if it.Type == EvidenceTypeVerification {
			verificationText = it.Observation
			reasonText = it.Verification
			break
		}
	}

	return FindingPackage{
		Finding:       cf,
		Risk:          assessment,
		Evidence:      items,
		Reproduction:  repro,
		Summary:       Summarize(cf, verificationText),
		WhyVulnerable: WhyVulnerable(cf, reasonText),
		Limitations:   limitationsFor(cf, items, repro),
	}
}

// limitationsFor generates task section 32's honest, deterministic
// limitations[] list from structural facts about what evidence is
// actually present -- never hiding uncertainty.
func limitationsFor(cf correlation.CanonicalFinding, items []CanonicalEvidence, repro ReproductionInfo) []string {
	var out []string
	hasBaselineItem := false
	hasDifferential := false
	for _, it := range items {
		if it.Type == EvidenceTypeBaseline {
			hasBaselineItem = true
		}
		if it.Baseline != nil {
			hasDifferential = true
		}
		if it.Response.Truncated || it.Request.Truncated {
			out = append(out, "response or request evidence was truncated to stay within evidence limits")
			break
		}
	}
	if !hasBaselineItem {
		// True for reflected_xss (no control request exists to record --
		// see docs/phase-3-11-scan-orchestrator.md "Real evidence
		// integration") and for any detector whose evidence predates
		// Phase 3.11's baseline-recording change.
		out = append(out, "no separate baseline request/response was persisted for this finding; verification relies on the detector's own internal check")
	}
	if !hasDifferential {
		// A structured, machine-computed baseline-vs-observed diff
		// (status/length comparison, see Diff() in reproduction.go) is a
		// distinct, stronger claim than "a baseline item exists" -- no
		// real detector computes and attaches one today even where a
		// baseline item is present, since each detector's own
		// baseline-vs-probe comparison logic runs internally and only its
		// conclusion (not a structured diff) survives into evidence.
		out = append(out, "no structured baseline-vs-observed differential was computed for this finding's evidence")
	}
	if repro.Level != ReproducibilityFull {
		out = append(out, "reproduction information is incomplete; see reproduction.level")
	}
	return out
}
