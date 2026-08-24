package idoractive

import (
	"bytes"
	"strings"

	"sakanner/internal/mutation"
)

// minSuccessfulBodyBytes is the bound below which a 2xx response is
// treated as an "empty object" (task section 15's own adversarial
// case), never as evidence of real object content -- deliberately
// small: this only needs to exclude a near-empty body ("{}", "OK",
// a blank page), not judge genuine content richness.
const minSuccessfulBodyBytes = 8

// loginPageSignatures is a small, deliberately narrow, case-
// insensitive substring list identifying a login/re-authentication
// page -- mirrors every other narrow, explicit signature list already
// established in this codebase (e.g. internal/detectors/sqliactive's
// dbErrorPatterns). A false negative here (a login page this list
// doesn't recognize) is the safe failure direction: it would be
// treated as "successful," but would then almost always fail the
// baseline-vs-known-bad structural distinction anyway (every denied
// request reaching the same login page looks identical), so nothing
// downstream trusts this check alone.
var loginPageSignatures = []string{
	"log in", "login", "sign in", "session expired", "please authenticate",
}

// looksLikeSuccessfulObjectResponse reports whether resp looks like it
// carries real, successfully-authorized object content -- never
// status-code alone (task section 10: "200 is not automatically
// authorized"). Used to gate all three probes in Detect: the baseline
// and cross-test responses must both pass this before a finding is
// ever possible.
func looksLikeSuccessfulObjectResponse(resp mutation.Response) bool {
	if resp.Outcome != mutation.OutcomeSuccess {
		return false
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false
	}
	body := bytes.TrimSpace(resp.Body)
	if len(body) < minSuccessfulBodyBytes {
		return false
	}
	lower := strings.ToLower(string(body))
	for _, sig := range loginPageSignatures {
		if strings.Contains(lower, sig) {
			return false
		}
	}
	return true
}

// bodyContainsValue reports whether resp's body echoes value verbatim
// -- opportunistic, additional ownership-corroborating evidence (task
// section 11), never required for a finding. Mirrors
// internal/detectors/idor's own isResourceSpecific idea, adapted to
// mutation.Response.
func bodyContainsValue(resp mutation.Response, value string) bool {
	return value != "" && bytes.Contains(resp.Body, []byte(value))
}
