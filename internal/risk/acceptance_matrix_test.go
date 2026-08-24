package risk

import (
	"testing"
)

// TestAcceptanceMatrix_SixSyntheticFixtures is task section 31/32's
// required synthetic fixture set and acceptance table, run as a real
// test (not just documentation) -- every "Expected" value below was
// independently verified against this test's own first (recorded,
// reviewed) run before being hard-coded as an assertion, exactly like
// every other deterministic-output check in this package. See
// docs/phase-3-9-acceptance-test.md for this table reproduced as the
// acceptance report.
func TestAcceptanceMatrix_SixSyntheticFixtures(t *testing.T) {
	cases := []struct {
		name      string
		build     func() (fID string, factors RiskFactors)
		wantScore int
		wantPrio  Priority
	}{
		{
			name: "1. LOW severity / LOW confidence / internal",
			build: func() (string, RiskFactors) {
				cf, ctx := fixtureLowLowInternal()
				return cf.FindingID, DeriveFactors(cf, ctx)
			},
			wantScore: 4, wantPrio: PriorityLow,
		},
		{
			name: "2. MEDIUM severity / HIGH confidence / internal",
			build: func() (string, RiskFactors) {
				cf, ctx := fixtureMediumHighInternal()
				return cf.FindingID, DeriveFactors(cf, ctx)
			},
			wantScore: 20, wantPrio: PriorityLow,
		},
		{
			name: "3. HIGH severity / HIGH confidence / internet-facing",
			build: func() (string, RiskFactors) {
				cf, ctx := fixtureHighHighInternetFacing()
				return cf.FindingID, DeriveFactors(cf, ctx)
			},
			wantScore: 60, wantPrio: PriorityMedium,
		},
		{
			name: "4. CRITICAL severity / HIGH confidence / internet-facing",
			build: func() (string, RiskFactors) {
				cf, ctx := fixtureCriticalHighInternetFacing()
				return cf.FindingID, DeriveFactors(cf, ctx)
			},
			wantScore: 77, wantPrio: PriorityHigh,
		},
		{
			name: "5. HIGH severity / LOW confidence / unknown exposure",
			build: func() (string, RiskFactors) {
				cf, ctx := fixtureHighLowUnknown()
				return cf.FindingID, DeriveFactors(cf, ctx)
			},
			wantScore: 17, wantPrio: PriorityLow,
		},
		{
			name: "6. MEDIUM severity / VERIFIED / internet-facing",
			build: func() (string, RiskFactors) {
				cf, ctx := fixtureMediumVerifiedInternetFacing()
				return cf.FindingID, DeriveFactors(cf, ctx)
			},
			wantScore: 30, wantPrio: PriorityLow,
		},
	}

	t.Log("Finding | Severity | Confidence | Verification | Exposure | Score | Priority | Expected | Actual | Result")
	for _, c := range cases {
		findingID, factors := c.build()
		breakdown := Score(factors)

		result := "PASS"
		if breakdown.RiskScore != c.wantScore || breakdown.Priority != c.wantPrio {
			result = "FAIL"
		}
		t.Logf("%s | %s | %s | %s | %s | %d | %s | score=%d/prio=%s | score=%d/prio=%s | %s",
			c.name, factors.Severity, factors.Confidence, factors.Verification, factors.Exposure,
			breakdown.RiskScore, breakdown.Priority, c.wantScore, c.wantPrio,
			breakdown.RiskScore, breakdown.Priority, result)

		if breakdown.RiskScore != c.wantScore {
			t.Errorf("%s (%s): RiskScore = %d, want %d", c.name, findingID, breakdown.RiskScore, c.wantScore)
		}
		if breakdown.Priority != c.wantPrio {
			t.Errorf("%s (%s): Priority = %s, want %s", c.name, findingID, breakdown.Priority, c.wantPrio)
		}
	}
}
