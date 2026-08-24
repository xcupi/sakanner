package scope

import (
	"context"
	"net"
	"testing"

	"sakanner/pkg/models"
)

func rule(typ models.ScopeRuleType, action models.ScopeAction, value string) models.ScopeRule {
	return models.ScopeRule{ID: value + string(action), Type: typ, Action: action, Value: value}
}

func TestCheckHost_DomainSuffix(t *testing.T) {
	v := NewValidator([]models.ScopeRule{
		rule(models.ScopeRuleDomainSuffix, models.ScopeActionAllow, "example.com"),
	}, false)

	tests := []struct {
		host    string
		allowed bool
	}{
		{"example.com", true},
		{"www.example.com", true},
		{"deep.sub.example.com", true},
		{"evilexample.com", false}, // must not match on bare suffix, no dot boundary
		{"example.com.evil.com", false},
		{"notexample.com", false},
	}
	for _, tt := range tests {
		d, err := v.CheckHost(context.Background(), tt.host)
		if err != nil {
			t.Fatalf("CheckHost(%q): %v", tt.host, err)
		}
		if d.Allowed != tt.allowed {
			t.Errorf("CheckHost(%q).Allowed = %v, want %v", tt.host, d.Allowed, tt.allowed)
		}
	}
}

func TestCheckHost_ExactHost(t *testing.T) {
	v := NewValidator([]models.ScopeRule{
		rule(models.ScopeRuleExactHost, models.ScopeActionAllow, "api.example.com"),
	}, false)

	d, _ := v.CheckHost(context.Background(), "api.example.com")
	if !d.Allowed {
		t.Errorf("expected exact host match to be allowed")
	}
	d, _ = v.CheckHost(context.Background(), "other.example.com")
	if d.Allowed {
		t.Errorf("expected non-matching host to be denied")
	}
}

func TestCheckIP_CIDR(t *testing.T) {
	v := NewValidator([]models.ScopeRule{
		rule(models.ScopeRuleCIDR, models.ScopeActionAllow, "203.0.113.0/24"),
	}, false)

	d, err := v.CheckIP(context.Background(), net.ParseIP("203.0.113.42"))
	if err != nil {
		t.Fatalf("CheckIP: %v", err)
	}
	if !d.Allowed {
		t.Errorf("expected IP in CIDR range to be allowed")
	}

	d, _ = v.CheckIP(context.Background(), net.ParseIP("203.0.114.1"))
	if d.Allowed {
		t.Errorf("expected IP outside CIDR range to be denied")
	}
}

func TestCheckIP_CIDR_IPv6(t *testing.T) {
	v := NewValidator([]models.ScopeRule{
		rule(models.ScopeRuleCIDR, models.ScopeActionAllow, "2001:db8::/32"),
	}, false)

	d, err := v.CheckIP(context.Background(), net.ParseIP("2001:db8::1"))
	if err != nil {
		t.Fatalf("CheckIP: %v", err)
	}
	if !d.Allowed {
		t.Errorf("expected IPv6 in CIDR range to be allowed")
	}
}

func TestDenyOverridesAllow(t *testing.T) {
	v := NewValidator([]models.ScopeRule{
		rule(models.ScopeRuleDomainSuffix, models.ScopeActionAllow, "example.com"),
		rule(models.ScopeRuleExactHost, models.ScopeActionDeny, "internal.example.com"),
	}, false)

	d, _ := v.CheckHost(context.Background(), "www.example.com")
	if !d.Allowed {
		t.Errorf("expected www.example.com to be allowed")
	}
	d, _ = v.CheckHost(context.Background(), "internal.example.com")
	if d.Allowed {
		t.Errorf("expected internal.example.com to be denied despite domain-suffix allow")
	}
}

func TestDefaultDeny_NoMatchingRule(t *testing.T) {
	v := NewValidator([]models.ScopeRule{
		rule(models.ScopeRuleDomainSuffix, models.ScopeActionAllow, "example.com"),
	}, false)

	d, _ := v.CheckHost(context.Background(), "totallyunrelated.org")
	if d.Allowed {
		t.Errorf("expected unrelated host with no matching rule to be denied by default")
	}
}

func TestReservedRanges_DeniedByDefault(t *testing.T) {
	// Broad allow-everything CIDR rules must not override reserved-range
	// denial -- this is the defense-in-depth property.
	v := NewValidator([]models.ScopeRule{
		rule(models.ScopeRuleCIDR, models.ScopeActionAllow, "0.0.0.0/0"),
		rule(models.ScopeRuleCIDR, models.ScopeActionAllow, "::/0"),
	}, false)

	reserved := []string{
		"127.0.0.1",       // loopback
		"169.254.169.254", // cloud metadata
		"169.254.1.1",     // link-local
		"224.0.0.1",       // multicast
		"0.0.0.0",         // unspecified
		"::1",             // IPv6 loopback
		"fe80::1",         // IPv6 link-local
		"ff02::1",         // IPv6 multicast
	}
	for _, ip := range reserved {
		d, err := v.CheckIP(context.Background(), net.ParseIP(ip))
		if err != nil {
			t.Fatalf("CheckIP(%q): %v", ip, err)
		}
		if d.Allowed {
			t.Errorf("CheckIP(%q).Allowed = true, want false (reserved range must be denied even under allow-all CIDR)", ip)
		}
	}
}

func TestReservedRanges_IPv4MappedIPv6BypassAttempt(t *testing.T) {
	// A classic SSRF/scope-bypass technique: encoding a loopback or
	// metadata IPv4 address in its IPv6-mapped form, hoping a naive
	// reserved-range check (e.g. one that only inspects raw bytes
	// without unmapping) fails to recognize it.
	v := NewValidator([]models.ScopeRule{
		rule(models.ScopeRuleCIDR, models.ScopeActionAllow, "::/0"),
		rule(models.ScopeRuleCIDR, models.ScopeActionAllow, "0.0.0.0/0"),
	}, false)

	mapped := []string{
		"::ffff:127.0.0.1",         // dotted-quad form
		"::ffff:7f00:1",            // hex form of the same address
		"0:0:0:0:0:ffff:127.0.0.1", // fully expanded
		"::ffff:169.254.169.254",   // cloud metadata via IPv4-mapped IPv6
		"::ffff:0.0.0.0",           // unspecified via IPv4-mapped IPv6
	}
	for _, ip := range mapped {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			t.Fatalf("net.ParseIP(%q) returned nil -- test input itself is invalid", ip)
		}
		d, err := v.CheckIP(context.Background(), parsed)
		if err != nil {
			t.Fatalf("CheckIP(%q): %v", ip, err)
		}
		if d.Allowed {
			t.Errorf("CheckIP(%q).Allowed = true, want false -- IPv4-mapped IPv6 must not bypass the reserved-range deny-list", ip)
		}
	}
}

func TestReservedRanges_CanBeOptedOut(t *testing.T) {
	v := NewValidator([]models.ScopeRule{
		rule(models.ScopeRuleExactHost, models.ScopeActionAllow, "127.0.0.1"),
	}, true) // allowReserved = true

	d, err := v.CheckIP(context.Background(), net.ParseIP("127.0.0.1"))
	if err != nil {
		t.Fatalf("CheckIP: %v", err)
	}
	if !d.Allowed {
		t.Errorf("expected loopback to be allowed when allowReserved=true and an explicit rule matches")
	}
}

func TestCheckHost_BareIPDelegatesToCheckIP(t *testing.T) {
	v := NewValidator([]models.ScopeRule{
		rule(models.ScopeRuleCIDR, models.ScopeActionAllow, "203.0.113.0/24"),
	}, false)

	d, err := v.CheckHost(context.Background(), "203.0.113.5")
	if err != nil {
		t.Fatalf("CheckHost: %v", err)
	}
	if !d.Allowed {
		t.Errorf("expected bare IP passed to CheckHost to be evaluated via CIDR rules")
	}

	// A reserved IP passed as a "host" string must still be denied.
	d, _ = v.CheckHost(context.Background(), "127.0.0.1")
	if d.Allowed {
		t.Errorf("expected loopback IP passed as host string to be denied")
	}
}

func TestCheckHost_EmptyHost(t *testing.T) {
	v := NewValidator(nil, false)
	d, err := v.CheckHost(context.Background(), "")
	if err != nil {
		t.Fatalf("CheckHost: %v", err)
	}
	if d.Allowed {
		t.Errorf("expected empty host to be denied")
	}
}

func TestCheckIP_NilIP(t *testing.T) {
	v := NewValidator(nil, false)
	d, err := v.CheckIP(context.Background(), nil)
	if err != nil {
		t.Fatalf("CheckIP: %v", err)
	}
	if d.Allowed {
		t.Errorf("expected nil IP to be denied")
	}
}

func TestCheckHost_ContextCancelled(t *testing.T) {
	v := NewValidator(nil, false)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := v.CheckHost(ctx, "example.com")
	if err == nil {
		t.Errorf("expected error from cancelled context")
	}
}

func TestCheckResolved_DomainSuffixAuthorizesNormalIP(t *testing.T) {
	v := NewValidator([]models.ScopeRule{
		rule(models.ScopeRuleDomainSuffix, models.ScopeActionAllow, "example.com"),
	}, false)

	d, err := v.CheckResolved(context.Background(), "sub.example.com", net.ParseIP("203.0.113.5"))
	if err != nil {
		t.Fatalf("CheckResolved: %v", err)
	}
	if !d.Allowed {
		t.Errorf("expected a domain-suffix rule to authorize the dial to its resolved IP, got denied: %s", d.Reason)
	}
}

func TestCheckResolved_DomainSuffixDoesNotBypassReservedRangeOnRebind(t *testing.T) {
	// This is the core DNS-rebinding protection: a hostname authorized by
	// a domain_suffix rule must NOT be allowed to dial a reserved/
	// dangerous address just because the hostname matched.
	v := NewValidator([]models.ScopeRule{
		rule(models.ScopeRuleDomainSuffix, models.ScopeActionAllow, "example.com"),
	}, false)

	tests := []string{"127.0.0.1", "169.254.169.254", "::1"}
	for _, ip := range tests {
		d, err := v.CheckResolved(context.Background(), "sub.example.com", net.ParseIP(ip))
		if err != nil {
			t.Fatalf("CheckResolved(%q): %v", ip, err)
		}
		if d.Allowed {
			t.Errorf("CheckResolved(sub.example.com -> %q).Allowed = true, want false (reserved range must win over a matching hostname rule)", ip)
		}
	}
}

func TestCheckResolved_ReservedRangeAllowedWhenOptedOutAndHostnameMatches(t *testing.T) {
	v := NewValidator([]models.ScopeRule{
		rule(models.ScopeRuleDomainSuffix, models.ScopeActionAllow, "example.com"),
	}, true) // allowReserved = true

	d, err := v.CheckResolved(context.Background(), "sub.example.com", net.ParseIP("127.0.0.1"))
	if err != nil {
		t.Fatalf("CheckResolved: %v", err)
	}
	if !d.Allowed {
		t.Errorf("expected reserved-range opt-out plus a matching hostname rule to allow the dial")
	}
}

func TestCheckResolved_UnmatchedHostnameFallsBackToIPRule(t *testing.T) {
	// Covers e.g. a CDN-fronted domain whose resolved IP is separately
	// authorized by a CIDR rule even though the hostname itself isn't
	// named by any rule.
	v := NewValidator([]models.ScopeRule{
		rule(models.ScopeRuleCIDR, models.ScopeActionAllow, "203.0.113.0/24"),
	}, false)

	d, err := v.CheckResolved(context.Background(), "unrelated.example.net", net.ParseIP("203.0.113.9"))
	if err != nil {
		t.Fatalf("CheckResolved: %v", err)
	}
	if !d.Allowed {
		t.Errorf("expected the IP-level CIDR rule to authorize the dial when the hostname matches no rule")
	}
}

func TestCheckResolved_ExplicitHostnameDenyIsTerminal(t *testing.T) {
	// An explicit deny on the hostname must not be overridden by an
	// otherwise-matching IP-level allow rule.
	v := NewValidator([]models.ScopeRule{
		rule(models.ScopeRuleDomainSuffix, models.ScopeActionDeny, "example.com"),
		rule(models.ScopeRuleCIDR, models.ScopeActionAllow, "203.0.113.0/24"),
	}, false)

	d, err := v.CheckResolved(context.Background(), "sub.example.com", net.ParseIP("203.0.113.9"))
	if err != nil {
		t.Fatalf("CheckResolved: %v", err)
	}
	if d.Allowed {
		t.Errorf("expected explicit hostname deny to be terminal despite a matching IP-level allow rule")
	}
}

func TestCheckResolved_NilIP(t *testing.T) {
	v := NewValidator(nil, false)
	d, err := v.CheckResolved(context.Background(), "example.com", nil)
	if err != nil {
		t.Fatalf("CheckResolved: %v", err)
	}
	if d.Allowed {
		t.Errorf("expected nil IP to be denied")
	}
}

func TestCheckHost_CIDRNotationAgainstCIDRRule(t *testing.T) {
	v := NewValidator([]models.ScopeRule{
		rule(models.ScopeRuleCIDR, models.ScopeActionAllow, "203.0.113.0/24"),
	}, false)

	tests := []struct {
		cidr    string
		allowed bool
	}{
		{"203.0.113.0/24", true},   // exact match
		{"203.0.113.0/28", true},   // sub-range of an authorized range
		{"203.0.113.0/23", false},  // broader than the authorized range
		{"198.51.100.0/24", false}, // disjoint range
	}
	for _, tt := range tests {
		d, err := v.CheckHost(context.Background(), tt.cidr)
		if err != nil {
			t.Fatalf("CheckHost(%q): %v", tt.cidr, err)
		}
		if d.Allowed != tt.allowed {
			t.Errorf("CheckHost(%q).Allowed = %v, want %v", tt.cidr, d.Allowed, tt.allowed)
		}
	}
}

func TestSnapshotIsolation(t *testing.T) {
	rules := []models.ScopeRule{
		rule(models.ScopeRuleDomainSuffix, models.ScopeActionAllow, "example.com"),
	}
	v := NewValidator(rules, false)

	// Mutating the original slice after construction must not affect the
	// validator -- it must have taken its own copy at scan-job start.
	rules[0].Action = models.ScopeActionDeny

	d, _ := v.CheckHost(context.Background(), "example.com")
	if !d.Allowed {
		t.Errorf("expected validator to be unaffected by post-construction mutation of the source rule slice")
	}
}
