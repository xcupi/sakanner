// Package scope is sakanner's authorization boundary. Validator is the
// single authority for whether the platform is allowed to touch a given
// host or IP address, and every module that opens a network connection
// (internal/ports, internal/http) must call it immediately before each
// dial -- not just once at the start of a scan.
//
// Rule precedence is fail-closed: an explicit deny always overrides an
// allow, and a host/IP that matches no rule at all is denied. Reserved IP
// ranges (loopback, link-local, cloud metadata, multicast, unspecified)
// are denied by default regardless of user rules, since a broad allow
// CIDR or a rebound DNS answer could otherwise steer a request at them.
package scope

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"sakanner/pkg/models"
)

// Decision is the outcome of a scope check, including enough detail to
// audit-log even an allowed request.
type Decision struct {
	Allowed     bool
	MatchedRule *models.ScopeRule
	Reason      string
}

// Validator decides whether a host or IP is in authorized scope.
type Validator interface {
	CheckHost(ctx context.Context, host string) (Decision, error)
	CheckIP(ctx context.Context, ip net.IP) (Decision, error)

	// CheckResolved is the check every dial (ports/http) must perform:
	// it combines hostname-based authorization (domain_suffix/exact_host
	// rules, via CheckHost) with IP-level protection (the reserved-range
	// deny-list, and CIDR/exact-IP rules as a fallback when the hostname
	// itself doesn't match anything). Neither CheckHost nor CheckIP
	// alone is sufficient at dial time: CheckHost has no visibility into
	// the concrete resolved address (so it can't catch a domain-suffix-
	// authorized name that DNS-rebound to a reserved/dangerous IP), and
	// CheckIP has no visibility into domain-based rules at all (so it
	// would deny every dial for the common case of a domain_suffix
	// scope rule, since the resolved IP never itself appears in any
	// rule).
	CheckResolved(ctx context.Context, hostname string, ip net.IP) (Decision, error)
}

type validator struct {
	rules         []models.ScopeRule
	allowReserved bool
}

// NewValidator builds a Validator from a fixed set of rules. Callers
// should pass a snapshot taken at scan-job start (see orchestration), not
// a live-editable slice, so a running scan isn't affected by concurrent
// rule edits.
//
// If allowReserved is false (the recommended default), reserved IP ranges
// are always denied regardless of rules.
func NewValidator(rules []models.ScopeRule, allowReserved bool) Validator {
	cp := make([]models.ScopeRule, len(rules))
	copy(cp, rules)
	return &validator{rules: cp, allowReserved: allowReserved}
}

// CheckHost evaluates a hostname against the rule set. It does not
// resolve the hostname -- resolved IPs must additionally pass CheckIP
// before any connection is opened.
func (v *validator) CheckHost(ctx context.Context, host string) (Decision, error) {
	if err := ctx.Err(); err != nil {
		return Decision{}, err
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" {
		return Decision{Allowed: false, Reason: "empty host"}, nil
	}

	// A bare IP passed as a "host" (e.g. from a Target of type IP) is
	// checked as an IP so CIDR rules and reserved-range denial apply.
	if ip := net.ParseIP(host); ip != nil {
		return v.CheckIP(ctx, ip)
	}

	// A CIDR-notation "host" (e.g. the literal value of a Target of type
	// CIDR, checked once up front before any per-IP dial happens) is
	// authorized only if some CIDR rule covers the *entire* range --
	// matching a single address within it is not enough to authorize
	// scanning the whole block.
	if _, targetNet, err := net.ParseCIDR(host); err == nil {
		return v.evaluate(func(r models.ScopeRule) bool {
			if r.Type != models.ScopeRuleCIDR {
				return false
			}
			_, ruleNet, err := net.ParseCIDR(r.Value)
			if err != nil {
				return false
			}
			ruleOnes, ruleBits := ruleNet.Mask.Size()
			targetOnes, targetBits := targetNet.Mask.Size()
			return ruleBits == targetBits && ruleOnes <= targetOnes && ruleNet.Contains(targetNet.IP)
		}), nil
	}

	return v.evaluate(func(r models.ScopeRule) bool {
		switch r.Type {
		case models.ScopeRuleExactHost:
			return strings.ToLower(r.Value) == host
		case models.ScopeRuleDomainSuffix:
			suffix := strings.ToLower(strings.TrimSuffix(r.Value, "."))
			return host == suffix || strings.HasSuffix(host, "."+suffix)
		default:
			return false
		}
	}), nil
}

// CheckIP evaluates a resolved IP address against the rule set and the
// built-in reserved-range deny-list. This must be called immediately
// before every socket dial, using the literal IP that will be dialed --
// never a hostname that could re-resolve differently between check and
// connect.
func (v *validator) CheckIP(ctx context.Context, ip net.IP) (Decision, error) {
	if err := ctx.Err(); err != nil {
		return Decision{}, err
	}
	if ip == nil {
		return Decision{Allowed: false, Reason: "nil IP"}, nil
	}

	if !v.allowReserved {
		if reason, reserved := reservedReason(ip); reserved {
			return Decision{Allowed: false, Reason: fmt.Sprintf("reserved range: %s", reason)}, nil
		}
	}

	return v.evaluate(func(r models.ScopeRule) bool {
		switch r.Type {
		case models.ScopeRuleCIDR:
			_, network, err := net.ParseCIDR(r.Value)
			if err != nil {
				return false
			}
			return network.Contains(ip)
		case models.ScopeRuleExactHost:
			ruleIP := net.ParseIP(r.Value)
			return ruleIP != nil && ruleIP.Equal(ip)
		default:
			return false
		}
	}), nil
}

// CheckResolved validates a hostname/IP pair together -- see the
// Validator interface doc for why both checks are necessary.
func (v *validator) CheckResolved(ctx context.Context, hostname string, ip net.IP) (Decision, error) {
	if err := ctx.Err(); err != nil {
		return Decision{}, err
	}
	if ip == nil {
		return Decision{Allowed: false, Reason: "nil IP"}, nil
	}

	// Reserved ranges are denied on the concrete address regardless of
	// how the hostname is authorized -- this is what stops a
	// domain-suffix-authorized name that DNS-rebinds to loopback/
	// metadata/link-local from silently succeeding.
	if !v.allowReserved {
		if reason, reserved := reservedReason(ip); reserved {
			return Decision{Allowed: false, Reason: fmt.Sprintf("reserved range: %s", reason)}, nil
		}
	}

	hostDecision, err := v.CheckHost(ctx, hostname)
	if err != nil {
		return Decision{}, err
	}
	if hostDecision.Allowed {
		return hostDecision, nil
	}
	if hostDecision.MatchedRule != nil && hostDecision.MatchedRule.Action == models.ScopeActionDeny {
		// An explicit deny rule matched the hostname -- terminal; do not
		// fall back to an IP-level rule that might otherwise allow it.
		return hostDecision, nil
	}

	// No rule matched the hostname at all (as opposed to an explicit
	// deny) -- fall back to a direct IP-level rule, e.g. a CIDR that
	// authorizes the resolved address even though the hostname itself
	// isn't named by any rule.
	return v.CheckIP(ctx, ip)
}

// evaluate applies fail-closed precedence: any matching deny rule wins
// outright; otherwise any matching allow rule wins; otherwise deny.
func (v *validator) evaluate(matches func(models.ScopeRule) bool) Decision {
	var matchedAllow *models.ScopeRule
	for i := range v.rules {
		r := v.rules[i]
		if !matches(r) {
			continue
		}
		if r.Action == models.ScopeActionDeny {
			return Decision{Allowed: false, MatchedRule: &r, Reason: "matched deny rule"}
		}
		if r.Action == models.ScopeActionAllow && matchedAllow == nil {
			rc := r
			matchedAllow = &rc
		}
	}
	if matchedAllow != nil {
		return Decision{Allowed: true, MatchedRule: matchedAllow, Reason: "matched allow rule"}
	}
	return Decision{Allowed: false, Reason: "no matching rule (default deny)"}
}

// reservedReason reports whether ip falls in a reserved range that is
// denied by default, and a short human-readable reason.
func reservedReason(ip net.IP) (string, bool) {
	addr, ok := netip.AddrFromSlice(ip.To16())
	if !ok {
		return "", false
	}
	addr = addr.Unmap()

	if addr.IsLoopback() {
		return "loopback", true
	}
	if addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() {
		return "link-local", true
	}
	if addr.IsMulticast() {
		return "multicast", true
	}
	if addr.IsUnspecified() {
		return "unspecified", true
	}
	if addr.Is4() && addr.As4() == [4]byte{169, 254, 169, 254} {
		return "cloud metadata endpoint", true
	}
	return "", false
}
