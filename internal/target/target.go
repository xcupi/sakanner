// Package target parses operator-supplied scan target strings (domains,
// hostnames, IP addresses, and CIDR ranges) into a typed models.Target.
package target

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"sakanner/pkg/models"
)

// Parse classifies raw operator input into a models.TargetType and a
// normalized value. It does not perform DNS resolution or scope
// checking -- both happen later in the pipeline.
//
// Accepted forms: bare IPv4/IPv6 addresses, CIDR ranges (e.g.
// 203.0.113.0/24), bare domains/hostnames (e.g. example.com,
// api.example.com), and http(s):// URLs (the host component is
// extracted and classified).
func Parse(raw string) (value string, typ models.TargetType, err error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", "", fmt.Errorf("target: empty input")
	}

	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil {
			return "", "", fmt.Errorf("target: invalid URL %q: %w", raw, err)
		}
		if u.Hostname() == "" {
			return "", "", fmt.Errorf("target: URL %q has no host", raw)
		}
		s = u.Hostname()
	}

	if _, _, err := net.ParseCIDR(s); err == nil {
		return s, models.TargetTypeCIDR, nil
	}

	if ip := net.ParseIP(s); ip != nil {
		return ip.String(), models.TargetTypeIP, nil
	}

	if looksLikeIPv4(s) {
		return "", "", fmt.Errorf("target: invalid input %q: looks like an IPv4 address but is not valid (octets must be 0-255)", raw)
	}

	if err := validateHostname(s); err != nil {
		return "", "", fmt.Errorf("target: invalid input %q: %w", raw, err)
	}

	// A trailing dot marks an FQDN (absolute name) in DNS notation --
	// "example.com" and "example.com." name the same host. Strip it so
	// the two forms normalize to one value; otherwise the same
	// real-world host supplied both ways would persist as two distinct
	// Assets, discovered and enumerated twice. This mirrors
	// internal/scope.Validator.CheckHost's own trailing-dot handling
	// (that layer never trusted Parse's output to already be
	// normalized), but neither layer should be the only one that does
	// it -- normalizing here means every consumer of Target.Value,
	// not just scope checks, sees one canonical form.
	s = strings.TrimSuffix(s, ".")

	if strings.Count(s, ".") == 0 {
		return strings.ToLower(s), models.TargetTypeHost, nil
	}
	return strings.ToLower(s), models.TargetTypeDomain, nil
}

// looksLikeIPv4 reports whether s has the shape of an IPv4 address --
// exactly four dot-separated, all-digit labels -- without necessarily
// being a *valid* one. net.ParseIP already rejects invalid IPv4 strings
// (e.g. octets > 255); this catches those before they'd otherwise fall
// through hostname validation and get silently accepted as a domain,
// since every label in "999.999.999.999" or "256.1.1.1" is a legal DNS
// label in isolation.
func looksLikeIPv4(s string) bool {
	labels := strings.Split(s, ".")
	if len(labels) != 4 {
		return false
	}
	for _, label := range labels {
		if label == "" {
			return false
		}
		for _, r := range label {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}

func validateHostname(s string) error {
	if len(s) == 0 || len(s) > 253 {
		return fmt.Errorf("length out of range")
	}
	labels := strings.Split(strings.TrimSuffix(s, "."), ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return fmt.Errorf("invalid label %q", label)
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("label %q must not start or end with a hyphen", label)
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') && !(r >= '0' && r <= '9') && r != '-' {
				return fmt.Errorf("label %q contains invalid character %q", label, r)
			}
		}
	}
	return nil
}
