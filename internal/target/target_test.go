package target

import (
	"testing"

	"sakanner/pkg/models"
)

func TestParse(t *testing.T) {
	tests := []struct {
		raw       string
		wantValue string
		wantType  models.TargetType
		wantErr   bool
	}{
		{"example.com", "example.com", models.TargetTypeDomain, false},
		{"EXAMPLE.com", "example.com", models.TargetTypeDomain, false},
		{"api.example.com", "api.example.com", models.TargetTypeDomain, false},
		{"localhost", "localhost", models.TargetTypeHost, false},
		{"192.0.2.1", "192.0.2.1", models.TargetTypeIP, false},
		{"2001:db8::1", "2001:db8::1", models.TargetTypeIP, false},
		{"203.0.113.0/24", "203.0.113.0/24", models.TargetTypeCIDR, false},
		{"2001:db8::/32", "2001:db8::/32", models.TargetTypeCIDR, false},
		{"https://example.com/path", "example.com", models.TargetTypeDomain, false},
		{"http://api.example.com:8080", "api.example.com", models.TargetTypeDomain, false},
		{"  example.com  ", "example.com", models.TargetTypeDomain, false},
		{"example.com.", "example.com", models.TargetTypeDomain, false},
		{"EXAMPLE.COM.", "example.com", models.TargetTypeDomain, false},
		{"localhost.", "localhost", models.TargetTypeHost, false},
		{"", "", "", true},
		{"not a domain", "", "", true},
		{"-badlabel.com", "", "", true},
		{"badlabel-.com", "", "", true},
		{"http://", "", "", true},
		{"999.999.999.999", "", "", true},
		{"256.1.1.1", "", "", true},
		{"1.2.3.999", "", "", true},
		{"300.300.300.300", "", "", true},
		{"192.168.001.1", "", "", true},       // leading zeros: net.ParseIP rejects (octal ambiguity); must not fall through to "domain"
		{"0177.0.0.1", "", "", true},          // classic dotted-octal SSRF bypass notation (0177 octal = 127 decimal)
		{"0251.0376.0251.0376", "", "", true}, // dotted-octal form of a link-local-range address
	}

	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			value, typ, err := Parse(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Parse(%q) = nil error, want error", tt.raw)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse(%q) error = %v", tt.raw, err)
			}
			if value != tt.wantValue {
				t.Errorf("Parse(%q) value = %q, want %q", tt.raw, value, tt.wantValue)
			}
			if typ != tt.wantType {
				t.Errorf("Parse(%q) type = %q, want %q", tt.raw, typ, tt.wantType)
			}
		})
	}
}
