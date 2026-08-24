package fingerprint

import (
	"net/http"
	"regexp"
	"testing"

	"sakanner/pkg/models"
)

func header(pairs map[string]string) http.Header {
	h := http.Header{}
	for k, v := range pairs {
		h.Set(k, v)
	}
	return h
}

func containsName(techs []models.Technology, name string) bool {
	for _, t := range techs {
		if t.Name == name {
			return true
		}
	}
	return false
}

func TestDefaultSignatures_HeaderMatches(t *testing.T) {
	m := NewMatcher(DefaultSignatures())

	tests := []struct {
		name    string
		headers http.Header
		body    []byte
		want    string
	}{
		{"nginx server header", header(map[string]string{"Server": "nginx/1.25.0"}), nil, "nginx"},
		{"apache server header", header(map[string]string{"Server": "Apache/2.4.54 (Ubuntu)"}), nil, "Apache"},
		{"iis server header", header(map[string]string{"Server": "Microsoft-IIS/10.0"}), nil, "Microsoft IIS"},
		{"php powered-by", header(map[string]string{"X-Powered-By": "PHP/8.1.2"}), nil, "PHP"},
		{"php session cookie", header(map[string]string{"Set-Cookie": "PHPSESSID=abc123; path=/"}), nil, "PHP"},
		{"aspnet powered-by", header(map[string]string{"X-Powered-By": "ASP.NET"}), nil, "ASP.NET"},
		{"express powered-by", header(map[string]string{"X-Powered-By": "Express"}), nil, "Express"},
		{"cloudflare server", header(map[string]string{"Server": "cloudflare"}), nil, "Cloudflare"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			techs := m.Identify(tt.headers, tt.body)
			if !containsName(techs, tt.want) {
				t.Errorf("Identify() = %+v, want to contain %q", techs, tt.want)
			}
		})
	}
}

func TestDefaultSignatures_BodyMatches(t *testing.T) {
	m := NewMatcher(DefaultSignatures())

	tests := []struct {
		name string
		body string
		want string
	}{
		{"wordpress content path", `<link rel="stylesheet" href="/wp-content/themes/foo/style.css">`, "WordPress"},
		{"wordpress generator meta", `<meta name="generator" content="WordPress 6.4">`, "WordPress"},
		{"drupal settings", `<script>var Drupal.settings = {};</script>`, "Drupal"},
		{"jquery script tag", `<script src="/js/jquery.min.js"></script>`, "jQuery"},
		{"react root", `<div id="root" data-reactroot=""></div>`, "React"},
		{"bootstrap css", `<link href="/css/bootstrap.min.css" rel="stylesheet">`, "Bootstrap"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			techs := m.Identify(http.Header{}, []byte(tt.body))
			if !containsName(techs, tt.want) {
				t.Errorf("Identify() = %+v, want to contain %q", techs, tt.want)
			}
		})
	}
}

func TestIdentify_NoMatch(t *testing.T) {
	m := NewMatcher(DefaultSignatures())
	techs := m.Identify(header(map[string]string{"Server": "totally-unknown-server"}), []byte("plain content"))
	if len(techs) != 0 {
		t.Errorf("Identify() = %+v, want empty", techs)
	}
}

func TestIdentify_MultipleMatches(t *testing.T) {
	m := NewMatcher(DefaultSignatures())
	techs := m.Identify(
		header(map[string]string{"Server": "nginx", "X-Powered-By": "PHP/8.1"}),
		[]byte(`<link href="/wp-content/theme.css">`),
	)
	for _, want := range []string{"nginx", "PHP", "WordPress"} {
		if !containsName(techs, want) {
			t.Errorf("Identify() = %+v, missing %q", techs, want)
		}
	}
}

func TestIdentify_ConfidenceDefaultsWhenUnset(t *testing.T) {
	m := NewMatcher([]Signature{
		{Name: "Custom", Category: "test", HeaderMatches: map[string]*regexp.Regexp{"X-Test": regexp.MustCompile(".+")}},
	})
	techs := m.Identify(header(map[string]string{"X-Test": "yes"}), nil)
	if len(techs) != 1 {
		t.Fatalf("Identify() = %+v, want 1 match", techs)
	}
	if techs[0].Confidence != 0.7 {
		t.Errorf("Confidence = %v, want default 0.7", techs[0].Confidence)
	}
}

func TestIdentify_SetsSourceToFingerprint(t *testing.T) {
	m := NewMatcher(DefaultSignatures())
	techs := m.Identify(header(map[string]string{"Server": "nginx"}), nil)
	if len(techs) != 1 || techs[0].Source != "fingerprint" {
		t.Fatalf("Identify() = %+v, want Source = \"fingerprint\"", techs)
	}
}

func TestIdentify_ExtractsVersionFromHeader(t *testing.T) {
	m := NewMatcher(DefaultSignatures())

	tests := []struct {
		name        string
		headers     http.Header
		wantName    string
		wantVersion string
	}{
		{"nginx with version", header(map[string]string{"Server": "nginx/1.25.3"}), "nginx", "1.25.3"},
		{"nginx without version", header(map[string]string{"Server": "nginx"}), "nginx", ""},
		{"apache with version", header(map[string]string{"Server": "Apache/2.4.54 (Ubuntu)"}), "Apache", "2.4.54"},
		{"iis with version", header(map[string]string{"Server": "Microsoft-IIS/10.0"}), "Microsoft IIS", "10.0"},
		{"php with version", header(map[string]string{"X-Powered-By": "PHP/8.1.2"}), "PHP", "8.1.2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			techs := m.Identify(tt.headers, nil)
			var got *models.Technology
			for i := range techs {
				if techs[i].Name == tt.wantName {
					got = &techs[i]
				}
			}
			if got == nil {
				t.Fatalf("Identify() = %+v, want a match for %q", techs, tt.wantName)
			}
			if got.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", got.Version, tt.wantVersion)
			}
		})
	}
}

func TestIdentify_ExtractsVersionFromBody(t *testing.T) {
	m := NewMatcher(DefaultSignatures())
	body := []byte(`<meta name="generator" content="WordPress 6.4.2">`)
	techs := m.Identify(http.Header{}, body)
	if !containsName(techs, "WordPress") {
		t.Fatalf("Identify() = %+v, want WordPress match", techs)
	}
	for _, tech := range techs {
		if tech.Name == "WordPress" {
			if tech.Version != "6.4.2" {
				t.Errorf("Version = %q, want \"6.4.2\"", tech.Version)
			}
		}
	}
}

func TestIdentify_ExtractsJQueryVersionFromScriptBanner(t *testing.T) {
	m := NewMatcher(DefaultSignatures())
	body := []byte(`/*! jQuery JavaScript Library v3.6.0 | (c) OpenJS Foundation */`)
	techs := m.Identify(http.Header{}, body)
	if !containsName(techs, "jQuery") {
		t.Fatalf("Identify() = %+v, want jQuery match", techs)
	}
	for _, tech := range techs {
		if tech.Name == "jQuery" && tech.Version != "3.6.0" {
			t.Errorf("Version = %q, want \"3.6.0\"", tech.Version)
		}
	}
}

func TestIdentify_ExtractsVueVersionFromScriptBanner(t *testing.T) {
	m := NewMatcher(DefaultSignatures())
	body := []byte(`/*!\n * Vue.js v2.6.14\n * (c) 2014-2021 Evan You\n */`)
	techs := m.Identify(http.Header{}, body)
	if !containsName(techs, "Vue.js") {
		t.Fatalf("Identify() = %+v, want Vue.js match", techs)
	}
	for _, tech := range techs {
		if tech.Name == "Vue.js" && tech.Version != "2.6.14" {
			t.Errorf("Version = %q, want \"2.6.14\"", tech.Version)
		}
	}
}

func TestIdentify_NoVersionPatternLeavesVersionEmpty(t *testing.T) {
	m := NewMatcher(DefaultSignatures())
	techs := m.Identify(header(map[string]string{"X-Powered-By": "Express"}), nil)
	if !containsName(techs, "Express") {
		t.Fatalf("Identify() = %+v, want Express match", techs)
	}
	for _, tech := range techs {
		if tech.Name == "Express" && tech.Version != "" {
			t.Errorf("Version = %q, want empty (Express signature has no VersionPattern)", tech.Version)
		}
	}
}
