// Package fingerprint identifies technologies from HTTP response headers
// and response bodies using a small built-in signature table. It does
// not make network requests itself -- it operates on data already
// collected by internal/http.
package fingerprint

import (
	"net/http"
	"regexp"

	"sakanner/pkg/models"
)

// Signature describes how to recognize one technology.
type Signature struct {
	Name          string
	Category      string
	HeaderMatches map[string]*regexp.Regexp // header name (canonical) -> pattern matched against its value
	BodyPattern   *regexp.Regexp
	Confidence    float64

	// VersionHeader + VersionPattern extract a version string once the
	// signature has otherwise matched. If VersionHeader is set, the
	// pattern is applied to that header's value; otherwise, if
	// VersionPattern is set, it's applied to the body. The pattern's
	// first capture group is used as the version; a pattern with no
	// capture group, or one that doesn't match, simply leaves Version
	// unset rather than erroring.
	VersionHeader  string
	VersionPattern *regexp.Regexp
}

// sourceFingerprint tags every Technology this package produces, so a
// report reader (or future correlation logic) can distinguish sakanner's
// own signature matches from a technology recorded by an external tool
// backend (e.g. "httpx"), which may have different confidence semantics.
const sourceFingerprint = "fingerprint"

// Fingerprinter identifies technologies present in an HTTP response.
type Fingerprinter interface {
	Identify(headers http.Header, body []byte) []models.Technology
}

type matcher struct {
	signatures []Signature
}

// NewMatcher returns a Fingerprinter that evaluates sigs against each
// response. A signature matches if any of its HeaderMatches match, or if
// its BodyPattern matches the body; both may be set, in which case
// either is sufficient.
func NewMatcher(sigs []Signature) Fingerprinter {
	return &matcher{signatures: sigs}
}

func (m *matcher) Identify(headers http.Header, body []byte) []models.Technology {
	var out []models.Technology
	for _, sig := range m.signatures {
		if tech, ok := sig.match(headers, body); ok {
			out = append(out, tech)
		}
	}
	return out
}

func (s Signature) match(headers http.Header, body []byte) (models.Technology, bool) {
	for headerName, pattern := range s.HeaderMatches {
		if pattern.MatchString(headers.Get(headerName)) {
			return s.technology(headers, body), true
		}
	}
	if s.BodyPattern != nil && s.BodyPattern.Match(body) {
		return s.technology(headers, body), true
	}
	return models.Technology{}, false
}

func (s Signature) technology(headers http.Header, body []byte) models.Technology {
	confidence := s.Confidence
	if confidence == 0 {
		confidence = 0.7
	}
	return models.Technology{Name: s.Name, Category: s.Category, Confidence: confidence, Version: s.extractVersion(headers, body), Source: sourceFingerprint}
}

// extractVersion applies VersionPattern (if set) to the configured
// source -- a specific header's value if VersionHeader is set, otherwise
// the body -- and returns its first capture group. Any failure to match
// simply yields an empty version, never an error: version extraction is
// best-effort, not required for the signature match itself to stand.
func (s Signature) extractVersion(headers http.Header, body []byte) string {
	if s.VersionPattern == nil {
		return ""
	}
	var m []string
	if s.VersionHeader != "" {
		m = s.VersionPattern.FindStringSubmatch(headers.Get(s.VersionHeader))
	} else {
		m = s.VersionPattern.FindStringSubmatch(string(body))
	}
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

// DefaultSignatures returns sakanner's built-in Phase 1 signature set:
// simple header and body patterns for widely-deployed web technologies.
// This is intentionally small; it is not a substitute for a maintained
// fingerprint database and is expected to grow over time.
func DefaultSignatures() []Signature {
	return []Signature{
		{
			Name: "nginx", Category: "web-server", Confidence: 0.9,
			HeaderMatches:  map[string]*regexp.Regexp{"Server": regexp.MustCompile(`(?i)nginx`)},
			VersionHeader:  "Server",
			VersionPattern: regexp.MustCompile(`(?i)nginx/([\d.]+)`),
		},
		{
			Name: "Apache", Category: "web-server", Confidence: 0.9,
			HeaderMatches:  map[string]*regexp.Regexp{"Server": regexp.MustCompile(`(?i)apache`)},
			VersionHeader:  "Server",
			VersionPattern: regexp.MustCompile(`(?i)apache/([\d.]+)`),
		},
		{
			Name: "Microsoft IIS", Category: "web-server", Confidence: 0.9,
			HeaderMatches:  map[string]*regexp.Regexp{"Server": regexp.MustCompile(`(?i)microsoft-iis`)},
			VersionHeader:  "Server",
			VersionPattern: regexp.MustCompile(`(?i)microsoft-iis/([\d.]+)`),
		},
		{
			Name: "PHP", Category: "language", Confidence: 0.8,
			HeaderMatches: map[string]*regexp.Regexp{
				"X-Powered-By": regexp.MustCompile(`(?i)php`),
				"Set-Cookie":   regexp.MustCompile(`(?i)PHPSESSID`),
			},
			VersionHeader:  "X-Powered-By",
			VersionPattern: regexp.MustCompile(`(?i)php/([\d.]+)`),
		},
		{
			Name: "ASP.NET", Category: "framework", Confidence: 0.8,
			HeaderMatches: map[string]*regexp.Regexp{
				"X-Powered-By":     regexp.MustCompile(`(?i)asp\.net`),
				"X-AspNet-Version": regexp.MustCompile(`.+`),
			},
		},
		{
			Name: "Express", Category: "framework", Confidence: 0.8,
			HeaderMatches: map[string]*regexp.Regexp{"X-Powered-By": regexp.MustCompile(`(?i)express`)},
		},
		{
			Name: "Cloudflare", Category: "cdn", Confidence: 0.85,
			HeaderMatches: map[string]*regexp.Regexp{"Server": regexp.MustCompile(`(?i)cloudflare`)},
		},
		{
			Name: "WordPress", Category: "cms", Confidence: 0.7,
			BodyPattern:    regexp.MustCompile(`(?i)wp-content|wp-includes|generator"\s+content="WordPress`),
			VersionPattern: regexp.MustCompile(`(?i)generator"\s+content="WordPress\s+([\d.]+)"`),
		},
		{
			Name: "Drupal", Category: "cms", Confidence: 0.7,
			BodyPattern: regexp.MustCompile(`(?i)Drupal\.settings|/sites/default/files`),
		},
		{
			// The BodyPattern matches both an HTML page referencing
			// jquery.js by filename and the library's own source (its
			// standard header banner, e.g. "jQuery JavaScript Library
			// v3.6.0"), so this signature matches whether it's run against
			// a probed page or a fetched script body.
			Name: "jQuery", Category: "javascript-library", Confidence: 0.6,
			BodyPattern:    regexp.MustCompile(`(?i)jquery(\.min)?\.js|jQuery JavaScript Library|jQuery\s+v[\d.]+`),
			VersionPattern: regexp.MustCompile(`jQuery(?:\s+JavaScript Library)?\s+v([\d.]+)`),
		},
		{
			Name: "React", Category: "javascript-library", Confidence: 0.5,
			BodyPattern: regexp.MustCompile(`(?i)data-reactroot|__REACT_DEVTOOLS`),
		},
		{
			// Matches Vue's runtime devtools hook and its source banner
			// (e.g. "Vue.js v2.6.14"), the same dual page-or-script-body
			// approach as the jQuery signature above.
			Name: "Vue.js", Category: "javascript-library", Confidence: 0.5,
			BodyPattern:    regexp.MustCompile(`__VUE__|Vue\.js v[\d.]+`),
			VersionPattern: regexp.MustCompile(`Vue\.js v([\d.]+)`),
		},
		{
			Name: "Bootstrap", Category: "css-framework", Confidence: 0.5,
			BodyPattern: regexp.MustCompile(`(?i)bootstrap(\.min)?\.css`),
		},
	}
}
