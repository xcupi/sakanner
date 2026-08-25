// Package config loads sakanner's configuration from a YAML/TOML file
// layered with environment variable overrides.
package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config is sakanner's full runtime configuration.
type Config struct {
	Storage     StorageConfig     `mapstructure:"storage"`
	Logging     LoggingConfig     `mapstructure:"logging"`
	Scope       ScopeConfig       `mapstructure:"scope"`
	Concurrency ConcurrencyConfig `mapstructure:"concurrency"`
	RateLimit   RateLimitConfig   `mapstructure:"rate_limit"`
	DNS         DNSConfig         `mapstructure:"dns"`
	Ports       PortsConfig       `mapstructure:"ports"`
	HTTP        HTTPConfig        `mapstructure:"http"`
	Discovery   DiscoveryConfig   `mapstructure:"discovery"`
	Crawler     CrawlerConfig     `mapstructure:"crawler"`
	Tools       ToolsConfig       `mapstructure:"tools"`
	Detection   DetectionConfig   `mapstructure:"detection"`
	// Authentication configures Phase 3.14's named authentication
	// profiles -- see AuthProfileConfig's own doc comment for why this
	// struct carries only raw, not-yet-secret-resolved references
	// (env var names, never values) rather than credentials themselves.
	Authentication AuthenticationConfig `mapstructure:"authentication"`
	// Identities configures Phase 3.16's named security principals --
	// each one REFERENCES an authentication.profiles entry rather than
	// duplicating its login mechanism; see IdentityConfig's own doc
	// comment for why.
	Identities IdentitiesConfig `mapstructure:"identities"`
}

// StorageConfig configures the persistence backend.
type StorageConfig struct {
	Driver string `mapstructure:"driver"` // "sqlite" (only supported driver in Phase 1)
	DSN    string `mapstructure:"dsn"`
}

// LoggingConfig configures structured logging output.
type LoggingConfig struct {
	Level  string `mapstructure:"level"`  // debug, info, warn, error
	Format string `mapstructure:"format"` // text, json
}

// ScopeConfig configures scope-enforcement behavior.
type ScopeConfig struct {
	// AllowReservedRanges disables the built-in deny of loopback,
	// link-local, metadata, and other reserved IP ranges. Dangerous;
	// off by default.
	AllowReservedRanges bool `mapstructure:"allow_reserved_ranges"`
}

// ConcurrencyConfig bounds parallel work per pipeline stage.
type ConcurrencyConfig struct {
	DNSWorkers  int `mapstructure:"dns_workers"`
	PortWorkers int `mapstructure:"port_workers"`
	HTTPWorkers int `mapstructure:"http_workers"`
}

// RateLimitConfig bounds outbound request rates per stage, in requests
// per second.
type RateLimitConfig struct {
	PortsPerSecond float64 `mapstructure:"ports_per_second"`
	HTTPPerSecond  float64 `mapstructure:"http_per_second"`
}

// DNSConfig configures DNS resolution.
type DNSConfig struct {
	Timeout time.Duration `mapstructure:"timeout"`
	// EnumerateRecords additionally looks up CNAME/MX/TXT/NS records for
	// every discovered asset (not just the A/AAAA records needed to
	// dial it). Enabled by default; disable for very large subdomain
	// enumerations where the extra DNS traffic matters.
	EnumerateRecords bool `mapstructure:"enumerate_records"`
}

// PortsConfig configures port/service discovery.
type PortsConfig struct {
	DialTimeout  time.Duration `mapstructure:"dial_timeout"`
	DefaultPorts []int         `mapstructure:"default_ports"`
}

// HTTPConfig configures HTTP/HTTPS probing.
type HTTPConfig struct {
	Timeout      time.Duration `mapstructure:"timeout"`
	MaxRedirects int           `mapstructure:"max_redirects"`
}

// DiscoveryConfig configures subdomain enumeration.
type DiscoveryConfig struct {
	Wordlist []string `mapstructure:"wordlist"`
}

// CrawlerConfig configures web crawling and endpoint discovery.
// Crawling is comparatively invasive/slow (many extra requests per
// service), so it's off by default.
type CrawlerConfig struct {
	Enabled  bool `mapstructure:"enabled"`
	MaxDepth int  `mapstructure:"max_depth"`
	MaxPages int  `mapstructure:"max_pages"`
	// StartPath is the path (e.g. "/DVWA/") the crawler begins same-
	// origin crawling from, instead of the target's own root "/" --
	// general-purpose support for an application hosted under a
	// subpath the site root has no link into. Overridable per-scan via
	// "scanner scan <target> --start-url". Empty means the target's
	// own root, unchanged from every prior phase's behavior.
	StartPath string `mapstructure:"start_path"`
}

// ToolsConfig selects, per pluggable stage, which backend to use: ""/
// "native" (sakanner's own built-in implementation), "auto" (use the
// matching external tool if it's found on PATH, otherwise fall back to
// native -- the default for every stage, so an install with none of
// these tools present behaves exactly like a build without this feature
// at all), or the tool's own name to require it explicitly and fail
// loudly if it's missing. See pkg/plugins.Resolve for the shared
// contract, and its package doc for which of these open their own
// sockets (httpx, naabu, katana) versus only enumerate names (subfinder,
// dnsx).
type ToolsConfig struct {
	Subfinder string `mapstructure:"subfinder"` // subdomain discovery
	Dnsx      string `mapstructure:"dnsx"`      // DNS record enumeration
	Naabu     string `mapstructure:"naabu"`     // port scanning
	Httpx     string `mapstructure:"httpx"`     // HTTP probing
	Katana    string `mapstructure:"katana"`    // crawling
}

// DetectionConfig bounds the Phase 3.1 detection engine's own request
// execution (internal/detection.Executor) -- the same shape of controls
// (worker concurrency, one rate limiter, a per-request timeout, a
// redirect cap) already established for the ports/HTTP recon stages
// above, applied to detector-issued requests instead. MaxRequestsPerRun
// is detection-specific: a hard ceiling on how many outbound requests
// one Engine.Run can make in total, regardless of how many detectors or
// targets are involved, so a misbehaving future detector can't turn one
// scan into unbounded traffic against a target.
type DetectionConfig struct {
	Workers           int           `mapstructure:"workers"`
	RequestsPerSecond float64       `mapstructure:"requests_per_second"`
	Timeout           time.Duration `mapstructure:"timeout"`
	MaxRedirects      int           `mapstructure:"max_redirects"`
	UserAgent         string        `mapstructure:"user_agent"`
	MaxRequestsPerRun int           `mapstructure:"max_requests_per_run"`
}

// AuthenticationConfig holds every named authentication profile an
// operator has configured -- Phase 3.14 task section 13's "add
// authentication configuration to the existing configuration system."
type AuthenticationConfig struct {
	Profiles []AuthProfileConfig `mapstructure:"profiles"`
}

// AuthProfileConfig is one authentication profile's raw configuration,
// as loaded from YAML/env -- mirrors internal/auth.ProfileConfig
// field-for-field (see cmd/scanner's translation function) but is
// defined here, locally, rather than embedding internal/auth's type
// directly, matching every other nested config struct in this file
// (CrawlerConfig, DetectionConfig, ...): internal/config never imports
// a domain package's own types, only mapstructure-tagged shapes of its
// own. Every credential-bearing field here is a REFERENCE (an
// environment variable NAME) rather than a value -- task section 2's
// "do not require credentials to be stored in the repository," and
// section 3's "secrets must be referenced securely rather than
// persisted as plaintext."
type AuthProfileConfig struct {
	Name string `mapstructure:"name"`
	// Type selects the authentication mechanism: "form_login",
	// "form_login_auto" (Phase 3.36: the same conventional HTML form
	// login, but with the login page/form/field names discovered
	// automatically from a start_url instead of operator-configured --
	// see internal/auth.TypeFormLoginAuto), "cookie", "bearer_token",
	// or "header" -- validated structurally in
	// Validate() below (a known type, required type-specific fields
	// present); the referenced env vars themselves are resolved lazily,
	// only when a profile is actually used (internal/auth.ResolveProfile),
	// so an unrelated command never fails to start merely because some
	// configured profile's secret isn't currently exported.
	Type string `mapstructure:"type"`

	// form_login fields.
	LoginURL      string            `mapstructure:"login_url"`
	UsernameEnv   string            `mapstructure:"username_env"`
	PasswordEnv   string            `mapstructure:"password_env"`
	UsernameField string            `mapstructure:"username_field"`
	PasswordField string            `mapstructure:"password_field"`
	ExtraFields   map[string]string `mapstructure:"extra_fields"`

	SuccessURLContains  string `mapstructure:"success_url_contains"`
	SuccessTextContains string `mapstructure:"success_text_contains"`
	FailureTextContains string `mapstructure:"failure_text_contains"`

	// form_login_auto fields -- see internal/auth.TypeFormLoginAuto's
	// own doc comment. Any reachable same-origin page on the target
	// app, not necessarily the exact login page.
	StartURL string `mapstructure:"start_url"`

	// cookie fields.
	CookieEnv string `mapstructure:"cookie_env"`

	// bearer_token fields.
	TokenEnv string `mapstructure:"token_env"`

	// header fields.
	HeaderName     string `mapstructure:"header_name"`
	HeaderValueEnv string `mapstructure:"header_value_env"`

	// ScopeHost is required for cookie/bearer_token/header (which have
	// no login URL to derive a host from); optional for form_login.
	ScopeHost string `mapstructure:"scope_host"`

	Timeout      time.Duration `mapstructure:"timeout"`
	MaxRedirects int           `mapstructure:"max_redirects"`
}

// IdentitiesConfig holds every named identity an operator has
// configured, plus a hard cap on how many may be configured at once --
// Phase 3.16 task section 3's "enforce maximum identity count." A
// scanner that let an operator (or, worse, a malformed/injected config
// file) define an unbounded number of identities would let one scan
// invocation trigger an unbounded number of authentication attempts
// and concurrent sessions -- MaxCount is the explicit resource limit
// task section 20 also asks for, checked structurally at config-load
// time, before any of them is ever resolved or authenticated.
type IdentitiesConfig struct {
	MaxCount   int              `mapstructure:"max_count"`
	Identities []IdentityConfig `mapstructure:"identities"`
}

// IdentityConfig is one identity's raw configuration -- mirrors
// internal/auth.IdentityConfig field-for-field (see cmd/scanner's
// translation function), matching AuthProfileConfig's own "raw,
// mapstructure-tagged shape, translated by cmd/scanner" pattern.
// Task section 2's "clearly separate Auth Profile from Identity":
// AuthProfile is a REFERENCE to an authentication.profiles entry, not
// a duplicated login mechanism; the credential-env fields below
// OVERRIDE that referenced profile's own defaults only when non-empty,
// which is what lets two identities share one profile's login
// mechanism while authenticating as two different accounts (see
// docs/phase-3-16-multi-identity.md "Auth Profile vs. Identity").
type IdentityConfig struct {
	Name        string `mapstructure:"name"`
	AuthProfile string `mapstructure:"auth_profile"`
	// Disabled administratively turns this identity off -- structurally
	// checked (never resolved, never authenticated) regardless of
	// whether its underlying auth profile is otherwise valid.
	Disabled bool `mapstructure:"disabled"`

	// Credential overrides -- see internal/auth.IdentityConfig's own
	// doc comment for exactly how these combine with the referenced
	// profile's own fields.
	UsernameEnv    string `mapstructure:"username_env"`
	PasswordEnv    string `mapstructure:"password_env"`
	TokenEnv       string `mapstructure:"token_env"`
	CookieEnv      string `mapstructure:"cookie_env"`
	HeaderValueEnv string `mapstructure:"header_value_env"`
}

// Load reads configuration from the given file path (if non-empty and
// present) layered with SAKANNER_-prefixed environment variable overrides,
// applies defaults for anything unset, and validates the result.
//
// A fresh viper instance is used per call so repeated invocations (e.g. in
// tests, or across CLI commands in the same process) never leak state.
func Load(path string) (*Config, error) {
	v := viper.New()
	setDefaults(v)

	v.SetEnvPrefix("SAKANNER")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	if path != "" {
		v.SetConfigFile(path)
		if err := v.ReadInConfig(); err != nil {
			var notFound viper.ConfigFileNotFoundError
			if !errors.As(err, &notFound) && !os.IsNotExist(err) {
				return nil, fmt.Errorf("config: reading %s: %w", path, err)
			}
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("config: unmarshal: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}

	return &cfg, nil
}

func setDefaults(v *viper.Viper) {
	v.SetDefault("storage.driver", "sqlite")
	v.SetDefault("storage.dsn", "sakanner.db")

	v.SetDefault("logging.level", "info")
	v.SetDefault("logging.format", "text")

	v.SetDefault("scope.allow_reserved_ranges", false)

	v.SetDefault("concurrency.dns_workers", 10)
	v.SetDefault("concurrency.port_workers", 20)
	v.SetDefault("concurrency.http_workers", 10)

	v.SetDefault("rate_limit.ports_per_second", 50.0)
	v.SetDefault("rate_limit.http_per_second", 10.0)

	v.SetDefault("dns.timeout", 5*time.Second)
	v.SetDefault("dns.enumerate_records", true)

	v.SetDefault("ports.dial_timeout", 3*time.Second)
	v.SetDefault("ports.default_ports", defaultPorts())

	v.SetDefault("http.timeout", 10*time.Second)
	v.SetDefault("http.max_redirects", 5)

	v.SetDefault("discovery.wordlist", defaultWordlist())

	v.SetDefault("crawler.enabled", false)
	v.SetDefault("crawler.max_depth", 2)
	v.SetDefault("crawler.max_pages", 20)

	v.SetDefault("detection.workers", 5)
	v.SetDefault("detection.requests_per_second", 5.0)
	v.SetDefault("detection.timeout", 10*time.Second)
	v.SetDefault("detection.max_redirects", 5)
	v.SetDefault("detection.user_agent", "sakanner-detection/1.0")
	v.SetDefault("detection.max_requests_per_run", 10000)

	v.SetDefault("tools.subfinder", "auto")
	v.SetDefault("tools.dnsx", "auto")
	v.SetDefault("tools.naabu", "auto")
	v.SetDefault("tools.httpx", "auto")
	v.SetDefault("tools.katana", "auto")

	v.SetDefault("identities.max_count", 10)
}

// Validate checks the config for values that would misconfigure the
// scanner in an unsafe or nonsensical way.
func (c *Config) Validate() error {
	if c.Storage.Driver != "sqlite" {
		return fmt.Errorf("storage.driver: unsupported driver %q (only \"sqlite\" is supported in Phase 1)", c.Storage.Driver)
	}
	if c.Storage.DSN == "" {
		return fmt.Errorf("storage.dsn: must not be empty")
	}
	switch c.Logging.Level {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("logging.level: invalid level %q", c.Logging.Level)
	}
	switch c.Logging.Format {
	case "text", "json":
	default:
		return fmt.Errorf("logging.format: invalid format %q", c.Logging.Format)
	}
	if c.Concurrency.DNSWorkers <= 0 || c.Concurrency.PortWorkers <= 0 || c.Concurrency.HTTPWorkers <= 0 {
		return fmt.Errorf("concurrency: worker counts must be positive")
	}
	if c.RateLimit.PortsPerSecond <= 0 || c.RateLimit.HTTPPerSecond <= 0 {
		return fmt.Errorf("rate_limit: rates must be positive")
	}
	if c.HTTP.MaxRedirects < 0 {
		return fmt.Errorf("http.max_redirects: must not be negative")
	}
	if c.Crawler.MaxDepth < 0 {
		return fmt.Errorf("crawler.max_depth: must not be negative")
	}
	if c.Crawler.Enabled && c.Crawler.MaxPages <= 0 {
		return fmt.Errorf("crawler.max_pages: must be positive when crawler.enabled is true")
	}
	if c.Detection.Workers <= 0 {
		return fmt.Errorf("detection.workers: must be positive")
	}
	if c.Detection.RequestsPerSecond <= 0 {
		return fmt.Errorf("detection.requests_per_second: must be positive")
	}
	if c.Detection.MaxRedirects < 0 {
		return fmt.Errorf("detection.max_redirects: must not be negative")
	}
	if c.Detection.MaxRequestsPerRun <= 0 {
		return fmt.Errorf("detection.max_requests_per_run: must be positive")
	}
	if err := c.Authentication.Validate(); err != nil {
		return err
	}
	if err := c.Identities.Validate(c.Authentication.Profiles); err != nil {
		return err
	}
	for _, tb := range []struct{ field, value, tool string }{
		{"tools.subfinder", c.Tools.Subfinder, "subfinder"},
		{"tools.dnsx", c.Tools.Dnsx, "dnsx"},
		{"tools.naabu", c.Tools.Naabu, "naabu"},
		{"tools.httpx", c.Tools.Httpx, "httpx"},
		{"tools.katana", c.Tools.Katana, "katana"},
	} {
		switch tb.value {
		case "", "native", "auto", tb.tool:
		default:
			return fmt.Errorf("%s: invalid backend %q (want \"native\", \"auto\", or %q)", tb.field, tb.value, tb.tool)
		}
	}
	return nil
}

// Validate checks every configured authentication profile's STRUCTURE
// only -- name uniqueness, a known type, and that type's own required
// fields are non-empty -- never whether the environment variables those
// fields NAME actually exist. Reading os.Getenv is deliberately left to
// internal/auth.ResolveProfile, called lazily only when a profile is
// actually used: if Validate() (which runs on EVERY command
// invocation, via config.Load) checked env var presence, an unrelated
// command (e.g. "scanner target list") would fail to even start just
// because some configured profile's secret isn't currently exported in
// the caller's shell.
func (a AuthenticationConfig) Validate() error {
	seen := make(map[string]bool, len(a.Profiles))
	for _, p := range a.Profiles {
		if p.Name == "" {
			return fmt.Errorf("authentication.profiles: a profile is missing \"name\"")
		}
		if seen[p.Name] {
			return fmt.Errorf("authentication.profiles: duplicate profile name %q", p.Name)
		}
		seen[p.Name] = true

		switch p.Type {
		case "form_login":
			if p.LoginURL == "" || p.UsernameEnv == "" || p.PasswordEnv == "" {
				return fmt.Errorf("authentication.profiles[%s]: type \"form_login\" requires login_url, username_env, and password_env", p.Name)
			}
		case "form_login_auto":
			if p.StartURL == "" || p.UsernameEnv == "" || p.PasswordEnv == "" {
				return fmt.Errorf("authentication.profiles[%s]: type \"form_login_auto\" requires start_url, username_env, and password_env", p.Name)
			}
		case "cookie":
			if p.CookieEnv == "" || p.ScopeHost == "" {
				return fmt.Errorf("authentication.profiles[%s]: type \"cookie\" requires cookie_env and scope_host", p.Name)
			}
		case "bearer_token":
			if p.TokenEnv == "" || p.ScopeHost == "" {
				return fmt.Errorf("authentication.profiles[%s]: type \"bearer_token\" requires token_env and scope_host", p.Name)
			}
		case "header":
			if p.HeaderName == "" || p.HeaderValueEnv == "" || p.ScopeHost == "" {
				return fmt.Errorf("authentication.profiles[%s]: type \"header\" requires header_name, header_value_env, and scope_host", p.Name)
			}
		default:
			return fmt.Errorf("authentication.profiles[%s]: type: invalid type %q (want \"form_login\", \"form_login_auto\", \"cookie\", \"bearer_token\", or \"header\")", p.Name, p.Type)
		}
		if p.MaxRedirects < 0 {
			return fmt.Errorf("authentication.profiles[%s]: max_redirects must not be negative", p.Name)
		}
	}
	return nil
}

// Validate checks every configured identity's STRUCTURE -- name
// non-empty, unique names, a maximum count, and (task section 3's
// "reject invalid references") that each identity's auth_profile names
// a profile that ACTUALLY EXISTS in profiles. This cross-references
// two sibling config sections deliberately: both live in the same
// Config, and "does this identity's reference resolve at all" is a
// structural fact about the config FILE itself, checkable with zero
// I/O -- the same "fail before network activity" principle
// AuthenticationConfig.Validate already follows for its own fields.
// Credential env var PRESENCE is, as with auth profiles, checked
// lazily by internal/auth.ResolveIdentityProfile only when an identity
// is actually used.
func (ic IdentitiesConfig) Validate(profiles []AuthProfileConfig) error {
	maxCount := ic.MaxCount
	if maxCount <= 0 {
		maxCount = 10 // matches setDefaults' own default -- defensive, in case Validate is ever called on a Config built without going through Load's defaults.
	}
	if len(ic.Identities) > maxCount {
		return fmt.Errorf("identities: %d identities configured, exceeds max_count %d", len(ic.Identities), maxCount)
	}

	profileNames := make(map[string]bool, len(profiles))
	for _, p := range profiles {
		profileNames[p.Name] = true
	}

	seen := make(map[string]bool, len(ic.Identities))
	for _, id := range ic.Identities {
		if id.Name == "" {
			return fmt.Errorf("identities: an identity is missing \"name\"")
		}
		if seen[id.Name] {
			return fmt.Errorf("identities[%s]: duplicate identity name", id.Name)
		}
		seen[id.Name] = true

		if id.AuthProfile == "" {
			return fmt.Errorf("identities[%s]: auth_profile is required", id.Name)
		}
		if !profileNames[id.AuthProfile] {
			return fmt.Errorf("identities[%s]: auth_profile %q does not match any configured authentication.profiles entry", id.Name, id.AuthProfile)
		}
	}
	return nil
}

func defaultPorts() []int {
	return []int{
		21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
		143, 443, 445, 993, 995, 1723, 3306, 3389, 5432, 5900,
		8000, 8080, 8443, 8888, 9090,
	}
}

func defaultWordlist() []string {
	return []string{
		"www", "mail", "ftp", "api", "dev", "staging", "test",
		"admin", "vpn", "portal", "app", "cdn", "static", "assets",
		"blog", "shop", "m", "mobile", "beta", "demo",
	}
}
