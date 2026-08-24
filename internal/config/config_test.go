package config

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Storage.Driver != "sqlite" {
		t.Errorf("Storage.Driver = %q, want sqlite", cfg.Storage.Driver)
	}
	if cfg.Storage.DSN != "sakanner.db" {
		t.Errorf("Storage.DSN = %q, want sakanner.db", cfg.Storage.DSN)
	}
	if cfg.Concurrency.HTTPWorkers != 10 {
		t.Errorf("Concurrency.HTTPWorkers = %d, want 10", cfg.Concurrency.HTTPWorkers)
	}
	if cfg.DNS.Timeout != 5*time.Second {
		t.Errorf("DNS.Timeout = %v, want 5s", cfg.DNS.Timeout)
	}
	if !cfg.DNS.EnumerateRecords {
		t.Errorf("DNS.EnumerateRecords = false, want true by default")
	}
	if len(cfg.Ports.DefaultPorts) == 0 {
		t.Errorf("Ports.DefaultPorts is empty")
	}
	if cfg.Scope.AllowReservedRanges {
		t.Errorf("Scope.AllowReservedRanges = true, want false by default")
	}
	if cfg.Crawler.Enabled {
		t.Errorf("Crawler.Enabled = true, want false by default")
	}
	if cfg.Crawler.MaxDepth != 2 {
		t.Errorf("Crawler.MaxDepth = %d, want 2", cfg.Crawler.MaxDepth)
	}
	if cfg.Crawler.MaxPages != 20 {
		t.Errorf("Crawler.MaxPages = %d, want 20", cfg.Crawler.MaxPages)
	}
	for name, got := range map[string]string{
		"Tools.Subfinder": cfg.Tools.Subfinder,
		"Tools.Dnsx":      cfg.Tools.Dnsx,
		"Tools.Naabu":     cfg.Tools.Naabu,
		"Tools.Httpx":     cfg.Tools.Httpx,
		"Tools.Katana":    cfg.Tools.Katana,
	} {
		if got != "auto" {
			t.Errorf("%s = %q, want \"auto\" by default", name, got)
		}
	}
}

func TestLoadFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	yaml := `
storage:
  dsn: /tmp/custom.db
logging:
  level: debug
concurrency:
  http_workers: 42
`
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Storage.DSN != "/tmp/custom.db" {
		t.Errorf("Storage.DSN = %q, want /tmp/custom.db", cfg.Storage.DSN)
	}
	if cfg.Logging.Level != "debug" {
		t.Errorf("Logging.Level = %q, want debug", cfg.Logging.Level)
	}
	if cfg.Concurrency.HTTPWorkers != 42 {
		t.Errorf("Concurrency.HTTPWorkers = %d, want 42", cfg.Concurrency.HTTPWorkers)
	}
	// Untouched defaults should still be present.
	if cfg.Concurrency.DNSWorkers != 10 {
		t.Errorf("Concurrency.DNSWorkers = %d, want default 10", cfg.Concurrency.DNSWorkers)
	}
}

func TestLoadFromFile_AuthenticationProfiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	yaml := `
authentication:
  profiles:
    - name: lab-user
      type: form_login
      login_url: http://app.test/login
      username_env: SAKANNER_LAB_USERNAME
      password_env: SAKANNER_LAB_PASSWORD
      username_field: username
      password_field: password
    - name: api-token
      type: bearer_token
      token_env: SAKANNER_API_TOKEN
      scope_host: api.test
`
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Authentication.Profiles) != 2 {
		t.Fatalf("got %d profiles, want 2", len(cfg.Authentication.Profiles))
	}
	p := cfg.Authentication.Profiles[0]
	if p.Name != "lab-user" || p.Type != "form_login" || p.LoginURL != "http://app.test/login" || p.UsernameEnv != "SAKANNER_LAB_USERNAME" {
		t.Errorf("profile[0] parsed incorrectly: %+v", p)
	}
}

func TestValidate_AuthenticationProfile_ValidTypesPass(t *testing.T) {
	tests := []AuthProfileConfig{
		{Name: "a", Type: "form_login", LoginURL: "http://x/login", UsernameEnv: "U", PasswordEnv: "P"},
		{Name: "b", Type: "cookie", CookieEnv: "C", ScopeHost: "h"},
		{Name: "c", Type: "bearer_token", TokenEnv: "T", ScopeHost: "h"},
		{Name: "d", Type: "header", HeaderName: "X-Api-Key", HeaderValueEnv: "V", ScopeHost: "h"},
	}
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	cfg.Authentication.Profiles = tests
	// Deliberately no env vars set for U/P/C/T/V -- Validate() must
	// still pass, since env var PRESENCE is checked lazily by
	// internal/auth.ResolveProfile, not by config.Validate.
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil (structurally valid profiles, env vars checked lazily elsewhere)", err)
	}
}

func TestValidate_Identities_ValidReferencesPass(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	cfg.Authentication.Profiles = []AuthProfileConfig{{Name: "customer-login", Type: "form_login", LoginURL: "http://x/login", UsernameEnv: "U", PasswordEnv: "P"}}
	cfg.Identities.Identities = []IdentityConfig{
		{Name: "account-a", AuthProfile: "customer-login", UsernameEnv: "UA", PasswordEnv: "PA"},
		{Name: "account-b", AuthProfile: "customer-login", UsernameEnv: "UB", PasswordEnv: "PB"},
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil (two identities sharing one valid auth profile)", err)
	}
}

func TestValidate_Identities_DefaultMaxCountAllowsUpToTen(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Identities.MaxCount != 10 {
		t.Fatalf("default identities.max_count = %d, want 10", cfg.Identities.MaxCount)
	}
	cfg.Authentication.Profiles = []AuthProfileConfig{{Name: "p", Type: "bearer_token", TokenEnv: "T", ScopeHost: "h"}}
	ids := make([]IdentityConfig, 10)
	for i := range ids {
		ids[i] = IdentityConfig{Name: fmt.Sprintf("account-%d", i), AuthProfile: "p"}
	}
	cfg.Identities.Identities = ids
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil (exactly 10 identities, the default max_count)", err)
	}
}

func TestLoadFromFile_Identities(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	yaml := `
authentication:
  profiles:
    - name: customer-login
      type: form_login
      login_url: http://app.test/login
      username_env: SHARED_USER
      password_env: SHARED_PASS
identities:
  max_count: 5
  identities:
    - name: account-a
      auth_profile: customer-login
      username_env: SAKANNER_ACCOUNT_A_USER
      password_env: SAKANNER_ACCOUNT_A_PASS
    - name: account-b
      auth_profile: customer-login
      username_env: SAKANNER_ACCOUNT_B_USER
      password_env: SAKANNER_ACCOUNT_B_PASS
`
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Identities.MaxCount != 5 {
		t.Errorf("MaxCount = %d, want 5", cfg.Identities.MaxCount)
	}
	if len(cfg.Identities.Identities) != 2 {
		t.Fatalf("got %d identities, want 2", len(cfg.Identities.Identities))
	}
	// Declaration order must be preserved -- task's determinism requirement.
	if cfg.Identities.Identities[0].Name != "account-a" || cfg.Identities.Identities[1].Name != "account-b" {
		t.Errorf("identity order not preserved: %+v", cfg.Identities.Identities)
	}
	if cfg.Identities.Identities[0].UsernameEnv != "SAKANNER_ACCOUNT_A_USER" {
		t.Errorf("identity[0] parsed incorrectly: %+v", cfg.Identities.Identities[0])
	}
}

func TestLoadEnvOverride(t *testing.T) {
	t.Setenv("SAKANNER_STORAGE_DSN", "/tmp/env.db")
	t.Setenv("SAKANNER_LOGGING_LEVEL", "warn")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Storage.DSN != "/tmp/env.db" {
		t.Errorf("Storage.DSN = %q, want /tmp/env.db (env override)", cfg.Storage.DSN)
	}
	if cfg.Logging.Level != "warn" {
		t.Errorf("Logging.Level = %q, want warn (env override)", cfg.Logging.Level)
	}
}

func TestLoadNonexistentFileFallsBackToDefaults(t *testing.T) {
	cfg, err := Load("/nonexistent/path/config.yaml")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Storage.Driver != "sqlite" {
		t.Errorf("Storage.Driver = %q, want sqlite default", cfg.Storage.Driver)
	}
}

func TestValidateRejectsBadValues(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{"bad driver", func(c *Config) { c.Storage.Driver = "postgres" }},
		{"empty dsn", func(c *Config) { c.Storage.DSN = "" }},
		{"bad log level", func(c *Config) { c.Logging.Level = "verbose" }},
		{"bad log format", func(c *Config) { c.Logging.Format = "xml" }},
		{"zero workers", func(c *Config) { c.Concurrency.HTTPWorkers = 0 }},
		{"negative rate", func(c *Config) { c.RateLimit.HTTPPerSecond = -1 }},
		{"negative redirects", func(c *Config) { c.HTTP.MaxRedirects = -1 }},
		{"negative crawl depth", func(c *Config) { c.Crawler.MaxDepth = -1 }},
		{"crawler enabled with zero max pages", func(c *Config) { c.Crawler.Enabled = true; c.Crawler.MaxPages = 0 }},
		{"invalid tools backend", func(c *Config) { c.Tools.Httpx = "nmap" }},
		{"auth profile missing name", func(c *Config) {
			c.Authentication.Profiles = []AuthProfileConfig{{Type: "form_login", LoginURL: "http://x/login", UsernameEnv: "U", PasswordEnv: "P"}}
		}},
		{"auth profile duplicate name", func(c *Config) {
			c.Authentication.Profiles = []AuthProfileConfig{
				{Name: "dup", Type: "bearer_token", TokenEnv: "T", ScopeHost: "x"},
				{Name: "dup", Type: "bearer_token", TokenEnv: "T2", ScopeHost: "y"},
			}
		}},
		{"auth profile invalid type", func(c *Config) {
			c.Authentication.Profiles = []AuthProfileConfig{{Name: "x", Type: "sso"}}
		}},
		{"auth profile form_login missing fields", func(c *Config) {
			c.Authentication.Profiles = []AuthProfileConfig{{Name: "x", Type: "form_login"}}
		}},
		{"auth profile cookie missing scope_host", func(c *Config) {
			c.Authentication.Profiles = []AuthProfileConfig{{Name: "x", Type: "cookie", CookieEnv: "C"}}
		}},
		{"auth profile bearer_token missing token_env", func(c *Config) {
			c.Authentication.Profiles = []AuthProfileConfig{{Name: "x", Type: "bearer_token", ScopeHost: "h"}}
		}},
		{"auth profile header missing header_name", func(c *Config) {
			c.Authentication.Profiles = []AuthProfileConfig{{Name: "x", Type: "header", HeaderValueEnv: "V", ScopeHost: "h"}}
		}},
		{"auth profile negative max_redirects", func(c *Config) {
			c.Authentication.Profiles = []AuthProfileConfig{{Name: "x", Type: "bearer_token", TokenEnv: "T", ScopeHost: "h", MaxRedirects: -1}}
		}},
		{"identity missing name", func(c *Config) {
			c.Authentication.Profiles = []AuthProfileConfig{{Name: "p", Type: "bearer_token", TokenEnv: "T", ScopeHost: "h"}}
			c.Identities.Identities = []IdentityConfig{{AuthProfile: "p"}}
		}},
		{"identity duplicate name", func(c *Config) {
			c.Authentication.Profiles = []AuthProfileConfig{{Name: "p", Type: "bearer_token", TokenEnv: "T", ScopeHost: "h"}}
			c.Identities.Identities = []IdentityConfig{{Name: "a", AuthProfile: "p"}, {Name: "a", AuthProfile: "p"}}
		}},
		{"identity missing auth_profile", func(c *Config) {
			c.Identities.Identities = []IdentityConfig{{Name: "a"}}
		}},
		{"identity invalid auth_profile reference", func(c *Config) {
			c.Authentication.Profiles = []AuthProfileConfig{{Name: "p", Type: "bearer_token", TokenEnv: "T", ScopeHost: "h"}}
			c.Identities.Identities = []IdentityConfig{{Name: "a", AuthProfile: "does-not-exist"}}
		}},
		{"identity count exceeds max_count", func(c *Config) {
			c.Authentication.Profiles = []AuthProfileConfig{{Name: "p", Type: "bearer_token", TokenEnv: "T", ScopeHost: "h"}}
			c.Identities.MaxCount = 1
			c.Identities.Identities = []IdentityConfig{{Name: "a", AuthProfile: "p"}, {Name: "b", AuthProfile: "p"}}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := Load("")
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			tt.mutate(cfg)
			if err := cfg.Validate(); err == nil {
				t.Errorf("Validate() = nil, want error")
			}
		})
	}
}
