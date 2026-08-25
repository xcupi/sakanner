package auth

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
)

// UnknownProfileError is returned when a caller names an authentication
// profile that does not exist in configuration -- mirrors
// internal/policy.UnknownProfileError's exact shape and wording
// convention, so `scanner scan --auth-profile <bad>` and `scanner
// profiles show <bad>` fail identically in style.
type UnknownProfileError struct {
	Name      string
	Available []string
}

func (e *UnknownProfileError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "unknown authentication profile %q\nAvailable profiles:", e.Name)
	if len(e.Available) == 0 {
		b.WriteString("\n  (none configured -- see \"authentication.profiles\" in your config file)")
		return b.String()
	}
	for _, name := range e.Available {
		fmt.Fprintf(&b, "\n  %s", name)
	}
	return b.String()
}

// ResolveProfile turns a ProfileConfig into a fully resolved Profile --
// reading every referenced environment variable and validating the
// result. This is the ONLY place this package reads os.Getenv or
// performs any I/O of its own; ResolveProfile makes no network call and
// touches no filesystem beyond the environment, so it can safely run
// BEFORE any scope/network activity (task section 12's "invalid
// authentication profile must fail before network activity, create no
// scan job").
//
// Every validation failure is collected and joined into one error
// (errors.Join) rather than returning on the first problem found, so an
// operator sees every missing environment variable / missing field at
// once instead of fixing them one at a time across repeated runs.
func ResolveProfile(pc ProfileConfig) (Profile, error) {
	var errs []error

	if strings.TrimSpace(pc.Name) == "" {
		errs = append(errs, errors.New("auth: profile name must not be empty"))
	}
	if !pc.Type.Valid() {
		errs = append(errs, fmt.Errorf("auth: profile %q: unknown authentication type %q (want one of %q, %q, %q, %q, %q)",
			pc.Name, pc.Type, TypeFormLogin, TypeCookie, TypeBearerToken, TypeHeader, TypeFormLoginAuto))
		// The type-specific branches below all assume a known Type;
		// bail out early rather than compounding one real error with
		// a wall of misleading "field required" noise for a type that
		// isn't even valid.
		return Profile{}, errors.Join(errs...)
	}

	p := Profile{
		Name:         pc.Name,
		Type:         pc.Type,
		Timeout:      pc.Timeout,
		MaxRedirects: pc.MaxRedirects,
	}
	if p.Timeout <= 0 {
		p.Timeout = DefaultTimeout
	}
	if pc.MaxRedirects < 0 {
		errs = append(errs, fmt.Errorf("auth: profile %q: max_redirects must not be negative", pc.Name))
	} else if pc.MaxRedirects == 0 {
		p.MaxRedirects = DefaultMaxRedirects
	}

	switch pc.Type {
	case TypeFormLogin:
		resolveFormLogin(pc, &p, &errs)
	case TypeFormLoginAuto:
		resolveFormLoginAuto(pc, &p, &errs)
	case TypeCookie:
		resolveCookie(pc, &p, &errs)
	case TypeBearerToken:
		resolveBearerToken(pc, &p, &errs)
	case TypeHeader:
		resolveHeader(pc, &p, &errs)
	}

	if len(errs) > 0 {
		return Profile{}, fmt.Errorf("auth: profile %q is invalid: %w", pc.Name, errors.Join(errs...))
	}
	return p, nil
}

func resolveFormLogin(pc ProfileConfig, p *Profile, errs *[]error) {
	if strings.TrimSpace(pc.LoginURL) == "" {
		*errs = append(*errs, errors.New("login_url is required for type \"form_login\""))
	} else {
		u, err := url.Parse(pc.LoginURL)
		if err != nil || u.Scheme == "" || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			*errs = append(*errs, fmt.Errorf("login_url %q is not a valid absolute http(s) URL", pc.LoginURL))
		} else {
			p.LoginURL = u
			p.Host = u.Hostname()
		}
	}
	if pc.ScopeHost != "" {
		// An explicit override always wins, even over a successfully
		// parsed login_url's own host -- e.g. a login form served from
		// one host that establishes a session valid on another.
		p.Host = pc.ScopeHost
	}

	username, uOK := lookupEnv(pc.UsernameEnv, "username_env", errs)
	password, pOK := lookupEnv(pc.PasswordEnv, "password_env", errs)
	if uOK {
		p.Username = username
	}
	if pOK {
		p.Password = password
	}

	p.UsernameField = pc.UsernameField
	if p.UsernameField == "" {
		p.UsernameField = "username"
	}
	p.PasswordField = pc.PasswordField
	if p.PasswordField == "" {
		p.PasswordField = "password"
	}
	p.ExtraFields = pc.ExtraFields
	p.SuccessURLContains = pc.SuccessURLContains
	p.SuccessTextContains = pc.SuccessTextContains
	p.FailureTextContains = pc.FailureTextContains
}

// resolveFormLoginAuto resolves a TypeFormLoginAuto profile -- the
// same username/password credential resolution resolveFormLogin
// performs, but with StartURL (not LoginURL) as the required location
// hint: any reachable same-origin page, since discover.go finds the
// actual login page/form/field names at authenticate-time rather than
// requiring them here. UsernameField/PasswordField/ExtraFields/
// Success*/FailureTextContains are deliberately NOT resolved here --
// this type has no operator-configured equivalents for them (they're
// discovered), and Profile's own zero values for those fields are
// exactly right until AutoFormLoginProvider fills them in post-discovery.
func resolveFormLoginAuto(pc ProfileConfig, p *Profile, errs *[]error) {
	if strings.TrimSpace(pc.StartURL) == "" {
		*errs = append(*errs, errors.New("start_url is required for type \"form_login_auto\""))
	} else {
		u, err := url.Parse(pc.StartURL)
		if err != nil || u.Scheme == "" || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			*errs = append(*errs, fmt.Errorf("start_url %q is not a valid absolute http(s) URL", pc.StartURL))
		} else {
			p.StartURL = u
			p.Host = u.Hostname()
		}
	}
	if pc.ScopeHost != "" {
		// Same override precedent as resolveFormLogin's own ScopeHost
		// handling -- e.g. discovery starts on one host but the login
		// flow is known to establish a session valid on a different one.
		p.Host = pc.ScopeHost
	}

	username, uOK := lookupEnv(pc.UsernameEnv, "username_env", errs)
	password, pOK := lookupEnv(pc.PasswordEnv, "password_env", errs)
	if uOK {
		p.Username = username
	}
	if pOK {
		p.Password = password
	}
}

func resolveCookie(pc ProfileConfig, p *Profile, errs *[]error) {
	requireScopeHost(pc, p, errs)
	if value, ok := lookupEnv(pc.CookieEnv, "cookie_env", errs); ok {
		p.CookieHeader = value
	}
}

func resolveBearerToken(pc ProfileConfig, p *Profile, errs *[]error) {
	requireScopeHost(pc, p, errs)
	if value, ok := lookupEnv(pc.TokenEnv, "token_env", errs); ok {
		p.Token = value
	}
}

func resolveHeader(pc ProfileConfig, p *Profile, errs *[]error) {
	requireScopeHost(pc, p, errs)
	if strings.TrimSpace(pc.HeaderName) == "" {
		*errs = append(*errs, errors.New("header_name is required for type \"header\""))
	} else {
		p.HeaderName = pc.HeaderName
	}
	if value, ok := lookupEnv(pc.HeaderValueEnv, "header_value_env", errs); ok {
		p.HeaderValue = value
	}
}

func requireScopeHost(pc ProfileConfig, p *Profile, errs *[]error) {
	if strings.TrimSpace(pc.ScopeHost) == "" {
		*errs = append(*errs, fmt.Errorf("scope_host is required for type %q", pc.Type))
		return
	}
	p.Host = pc.ScopeHost
}

// lookupEnv reads env var name, appending a validation error (that
// names the CONFIG FIELD, e.g. "password_env", not the secret value
// itself) if envVar is empty or the variable is unset/empty -- exactly
// the deterministic, secret-free error task section 12 requires.
func lookupEnv(envVar, fieldName string, errs *[]error) (string, bool) {
	if strings.TrimSpace(envVar) == "" {
		*errs = append(*errs, fmt.Errorf("%s is required", fieldName))
		return "", false
	}
	value, ok := os.LookupEnv(envVar)
	if !ok || value == "" {
		*errs = append(*errs, fmt.Errorf("environment variable %s (referenced by %s) is not set", envVar, fieldName))
		return "", false
	}
	return value, true
}

// FindProfileConfig looks up name in profiles by exact match, returning
// an *UnknownProfileError (with every configured name, sorted, as
// Available) if not found -- shared by every caller that resolves a
// profile by name from a configured list (cmd/scanner's CLI commands),
// so the "unknown profile" error is worded identically everywhere.
func FindProfileConfig(profiles []ProfileConfig, name string) (ProfileConfig, error) {
	for _, pc := range profiles {
		if pc.Name == name {
			return pc, nil
		}
	}
	names := make([]string, 0, len(profiles))
	for _, pc := range profiles {
		names = append(names, pc.Name)
	}
	sort.Strings(names)
	return ProfileConfig{}, &UnknownProfileError{Name: name, Available: names}
}
