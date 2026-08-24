package auth

import (
	"fmt"
	"sort"
	"strings"
)

// IdentityState is Phase 3.16's identity lifecycle -- deliberately its
// own type, never conflated with State (which describes a SESSION's
// own authentication outcome) or any scan-level status
// (internal/orchestrator.Status/DetectionState). The distinction:
//
//   - Scan state (internal/orchestrator.Status) describes whether the
//     PIPELINE finished -- SCOPE/RECON/DETECTION/etc.
//   - Authentication state (State, this package, Phase 3.14) describes
//     whether ONE login/setup attempt succeeded -- a property of a
//     Session.
//   - Identity state (IdentityState, this type) describes the
//     LIFECYCLE of a configured security principal, a superset of
//     authentication state: an identity can be IDENTITY_DISABLED or
//     IDENTITY_CONFIGURED before authentication is ever attempted at
//     all, states State has no equivalent for (see NewIdentity's doc
//     comment for exactly when each applies).
type IdentityState string

const (
	// IdentityConfigured is an identity's state before Authenticate has
	// ever been attempted for it -- structurally valid configuration
	// (a resolvable name, a real auth_profile reference), nothing more
	// asserted yet. Mirrors what `scanner auth profiles show` already
	// calls "ready" for a bare auth profile, given a formal name now
	// that identities are explicitly configured, listed, and resolved
	// before any scan runs.
	IdentityConfigured IdentityState = "IDENTITY_CONFIGURED"
	// IdentityAuthenticating mirrors StateAuthenticating -- observable
	// mid-Authenticate, never a Provider's final return value.
	IdentityAuthenticating IdentityState = "IDENTITY_AUTHENTICATING"
	// IdentityAuthenticated mirrors StateAuthenticated.
	IdentityAuthenticated IdentityState = "IDENTITY_AUTHENTICATED"
	// IdentityAuthFailed mirrors StateFailed.
	IdentityAuthFailed IdentityState = "IDENTITY_AUTH_FAILED"
	// IdentityExpired mirrors StateExpired.
	IdentityExpired IdentityState = "IDENTITY_EXPIRED"
	// IdentityDisabled is an identity administratively turned off in
	// configuration (IdentityConfig.Disabled) -- checked BEFORE any
	// resolution or network activity, so a disabled identity can never
	// be selected for a scan regardless of whether its underlying auth
	// profile is otherwise valid. Has no State equivalent at all: a
	// Session is never even constructed for a disabled identity.
	IdentityDisabled IdentityState = "IDENTITY_DISABLED"
)

// identityStateFromAuthState translates a Session's own State into the
// Identity vocabulary -- the ONE place that mapping happens, so
// IdentityConfigured/IdentityDisabled (which have no State equivalent)
// and the four states that DO map directly never drift into two
// independently-maintained enumerations.
func identityStateFromAuthState(s State) IdentityState {
	switch s {
	case StateAuthenticating:
		return IdentityAuthenticating
	case StateAuthenticated:
		return IdentityAuthenticated
	case StateFailed:
		return IdentityAuthFailed
	case StateExpired:
		return IdentityExpired
	default:
		// StateUnauthenticated/StateUnknown have no natural Identity
		// equivalent once authentication was actually attempted --
		// treated as a failure rather than silently reporting
		// IdentityConfigured (which would misleadingly suggest
		// authentication was never attempted at all).
		return IdentityAuthFailed
	}
}

// IdentityConfig is the raw, not-yet-resolved shape of one configured
// identity -- mirrors ProfileConfig's own "raw vs. resolved" pattern
// (see config.go's doc comment). Defined here, in internal/auth,
// rather than embedded in internal/config, for the identical reason
// ProfileConfig is: internal/config never imports a domain package's
// own types; cmd/scanner translates config.IdentityConfig into this
// shape field-by-field, exactly as it already does for
// config.AuthProfileConfig -> auth.ProfileConfig.
//
// An IdentityConfig deliberately does NOT duplicate an auth profile's
// own mechanism fields (login_url, field names, success indicators) --
// task section 2's "clearly separate Auth Profile from Identity": an
// Identity REFERENCES an AuthProfile by name (AuthProfile field) and
// optionally overrides ONLY the credential-bearing fields, so two
// identities can share one profile's login MECHANISM while
// authenticating as two completely different accounts (task's
// "account-a -> customer-login, account-b -> customer-login" example).
// An override field left empty inherits the referenced profile's own
// value -- an identity that needs no override at all (the profile IS
// already account-specific) works with nothing but Name/AuthProfile
// set.
type IdentityConfig struct {
	Name        string
	AuthProfile string
	// Disabled administratively turns this identity off -- checked
	// before any resolution or authentication attempt (IdentityDisabled).
	Disabled bool

	// Credential overrides -- each applies only when non-empty, and
	// only the ones relevant to the referenced profile's own Type ever
	// matter (a form_login profile ignores TokenEnv, etc., exactly as
	// ResolveProfile already does for a bare ProfileConfig).
	UsernameEnv    string
	PasswordEnv    string
	TokenEnv       string
	CookieEnv      string
	HeaderValueEnv string
}

// Identity is a resolved security principal -- task section 1's model.
// Its normal, zero-value-safe output representation (Redacted) never
// includes a password, cookie value, Authorization header value, CSRF
// value, token, or any other secret -- see Redacted's own doc comment.
type Identity struct {
	Name          string
	AuthProfile   string
	State         IdentityState
	Session       *Session // nil until Authenticate succeeds or fails
	FailureReason string
}

// NewIdentity returns an Identity in its initial IdentityConfigured
// (or IdentityDisabled) state -- BEFORE any authentication attempt,
// matching task section 9's "Identity state" existing independently of
// "Authentication state." Callers that go on to authenticate should
// call WithSession afterward to record the outcome.
func NewIdentity(ic IdentityConfig) Identity {
	state := IdentityConfigured
	if ic.Disabled {
		state = IdentityDisabled
	}
	return Identity{Name: ic.Name, AuthProfile: ic.AuthProfile, State: state}
}

// WithSession returns a copy of i reflecting the outcome of an
// authentication attempt -- sess is the Session Provider.Authenticate
// returned (always non-nil, even on failure; see Provider's doc
// comment), authErr is what Authenticate returned alongside it.
func (i Identity) WithSession(sess *Session, authErr error) Identity {
	i.Session = sess
	if sess != nil {
		i.State = identityStateFromAuthState(sess.State)
		i.FailureReason = sess.FailureReason
	} else if authErr != nil {
		i.State = IdentityAuthFailed
		i.FailureReason = authErr.Error()
	}
	return i
}

// IdentitySummary is a secret-free view of an Identity, safe to print
// (`scanner identities show`) or log -- mirrors ProfileSummary/
// SessionSummary's own pattern exactly: every credential-bearing field
// is reduced to a boolean/name-only view via the embedded
// SessionSummary, never the real value.
type IdentitySummary struct {
	Name          string
	AuthProfile   string
	State         IdentityState
	FailureReason string
	Session       SessionSummary
}

// Redacted returns a secret-free summary of i -- the only form of an
// Identity's own session state this package ever exposes for display.
// Identity labels (Name) are always safe: task section 1's own
// examples ("anonymous", "account-a", "account-b") are operator-chosen
// strings, never a credential.
func (i Identity) Redacted() IdentitySummary {
	return IdentitySummary{
		Name:          i.Name,
		AuthProfile:   i.AuthProfile,
		State:         i.State,
		FailureReason: i.FailureReason,
		Session:       i.Session.Redacted(),
	}
}

// UnknownIdentityError mirrors UnknownProfileError's exact shape and
// wording convention -- `scanner scan --identity <bad>` and `scanner
// identities show <bad>` fail identically in style to an unknown auth
// profile.
type UnknownIdentityError struct {
	Name      string
	Available []string
}

func (e *UnknownIdentityError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "unknown identity %q\nAvailable identities:", e.Name)
	if len(e.Available) == 0 {
		b.WriteString("\n  (none configured -- see \"identities\" in your config file)")
		return b.String()
	}
	for _, name := range e.Available {
		fmt.Fprintf(&b, "\n  %s", name)
	}
	return b.String()
}

// IdentityRegistry is a read-only, deterministically-ordered view over
// a configured identity list -- mirrors internal/policy.Registry's
// exact pattern (an ordered slice for declaration-order iteration, a
// map for O(1) lookup), applied to operator-configured identities
// instead of a fixed built-in profile set. Task section 13's
// determinism requirement ("do not depend on Go map iteration order")
// is what this type exists to guarantee.
type IdentityRegistry struct {
	byName map[string]IdentityConfig
	order  []string
}

// NewIdentityRegistry builds a registry from configs, rejecting
// duplicate names -- defense in depth alongside
// internal/config.IdentitiesConfig's own structural validation (which
// every caller going through config.Load already gets): this
// package's own public API must not silently accept malformed input
// either, since a caller could construct []IdentityConfig directly
// without ever going through config validation (as this package's own
// tests do).
func NewIdentityRegistry(configs []IdentityConfig) (*IdentityRegistry, error) {
	r := &IdentityRegistry{byName: make(map[string]IdentityConfig, len(configs))}
	for _, ic := range configs {
		if strings.TrimSpace(ic.Name) == "" {
			return nil, fmt.Errorf("auth: an identity is missing a name")
		}
		if _, dup := r.byName[ic.Name]; dup {
			return nil, fmt.Errorf("auth: duplicate identity name %q", ic.Name)
		}
		r.byName[ic.Name] = ic
		r.order = append(r.order, ic.Name)
	}
	return r, nil
}

// Get looks up one identity config by exact, case-sensitive name.
func (r *IdentityRegistry) Get(name string) (IdentityConfig, bool) {
	ic, ok := r.byName[name]
	return ic, ok
}

// List returns every identity config in declared order -- never map
// iteration order.
func (r *IdentityRegistry) List() []IdentityConfig {
	out := make([]IdentityConfig, 0, len(r.order))
	for _, name := range r.order {
		out = append(out, r.byName[name])
	}
	return out
}

// Names returns every registered identity name, sorted -- used to
// build the "Available identities:" list in an unknown-identity error,
// matching Registry.Names' own established convention.
func (r *IdentityRegistry) Names() []string {
	names := make([]string, 0, len(r.byName))
	for name := range r.byName {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// ResolveIdentityProfile builds the fully-resolved auth.Profile an
// identity should authenticate with: ic.AuthProfile's own mechanism
// fields (login_url, field names, success indicators, scope_host,
// timeout, ...), with ic's own credential-env overrides applied where
// non-empty (task section 2's "completely independent credentials"
// while sharing one login mechanism). Pure/deterministic except for
// the eventual os.Getenv calls ResolveProfile itself performs -- no
// network activity, matching every other profile-resolution path in
// this codebase.
func ResolveIdentityProfile(ic IdentityConfig, profiles []ProfileConfig) (Profile, error) {
	pc, err := FindProfileConfig(profiles, ic.AuthProfile)
	if err != nil {
		return Profile{}, fmt.Errorf("auth: identity %q: %w", ic.Name, err)
	}
	if ic.UsernameEnv != "" {
		pc.UsernameEnv = ic.UsernameEnv
	}
	if ic.PasswordEnv != "" {
		pc.PasswordEnv = ic.PasswordEnv
	}
	if ic.TokenEnv != "" {
		pc.TokenEnv = ic.TokenEnv
	}
	if ic.CookieEnv != "" {
		pc.CookieEnv = ic.CookieEnv
	}
	if ic.HeaderValueEnv != "" {
		pc.HeaderValueEnv = ic.HeaderValueEnv
	}
	profile, err := ResolveProfile(pc)
	if err != nil {
		return Profile{}, fmt.Errorf("auth: identity %q: %w", ic.Name, err)
	}
	return profile, nil
}
