package auth

import (
	"context"
	"fmt"

	"sakanner/internal/safedial"
	"sakanner/internal/scope"
)

// Dependencies are the shared, caller-constructed resources every
// Provider needs -- exactly the same Dialer/Validator pair every other
// network-touching stage in this codebase already receives from its
// caller (internal/http.Prober, internal/crawler.Crawler), so
// authentication introduces no new way to reach the network and no new
// scope-validation surface.
type Dependencies struct {
	Dialer    *safedial.Dialer
	Validator scope.Validator
}

// Provider performs one authentication mechanism's own login/setup flow
// and returns an authenticated Session. Authenticate always returns a
// non-nil Session (even on failure -- State/FailureReason describe what
// happened, mirroring internal/orchestrator.Orchestrator.Run's own
// "always return what happened so far" convention) alongside any error.
type Provider interface {
	Authenticate(ctx context.Context, deps Dependencies) (*Session, error)
}

// NewProvider selects the Provider implementation for p.Type -- the
// ONLY place in this package that branches on Type to choose an
// implementation; every other file operates on an already-selected
// Provider or a Profile's plain fields.
func NewProvider(p Profile) (Provider, error) {
	switch p.Type {
	case TypeFormLogin:
		return &FormLoginProvider{Profile: p}, nil
	case TypeCookie, TypeBearerToken, TypeHeader:
		return &StaticProvider{Profile: p}, nil
	default:
		return nil, fmt.Errorf("auth: profile %q: unsupported authentication type %q", p.Name, p.Type)
	}
}
