package auth

import (
	"context"
	"strings"
	"testing"

	"sakanner/internal/dns"
)

func TestStaticProvider_Cookie(t *testing.T) {
	p := Profile{Name: "c", Type: TypeCookie, Host: "app.test", CookieHeader: "session_id=abc123"}
	prov, err := NewProvider(p)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	sess, err := prov.Authenticate(context.Background(), deps(t, dns.NewFakeResolver(), allowAllValidator{}))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if sess.State != StateAuthenticated {
		t.Fatalf("State = %s, want AUTHENTICATED", sess.State)
	}
	if sess.Headers["Cookie"] != "session_id=abc123" {
		t.Errorf("Cookie header = %q, want the configured cookie value", sess.Headers["Cookie"])
	}
	if sess.Host != "app.test" {
		t.Errorf("Host = %q, want app.test", sess.Host)
	}
}

func TestStaticProvider_BearerToken(t *testing.T) {
	p := Profile{Name: "b", Type: TypeBearerToken, Host: "api.test", Token: "tok-xyz"}
	prov, _ := NewProvider(p)
	sess, err := prov.Authenticate(context.Background(), deps(t, dns.NewFakeResolver(), allowAllValidator{}))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if sess.Headers["Authorization"] != "Bearer tok-xyz" {
		t.Errorf("Authorization = %q, want %q", sess.Headers["Authorization"], "Bearer tok-xyz")
	}
}

func TestStaticProvider_Header(t *testing.T) {
	p := Profile{Name: "h", Type: TypeHeader, Host: "api.test", HeaderName: "X-Api-Key", HeaderValue: "key-123"}
	prov, _ := NewProvider(p)
	sess, err := prov.Authenticate(context.Background(), deps(t, dns.NewFakeResolver(), allowAllValidator{}))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if sess.Headers["X-Api-Key"] != "key-123" {
		t.Errorf("X-Api-Key = %q, want key-123", sess.Headers["X-Api-Key"])
	}
}

func TestStaticProvider_OutOfScopeHost_Fails(t *testing.T) {
	p := Profile{Name: "b", Type: TypeBearerToken, Host: "not-authorized.test", Token: "tok-xyz"}
	prov, _ := NewProvider(p)
	validator := realValidator(allowHost("only-this.test"))
	sess, err := prov.Authenticate(context.Background(), deps(t, dns.NewFakeResolver(), validator))
	if err == nil {
		t.Fatal("expected an out-of-scope error, got none")
	}
	if sess.State != StateFailed {
		t.Fatalf("State = %s, want AUTHENTICATION_FAILED", sess.State)
	}
	if !strings.Contains(err.Error(), "out of scope") {
		t.Errorf("error = %v, want it to mention out-of-scope", err)
	}
	if strings.Contains(err.Error(), "tok-xyz") {
		t.Fatal("SECURITY: out-of-scope error leaked the raw token value")
	}
	if strings.Contains(sess.FailureReason, "tok-xyz") {
		t.Fatal("SECURITY: FailureReason leaked the raw token value")
	}
}

func TestNewProvider_UnknownType(t *testing.T) {
	_, err := NewProvider(Profile{Name: "x", Type: "bogus"})
	if err == nil {
		t.Fatal("expected an error for an unsupported type")
	}
}
