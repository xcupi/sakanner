package http

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"path/filepath"
	"testing"
	"time"

	"sakanner/internal/dns"
	"sakanner/internal/scope"
	"sakanner/internal/testutil"
)

// httpxFakeValidator lets tests control scope decisions directly.
type httpxFakeValidator struct{ allowed bool }

func (f *httpxFakeValidator) CheckHost(ctx context.Context, host string) (scope.Decision, error) {
	return f.check()
}
func (f *httpxFakeValidator) CheckIP(ctx context.Context, ip net.IP) (scope.Decision, error) {
	return f.check()
}
func (f *httpxFakeValidator) CheckResolved(ctx context.Context, hostname string, ip net.IP) (scope.Decision, error) {
	return f.check()
}
func (f *httpxFakeValidator) check() (scope.Decision, error) {
	if f.allowed {
		return scope.Decision{Allowed: true, Reason: "test allow"}, nil
	}
	return scope.Decision{Allowed: false, Reason: "test deny"}, nil
}

func TestHttpxProber_ParsesFirstResult(t *testing.T) {
	binary := testutil.WriteScript(t, "httpx", `
echo '{"url":"https://example.com/","status_code":200,"title":"Example","scheme":"https","header":{"Server":"nginx"},"body":"<html>hi</html>"}'
exit 0
`)
	p := NewHttpxProber(binary, &httpxFakeValidator{allowed: true})

	svc, body, err := p.Probe(context.Background(), net.ParseIP("203.0.113.5"), 443, "example.com")
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if svc.URL != "https://example.com/" || svc.StatusCode != 200 || svc.Title != "Example" {
		t.Errorf("svc = %+v", svc)
	}
	if svc.Headers["Server"] != "nginx" {
		t.Errorf("Headers = %v, want Server=nginx", svc.Headers)
	}
	if string(body) != "<html>hi</html>" {
		t.Errorf("body = %q", body)
	}
}

func TestHttpxProber_NoResultIsError(t *testing.T) {
	binary := testutil.WriteScript(t, "httpx", "exit 0\n")
	p := NewHttpxProber(binary, &httpxFakeValidator{allowed: true})

	if _, _, err := p.Probe(context.Background(), net.ParseIP("203.0.113.5"), 443, "example.com"); err == nil {
		t.Fatal("expected an error when httpx reports nothing")
	}
}

func TestHttpxProber_DeniedScopeReturnsErrorWithoutRunning(t *testing.T) {
	binary := testutil.WriteScript(t, "httpx", `echo '{"url":"https://example.com/","status_code":200}'`+"\n")
	p := NewHttpxProber(binary, &httpxFakeValidator{allowed: false})

	if _, _, err := p.Probe(context.Background(), net.ParseIP("203.0.113.5"), 443, "example.com"); err == nil {
		t.Fatal("expected an error for a denied scope check")
	}
}

func TestNewProberForBackend_BackendSelection(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	resolver := dns.NewFakeResolver()
	cfg := Config{Timeout: time.Second, MaxRedirects: 3}

	p, err := NewProberForBackend("native", &httpxFakeValidator{allowed: true}, resolver, cfg, nil, logger)
	if err != nil {
		t.Fatalf("NewProberForBackend(native): %v", err)
	}
	if _, ok := p.(*prober); !ok {
		t.Errorf("backend=native: got %T, want *prober", p)
	}

	if _, err := NewProberForBackend("not-a-real-backend", &httpxFakeValidator{allowed: true}, resolver, cfg, nil, logger); err == nil {
		t.Error("NewProberForBackend(garbage backend) = nil error, want an error")
	}
}

func TestNewProberForBackend_AutoUsesHttpxWhenPresent(t *testing.T) {
	binary := testutil.WriteScript(t, "httpx", "exit 0\n")
	t.Setenv("PATH", filepath.Dir(binary))

	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	resolver := dns.NewFakeResolver()
	cfg := Config{Timeout: time.Second, MaxRedirects: 3}

	p, err := NewProberForBackend("auto", &httpxFakeValidator{allowed: true}, resolver, cfg, nil, logger)
	if err != nil {
		t.Fatalf("NewProberForBackend(auto): %v", err)
	}
	if _, ok := p.(*httpxProber); !ok {
		t.Errorf("got %T, want *httpxProber when httpx is present on PATH", p)
	}
}

func TestNewProberForBackend_AutoFallsBackWhenHttpxAbsent(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	resolver := dns.NewFakeResolver()
	cfg := Config{Timeout: time.Second, MaxRedirects: 3}

	p, err := NewProberForBackend("auto", &httpxFakeValidator{allowed: true}, resolver, cfg, nil, logger)
	if err != nil {
		t.Fatalf("NewProberForBackend(auto): %v", err)
	}
	if _, ok := p.(*prober); !ok {
		t.Errorf("got %T, want *prober when httpx is absent", p)
	}
}
