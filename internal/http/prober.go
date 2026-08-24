// Package http implements HTTP/HTTPS probing of discovered services.
// The scope-safe dialing logic itself lives in internal/safedial, shared
// with internal/crawler; this package focuses on probing semantics
// (scheme selection, title/header extraction, TLS field capture).
package http

import (
	"context"
	"fmt"
	"io"
	"net"
	nethttp "net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"golang.org/x/time/rate"

	"sakanner/internal/dns"
	"sakanner/internal/safedial"
	"sakanner/internal/scope"
	"sakanner/pkg/models"
)

// Config bounds Prober behavior.
type Config struct {
	Timeout      time.Duration
	MaxRedirects int
}

// Prober probes a single service for HTTP(S).
type Prober interface {
	// Probe attempts HTTPS then HTTP against ip:port, presenting hostname
	// for the Host header and TLS SNI, and returns the first successful
	// result along with a bounded sample of the response body (for the
	// caller to pass to fingerprint.Fingerprinter -- Prober itself does
	// not fingerprint, keeping that a separate pipeline stage). ip must
	// already be scope-validated by the caller (e.g. the DNS/ports
	// stages); Probe re-validates it anyway before dialing.
	Probe(ctx context.Context, ip net.IP, port int, hostname string) (*models.HTTPService, []byte, error)
}

type prober struct {
	dialer  *safedial.Dialer
	cfg     Config
	limiter *rate.Limiter
}

// NewProber returns a Prober that validates every dial (initial connect
// and every redirect hop) against validator before it happens.
func NewProber(validator scope.Validator, resolver dns.Resolver, cfg Config, limiter *rate.Limiter) Prober {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.MaxRedirects < 0 {
		cfg.MaxRedirects = 0
	}
	return &prober{dialer: safedial.New(validator, resolver), cfg: cfg, limiter: limiter}
}

func (p *prober) Probe(ctx context.Context, ip net.IP, port int, hostname string) (*models.HTTPService, []byte, error) {
	if ip == nil {
		return nil, nil, fmt.Errorf("http: nil IP")
	}
	if p.limiter != nil {
		if err := p.limiter.Wait(ctx); err != nil {
			return nil, nil, err
		}
	}

	var lastErr error
	for _, scheme := range []string{"https", "http"} {
		svc, body, err := p.probeScheme(ctx, scheme, ip, port, hostname)
		if err != nil {
			lastErr = err
			continue
		}
		return svc, body, nil
	}
	return nil, nil, fmt.Errorf("http: no scheme responded for %s:%d: %w", ip, port, lastErr)
}

// maxBodySample bounds how much of a response body is read into memory,
// for title extraction here and technology fingerprinting by the caller.
const maxBodySample = 256 * 1024

func (p *prober) probeScheme(ctx context.Context, scheme string, ip net.IP, port int, hostname string) (*models.HTTPService, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, p.cfg.Timeout)
	defer cancel()

	target := &url.URL{Scheme: scheme, Host: fmt.Sprintf("%s:%d", hostname, port)}

	tlsInfo := &safedial.TLSCapture{}
	var chain []models.RedirectHop
	client := p.dialer.NewClient(hostname, ip, tlsInfo, &chain, p.cfg.Timeout, p.cfg.MaxRedirects)

	req, err := nethttp.NewRequestWithContext(ctx, nethttp.MethodGet, target.String(), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("http: build request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("http: request %s: %w", target, err)
	}
	defer resp.Body.Close()

	body := make([]byte, maxBodySample)
	n, _ := io.ReadFull(resp.Body, body)
	body = body[:n]

	headers := map[string]string{}
	for k := range resp.Header {
		headers[k] = resp.Header.Get(k)
	}

	svc := &models.HTTPService{
		URL: resp.Request.URL.String(), // final URL after any in-scope redirects
		// Scheme reflects the same final state as URL, not the scheme
		// this probe attempt started with -- a port that speaks plain
		// HTTP but immediately redirects to HTTPS must not be recorded
		// as Scheme="http" while URL and the TLS* fields both describe
		// an https:// response; that combination is self-contradictory
		// to a report reader. resp.Request.URL.Scheme is exactly the
		// scheme of the URL string right above it.
		Scheme:        resp.Request.URL.Scheme,
		StatusCode:    resp.StatusCode,
		Title:         extractTitle(resp.Header.Get("Content-Type"), body),
		Headers:       headers,
		RedirectChain: chain,
	}

	if tlsInfo.Subject != "" || tlsInfo.Issuer != "" {
		svc.TLSSubject = tlsInfo.Subject
		svc.TLSIssuer = tlsInfo.Issuer
		svc.TLSVersion = tlsInfo.Version
		svc.TLSSelfSigned = tlsInfo.SelfSigned
		svc.TLSSANs = tlsInfo.SANs
		if !tlsInfo.NotAfter.IsZero() {
			na := tlsInfo.NotAfter
			svc.TLSNotAfter = &na
		}
	}

	return svc, body, nil
}

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

func extractTitle(contentType string, body []byte) string {
	if contentType != "" && !strings.Contains(strings.ToLower(contentType), "html") {
		return ""
	}
	m := titleRe.FindSubmatch(body)
	if m == nil {
		return ""
	}
	return strings.TrimSpace(string(m[1]))
}
