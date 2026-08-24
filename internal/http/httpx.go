package http

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"

	"golang.org/x/time/rate"

	"sakanner/internal/dns"
	"sakanner/internal/scope"
	"sakanner/pkg/models"
	"sakanner/pkg/plugins"
)

// NewProberForBackend selects a Prober per sakanner's uniform
// auto|native|<tool> backend contract (see pkg/plugins.Resolve): httpx if
// backend selects it, the built-in Prober (NewProber) otherwise. httpx
// dials its own sockets from its own process (pkg/plugins' Trust
// boundary), so this stage is sensitive -- Resolve logs accordingly
// whenever httpx is actually selected.
func NewProberForBackend(backend string, validator scope.Validator, resolver dns.Resolver, cfg Config, limiter *rate.Limiter, logger *slog.Logger) (Prober, error) {
	decision, err := plugins.Resolve(backend, plugins.Httpx, true, logger)
	if err != nil {
		return nil, err
	}
	if decision == plugins.UseTool {
		path, _ := plugins.Detect(plugins.Httpx.BinaryName)
		return NewHttpxProber(path, validator), nil
	}
	return NewProber(validator, resolver, cfg, limiter), nil
}

type httpxProber struct {
	binary    string
	validator scope.Validator
}

// NewHttpxProber returns a Prober backed by the httpx CLI tool (found at
// binary). Probe still re-validates ip against validator itself,
// immediately before invoking httpx, exactly like the native prober --
// httpx is pointed at hostname:port with the already-resolved,
// already-approved ip having been the basis for that approval, though
// httpx (unlike the native prober) performs its own DNS resolution and
// dial rather than being handed the literal IP -- the residual
// DNS-rebinding exposure the package doc for pkg/plugins documents.
//
// httpx's JSON output does not include TLS certificate detail or a
// redirect-hop chain in the fields read here; HTTPService.TLS* and
// RedirectChain are left unset for this backend. Extending this to
// capture them (httpx's -tls-grab/-include-chain flags) is future work
// and should be verified against the installed httpx version's actual
// JSON schema before relying on it.
func NewHttpxProber(binary string, validator scope.Validator) Prober {
	return &httpxProber{binary: binary, validator: validator}
}

// httpxLine models the subset of httpx's -json output this package
// reads. Field names follow httpx's documented JSON convention as of
// this writing; verify against the installed httpx version if probing
// silently yields nothing.
type httpxLine struct {
	URL        string            `json:"url"`
	StatusCode int               `json:"status_code"`
	Title      string            `json:"title"`
	Scheme     string            `json:"scheme"`
	Header     map[string]string `json:"header"`
	Body       string            `json:"body"`
}

var errHttpxGotResult = errors.New("http: httpx returned a result")

func (p *httpxProber) Probe(ctx context.Context, ip net.IP, port int, hostname string) (*models.HTTPService, []byte, error) {
	if ip == nil {
		return nil, nil, fmt.Errorf("http: nil IP")
	}
	decision, err := p.validator.CheckResolved(ctx, hostname, ip)
	if err != nil {
		return nil, nil, fmt.Errorf("http: scope check for %s: %w", ip, err)
	}
	if !decision.Allowed {
		return nil, nil, fmt.Errorf("http: %s is out of scope: %s", ip, decision.Reason)
	}

	target := fmt.Sprintf("%s:%d", hostname, port)
	args := []string{"-u", target, "-silent", "-json", "-title", "-location", "-include-response", "-no-color"}

	var svc *models.HTTPService
	var body []byte
	runErr := plugins.RunJSONLines(ctx, p.binary, args, func(line httpxLine) error {
		if line.StatusCode == 0 {
			return nil
		}
		headers := make(map[string]string, len(line.Header))
		for k, v := range line.Header {
			headers[k] = v
		}
		svc = &models.HTTPService{
			URL:        line.URL,
			Scheme:     line.Scheme,
			StatusCode: line.StatusCode,
			Title:      line.Title,
			Headers:    headers,
		}
		body = []byte(line.Body)
		return errHttpxGotResult
	})
	if runErr != nil && !errors.Is(runErr, errHttpxGotResult) {
		return nil, nil, fmt.Errorf("http: httpx probe %s: %w", target, runErr)
	}
	if svc == nil {
		return nil, nil, fmt.Errorf("http: no scheme responded for %s:%d (httpx)", ip, port)
	}
	return svc, body, nil
}
