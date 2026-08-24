package ports

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/time/rate"

	"sakanner/internal/scope"
	"sakanner/pkg/plugins"
)

// NewScanner selects a Scanner per sakanner's uniform auto|native|<tool>
// backend contract (see pkg/plugins.Resolve): naabu if backend selects
// it, the built-in TCP-connect scanner otherwise. naabu dials its own
// sockets from its own process (pkg/plugins' Trust boundary), so this
// stage is sensitive -- Resolve logs accordingly whenever naabu is
// actually selected.
func NewScanner(backend string, validator scope.Validator, dialTimeout time.Duration, concurrency int, limiter *rate.Limiter, logger *slog.Logger) (Scanner, error) {
	decision, err := plugins.Resolve(backend, plugins.Naabu, true, logger)
	if err != nil {
		return nil, err
	}
	if decision == plugins.UseTool {
		path, _ := plugins.Detect(plugins.Naabu.BinaryName)
		return NewNaabuScanner(path, validator, logger), nil
	}
	return NewTCPConnectScanner(validator, dialTimeout, concurrency, limiter), nil
}

type naabuScanner struct {
	binary    string
	validator scope.Validator
	logger    *slog.Logger
}

// NewNaabuScanner returns a Scanner backed by the naabu CLI tool (found
// at binary). Scan still re-validates ip against validator itself,
// immediately before invoking naabu, exactly like the native scanner --
// naabu is only ever pointed at a literal IP sakanner has already
// resolved and approved, never a hostname it would resolve on its own.
func NewNaabuScanner(binary string, validator scope.Validator, logger *slog.Logger) Scanner {
	return &naabuScanner{binary: binary, validator: validator, logger: logger}
}

func (s *naabuScanner) Name() string { return "naabu" }

type naabuLine struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

func (s *naabuScanner) Scan(ctx context.Context, hostname string, ip net.IP, portList []int) (<-chan Result, error) {
	if ip == nil {
		return nil, fmt.Errorf("ports: nil IP")
	}
	decision, err := s.validator.CheckResolved(ctx, hostname, ip)
	if err != nil {
		return nil, fmt.Errorf("ports: scope check for %s: %w", ip, err)
	}
	if !decision.Allowed {
		return nil, fmt.Errorf("ports: %s is out of scope: %s", ip, decision.Reason)
	}
	if len(portList) == 0 {
		out := make(chan Result)
		close(out)
		return out, nil
	}

	ports := make([]string, len(portList))
	for i, p := range portList {
		ports[i] = strconv.Itoa(p)
	}
	args := []string{"-host", ip.String(), "-port", strings.Join(ports, ","), "-silent", "-json"}

	out := make(chan Result)
	go func() {
		defer close(out)
		if err := plugins.RunJSONLines(ctx, s.binary, args, func(line naabuLine) error {
			if line.Port <= 0 {
				return nil
			}
			select {
			case out <- Result{Port: line.Port, Open: true}:
			case <-ctx.Done():
				return ctx.Err()
			}
			return nil
		}); err != nil && s.logger != nil {
			s.logger.Warn("naabu scan failed", slog.String("ip", ip.String()), slog.String("error", err.Error()))
		}
	}()
	return out, nil
}
