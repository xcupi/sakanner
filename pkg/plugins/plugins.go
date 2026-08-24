// Package plugins provides sakanner's generic external-tool plumbing:
// detecting whether an optional CLI tool (subfinder, httpx, dnsx, naabu,
// katana, ...) is installed, deciding whether to use it per the
// project's uniform auto|native|<tool> backend contract, and running one
// as a subprocess whose stdout is a stream of JSON objects (the
// -json/-jsonl convention these tools share).
//
// This package intentionally holds no domain-specific adapters --
// mapping a particular tool's output into sakanner's models, and
// building its argv safely (e.g. passing only pre-resolved literal IPs
// to a port scanner, never a hostname it would resolve itself) belongs
// in the internal/ package for that pipeline stage, alongside the
// built-in Go implementation it's an alternative to. Domain packages
// under internal/ are free to import this package; it must never import
// them.
//
// Trust boundary: subfinder and dnsx only enumerate names -- sakanner
// still resolves and scope-validates every candidate the normal way
// before ever dialing it, so using them changes nothing about the
// platform's safety guarantees. httpx, naabu, and katana, by contrast,
// open their own sockets from their own process when used as a stage's
// backend -- sakanner's per-dial scope re-validation (internal/scope,
// internal/safedial) cannot reach into another process's connect()
// calls. Each such adapter must still harden what it hands the tool
// (literal pre-validated IPs, not raw hostnames, wherever the tool's
// interface allows it) as a mitigation, but this is a real reduction in
// assurance compared to the native path, and Resolve logs it plainly
// every time such a backend is actually selected.
package plugins

import (
	"fmt"
	"log/slog"
	"os/exec"
)

// Tool describes one optional external CLI tool.
type Tool struct {
	// Name is both a human-readable label and the exact backend config
	// value that selects this tool explicitly (e.g. "subfinder").
	Name string
	// BinaryName is the executable looked up on PATH.
	BinaryName string
	// InstallHint is shown whenever the tool is requested (explicitly or
	// via "auto") but not found.
	InstallHint string
}

// The five external tools sakanner knows how to plug in, one per
// pluggable stage. Every domain package's backend factory resolves
// against exactly one of these, so the binary name, human-readable
// label, and install hint are defined here once rather than duplicated
// at each call site.
var (
	Subfinder = Tool{Name: "subfinder", BinaryName: "subfinder", InstallHint: "install via: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"}
	Dnsx      = Tool{Name: "dnsx", BinaryName: "dnsx", InstallHint: "install via: go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest"}
	Naabu     = Tool{Name: "naabu", BinaryName: "naabu", InstallHint: "install via: go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"}
	Httpx     = Tool{Name: "httpx", BinaryName: "httpx", InstallHint: "install via: go install github.com/projectdiscovery/httpx/cmd/httpx@latest"}
	Katana    = Tool{Name: "katana", BinaryName: "katana", InstallHint: "install via: go install github.com/projectdiscovery/katana/cmd/katana@latest"}
)

// AllTools lists every tool sakanner integrates with, in a stable order
// -- for `scanner tools status` and anything else that needs to report on
// all of them together.
func AllTools() []Tool {
	return []Tool{Subfinder, Dnsx, Naabu, Httpx, Katana}
}

// Detect reports whether binaryName is available on PATH, and its
// resolved path if so.
func Detect(binaryName string) (path string, ok bool) {
	p, err := exec.LookPath(binaryName)
	if err != nil {
		return "", false
	}
	return p, true
}

// Decision is what a per-stage factory should do.
type Decision int

const (
	UseNative Decision = iota
	UseTool
)

// Resolve implements sakanner's uniform auto|native|<tool> backend
// contract:
//
//   - "" or "native": always UseNative, no I/O.
//   - "auto" (the default): UseTool if Detect(tool.BinaryName) finds it,
//     otherwise UseNative. Either outcome is logged once.
//   - backend == tool.Name: requires the binary; returns a clear,
//     install-hint-bearing error if it's absent rather than silently
//     falling back -- an operator who explicitly asked for a tool should
//     know immediately if it can't be used.
//   - anything else: a configuration error.
//
// sensitiveStage should be true for any stage where UseTool means the
// external tool opens its own sockets from its own process (see the
// package doc's Trust boundary section) -- Resolve logs a louder warning
// in that case whenever UseTool is actually returned.
func Resolve(backend string, tool Tool, sensitiveStage bool, logger *slog.Logger) (Decision, error) {
	switch backend {
	case "", "native":
		return UseNative, nil

	case "auto":
		path, ok := Detect(tool.BinaryName)
		if !ok {
			logger.Info("optional external tool not found; using built-in implementation",
				slog.String("tool", tool.Name), slog.String("binary", tool.BinaryName), slog.String("install_hint", tool.InstallHint))
			return UseNative, nil
		}
		logUseTool(logger, tool, path, sensitiveStage, false)
		return UseTool, nil

	case tool.Name:
		path, ok := Detect(tool.BinaryName)
		if !ok {
			return UseNative, fmt.Errorf("plugins: backend %q requested but %q was not found on PATH -- %s", tool.Name, tool.BinaryName, tool.InstallHint)
		}
		logUseTool(logger, tool, path, sensitiveStage, true)
		return UseTool, nil

	default:
		return UseNative, fmt.Errorf("plugins: unknown backend %q for %s (want \"native\", \"auto\", or %q)", backend, tool.Name, tool.Name)
	}
}

func logUseTool(logger *slog.Logger, tool Tool, path string, sensitiveStage, explicit bool) {
	attrs := []any{slog.String("tool", tool.Name), slog.String("path", path)}
	suffix := ""
	if explicit {
		suffix = " (explicitly requested)"
	}
	if sensitiveStage {
		logger.Warn("using external tool"+suffix+" -- scope re-validation for this stage is delegated to the tool's own process and is not covered by sakanner's per-dial guarantee", attrs...)
		return
	}
	logger.Info("using external tool"+suffix, attrs...)
}
