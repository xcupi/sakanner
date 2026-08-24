package orchestrator

import (
	"context"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sakanner/internal/orchestration"
	"sakanner/internal/storage/sqlite"
)

// Security tests (task section 40-41): the orchestrator must never
// execute target-controlled values through a shell, must never make
// requests outside the safedial/scope.Validator-mediated path every
// dependency it calls already enforces, and must contain no
// vulnerability-detection logic of its own.

func TestSecurity_SourceNeverTouchesShellOrRawSockets(t *testing.T) {
	// os/exec, syscall: no shell/process execution (task section 41).
	// net/http: this package must reach the network ONLY through its
	// caller-supplied Pipeline/detection.Executor (both already enforce
	// scope via safedial.Dialer) -- never dial anything itself. Plain
	// "net" is NOT forbidden: target.go legitimately uses net.IP/
	// net.ParseIP as pure value types when calling
	// scope.Validator.CheckIP (the same interface internal/scope itself
	// exposes) -- it never dials a socket.
	forbidden := map[string]bool{
		"os/exec": true, "syscall": true, "net/http": true,
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(".", name), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("ParseFile(%s): %v", name, err)
		}
		for _, imp := range file.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			if forbidden[path] {
				t.Errorf("%s imports %q -- the orchestrator must reach the network only through its caller-supplied Pipeline/Executor, and must never execute a shell", name, path)
			}
		}
	}
}

func TestSecurity_MalformedTarget_NoCrash(t *testing.T) {
	ctx := context.Background()
	store, err := sqlite.New(ctx, ":memory:")
	if err != nil {
		t.Fatalf("sqlite.New: %v", err)
	}
	defer store.Close()

	o := &Orchestrator{Store: store, Pipeline: &orchestration.Pipeline{}}

	targets := []string{
		"", " ", "\x00\x01", "; rm -rf / #", "$(whoami)", "`id`",
		strings.Repeat("a", 100000), "http://[::1", "not a url at all !!",
		"\r\nX-Injected: evil",
		// RTL-override/BOM, written as escapes so this source file
		// itself stays plain ASCII (a literal byte here previously
		// caused a Go parser "illegal byte order mark" error -- see
		// internal/evidence/security_test.go).
		"\u202eevil\u202c\ufeff",
	}

	for _, target := range targets {
		// No panic is the assertion; every malformed/adversarial target
		// must be rejected safely (an empty/invalid value never resolves
		// to anything in scope), never crash the process.
		if _, err := o.resolveAndRegisterTarget(ctx, target); err == nil {
			t.Errorf("target %q: resolveAndRegisterTarget succeeded with no scope rules configured at all, want an error", target)
		}
	}
}
