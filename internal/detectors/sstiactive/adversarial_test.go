package sstiactive

import (
	"context"
	"fmt"
	"go/parser"
	"go/token"
	nethttp "net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"sakanner/internal/detection"
)

// --- Host safety -----------------------------------------------------------

func TestAdversarial_ProbeRequest_NeverChangesHost(t *testing.T) {
	var sawHost string
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		sawHost = r.Host
		vulnerableHandler(w, r)
	}))
	defer srv.Close()

	tgt := targetFor(t, srv, "name", "query", "GET")
	x := newExecutor(true, detection.ExecutorConfig{})
	if _, err := New().Detect(context.Background(), tgt, x); err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if sawHost == "" {
		t.Fatal("expected the server to observe at least one request")
	}
	if !strings.HasPrefix(sawHost, tgt.Host) {
		t.Fatalf("SECURITY: server observed Host = %q, want a host beginning with %q -- an injected template payload must never change the scanner's own dial target", sawHost, tgt.Host)
	}
}

// --- No code execution / no real template engine ----------------------

// TestSourceNeverInvokesLocalShellOrTemplateEngine proves this
// package only ever performs a single, self-contained Go integer
// multiplication -- no os/exec, no text/template, no html/template
// evaluation of attacker-controlled input, no plugin loading -- checked
// via go/parser against the actual parsed import declarations, never a
// naive substring search, mirroring
// traversalactive/cmdinjection(active)'s own identical static-proof
// pattern.
func TestSourceNeverInvokesLocalShellOrTemplateEngine(t *testing.T) {
	forbiddenImports := map[string]bool{
		"os/exec": true, "text/template": true, "html/template": true, "plugin": true,
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
		path := filepath.Join(".", name)
		file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("ParseFile(%s): %v", name, err)
		}
		for _, imp := range file.Imports {
			importPath := strings.Trim(imp.Path.Value, `"`)
			if forbiddenImports[importPath] {
				t.Errorf("SECURITY: %s imports %q -- this detector must never invoke a real template engine or local process", name, importPath)
			}
		}
	}
}

// --- Concurrent scans ----------------------------------------------------

func TestAdversarial_ConcurrentDetects_NoCrossContamination(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(vulnerableHandler))
	defer srv.Close()

	const n = 20
	var wg sync.WaitGroup
	errs := make(chan string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tgt := targetFor(t, srv, "name", "query", "GET")
			x := newExecutor(true, detection.ExecutorConfig{})
			result, err := New().Detect(context.Background(), tgt, x)
			if err != nil {
				errs <- fmt.Sprintf("goroutine %d: Detect error: %v", i, err)
				return
			}
			if result.Outcome != detection.OutcomeFinding {
				errs <- fmt.Sprintf("goroutine %d: Outcome = %s, want finding", i, result.Outcome)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}

// --- False-positive resistance: raw payload reflection -----------------

// TestAdversarial_RawPayloadReflectedUnevaluated_NeverConfirms proves
// an endpoint that reflects the RAW, un-evaluated payload text (e.g. a
// naive app that echoes "{{37*41}}" literally, never computing it)
// never produces a finding -- the digits "37" and "41" appearing
// verbatim must never be mistaken for the evaluated PRODUCT.
func TestAdversarial_RawPayloadReflectedUnevaluated_NeverConfirms(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		fmt.Fprintf(w, "You searched for: %s", r.FormValue("name"))
	}))
	defer srv.Close()

	tgt := targetFor(t, srv, "name", "query", "GET")
	x := newExecutor(true, detection.ExecutorConfig{})
	result, err := New().Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome == detection.OutcomeFinding {
		t.Fatal("SECURITY: raw, unevaluated payload reflection was flagged as a finding")
	}
}

// --- Cancellation ------------------------------------------------------

func TestDetect_ContextCancelled_ReturnsPromptlyNoFinding(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		time.Sleep(50 * time.Millisecond)
		fmt.Fprint(w, "some response")
	}))
	defer srv.Close()

	tgt := targetFor(t, srv, "name", "query", "GET")
	x := newExecutor(true, detection.ExecutorConfig{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()

	result, err := New().Detect(ctx, tgt, x)
	if err == nil {
		t.Fatal("expected a context-cancellation/timeout error")
	}
	if result.Outcome == detection.OutcomeFinding {
		t.Fatal("a cancelled context must never produce a finding")
	}
}

// --- Resource bounds -------------------------------------------------------

// TestDetect_RequestCount_Bounded proves the total number of requests
// issued per eligible target is small and bounded: 1 baseline + up to
// 4 template-syntax variants, never unbounded.
func TestDetect_RequestCount_Bounded(t *testing.T) {
	var hits int
	var mu sync.Mutex
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		fmt.Fprint(w, "never matches any template syntax")
	}))
	defer srv.Close()

	tgt := targetFor(t, srv, "name", "query", "GET")
	x := newExecutor(true, detection.ExecutorConfig{})
	if _, err := New().Detect(context.Background(), tgt, x); err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if hits != 5 {
		t.Errorf("hits = %d, want exactly 5 (1 baseline + 4 template-syntax variants, none confirming)", hits)
	}
}
