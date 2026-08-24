package traversalactive

import (
	"context"
	"go/parser"
	"go/token"
	nethttp "net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sakanner/internal/detection"
	"sakanner/internal/detectors/traversal"
)

// This file exists for the identical CRITICAL SAFETY PROPERTY
// internal/detectors/traversal/filesystem_safety_test.go already
// establishes: the scanner must never interpret target-controlled
// input, or its own configured TraversalCase values, as a LOCAL
// filesystem path. Every "path" this package ever handles is data
// inside an HTTP request/response, never a local filesystem call.

// TestSourceNeverTouchesLocalFilesystem is a static, belt-and-
// suspenders guarantee: this package's own .go source (excluding test
// files) never imports "os" for anything beyond what's already
// reviewed here -- specifically, never imports "io/ioutil" or calls a
// local file-reading API. Checked via go/parser against the actual
// parsed import declarations, never a naive substring search.
func TestSourceNeverTouchesLocalFilesystem(t *testing.T) {
	forbiddenImports := map[string]bool{"io/ioutil": true}

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
				t.Errorf("%s imports %q -- this package must never read a local file; every \"path\" it handles is HTTP request/response data only", name, importPath)
			}
		}
	}
}

// TestDetect_MaliciousTraversalCase_NeverTouchesLocalFilesystem runs
// Detect with TraversalCase values shaped like an attempt to read a
// REAL local file from the scanner's own machine, from a temp,
// otherwise-empty working directory -- so any accidental local file
// access would be immediately visible via a changed working directory
// listing. Only HTTP requests to the fake server are ever expected.
func TestDetect_MaliciousTraversalCase_NeverTouchesLocalFilesystem(t *testing.T) {
	tmp := t.TempDir()
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("Chdir: %v", err)
	}
	defer os.Chdir(oldWD)

	srv := httptest.NewServer(nethttp.HandlerFunc(vulnerableHandler))
	defer srv.Close()

	dangerous := []traversal.TraversalCase{
		{RelativePath: "../../../../../../etc/passwd", Marker: "root:"},
		{RelativePath: "../../../../../../../../etc/shadow", Marker: "root:"},
		{RelativePath: "..\\..\\..\\..\\windows\\system32\\config\\sam", Marker: "SAM"},
	}

	for _, c := range dangerous {
		d := New([]traversal.TraversalCase{c})
		tgt := targetFor(t, srv, "file", "query", "GET")
		x := newExecutor(true, detection.ExecutorConfig{})

		result, err := d.Detect(context.Background(), tgt, x)
		if err != nil {
			t.Errorf("Detect(%+v): unexpected error %v -- must degrade gracefully, never touch a local file", c, err)
			continue
		}
		if result.Outcome == detection.OutcomeFinding {
			t.Errorf("Detect(%+v): got a finding, want none (the fake server never has these real files)", c)
		}
	}

	entries, err := os.ReadDir(tmp)
	if err != nil {
		t.Fatalf("ReadDir(tmp): %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("temp working directory has %d entries after Detect, want 0 -- Detect must never create, read, or otherwise touch local files", len(entries))
	}
}
