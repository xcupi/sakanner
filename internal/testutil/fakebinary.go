// Package testutil provides small test-only helpers shared across the
// packages that test adapters for pluggable external CLI tools
// (pkg/plugins).
package testutil

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// WriteScript writes a shell script at <tempdir>/name whose body is
// script (a shebang is prepended), marks it executable, and returns its
// full path -- for constructing a fake external-tool binary whose stdout
// is controlled directly by the test, without depending on any real tool
// being installed. Unix-only; skips the calling test on Windows.
func WriteScript(t *testing.T, name, script string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake-binary script test is Unix-specific")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	content := "#!/bin/sh\n" + script
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatalf("write fake binary %s: %v", name, err)
	}
	return path
}
