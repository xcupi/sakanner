package plugins

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func testLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// withFakeBinary creates an executable file named name in a temp dir and
// prepends that dir to PATH for the duration of the test, so Detect can
// find it deterministically without depending on what's actually
// installed on the machine running the tests.
func withFakeBinary(t *testing.T, name string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if runtime.GOOS == "windows" {
		t.Skip("fake-binary PATH manipulation test is Unix-specific")
	}
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write fake binary: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestDetect_Found(t *testing.T) {
	withFakeBinary(t, "fake-tool-present")
	path, ok := Detect("fake-tool-present")
	if !ok {
		t.Fatal("Detect() ok = false, want true for a binary present on PATH")
	}
	if path == "" {
		t.Error("Detect() path is empty despite ok = true")
	}
}

func TestDetect_NotFound(t *testing.T) {
	_, ok := Detect("sakanner-definitely-does-not-exist-as-a-binary")
	if ok {
		t.Error("Detect() ok = true for a binary that should not exist")
	}
}

var testTool = Tool{Name: "faketool", BinaryName: "fake-tool-present", InstallHint: "install it from https://example.com/faketool"}

func TestResolve_NativeExplicit(t *testing.T) {
	var buf bytes.Buffer
	d, err := Resolve("native", testTool, false, testLogger(&buf))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if d != UseNative {
		t.Errorf("Decision = %v, want UseNative", d)
	}
}

func TestResolve_EmptyBackendDefaultsToNative(t *testing.T) {
	var buf bytes.Buffer
	d, err := Resolve("", testTool, false, testLogger(&buf))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if d != UseNative {
		t.Errorf("Decision = %v, want UseNative", d)
	}
}

func TestResolve_AutoFallsBackWhenMissing(t *testing.T) {
	missing := Tool{Name: "missingtool", BinaryName: "sakanner-definitely-does-not-exist-as-a-binary", InstallHint: "install it"}
	var buf bytes.Buffer
	d, err := Resolve("auto", missing, false, testLogger(&buf))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if d != UseNative {
		t.Errorf("Decision = %v, want UseNative when the tool is not installed", d)
	}
	var logged map[string]any
	if err := json.Unmarshal(buf.Bytes(), &logged); err != nil {
		t.Fatalf("unmarshal log line: %v", err)
	}
	if logged["install_hint"] != missing.InstallHint {
		t.Errorf("log line missing install hint: %+v", logged)
	}
}

func TestResolve_AutoUsesToolWhenPresent(t *testing.T) {
	withFakeBinary(t, "fake-tool-present")
	var buf bytes.Buffer
	d, err := Resolve("auto", testTool, false, testLogger(&buf))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if d != UseTool {
		t.Errorf("Decision = %v, want UseTool when the tool is installed", d)
	}
}

func TestResolve_ExplicitToolRequiresPresence(t *testing.T) {
	missing := Tool{Name: "missingtool", BinaryName: "sakanner-definitely-does-not-exist-as-a-binary", InstallHint: "install it from https://example.com"}
	var buf bytes.Buffer
	_, err := Resolve("missingtool", missing, false, testLogger(&buf))
	if err == nil {
		t.Fatal("expected an error when explicitly requesting a tool that isn't installed")
	}
	if !strings.Contains(err.Error(), missing.InstallHint) {
		t.Errorf("error %q does not include the install hint", err.Error())
	}
}

func TestResolve_ExplicitToolSucceedsWhenPresent(t *testing.T) {
	withFakeBinary(t, "fake-tool-present")
	var buf bytes.Buffer
	d, err := Resolve("faketool", testTool, false, testLogger(&buf))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if d != UseTool {
		t.Errorf("Decision = %v, want UseTool", d)
	}
}

func TestResolve_UnknownBackendIsAnError(t *testing.T) {
	var buf bytes.Buffer
	_, err := Resolve("not-a-real-backend-value", testTool, false, testLogger(&buf))
	if err == nil {
		t.Fatal("expected an error for an unrecognized backend value")
	}
}

func TestResolve_SensitiveStageLogsWarning(t *testing.T) {
	withFakeBinary(t, "fake-tool-present")
	var buf bytes.Buffer
	_, err := Resolve("auto", testTool, true, testLogger(&buf))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	var logged map[string]any
	if err := json.Unmarshal(buf.Bytes(), &logged); err != nil {
		t.Fatalf("unmarshal log line: %v", err)
	}
	if logged["level"] != "WARN" {
		t.Errorf("level = %v, want WARN for a sensitive-stage tool selection", logged["level"])
	}
}
