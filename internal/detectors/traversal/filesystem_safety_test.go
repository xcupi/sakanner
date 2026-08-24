package traversal

import (
	"context"
	nethttp "net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sakanner/internal/detection"
)

// This file exists specifically for section 21's CRITICAL SECURITY
// REQUIREMENT: traversal input must remain data passed to the TARGET,
// and must never cause the scanner itself to touch its own local
// filesystem. See docs/phase-3-6-path-traversal.md "Scanner filesystem
// safety."

// TestSourceNeverCallsLocalFileReadAPIs is a static, belt-and-suspenders
// guarantee: this package's own .go source (excluding this test file
// and other _test.go files, which legitimately use os/filepath for
// test setup) never references any local-file-reading API at all. The
// detector operates ENTIRELY over HTTP; there is no code path in it
// that could construct a local filesystem path from untrusted input,
// because there is no local filesystem access of any kind.
func TestSourceNeverCallsLocalFileReadAPIs(t *testing.T) {
	forbidden := []string{"os.Open(", "os.OpenFile(", "os.ReadFile(", "ioutil.ReadFile(", "os.Create("}

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		content, err := os.ReadFile(filepath.Join(".", name))
		if err != nil {
			t.Fatalf("ReadFile(%s): %v", name, err)
		}
		for _, f := range forbidden {
			if strings.Contains(string(content), f) {
				t.Errorf("%s contains %q -- this package must never touch the local filesystem; every \"path\" it handles is HTTP request/response data only", name, f)
			}
		}
	}
}

// TestDetect_MaliciousOriginalValue_NeverTouchesLocalFilesystem runs
// Detect with a discovered parameter value AND a configured
// TraversalCase both shaped like an attempt to reach a real, sensitive
// local path (as if a compromised/malicious recon result tried to feed
// this detector something dangerous) -- from a temp, otherwise-empty
// working directory, so any accidental local file access would be
// immediately visible as an unexpected file appearing, or as an error
// referencing a real path. Only HTTP requests to the fake server are
// ever expected to occur.
func TestDetect_MaliciousOriginalValue_NeverTouchesLocalFilesystem(t *testing.T) {
	tmp := t.TempDir()
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("Chdir: %v", err)
	}
	defer os.Chdir(oldWD)

	srv := httptest.NewServer(vulnerableHandler())
	defer srv.Close()

	dangerous := []string{
		"../../../../../../etc/shadow",
		"../../../../home/user/.ssh/id_rsa",
		"/root/.aws/credentials",
		"../../../../../proc/self/environ",
		"C:\\Windows\\System32\\config\\SAM",
	}

	for _, value := range dangerous {
		d := New([]TraversalCase{{RelativePath: value, Marker: "SHOULD_NEVER_MATCH_ANYTHING_REAL"}})
		tgt := targetFor(t, srv, "file", "index.html")
		x := newExecutor(true, detection.ExecutorConfig{})

		result, err := d.Detect(context.Background(), tgt, x)
		if err != nil {
			t.Errorf("Detect(%q): unexpected error %v -- must degrade gracefully, never touch local disk", value, err)
			continue
		}
		if result.Outcome == detection.OutcomeFinding {
			t.Errorf("Detect(%q): got a finding, want none -- this synthetic fixture has no such file and the marker can never match", value)
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

// TestRequestURL_SendsPercentEncodedVariantsRawOnWire is the concrete,
// conclusive proof that this package correctly delivers each encoded
// traversal representation to the TARGET without re-escaping it
// (double-encoding would silently defeat every encoded variant this
// detector tries): a custom handler inspects r.URL.RawQuery directly
// (bypassing Go's own query decoding) and asserts it received the
// LITERAL percent-encoded bytes this package built, not a doubly
// escaped form (e.g. "%2e" surviving as "%2e", never becoming "%252e").
func TestRequestURL_SendsPercentEncodedVariantsRawOnWire(t *testing.T) {
	var gotRawQuery string
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		gotRawQuery = r.URL.RawQuery
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	tgt := targetFor(t, srv, "file", "index.html")
	x := newExecutor(true, detection.ExecutorConfig{})

	variant := "%2e%2e/protected/secret-marker.txt"
	_, _, err := probe(context.Background(), x, tgt, variant)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}

	want := "file=" + variant
	if gotRawQuery != want {
		t.Errorf("server observed RawQuery = %q, want %q -- the encoded variant must reach the target unescaped a second time", gotRawQuery, want)
	}
}
