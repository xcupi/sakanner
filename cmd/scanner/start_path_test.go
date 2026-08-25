package main

import (
	"strings"
	"testing"
)

// resolveScanStartPath implements general web application
// start-URL/base-path support (--start-url / crawler.start_path):
// bare-path normalization, and same-origin validation for a full
// http(s) URL. Deliberately application-agnostic -- no test here
// names any specific real-world application.

func TestResolveScanStartPath_BarePath_AddsLeadingSlash(t *testing.T) {
	got, err := resolveScanStartPath("192.168.10.129", "DVWA/")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "/DVWA/" {
		t.Errorf("got %q, want %q", got, "/DVWA/")
	}
}

func TestResolveScanStartPath_BarePath_AlreadyLeadingSlash_Unchanged(t *testing.T) {
	got, err := resolveScanStartPath("192.168.10.129", "/DVWA/")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "/DVWA/" {
		t.Errorf("got %q, want %q", got, "/DVWA/")
	}
}

func TestResolveScanStartPath_EmptyValue_NormalizesToRoot(t *testing.T) {
	// The caller (runFullScan) never invokes this with "" today (it
	// short-circuits to "no override" first), but the function itself
	// must still behave sanely if it ever were: no host was named, so
	// this is trivially same-origin, same as any other bare path.
	got, err := resolveScanStartPath("192.168.10.129", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "/" {
		t.Errorf("got %q, want %q", got, "/")
	}
}

func TestResolveScanStartPath_FullURL_SameOrigin_ExtractsPath(t *testing.T) {
	got, err := resolveScanStartPath("192.168.10.129", "http://192.168.10.129/DVWA/")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "/DVWA/" {
		t.Errorf("got %q, want %q", got, "/DVWA/")
	}
}

func TestResolveScanStartPath_FullURL_HostComparisonIsCaseInsensitive(t *testing.T) {
	got, err := resolveScanStartPath("Example.com", "http://EXAMPLE.COM/app/")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "/app/" {
		t.Errorf("got %q, want %q", got, "/app/")
	}
}

func TestResolveScanStartPath_FullURL_NoPath_DefaultsToRoot(t *testing.T) {
	got, err := resolveScanStartPath("192.168.10.129", "http://192.168.10.129")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "/" {
		t.Errorf("got %q, want %q", got, "/")
	}
}

func TestResolveScanStartPath_FullURL_DifferentHost_Rejected(t *testing.T) {
	_, err := resolveScanStartPath("192.168.10.129", "http://10.0.0.5/DVWA/")
	if err == nil {
		t.Fatal("expected an error for a --start-url host that does not match the scan target, got nil")
	}
	if !strings.Contains(err.Error(), "does not match the scan target") {
		t.Errorf("error %q does not explain the same-origin mismatch", err.Error())
	}
}

func TestResolveScanStartPath_NonHTTPScheme_Rejected(t *testing.T) {
	_, err := resolveScanStartPath("192.168.10.129", "ftp://192.168.10.129/DVWA/")
	if err == nil {
		t.Fatal("expected an error for a non-http(s) --start-url scheme, got nil")
	}
	if !strings.Contains(err.Error(), "not a valid path or absolute http(s) URL") {
		t.Errorf("error %q does not explain the invalid scheme", err.Error())
	}
}

func TestResolveScanStartPath_URLWithNoHost_Rejected(t *testing.T) {
	_, err := resolveScanStartPath("192.168.10.129", "http:///DVWA/")
	if err == nil {
		t.Fatal("expected an error for a --start-url with no host, got nil")
	}
}

func TestResolveScanStartPath_InvalidTarget_ReportsCannotVerify(t *testing.T) {
	_, err := resolveScanStartPath("", "http://192.168.10.129/DVWA/")
	if err == nil {
		t.Fatal("expected an error when the scan target itself cannot be parsed, got nil")
	}
	if !strings.Contains(err.Error(), "cannot verify same-origin") {
		t.Errorf("error %q does not explain the unparseable target", err.Error())
	}
}
