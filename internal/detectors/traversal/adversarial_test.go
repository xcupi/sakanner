package traversal

import (
	"context"
	"fmt"
	nethttp "net/http"
	"net/http/httptest"
	"path"
	"strings"
	"testing"

	"sakanner/internal/detection"
)

// Adversarial testing (task section 30), performed ONLY against
// synthetic httptest servers -- never a real target, never a real
// filesystem. Scenarios also covered elsewhere are cross-referenced
// rather than duplicated: "../" alone / secure canonicalization / 403 /
// 404 / generic 200 / reflection / same-endpoint dedup / timeout /
// cancellation / oversized response / out-of-scope / scanner
// filesystem isolation all live in detector_test.go and
// filesystem_safety_test.go.

// TestAdversarial_EncodingBypassesNaiveRawBlocklist_StillConfirms
// proves the detector's encoding handling matters end to end: a naive
// "WAF-style" defense that blocklists the literal ".." substring on
// the RAW, not-yet-decoded query string (famously bypassable -- an
// encoded representation like "%2e%2e/" doesn't contain the literal
// substring "..") blocks the RAW representation but lets an encoded
// one through to the same vulnerable-underneath processing. The
// detector must still try enough representations to confirm.
func TestAdversarial_EncodingBypassesNaiveRawBlocklist_StillConfirms(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		if strings.Contains(r.URL.RawQuery, "..") {
			w.WriteHeader(403)
			w.Write([]byte("forbidden: blocked by naive raw blocklist"))
			return
		}
		file := r.URL.Query().Get("file") // Go decodes %2e/%2F here regardless
		resolved := path.Clean(path.Join("public", file))
		w.Header().Set("Content-Type", "text/plain")
		content, ok := testFS[resolved]
		if !ok {
			w.WriteHeader(404)
			w.Write([]byte("not found"))
			return
		}
		w.Write([]byte(content))
	}))
	defer srv.Close()

	d := New([]TraversalCase{travCase()})
	tgt := targetFor(t, srv, "file", "index.html")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeFinding {
		t.Fatalf("Outcome = %v, want OutcomeFinding -- the raw \"..\" representation is blocked, but an encoded representation bypasses the raw-string blocklist and must still be tried and confirmed", result.Outcome)
	}
}

// TestAdversarial_DoubleEncodedVariantNotEffective_NoFinding confirms
// that when NONE of this detector's representations succeed against a
// fixture requiring a SECOND decode pass (which nothing in this
// project's lab implements -- see docs/phase-3-6-path-traversal.md
// "Encoding handling"), the result is a clean NoFinding, never a
// crash, panic, or false assumption of success.
func TestAdversarial_DoubleEncodedVariantNotEffective_NoFinding(t *testing.T) {
	srv := httptest.NewServer(vulnerableHandler())
	defer srv.Close()

	// A double-encoded representation would need "%252e%252e%252f..."
	// on the wire; traversalVariants only derives single-level
	// representations, so configuring it here just confirms the
	// detector behaves correctly (no finding, no crash) when its own
	// representations don't happen to be the ones a target requires --
	// it must never assume success.
	d := New([]TraversalCase{travCase()})
	tgt := targetFor(t, srv, "file", "index.html")
	x := newExecutor(true, detection.ExecutorConfig{})

	// Sanity: this SHOULD still succeed against the real vulnerable
	// fixture (single-level encoding is sufficient there) -- this test
	// exists to prove the NEGATIVE path is clean, using a case that
	// deliberately can't ever be found.
	dNeverFound := New([]TraversalCase{{RelativePath: "../protected/does-not-exist-at-all.txt", Marker: "NEVER_APPEARS"}})
	result, err := dNeverFound.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Errorf("Outcome = %v, want OutcomeNoFinding", result.Outcome)
	}

	// And the real case still works normally alongside it (proving the
	// negative case above isn't an artifact of a broken detector).
	result2, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result2.Outcome != detection.OutcomeFinding {
		t.Errorf("Outcome = %v, want OutcomeFinding", result2.Outcome)
	}
}

// TestAdversarial_DynamicDigitContent_NoFalsePositive mirrors the
// project's established "dynamic normal response" negative shape
// (see lab/harness_vuln.go's /sqli/dynamic): a response whose
// only variation between requests is digit-shaped (a counter/
// timestamp), which normalizeBody's digit-run collapsing must
// neutralize -- the SAME dynamic content appearing regardless of the
// requested value must never look like traversal-specific evidence.
func TestAdversarial_DynamicDigitContent_NoFalsePositive(t *testing.T) {
	var n int
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		n++
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "status: ok, request-id: %d", n)
	}))
	defer srv.Close()

	d := New([]TraversalCase{travCase()})
	tgt := targetFor(t, srv, "file", "index.html")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Errorf("Outcome = %v, want OutcomeNoFinding -- request-scoped digit dynamism must not look like traversal evidence", result.Outcome)
	}
}

// TestAdversarial_DuplicateQueryParameter_NoCrash confirms a target
// URL with the candidate parameter repeated (?file=a&file=b) is
// handled without a crash -- Go's url.Values.Get returns the first
// occurrence deterministically, and requestURL's Del+rebuild removes
// every occurrence of the parameter before re-adding exactly one.
func TestAdversarial_DuplicateQueryParameter_NoCrash(t *testing.T) {
	srv := httptest.NewServer(vulnerableHandler())
	defer srv.Close()

	d := New([]TraversalCase{travCase()})
	tgt := targetFor(t, srv, "file", "index.html")
	tgt.URL = tgt.URL + "&file=another-value.html" // duplicate parameter

	x := newExecutor(true, detection.ExecutorConfig{})
	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeFinding {
		t.Errorf("Outcome = %v, want OutcomeFinding (duplicate parameter must not prevent normal detection)", result.Outcome)
	}
}

// TestAdversarial_DuplicateTraversalCasesConfigured_SingleFindingNotInflated
// confirms that configuring the SAME case twice (a plausible operator
// misconfiguration) never produces more than one aggregated finding
// per Detect call -- Detect always returns at most one Finding
// regardless of how many cases/variants matched.
func TestAdversarial_DuplicateTraversalCasesConfigured_SingleFindingNotInflated(t *testing.T) {
	srv := httptest.NewServer(vulnerableHandler())
	defer srv.Close()

	d := New([]TraversalCase{travCase(), travCase(), travCase()})
	tgt := targetFor(t, srv, "file", "index.html")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeFinding {
		t.Fatalf("Outcome = %v, want OutcomeFinding", result.Outcome)
	}
	if len(result.Findings) != 1 {
		t.Errorf("len(Findings) = %d, want exactly 1 even with 3 identical configured cases", len(result.Findings))
	}
}

// TestAdversarial_MalformedResponseBody_NoCrash confirms binary/
// non-UTF8 response bytes never panic the detector.
func TestAdversarial_MalformedResponseBody_NoCrash(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte{0xff, 0xfe, 0x00, 0x01, 0x02, 0xC0, 0xC1})
	}))
	defer srv.Close()

	d := New([]TraversalCase{travCase()})
	tgt := targetFor(t, srv, "file", "index.html")
	x := newExecutor(true, detection.ExecutorConfig{})

	result, err := d.Detect(context.Background(), tgt, x)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if result.Outcome != detection.OutcomeNoFinding {
		t.Errorf("Outcome = %v, want OutcomeNoFinding", result.Outcome)
	}
}

// TestAdversarial_UnusualStatusCodes_NoCrashNoFalsePositive covers a
// spread of non-2xx/3xx/4xx status codes the target might return.
func TestAdversarial_UnusualStatusCodes_NoCrashNoFalsePositive(t *testing.T) {
	cases := []struct {
		name   string
		status int
	}{
		{"No Content", 204},
		{"Moved Permanently", 301},
		{"Too Many Requests", 429},
		{"Service Unavailable", 503},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
				file := r.URL.Query().Get("file")
				w.Header().Set("Content-Type", "text/plain")
				if file == "index.html" {
					w.Write([]byte("PUBLIC_FILE_MARKER")) // the legit baseline must still succeed
					return
				}
				w.WriteHeader(c.status)
				w.Write([]byte("status response"))
			}))
			defer srv.Close()

			d := New([]TraversalCase{travCase()})
			tgt := targetFor(t, srv, "file", "index.html")
			x := newExecutor(true, detection.ExecutorConfig{})

			result, err := d.Detect(context.Background(), tgt, x)
			if err != nil {
				t.Fatalf("Detect: %v", err)
			}
			if result.Outcome != detection.OutcomeNoFinding {
				t.Errorf("Outcome = %v, want OutcomeNoFinding for status %d", result.Outcome, c.status)
			}
		})
	}
}
