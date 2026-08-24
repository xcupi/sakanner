package evidence

import (
	"bytes"
	"mime/multipart"
	"strings"
	"testing"
)

// --- Header redaction (task section 5) --------------------------------

func TestRedactHeaders_Authorization(t *testing.T) {
	got := redactHeaders(map[string]string{"Authorization": "Bearer SECRET123"})
	if got["Authorization"] != redactedPlaceholder {
		t.Errorf("Authorization = %q, want %q", got["Authorization"], redactedPlaceholder)
	}
}

func TestRedactHeaders_CookieAndSetCookie(t *testing.T) {
	got := redactHeaders(map[string]string{"Cookie": "session=SECRET456", "Set-Cookie": "session=SECRET456; Path=/"})
	if got["Cookie"] != redactedPlaceholder || got["Set-Cookie"] != redactedPlaceholder {
		t.Errorf("Cookie/Set-Cookie not redacted: %+v", got)
	}
}

func TestRedactHeaders_ProxyAuthorization(t *testing.T) {
	got := redactHeaders(map[string]string{"Proxy-Authorization": "Basic SECRET"})
	if got["Proxy-Authorization"] != redactedPlaceholder {
		t.Errorf("Proxy-Authorization not redacted: %+v", got)
	}
}

func TestRedactHeaders_CaseInsensitive(t *testing.T) {
	got := redactHeaders(map[string]string{"AUTHORIZATION": "Bearer X", "cookie": "y"})
	if got["AUTHORIZATION"] != redactedPlaceholder || got["cookie"] != redactedPlaceholder {
		t.Errorf("case-insensitive match failed: %+v", got)
	}
}

func TestRedactHeaders_NonSensitivePreserved(t *testing.T) {
	got := redactHeaders(map[string]string{"Content-Type": "application/json", "X-Test-Auth-User": "user-a"})
	if got["Content-Type"] != "application/json" {
		t.Error("Content-Type must not be redacted")
	}
	if got["X-Test-Auth-User"] != "user-a" {
		t.Error("a lab-only synthetic identity header (not on the blocklist) must not be redacted")
	}
}

func TestRedactHeaders_NilInputNilOutput(t *testing.T) {
	if got := redactHeaders(nil); got != nil {
		t.Errorf("redactHeaders(nil) = %+v, want nil", got)
	}
}

func TestRedactHeaders_DoesNotMutateInput(t *testing.T) {
	original := map[string]string{"Authorization": "Bearer X"}
	_ = redactHeaders(original)
	if original["Authorization"] != "Bearer X" {
		t.Error("redactHeaders must not mutate its input map")
	}
}

// --- URL redaction (task section 8) ------------------------------------

func TestRedactURL_TokenParameter(t *testing.T) {
	got := redactURL("https://example.com/api?token=SECRET")
	if strings.Contains(got, "SECRET") {
		t.Errorf("redactURL leaked the secret: %q", got)
	}
	if !strings.Contains(got, "REDACTED") {
		// The value is URL-encoded ("<"/">" become %3C/%3E, as any
		// valid query string must), so the readable word "REDACTED"
		// itself is what's checked here, not the literal bracketed form.
		t.Errorf("redactURL = %q, want it to contain REDACTED", got)
	}
}

func TestRedactURL_PreservesNonSensitiveParameters(t *testing.T) {
	got := redactURL("https://example.com/search?q=test&token=SECRET&page=2")
	if !strings.Contains(got, "q=test") {
		t.Errorf("redactURL = %q, want q=test preserved", got)
	}
	if !strings.Contains(got, "page=2") {
		t.Errorf("redactURL = %q, want page=2 preserved", got)
	}
	if strings.Contains(got, "SECRET") {
		t.Errorf("redactURL leaked the secret: %q", got)
	}
}

func TestRedactURL_MalformedURLReturnedUnchanged(t *testing.T) {
	malformed := "http://[::1:bad"
	if got := redactURL(malformed); got != malformed {
		t.Errorf("redactURL(malformed) = %q, want unchanged %q", got, malformed)
	}
}

func TestRedactURL_NoSensitiveParametersUnchanged(t *testing.T) {
	original := "https://example.com/search?q=test&page=2"
	if got := redactURL(original); got != original {
		t.Errorf("redactURL with nothing to redact = %q, want unchanged %q", got, original)
	}
}

// --- JSON body redaction (task section 9) -------------------------------

func TestRedactBody_JSON_TopLevelSecret(t *testing.T) {
	got := redactBody("application/json", `{"username":"alice","password":"SECRET789"}`)
	if strings.Contains(got, "SECRET789") {
		t.Errorf("redactBody leaked the secret: %q", got)
	}
	if !strings.Contains(got, "alice") {
		t.Errorf("redactBody destroyed unrelated data: %q", got)
	}
}

// TestRedactBody_JSON_CSRFTokenField is Phase 3.15's regression test
// for the CSRF/XSRF field-name gap found during authenticated-crawling
// development: a discovered form field literally named "csrf_token"
// (or "xsrf"/"xsrf_token") must be redacted exactly like "password"/
// "api_key" already were.
func TestRedactBody_JSON_CSRFTokenField(t *testing.T) {
	for _, field := range []string{"csrf_token", "csrf", "xsrf", "xsrf_token"} {
		t.Run(field, func(t *testing.T) {
			got := redactBody("application/json", `{"username":"alice","`+field+`":"SECRET-CSRF-VALUE"}`)
			if strings.Contains(got, "SECRET-CSRF-VALUE") {
				t.Errorf("redactBody leaked the %s value: %q", field, got)
			}
			if !strings.Contains(got, "alice") {
				t.Errorf("redactBody destroyed unrelated data: %q", got)
			}
		})
	}
}

func TestRedactBody_JSON_NestedSecret(t *testing.T) {
	got := redactBody("application/json", `{"user":{"name":"alice","credentials":{"api_key":"SECRET000"}}}`)
	if strings.Contains(got, "SECRET000") {
		t.Errorf("redactBody leaked a nested secret: %q", got)
	}
	if !strings.Contains(got, "alice") {
		t.Errorf("redactBody destroyed unrelated nested data: %q", got)
	}
}

func TestRedactBody_JSON_SecretInArray(t *testing.T) {
	got := redactBody("application/json", `{"items":[{"token":"SECRET111"},{"name":"ok"}]}`)
	if strings.Contains(got, "SECRET111") {
		t.Errorf("redactBody leaked a secret inside an array: %q", got)
	}
}

func TestRedactBody_JSON_CaseInsensitiveFieldMatch(t *testing.T) {
	got := redactBody("application/json", `{"API_KEY":"SECRET222","Password":"SECRET333"}`)
	if strings.Contains(got, "SECRET222") || strings.Contains(got, "SECRET333") {
		t.Errorf("redactBody case-insensitive match failed: %q", got)
	}
}

func TestRedactBody_JSON_MalformedFallsBackToTextRedaction(t *testing.T) {
	got := redactBody("application/json", `{"password":"SECRET444" not valid json`)
	if strings.Contains(got, "SECRET444") {
		t.Errorf("malformed JSON must still fall back to text redaction: %q", got)
	}
}

// --- Form body redaction (task section 9) -------------------------------

func TestRedactBody_Form_Secret(t *testing.T) {
	got := redactBody("application/x-www-form-urlencoded", "username=alice&password=SECRET555")
	if strings.Contains(got, "SECRET555") {
		t.Errorf("redactBody leaked the secret: %q", got)
	}
	if !strings.Contains(got, "alice") {
		t.Errorf("redactBody destroyed unrelated form data: %q", got)
	}
}

func TestRedactBody_Form_ClientSecret(t *testing.T) {
	got := redactBody("application/x-www-form-urlencoded", "client_id=abc&client_secret=SECRET666")
	if strings.Contains(got, "SECRET666") {
		t.Errorf("redactBody leaked client_secret: %q", got)
	}
	if !strings.Contains(got, "abc") {
		t.Error("client_id must survive redaction")
	}
}

// --- Multipart (task section 9) ------------------------------------------

func TestRedactBody_Multipart_FieldRedacted(t *testing.T) {
	contentType, body := buildMultipartBody(map[string]string{"username": "alice", "password": "SECRET777"})
	got := redactBody(contentType, body)
	if strings.Contains(got, "SECRET777") {
		t.Errorf("redactBody leaked a multipart secret: %q", got)
	}
	if !strings.Contains(got, "alice") {
		t.Errorf("redactBody destroyed unrelated multipart data: %q", got)
	}
}

func TestRedactBody_Multipart_MalformedFallsBackToTextRedaction(t *testing.T) {
	got := redactBody("multipart/form-data; boundary=XYZ", "not actually valid multipart content password=SECRET888")
	if strings.Contains(got, "SECRET888") {
		t.Errorf("malformed multipart must still fall back to text redaction: %q", got)
	}
}

func buildMultipartBody(fields map[string]string) (contentType, body string) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for k, v := range fields {
		fw, err := w.CreateFormField(k)
		if err != nil {
			panic(err)
		}
		fw.Write([]byte(v))
	}
	w.Close()
	return w.FormDataContentType(), buf.String()
}

// --- Generic text redaction (task section 10) ---------------------------

func TestRedactText_KeyEqualsValue(t *testing.T) {
	got := redactText("password=SECRET888 other=fine")
	if strings.Contains(got, "SECRET888") {
		t.Errorf("redactText leaked the secret: %q", got)
	}
	if !strings.Contains(got, "other=fine") {
		t.Errorf("redactText destroyed unrelated content: %q", got)
	}
}

func TestRedactText_PreservesSeparatorStyle(t *testing.T) {
	got := redactText("password=SECRET888")
	if !strings.Contains(got, "password="+redactedPlaceholder) {
		t.Errorf("redactText = %q, want the original \"=\" separator preserved", got)
	}
}

func TestRedactText_NoSensitiveContentUnchanged(t *testing.T) {
	original := "context=html reflected=true"
	if got := redactText(original); got != original {
		t.Errorf("redactText with nothing to redact = %q, want unchanged %q", got, original)
	}
}

// --- Secret leak tests (task section 37): synthetic secrets injected
// into every layer, verified absent from stored evidence. ------------

func TestSecretLeak_AuthorizationBearerNeverAppearsInEvidence(t *testing.T) {
	cf := findingWith("reflected_xss", "h.test", "/p", "q", "high", 0.9, rawRequestResponseEvidence{
		Request: "GET http://h.test/p?q=x", Response: "HTTP 200", StatusCode: 200,
		Headers:          map[string]string{"Authorization": "Bearer SECRET123"},
		ResponseFragment: "ok", Parameter: "q", Payload: "x",
	})
	items := BuildEvidence(cf, DefaultLimits())
	assertNeverContains(t, items, "SECRET123")
}

func TestSecretLeak_CookieSessionNeverAppearsInEvidence(t *testing.T) {
	cf := findingWith("reflected_xss", "h.test", "/p", "q", "high", 0.9, rawRequestResponseEvidence{
		Request: "GET http://h.test/p?q=x", Response: "HTTP 200", StatusCode: 200,
		Headers:          map[string]string{"Cookie": "session=SECRET456"},
		ResponseFragment: "ok", Parameter: "q", Payload: "x",
	})
	items := BuildEvidence(cf, DefaultLimits())
	assertNeverContains(t, items, "SECRET456")
}

func TestSecretLeak_PasswordInResponseBodyNeverAppears(t *testing.T) {
	cf := findingWith("sql_injection", "h.test", "/p", "id", "critical", 0.9, rawRequestResponseEvidence{
		Request: "GET http://h.test/p?id=1", Response: "HTTP 200", StatusCode: 200,
		Headers:          map[string]string{"Content-Type": "application/json"},
		ResponseFragment: `{"password":"SECRET789"}`, Parameter: "id", Payload: "1",
	})
	items := BuildEvidence(cf, DefaultLimits())
	assertNeverContains(t, items, "SECRET789")
}

func TestSecretLeak_APIKeyInURLNeverAppears(t *testing.T) {
	cf := findingWith("ssrf", "h.test", "/p", "url", "critical", 0.9, rawRequestResponseEvidence{
		Request: "GET http://h.test/p?url=http://x.test?api_key=SECRET000", Response: "HTTP 200", StatusCode: 200,
		ResponseFragment: "ok", Parameter: "url", Payload: "http://x.test?api_key=SECRET000",
	})
	items := BuildEvidence(cf, DefaultLimits())
	assertNeverContains(t, items, "SECRET000")
}

func TestSecretLeak_RedactionAppliedToReproductionToo(t *testing.T) {
	cf := findingWith("reflected_xss", "h.test", "/p", "token", "high", 0.9, rawRequestResponseEvidence{
		Request: "GET http://h.test/p?token=SECRETABC", Response: "HTTP 200", StatusCode: 200,
		ResponseFragment: "ok", Parameter: "token", Payload: "SECRETABC",
	})
	info := buildReproductionInfo(cf, BuildEvidence(cf, DefaultLimits()), DefaultLimits())
	if strings.Contains(info.URL, "SECRETABC") || strings.Contains(info.SafeTestValue, "SECRETABC") {
		t.Errorf("reproduction leaked the secret: URL=%q SafeTestValue=%q", info.URL, info.SafeTestValue)
	}
}

func assertNeverContains(t *testing.T, items []CanonicalEvidence, secret string) {
	t.Helper()
	for _, it := range items {
		if strings.Contains(it.Request.URL, secret) {
			t.Errorf("secret %q leaked in Request.URL: %q", secret, it.Request.URL)
		}
		if strings.Contains(it.Request.Body, secret) {
			t.Errorf("secret %q leaked in Request.Body: %q", secret, it.Request.Body)
		}
		for k, v := range it.Request.Headers {
			if strings.Contains(v, secret) {
				t.Errorf("secret %q leaked in Request.Headers[%q]: %q", secret, k, v)
			}
		}
		if strings.Contains(it.Response.Excerpt, secret) {
			t.Errorf("secret %q leaked in Response.Excerpt: %q", secret, it.Response.Excerpt)
		}
		for k, v := range it.Response.Headers {
			if strings.Contains(v, secret) {
				t.Errorf("secret %q leaked in Response.Headers[%q]: %q", secret, k, v)
			}
		}
		if strings.Contains(it.Observation, secret) {
			t.Errorf("secret %q leaked in Observation: %q", secret, it.Observation)
		}
		if strings.Contains(it.Verification, secret) {
			t.Errorf("secret %q leaked in Verification: %q", secret, it.Verification)
		}
		for k, v := range it.DetectorFields {
			if strings.Contains(v, secret) {
				t.Errorf("secret %q leaked in DetectorFields[%q]: %q", secret, k, v)
			}
		}
		if strings.Contains(it.IntegrityHash, secret) {
			t.Errorf("secret %q leaked in IntegrityHash (impossible for a hash, but checked anyway): %q", secret, it.IntegrityHash)
		}
	}
}
