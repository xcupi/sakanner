package xssactive

import "testing"

func TestClassifyReflection_None(t *testing.T) {
	body := []byte(`<html><body>no match here</body></html>`)
	if got := classifyReflection(body, contextPayload()); got != ReflectionNone {
		t.Errorf("got %s, want none", got)
	}
}

func TestClassifyReflection_HTMLEncoded_SafeNotAFinding(t *testing.T) {
	body := []byte(`<html><body><p>You searched for: &#34;&#39;&gt;&lt;script&gt;ACTIVEXSSMARK&lt;/script&gt;</p></body></html>`)
	if got := classifyReflection(body, contextPayload()); got != ReflectionHTMLEncoded {
		t.Errorf("got %s, want html_encoded", got)
	}
}

func TestClassifyReflection_Exact_PlainTextContext(t *testing.T) {
	body := []byte(`<html><body><p>You searched for: ` + contextPayload() + `</p></body></html>`)
	if got := classifyReflection(body, contextPayload()); got != ReflectionExact {
		t.Errorf("got %s, want exact", got)
	}
}

func TestClassifyReflection_Attribute_UnclosedTagQuote(t *testing.T) {
	body := []byte(`<html><body><input type="text" name="q" value="` + contextPayload() + `"></body></html>`)
	if got := classifyReflection(body, contextPayload()); got != ReflectionAttribute {
		t.Errorf("got %s, want attribute", got)
	}
}

func TestClassifyReflection_JavaScript_InsideOpenScriptBlock(t *testing.T) {
	body := []byte(`<html><body><script>var x = "` + contextPayload() + `";</script></body></html>`)
	if got := classifyReflection(body, contextPayload()); got != ReflectionJavaScript {
		t.Errorf("got %s, want javascript", got)
	}
}

func TestClassifyReflection_NotInsideScript_AfterClosedScriptBlock(t *testing.T) {
	// A CLOSED script block before the payload must not be mistaken
	// for an open one.
	body := []byte(`<html><body><script>var y = 1;</script><p>` + contextPayload() + `</p></body></html>`)
	if got := classifyReflection(body, contextPayload()); got != ReflectionExact {
		t.Errorf("got %s, want exact (the earlier script block is already closed)", got)
	}
}

func TestClassifyReflection_StaticDecoy_UnrelatedScriptTagIgnored(t *testing.T) {
	// A page that already contains an unrelated, closed <script> tag
	// (the lab's own "static decoy" scenario) must not cause the
	// payload's OWN plain-text reflection to be misclassified as
	// JavaScript context.
	body := []byte(`<html><body><code>&lt;script&gt;alert(1)&lt;/script&gt; -- also raw: <script>legacyWidget()</script></code><p>` + contextPayload() + `</p></body></html>`)
	if got := classifyReflection(body, contextPayload()); got != ReflectionExact {
		t.Errorf("got %s, want exact", got)
	}
}

func TestIsJSONContentType(t *testing.T) {
	cases := map[string]bool{
		"application/json":                true,
		"application/json; charset=utf-8": true,
		"text/html":                       false,
		"":                                false,
		"application/xml":                 false,
	}
	for ct, want := range cases {
		if got := isJSONContentType(ct); got != want {
			t.Errorf("isJSONContentType(%q) = %v, want %v", ct, got, want)
		}
	}
}
