package parameters

import (
	"strconv"
	"strings"
	"sync"
	"testing"

	"sakanner/internal/crawler"
)

// Phase 3.18 task section 17's JSON-specific adversarial suite.

func TestParseJSONBody_HugeBody_BoundedNoCrash(t *testing.T) {
	var b strings.Builder
	b.WriteString("{")
	for i := 0; i < 5000; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`"f`)
		b.WriteString(strconv.Itoa(i))
		b.WriteString(`":"v"`)
	}
	b.WriteString("}")

	res := ParseJSONBody([]byte(b.String()), Limits{MaxJSONFields: 100}, ProvenanceRequestInput)
	if len(res.Candidates) != 100 {
		t.Fatalf("got %d candidates, want exactly 100 (bounded), from a 5000-field body", len(res.Candidates))
	}
	if len(res.Warnings) == 0 {
		t.Error("expected a field-limit warning for a huge body")
	}
}

func TestParseJSONBody_HugeArray_OneCandidateNotUnboundedWork(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"items":[`)
	for i := 0; i < 100000; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(strconv.Itoa(i))
	}
	b.WriteString(`]}`)

	res := ParseJSONBody([]byte(b.String()), Limits{}, ProvenanceRequestInput)
	if len(res.Candidates) != 1 {
		t.Fatalf("got %d candidates for a huge array field, want exactly 1 (never descended into)", len(res.Candidates))
	}
}

func TestParseJSONBody_DuplicateJSONKeys_NoCrashLastWins(t *testing.T) {
	// encoding/json's own documented behavior for duplicate object keys
	// is "the last value wins" -- this test proves ParseJSONBody
	// inherits that cleanly (no crash, no duplicated candidate, a
	// single deterministic value), not that it invents its own
	// duplicate-key semantics.
	res := ParseJSONBody([]byte(`{"a":"first","a":"second"}`), Limits{}, ProvenanceRequestInput)
	if len(res.Candidates) != 1 {
		t.Fatalf("got %d candidates for a duplicate-key body, want 1", len(res.Candidates))
	}
	if res.Candidates[0].Value != "second" {
		t.Errorf("value = %q, want %q (last value wins, matching encoding/json's own behavior)", res.Candidates[0].Value, "second")
	}
}

func TestParseJSONBody_UnicodeKeys_NoCrash(t *testing.T) {
	cjkKey := "\u7528\u6237\u540d" // username in CJK, written as escapes to avoid source-encoding ambiguity
	emojiKey := "emoji_\U0001F511" // key emoji
	body := []byte(`{"` + cjkKey + `":"alice","` + emojiKey + `":"value","user name":"x"}`)

	res := ParseJSONBody(body, Limits{}, ProvenanceRequestInput)
	names := map[string]bool{}
	for _, c := range res.Candidates {
		names[c.Name] = true
	}
	if !names[cjkKey] {
		t.Errorf("expected a Unicode CJK key to be discovered, got %+v", res.Candidates)
	}
	if !names[emojiKey] {
		t.Errorf("expected an emoji-containing key to be discovered, got %+v", res.Candidates)
	}
}

func TestParseJSONBody_URLLikeStringValue_TreatedAsPlainValue(t *testing.T) {
	// A JSON string VALUE that looks like a URL must never be treated
	// specially (fetched, resolved, executed) by this pure parsing
	// function -- it is just a string.
	res := ParseJSONBody([]byte(`{"callback":"https://evil.test/steal?x=1"}`), Limits{}, ProvenanceRequestInput)
	if len(res.Candidates) != 1 || res.Candidates[0].Value != "https://evil.test/steal?x=1" {
		t.Errorf("got %+v, want the URL-shaped value preserved verbatim as plain data", res.Candidates)
	}
}

func TestParseJSONBody_DeeplyNestedBeyondLimit_NoCrashBoundedWork(t *testing.T) {
	var open, close string
	for i := 0; i < 500; i++ {
		open += `{"a":`
		close += `}`
	}
	body := open + `"deep"` + close
	res := ParseJSONBody([]byte(body), Limits{MaxJSONDepth: 5}, ProvenanceRequestInput)
	for _, c := range res.Candidates {
		if strings.Count(c.Name, ".") > 5 {
			t.Errorf("candidate %q exceeds the configured depth limit of 5", c.Name)
		}
	}
	if len(res.Warnings) == 0 {
		t.Error("expected a depth-limit warning for a 500-level-deep body")
	}
}

func TestNormalizeJSONResponses_ConcurrentCalls_NoRace(t *testing.T) {
	pages := []crawler.Page{{
		URL: "https://example.test/api/data", ContentType: "application/json",
		ResponseBody: []byte(`{"a":1,"b":{"c":2}}`),
	}}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res := NormalizeJSONResponses(pages, Limits{})
			if len(res.Candidates) != 2 {
				t.Errorf("concurrent call got %d candidates, want 2", len(res.Candidates))
			}
		}()
	}
	wg.Wait()
}

func TestNormalizeJSONResponses_DuplicateEndpointAcrossPages_Deduplicated(t *testing.T) {
	// The SAME URL appearing twice in the input (a defensive case --
	// Normalize's own dedup discipline must hold here too, not just
	// for query/form candidates).
	pages := []crawler.Page{
		{URL: "https://example.test/api/data", ContentType: "application/json", ResponseBody: []byte(`{"x":1}`)},
		{URL: "https://example.test/api/data", ContentType: "application/json", ResponseBody: []byte(`{"x":1}`)},
	}
	res := NormalizeJSONResponses(pages, Limits{})
	if len(res.Candidates) != 1 {
		t.Fatalf("got %d candidates, want 1 (deduplicated across identical pages)", len(res.Candidates))
	}
	if res.DuplicateCount != 1 {
		t.Errorf("DuplicateCount = %d, want 1", res.DuplicateCount)
	}
}

func TestParseJSONBody_AuthorizationLikeAndCookieLikeFields_Redacted(t *testing.T) {
	res := ParseJSONBody([]byte(`{"authorization":"Bearer secret-abc","session":"sid-xyz","csrf_token":"tok-123","name":"alice"}`), Limits{}, ProvenanceResponseField)
	byName := map[string]string{}
	for _, c := range res.Candidates {
		byName[c.Name] = c.Value
	}
	for _, name := range []string{"authorization", "session", "csrf_token"} {
		if strings.Contains(byName[name], "secret") || strings.Contains(byName[name], "sid-xyz") || strings.Contains(byName[name], "tok-123") {
			t.Errorf("SECURITY: sensitive field %q was not redacted, value=%q", name, byName[name])
		}
	}
	if byName["name"] != "alice" {
		t.Errorf("non-sensitive field 'name' unexpectedly altered: %q", byName["name"])
	}
}
