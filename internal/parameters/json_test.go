package parameters

import (
	"strconv"
	"strings"
	"testing"
)

func TestParseJSONBody_TopLevelFields(t *testing.T) {
	res := ParseJSONBody([]byte(`{"q": "test", "page": 2, "active": true}`), Limits{}, ProvenanceRequestInput)
	if len(res.Candidates) != 3 {
		t.Fatalf("got %d candidates, want 3: %+v", len(res.Candidates), res.Candidates)
	}
	byName := map[string]Candidate{}
	for _, c := range res.Candidates {
		byName[c.Name] = c
		if c.Location != LocationJSON || c.Source != SourceJSONBody || c.ContentType != "application/json" {
			t.Errorf("unexpected candidate shape: %+v", c)
		}
	}
	if byName["q"].Value != "test" {
		t.Errorf("q value = %q, want test", byName["q"].Value)
	}
	if byName["page"].Value != "2" {
		t.Errorf("page value = %q, want \"2\"", byName["page"].Value)
	}
}

func TestParseJSONBody_NestedFields_DotPath(t *testing.T) {
	res := ParseJSONBody([]byte(`{"user": {"name": "alice", "address": {"city": "NYC"}}}`), Limits{}, ProvenanceRequestInput)
	names := map[string]string{}
	for _, c := range res.Candidates {
		names[c.Name] = c.Value
	}
	if names["user.name"] != "alice" {
		t.Errorf("user.name = %q, want alice; got fields: %+v", names["user.name"], res.Candidates)
	}
	if names["user.address.city"] != "NYC" {
		t.Errorf("user.address.city = %q, want NYC; got fields: %+v", names["user.address.city"], res.Candidates)
	}
}

func TestParseJSONBody_MalformedJSON_NoCrashReturnsWarning(t *testing.T) {
	res := ParseJSONBody([]byte(`{"a": "unterminated`), Limits{}, ProvenanceRequestInput)
	if len(res.Candidates) != 0 {
		t.Errorf("got candidates %+v from malformed JSON, want none", res.Candidates)
	}
	if len(res.Warnings) == 0 {
		t.Error("expected a warning for malformed JSON")
	}
}

func TestParseJSONBody_NonObjectTopLevel_NoCandidatesNoError(t *testing.T) {
	for _, body := range []string{`[1,2,3]`, `"just a string"`, `42`, `true`, `null`} {
		res := ParseJSONBody([]byte(body), Limits{}, ProvenanceRequestInput)
		if len(res.Candidates) != 0 || len(res.Warnings) != 0 {
			t.Errorf("body %q: got %+v, want empty result", body, res)
		}
	}
}

func TestParseJSONBody_DepthLimit_TruncatesAndWarns(t *testing.T) {
	// depth 0=a, 1=b, 2=c, 3=d -- with MaxJSONDepth=2, "a.b" (depth 1
	// object) is descended into producing "a.b.c" only if depth < limit
	// at each step; exact boundary behavior is less important than:
	// deeply nested content is not silently included AND a warning
	// fires.
	res := ParseJSONBody([]byte(`{"a":{"b":{"c":{"d":{"e":"too deep"}}}}}`), Limits{MaxJSONDepth: 2}, ProvenanceRequestInput)
	for _, c := range res.Candidates {
		if strings.Count(c.Name, ".") > 2 {
			t.Errorf("candidate %q exceeds the configured depth limit", c.Name)
		}
	}
	if len(res.Warnings) == 0 {
		t.Error("expected a depth-limit warning")
	}
}

func TestParseJSONBody_FieldLimit_TruncatesAndWarns(t *testing.T) {
	var b strings.Builder
	b.WriteString("{")
	for i := 0; i < 20; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`"f` + strconv.Itoa(i) + `":"v"`)
	}
	b.WriteString("}")

	res := ParseJSONBody([]byte(b.String()), Limits{MaxJSONFields: 5}, ProvenanceRequestInput)
	if len(res.Candidates) != 5 {
		t.Fatalf("got %d candidates, want 5 (truncated): %+v", len(res.Candidates), res.Candidates)
	}
	if len(res.Warnings) == 0 {
		t.Error("expected a field-limit warning")
	}
}

func TestParseJSONBody_ArrayField_NotDescendedInto(t *testing.T) {
	res := ParseJSONBody([]byte(`{"items": [{"name": "a"}, {"name": "b"}], "tags": ["x", "y"]}`), Limits{}, ProvenanceRequestInput)
	names := map[string]string{}
	for _, c := range res.Candidates {
		names[c.Name] = c.Value
	}
	if _, ok := names["items.name"]; ok {
		t.Error("array elements' fields must not be individually discovered (items.name found)")
	}
	if _, ok := names["items"]; !ok {
		t.Error("the array field itself (items) must still be represented as one candidate")
	}
	if _, ok := names["tags"]; !ok {
		t.Error("the array field itself (tags) must still be represented as one candidate")
	}
}

func TestParseJSONBody_SensitiveFieldRedacted(t *testing.T) {
	res := ParseJSONBody([]byte(`{"username": "alice", "password": "hunter2"}`), Limits{}, ProvenanceRequestInput)
	for _, c := range res.Candidates {
		if c.Name == "password" && c.Value == "hunter2" {
			t.Error("password field was not redacted")
		}
	}
}

func TestParseJSONBody_EmptyObject_NoCandidates(t *testing.T) {
	res := ParseJSONBody([]byte(`{}`), Limits{}, ProvenanceRequestInput)
	if len(res.Candidates) != 0 || len(res.Warnings) != 0 {
		t.Errorf("got %+v, want empty", res)
	}
}

func TestParseJSONBody_Deterministic(t *testing.T) {
	body := []byte(`{"b": 1, "a": {"z": 1, "y": 2}, "c": [1,2,3]}`)
	first := ParseJSONBody(body, Limits{}, ProvenanceRequestInput)
	for i := 0; i < 20; i++ {
		got := ParseJSONBody(body, Limits{}, ProvenanceRequestInput)
		if len(got.Candidates) != len(first.Candidates) {
			t.Fatalf("iteration %d: candidate count changed", i)
		}
		for j := range got.Candidates {
			if got.Candidates[j] != first.Candidates[j] {
				t.Fatalf("iteration %d: candidate %d differs: %+v vs %+v", i, j, got.Candidates[j], first.Candidates[j])
			}
		}
	}
}
