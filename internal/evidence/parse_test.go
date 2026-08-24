package evidence

import "testing"

func TestParseMethodAndPath_GET(t *testing.T) {
	method, url := parseMethodAndPath("GET http://h.test/p?q=1")
	if method != "GET" || url != "http://h.test/p?q=1" {
		t.Errorf("got (%q, %q)", method, url)
	}
}

func TestParseMethodAndPath_TrailingAnnotation(t *testing.T) {
	// idor/traversal/cmdinjection detectors append "(...)" annotations
	// after the URL -- strings.Fields naturally isolates just the URL
	// as the second whitespace-delimited token.
	method, url := parseMethodAndPath("GET http://h.test/p?resource_id=x (as user-b)")
	if method != "GET" || url != "http://h.test/p?resource_id=x" {
		t.Errorf("got (%q, %q)", method, url)
	}
}

func TestParseMethodAndPath_UnrecognizedShapeFallsBackSafely(t *testing.T) {
	method, rest := parseMethodAndPath("not a request line at all")
	if method != "" {
		t.Errorf("method = %q, want empty for an unrecognized shape", method)
	}
	if rest != "not a request line at all" {
		t.Errorf("rest = %q, want the original string unchanged", rest)
	}
}

func TestParseMethodAndPath_Empty(t *testing.T) {
	method, rest := parseMethodAndPath("")
	if method != "" || rest != "" {
		t.Errorf("got (%q, %q), want (\"\", \"\")", method, rest)
	}
}

func TestParseRawEvidence_ValidJSON(t *testing.T) {
	raw, ok := parseRawEvidence(`{"request":"GET /p","status_code":200}`)
	if !ok {
		t.Fatal("ok = false, want true")
	}
	if raw.Request != "GET /p" || raw.StatusCode != 200 {
		t.Errorf("got %+v", raw)
	}
}

func TestParseRawEvidence_InvalidJSON(t *testing.T) {
	_, ok := parseRawEvidence("not json at all")
	if ok {
		t.Error("ok = true, want false for non-JSON content")
	}
}

func TestParseDetectorFields_SimpleKeyValue(t *testing.T) {
	got := parseDetectorFields("context=html reflected=true")
	if got["context"] != "html" || got["reflected"] != "true" {
		t.Errorf("got %+v", got)
	}
}

func TestParseDetectorFields_QuotedValueWithSpaces(t *testing.T) {
	got := parseDetectorFields(`detail="fetched, 200 bytes" callback_observed=true`)
	if got["detail"] != "fetched, 200 bytes" {
		t.Errorf("detail = %q, want %q (quoted value with spaces must stay one token)", got["detail"], "fetched, 200 bytes")
	}
	if got["callback_observed"] != "true" {
		t.Errorf("got %+v", got)
	}
}

func TestParseDetectorFields_NoRecognizablePattern(t *testing.T) {
	got := parseDetectorFields("this has no key value pairs")
	if got != nil {
		t.Errorf("got %+v, want nil", got)
	}
}

func TestParseDetectorFields_Empty(t *testing.T) {
	got := parseDetectorFields("")
	if got != nil {
		t.Errorf("got %+v, want nil", got)
	}
}

func TestParseDetectorFields_EveryRealDetectorFormat(t *testing.T) {
	// Every one of the 6 real detectors' actual Observation formats --
	// confirming the ONE generic parser handles all of them without any
	// detector-specific knowledge.
	cases := map[string]string{
		"context=html": "context",
		`error_family="mysql" boolean_differential=true`:                                                                       "error_family",
		"callback_token=tok callback_observed=true detail=\"x\"":                                                               "callback_token",
		"who=user-b what=resource-a owner=user-a expected=denied actual=200 proof_matches_owner_baseline=true":                 "who",
		"target=/p parameter=file original=index.html probe=x expected=denied actual=200 proof_marker_matched=true":            "target",
		"target=/p parameter=host probe=x expected=input_treated_as_data actual=controlled_command_execution_occurred proof=Y": "target",
	}
	for observation, wantKey := range cases {
		got := parseDetectorFields(observation)
		if _, ok := got[wantKey]; !ok {
			t.Errorf("parseDetectorFields(%q) = %+v, want key %q present", observation, got, wantKey)
		}
	}
}
