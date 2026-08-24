package mutation

import (
	"net/http"
	"testing"
)

func TestCompare_IdenticalResponses_NotStructurallyDifferent(t *testing.T) {
	a := Response{StatusCode: 200, ContentType: "text/html", Body: []byte("hello world"), BodySize: 11, Headers: http.Header{"X-Custom": {"1"}}}
	b := a
	r := Compare(a, b)
	if r.StructurallyDifferent {
		t.Errorf("identical responses reported as structurally different: %+v", r)
	}
	if !r.BodyIdentical || !r.BodyNormalizedIdentical || !r.StatusCodeMatch || !r.ContentTypeMatch || !r.SizeMatch {
		t.Errorf("expected every match flag true for identical responses: %+v", r)
	}
}

func TestCompare_DifferentStatusCode_StructurallyDifferent(t *testing.T) {
	a := Response{StatusCode: 200, Body: []byte("ok")}
	b := Response{StatusCode: 403, Body: []byte("ok")}
	r := Compare(a, b)
	if !r.StructurallyDifferent {
		t.Error("different status codes must be reported as structurally different")
	}
	if r.StatusCodeMatch {
		t.Error("StatusCodeMatch should be false")
	}
}

func TestCompare_ContentTypeCharsetIgnored(t *testing.T) {
	a := Response{StatusCode: 200, ContentType: "text/html; charset=utf-8", Body: []byte("x")}
	b := Response{StatusCode: 200, ContentType: "text/html; charset=iso-8859-1", Body: []byte("x")}
	r := Compare(a, b)
	if !r.ContentTypeMatch {
		t.Error("content types differing only by charset parameter should match")
	}
	if r.StructurallyDifferent {
		t.Error("should not be structurally different when only the charset parameter differs")
	}
}

func TestCompare_DifferentContentType_StructurallyDifferent(t *testing.T) {
	a := Response{StatusCode: 200, ContentType: "text/html", Body: []byte("x")}
	b := Response{StatusCode: 200, ContentType: "application/json", Body: []byte("x")}
	r := Compare(a, b)
	if r.ContentTypeMatch {
		t.Error("genuinely different content types should not match")
	}
	if !r.StructurallyDifferent {
		t.Error("expected StructurallyDifferent for a real content-type change")
	}
}

func TestCompare_DigitRunNormalization_IgnoresNumericDifferences(t *testing.T) {
	a := Response{StatusCode: 200, ContentType: "application/json", Body: []byte(`{"order_id":123,"total":45}`)}
	b := Response{StatusCode: 200, ContentType: "application/json", Body: []byte(`{"order_id":987654,"total":9}`)}
	r := Compare(a, b)
	if r.BodyIdentical {
		t.Error("bodies with different digits should not be byte-identical")
	}
	if !r.BodyNormalizedIdentical {
		t.Errorf("bodies differing only in digit runs should be normalized-identical, got %+v", r)
	}
	if r.StructurallyDifferent {
		t.Error("should not be structurally different when only numeric IDs differ")
	}
}

func TestCompare_DigitRunNormalization_PreservesNonNumericDifferences(t *testing.T) {
	// Guards against over-normalization: a genuine textual difference
	// (not just digits) must still be caught.
	a := Response{StatusCode: 200, ContentType: "application/json", Body: []byte(`{"user":"alice","id":1}`)}
	b := Response{StatusCode: 200, ContentType: "application/json", Body: []byte(`{"user":"bob","id":1}`)}
	r := Compare(a, b)
	if r.BodyNormalizedIdentical {
		t.Error("a genuine non-numeric textual difference must not be normalized away")
	}
	if !r.StructurallyDifferent {
		t.Error("expected StructurallyDifferent when body text genuinely differs")
	}
}

func TestCompare_VolatileHeadersIgnored(t *testing.T) {
	a := Response{StatusCode: 200, Body: []byte("x"), Headers: http.Header{"Date": {"Mon, 01 Jan 2024 00:00:00 GMT"}, "X-Request-Id": {"abc-123"}}}
	b := Response{StatusCode: 200, Body: []byte("x"), Headers: http.Header{"Date": {"Tue, 02 Jan 2024 00:00:00 GMT"}, "X-Request-Id": {"xyz-789"}}}
	r := Compare(a, b)
	if len(r.HeaderDeltas) != 0 {
		t.Errorf("Date/X-Request-Id are volatile and must never appear in HeaderDeltas, got %v", r.HeaderDeltas)
	}
}

func TestCompare_SetCookieComparedByNameOnly(t *testing.T) {
	a := Response{StatusCode: 200, Body: []byte("x"), Headers: http.Header{"Set-Cookie": {"sid=aaa111; Path=/"}}}
	b := Response{StatusCode: 200, Body: []byte("x"), Headers: http.Header{"Set-Cookie": {"sid=bbb222; Path=/"}}}
	r := Compare(a, b)
	if len(r.HeaderDeltas) != 0 {
		t.Errorf("Set-Cookie values rotating (same cookie NAME) should not appear in HeaderDeltas, got %v", r.HeaderDeltas)
	}
}

func TestCompare_SetCookieDifferentNames_Detected(t *testing.T) {
	a := Response{StatusCode: 200, Body: []byte("x"), Headers: http.Header{"Set-Cookie": {"sid=aaa"}}}
	b := Response{StatusCode: 200, Body: []byte("x"), Headers: http.Header{"Set-Cookie": {"admin_token=bbb"}}}
	r := Compare(a, b)
	if len(r.HeaderDeltas) == 0 {
		t.Error("a genuinely different cookie NAME being set is a structural signal and must appear in HeaderDeltas")
	}
}

func TestCompare_HeaderDeltas_SortedAndAccurate(t *testing.T) {
	a := Response{StatusCode: 200, Body: []byte("x"), Headers: http.Header{"X-Zeta": {"1"}, "X-Alpha": {"1"}, "X-Same": {"1"}}}
	b := Response{StatusCode: 200, Body: []byte("x"), Headers: http.Header{"X-Zeta": {"2"}, "X-Alpha": {"2"}, "X-Same": {"1"}}}
	r := Compare(a, b)
	want := []string{"x-alpha", "x-zeta"}
	if len(r.HeaderDeltas) != len(want) || r.HeaderDeltas[0] != want[0] || r.HeaderDeltas[1] != want[1] {
		t.Errorf("HeaderDeltas = %v, want sorted %v", r.HeaderDeltas, want)
	}
}

func TestCompare_Deterministic_RepeatedCallsIdentical(t *testing.T) {
	a := Response{StatusCode: 200, ContentType: "text/html", Body: []byte("body123"), Headers: http.Header{"X-A": {"1"}, "X-B": {"2"}}}
	b := Response{StatusCode: 200, ContentType: "text/html", Body: []byte("body456"), Headers: http.Header{"X-A": {"9"}, "X-B": {"2"}}}
	r1 := Compare(a, b)
	r2 := Compare(a, b)
	if r1.StructurallyDifferent != r2.StructurallyDifferent || len(r1.HeaderDeltas) != len(r2.HeaderDeltas) {
		t.Fatalf("Compare not deterministic across repeated calls: %+v vs %+v", r1, r2)
	}
}
