package parameters

import "testing"

func TestClassificationFor_MapsEveryDocumentedLocation(t *testing.T) {
	cases := map[Location]Classification{
		LocationQuery:  ClassificationParameter,
		LocationPath:   ClassificationPathInput,
		LocationForm:   ClassificationFormField,
		LocationJSON:   ClassificationJSONField,
		LocationHeader: ClassificationOther,
		LocationCookie: ClassificationOther,
	}
	for loc, want := range cases {
		if got := ClassificationFor(loc); got != want {
			t.Errorf("ClassificationFor(%q) = %q, want %q", loc, got, want)
		}
	}
}

func TestClassificationFor_UnknownLocation_NeverPanics(t *testing.T) {
	if got := ClassificationFor(Location("bogus")); got != ClassificationOther {
		t.Errorf("ClassificationFor(bogus) = %q, want OTHER", got)
	}
}

func TestLimits_Normalized_ZeroValueBecomesDefaults(t *testing.T) {
	got := Limits{}.normalized()
	want := DefaultLimits()
	if got != want {
		t.Errorf("Limits{}.normalized() = %+v, want %+v", got, want)
	}
}

func TestLimits_Normalized_PositiveValuesPreserved(t *testing.T) {
	l := Limits{MaxInputsPerEndpoint: 5, MaxTotalInputs: 6, MaxFormFields: 7, MaxJSONDepth: 8, MaxJSONFields: 9, MaxPathSegments: 10}
	got := l.normalized()
	if got != l {
		t.Errorf("normalized() changed positive values: got %+v, want %+v", got, l)
	}
}

func TestLimits_Normalized_NegativeValuesBecomeDefaults(t *testing.T) {
	l := Limits{MaxInputsPerEndpoint: -1, MaxTotalInputs: -1, MaxFormFields: -1, MaxJSONDepth: -1, MaxJSONFields: -1, MaxPathSegments: -1}
	got := l.normalized()
	want := DefaultLimits()
	if got != want {
		t.Errorf("negative Limits{} normalized() = %+v, want defaults %+v", got, want)
	}
}
