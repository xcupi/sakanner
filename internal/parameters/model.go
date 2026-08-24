package parameters

// Location is where a discovered input's value is transmitted --
// task's explicit, closed vocabulary. Never invent a value outside
// this set.
type Location string

const (
	LocationQuery  Location = "query"  // URL query string (?name=value)
	LocationPath   Location = "path"   // a variable URL path segment
	LocationForm   Location = "form"   // application/x-www-form-urlencoded or multipart form body
	LocationJSON   Location = "json"   // a JSON request body field
	LocationHeader Location = "header" // an HTTP request header (not yet discovered by any source in this phase -- see doc.go)
	LocationCookie Location = "cookie" // an HTTP cookie (not yet discovered by any source in this phase -- see doc.go)
)

// Classification is a coarse grouping ALWAYS derived from Location via
// ClassificationFor -- never set independently, so it can never
// disagree with the Location it describes. Task's explicit "do not
// create unnecessary categories: the location remains authoritative."
type Classification string

const (
	ClassificationParameter Classification = "PARAMETER"  // query
	ClassificationPathInput Classification = "PATH_INPUT" // path
	ClassificationFormField Classification = "FORM_FIELD" // form
	ClassificationJSONField Classification = "JSON_FIELD" // json
	// ClassificationOther covers header/cookie locations -- no
	// dedicated category exists for them (task: "do not create
	// unnecessary categories"), since no discovery source in this
	// phase produces them; kept so ClassificationFor is total (never
	// panics) rather than silently mishandling a future Location.
	ClassificationOther Classification = "OTHER"
)

// ClassificationFor derives the Classification for a Location -- the
// ONLY place this mapping is defined, so Location and Classification
// can never drift out of sync.
func ClassificationFor(loc Location) Classification {
	switch loc {
	case LocationQuery:
		return ClassificationParameter
	case LocationPath:
		return ClassificationPathInput
	case LocationForm:
		return ClassificationFormField
	case LocationJSON:
		return ClassificationJSONField
	default:
		return ClassificationOther
	}
}

// Discovery source labels -- task's Input.Source field, describing HOW
// an input was found (distinct from Location, which describes WHERE
// its value is transmitted).
const (
	SourceURLQuery      = "url_query"      // a query string observed on a crawled/linked URL
	SourceHTMLForm      = "html_form"      // a field parsed from a <form>
	SourceJSONBody      = "json_body"      // a field parsed from a captured JSON REQUEST body (still not produced by any live pipeline source -- see Provenance's own doc comment)
	SourceJSONResponse  = "json_response"  // a field parsed from a captured JSON RESPONSE body (Phase 3.18) -- always Provenance == ProvenanceResponseField
	SourcePathInference = "path_inference" // a path segment inferred variable by cross-observation
)

// Provenance distinguishes WHETHER a discovered field was ever
// actually confirmed as something the application accepts as an
// input, from something merely OBSERVED being returned in a response
// -- Phase 3.18's task section 18 "IMPORTANT SECURITY DISTINCTION":
// a response field is never automatically a writable request
// parameter. See docs/phase-3-18-api-json-discovery.md section 2 for
// the full rationale.
type Provenance string

const (
	// ProvenanceRequestInput means this field was observed being
	// ACCEPTED by the application -- it appeared in a URL a page
	// actually links to, or a form the application actually renders
	// for submission. Every Phase 3.13 discovery source (query, form)
	// has only ever produced this value; it is the correct backfill
	// for every Parameter row that predates this field (see migration
	// 0010's column DEFAULT).
	ProvenanceRequestInput Provenance = "REQUEST_INPUT"
	// ProvenanceResponseField means this field was observed IN A
	// RESPONSE BODY -- an API returned it, which proves nothing about
	// whether the application accepts it back as an input. Never
	// automatically treated as a mutation target (see
	// docs/phase-3-18-api-json-discovery.md section 7).
	ProvenanceResponseField Provenance = "RESPONSE_FIELD"
)

// Limits bounds one scan's input discovery work -- task's "RESOURCE
// LIMITS" section. Every field defaults to a positive, safe value (see
// DefaultLimits); a non-positive value anywhere is normalized up to
// that default rather than treated as unbounded, mirroring
// internal/orchestrator.Limits' own established convention.
type Limits struct {
	// MaxInputsPerEndpoint bounds how many Input candidates one single
	// endpoint may contribute.
	MaxInputsPerEndpoint int
	// MaxTotalInputs bounds how many Input candidates one whole scan
	// may persist in total, across every endpoint.
	MaxTotalInputs int
	// MaxFormFields bounds how many <input>/<select>/<textarea>
	// elements are read from any single <form> before the rest of that
	// form's fields are ignored.
	MaxFormFields int
	// MaxJSONDepth bounds how many levels of object nesting
	// ParseJSONBody will descend into.
	MaxJSONDepth int
	// MaxJSONFields bounds how many total fields ParseJSONBody will
	// extract from one JSON body.
	MaxJSONFields int
	// MaxPathSegments is Phase 3.23's own addition: a PathEndpoint
	// whose path has more segments than this is skipped entirely
	// before InferPathInputs groups it -- prevents a pathologically
	// deep URL from adding unbounded prefix-grouping work.
	MaxPathSegments int
}

// DefaultLimits returns safe, positive defaults for every field --
// generous enough that ordinary applications never hit them, bounded
// enough that a pathological page (a form with ten thousand fields, a
// JSON body nested a thousand levels deep) cannot make discovery
// unbounded.
func DefaultLimits() Limits {
	return Limits{
		MaxInputsPerEndpoint: 100,
		MaxTotalInputs:       2000,
		MaxFormFields:        200,
		MaxJSONDepth:         10,
		MaxJSONFields:        500,
		MaxPathSegments:      20,
	}
}

// normalized returns l with every non-positive field replaced by
// DefaultLimits()'s value -- called once by callers before using a
// caller-supplied Limits, so a zero-value Limits{} behaves exactly
// like DefaultLimits() rather than "unbounded."
func (l Limits) normalized() Limits {
	d := DefaultLimits()
	if l.MaxInputsPerEndpoint <= 0 {
		l.MaxInputsPerEndpoint = d.MaxInputsPerEndpoint
	}
	if l.MaxTotalInputs <= 0 {
		l.MaxTotalInputs = d.MaxTotalInputs
	}
	if l.MaxFormFields <= 0 {
		l.MaxFormFields = d.MaxFormFields
	}
	if l.MaxJSONDepth <= 0 {
		l.MaxJSONDepth = d.MaxJSONDepth
	}
	if l.MaxJSONFields <= 0 {
		l.MaxJSONFields = d.MaxJSONFields
	}
	if l.MaxPathSegments <= 0 {
		l.MaxPathSegments = d.MaxPathSegments
	}
	return l
}
