package parameters

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	"sakanner/internal/crawler"
	"sakanner/internal/endpoints"
	"sakanner/internal/evidence"
)

// Candidate is one discovered input BEFORE it is correlated to a
// persisted models.Endpoint row -- EndpointPath/EndpointMethod/
// EndpointSource together identify exactly the same endpoint identity
// internal/endpoints.Normalize computes from the same crawler.Page
// data (same PathOf call, same method, same Source constant), so a
// caller that already ran endpoints.Normalize over the identical pages
// can match each Candidate to the Endpoint row it belongs to by that
// triple. This mirrors models.Endpoint itself before ID/ScanJobID/
// HTTPServiceID/CreatedAt are filled in by the caller at persistence
// time.
type Candidate struct {
	EndpointPath   string
	EndpointMethod string
	EndpointSource string

	Name        string
	Location    Location
	Value       string
	Source      string
	ContentType string
	// Provenance is Phase 3.18's addition -- see Provenance's own doc
	// comment. Every query/form candidate this file produces is
	// explicitly ProvenanceRequestInput (set at each call site below,
	// never left to a zero-value default, so a future new candidate
	// source can never accidentally inherit an unintended meaning).
	Provenance Provenance
	// FieldType is Phase 3.21's own addition: the raw HTML input type
	// attribute (crawler.FormField.Type -- "hidden", "text", "select",
	// "textarea", "checkbox", ...) for a form-discovered candidate, ""
	// for every other candidate (query, JSON). Lets a caller derive
	// models.Parameter.Hidden without inventing a new Location or
	// Classification value -- see docs/phase-3-21-form-mutation.md
	// section 2.
	FieldType string
	// PathSegmentIndex is Phase 3.23's own addition: the 0-based path
	// segment InferPathInputs identified as variable, meaningful only
	// when Location == LocationPath (-1 for every other candidate --
	// never 0, which is a genuine, valid segment index). Needed so
	// mutation.NewPathMutation (which requires an explicit segment
	// index) knows which segment to target -- see
	// docs/phase-3-23-path-parameters.md section 1.3.
	PathSegmentIndex int
}

// Result is Normalize's output -- candidates plus any resource-limit
// warnings encountered while producing them. Warnings never cause
// Normalize to fail or panic -- task's "do not silently discard
// inputs... report a structured warning."
type Result struct {
	Candidates []Candidate
	Warnings   []string
	// DuplicateCount is how many discovered inputs collapsed into an
	// already-seen Candidate (same endpoint identity, location, and
	// name) -- task's OBSERVABILITY "duplicate_count" field.
	DuplicateCount int
}

type candidateKey struct {
	endpointPath   string
	endpointMethod string
	endpointSource string
	location       Location
	name           string
}

// Normalize discovers query-parameter and HTML-form-field candidates
// from already-crawled pages -- task's input sources 1-9 (query
// parameters, form fields across GET/POST, text/hidden/select/
// textarea/checkbox/radio). JSON body discovery (ParseJSONBody) and
// path-segment inference (InferPathInputs) are separate, independently
// callable functions -- see doc.go for why they are not folded into
// this same pass (no JSON body is available at this point in the
// pipeline; path inference needs the FULL set of an endpoint's sibling
// paths across the whole scan, not just one page's).
//
// Deterministic: iterates pages/links/forms/fields in the exact order
// they appear in the input slices (which is itself the crawler's own
// deterministic breadth-first order), and produces a stably-sorted
// output independent of map iteration -- the same input always
// produces the same Result.
func Normalize(pages []crawler.Page, limits Limits) Result {
	limits = limits.normalized()
	agg := newCandidateAggregator()

	var warnings []string
	for _, page := range pages {
		addQueryCandidates(agg.add, page.URL, endpoints.SourceCrawl)
		for _, link := range page.Links {
			addQueryCandidates(agg.add, link, endpoints.SourceLink)
		}
		for _, form := range page.Forms {
			addFormCandidates(agg.add, form, limits.MaxFormFields, &warnings)
		}
	}
	agg.warnings = append(agg.warnings, warnings...)
	return agg.finalize(limits)
}

// NormalizeJSONResponses discovers JSON fields from already-crawled
// pages' captured RESPONSE bodies -- Phase 3.18's live wiring of
// ParseJSONBody (see docs/phase-3-18-api-json-discovery.md section 3
// for why this is a RESPONSE body, never a request body: the crawler
// never issues anything but GET, so there is no live JSON request body
// anywhere in this codebase to capture). Every resulting Candidate has
// Provenance == ProvenanceResponseField -- an observed response field
// is never automatically a confirmed request input (task section 18).
//
// Kept as a separate, independently-callable function from Normalize,
// exactly matching this package's own established precedent (JSON
// body discovery has always been "separate, independently callable" --
// see Normalize's own doc comment, unchanged since Phase 3.13) --
// callers that want both call both, exactly as
// internal/orchestration.crawlAndDiscoverEndpoints does.
//
// A page contributes candidates only when its ContentType indicates
// JSON and it has a non-empty ResponseBody -- crawler.Page only ever
// populates ResponseBody for such pages in the first place (see
// internal/crawler's own doc comment), so this check is a defensive,
// always-true-in-practice guard, not a filter that silently drops
// eligible pages.
func NormalizeJSONResponses(pages []crawler.Page, limits Limits) Result {
	limits = limits.normalized()
	agg := newCandidateAggregator()

	for _, page := range pages {
		if !isJSONContentType(page.ContentType) || len(page.ResponseBody) == 0 {
			continue
		}
		res := ParseJSONBody(page.ResponseBody, limits, ProvenanceResponseField)
		agg.warnings = append(agg.warnings, res.Warnings...)
		endpointPath := endpoints.PathOf(page.URL)
		for _, c := range res.Candidates {
			c.EndpointPath = endpointPath
			c.EndpointMethod = "GET"
			c.EndpointSource = endpoints.SourceCrawl
			c.Source = SourceJSONResponse
			agg.add(c)
		}
	}
	return agg.finalize(limits)
}

// isJSONContentType reports whether ct (an HTTP Content-Type header
// value) indicates a JSON body -- the same substring-match idiom
// internal/crawler already uses to detect HTML, applied to JSON.
func isJSONContentType(ct string) bool {
	return ct != "" && strings.Contains(strings.ToLower(ct), "json")
}

// candidateAggregator accumulates Candidates with one shared dedup/
// group/cap/sort discipline, reused by both Normalize and
// NormalizeJSONResponses so neither re-derives "how many can we keep,
// deterministically" independently.
type candidateAggregator struct {
	seen           map[candidateKey]bool
	byEndpoint     map[string][]Candidate
	order          []string // first-seen order of endpoint keys, for deterministic warning order
	warnings       []string
	duplicateCount int
}

func newCandidateAggregator() *candidateAggregator {
	return &candidateAggregator{seen: map[candidateKey]bool{}, byEndpoint: map[string][]Candidate{}}
}

func (a *candidateAggregator) add(c Candidate) {
	if c.Name == "" {
		return // an unnamed input carries no identity to discover -- see crawler.extractFormFields' identical rule
	}
	key := candidateKey{c.EndpointPath, c.EndpointMethod, c.EndpointSource, c.Location, c.Name}
	if a.seen[key] {
		a.duplicateCount++
		return
	}
	a.seen[key] = true

	ek := endpointGroupKey(c.EndpointPath, c.EndpointMethod, c.EndpointSource)
	if _, ok := a.byEndpoint[ek]; !ok {
		a.order = append(a.order, ek)
	}
	a.byEndpoint[ek] = append(a.byEndpoint[ek], c)
}

func (a *candidateAggregator) finalize(limits Limits) Result {
	total := 0
	var out []Candidate
	for _, ek := range a.order {
		group := a.byEndpoint[ek]
		sort.Slice(group, func(i, j int) bool {
			if group[i].Location != group[j].Location {
				return group[i].Location < group[j].Location
			}
			return group[i].Name < group[j].Name
		})
		if len(group) > limits.MaxInputsPerEndpoint {
			a.warnings = append(a.warnings, fmt.Sprintf("input limit reached for endpoint %s: %d discovered, kept %d", ek, len(group), limits.MaxInputsPerEndpoint))
			group = group[:limits.MaxInputsPerEndpoint]
		}
		for _, c := range group {
			if total >= limits.MaxTotalInputs {
				a.warnings = append(a.warnings, fmt.Sprintf("total input limit reached (%d): remaining inputs discarded", limits.MaxTotalInputs))
				return finalizeResult(out, a.warnings, a.duplicateCount)
			}
			out = append(out, c)
			total++
		}
	}
	return finalizeResult(out, a.warnings, a.duplicateCount)
}

func finalizeResult(candidates []Candidate, warnings []string, duplicateCount int) Result {
	sort.Slice(candidates, func(i, j int) bool {
		a, b := candidates[i], candidates[j]
		if a.EndpointPath != b.EndpointPath {
			return a.EndpointPath < b.EndpointPath
		}
		if a.EndpointMethod != b.EndpointMethod {
			return a.EndpointMethod < b.EndpointMethod
		}
		if a.EndpointSource != b.EndpointSource {
			return a.EndpointSource < b.EndpointSource
		}
		if a.Location != b.Location {
			return a.Location < b.Location
		}
		return a.Name < b.Name
	})
	return Result{Candidates: candidates, Warnings: warnings, DuplicateCount: duplicateCount}
}

func endpointGroupKey(path, method, source string) string {
	return path + "\x00" + method + "\x00" + source
}

// addQueryCandidates parses rawURL's own query string, adding one
// query-location Candidate per parameter name -- task's input source
// 1. The endpoint identity is computed exactly as internal/endpoints
// would for the SAME URL (GET, the given source), so these candidates
// correlate to the Endpoint row that URL produces.
func addQueryCandidates(add func(Candidate), rawURL, source string) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return
	}
	if u.RawQuery == "" {
		return
	}
	values, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return // a malformed query string yields no parameters, not an error -- task's "do not crash on malformed input"
	}
	endpointPath := endpoints.PathOf(rawURL)
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names) // deterministic: url.Values is a map, iteration order is not stable
	for _, name := range names {
		vs := values[name]
		value := ""
		if len(vs) > 0 {
			value = vs[0] // task's "duplicated parameters/repeated form fields": the first observed value is kept, the name's PRESENCE is what matters for candidate identity
		}
		add(Candidate{
			EndpointPath: endpointPath, EndpointMethod: "GET", EndpointSource: source,
			Name: name, Location: LocationQuery, Value: redactIfSensitive(name, value), Source: SourceURLQuery,
			Provenance: ProvenanceRequestInput,
		})
	}
}

// addFormCandidates adds one Candidate per named field crawler already
// parsed out of an HTML form -- task's input sources 2-9. A GET form's
// fields are modeled with Location == LocationQuery (submitting a GET
// form transmits its fields as the URL's query string -- the same
// wire format the 6 existing detectors already expect, see
// docs/phase-3-13-parameter-discovery.md "Why GET-form fields use the
// query location"); a POST (or any other method) form's fields use
// LocationForm.
func addFormCandidates(add func(Candidate), form crawler.FormRef, maxFields int, warnings *[]string) {
	endpointPath := endpoints.PathOf(form.Action)
	location := LocationForm
	contentType := "application/x-www-form-urlencoded"
	if form.Method == "GET" {
		location = LocationQuery
		contentType = ""
	}

	fields := form.Fields
	if len(fields) > maxFields {
		*warnings = append(*warnings, fmt.Sprintf("form field limit reached for endpoint %s %s: %d fields discovered, kept %d", form.Method, endpointPath, len(fields), maxFields))
		fields = fields[:maxFields]
	}

	for _, f := range fields {
		if f.Name == "" {
			continue
		}
		add(Candidate{
			EndpointPath: endpointPath, EndpointMethod: form.Method, EndpointSource: endpoints.SourceForm,
			Name: f.Name, Location: location, Value: redactIfSensitive(f.Name, f.Value),
			Source: SourceHTMLForm, ContentType: contentType, FieldType: f.Type,
			Provenance: ProvenanceRequestInput,
		})
	}
}

// redactIfSensitive replaces value with evidence.RedactedPlaceholder
// when name matches the shared sensitive-field-name blocklist --
// task's "SECRET REDACTION" section: a discovered input's VALUE is
// never persisted verbatim when its NAME looks like a credential, even
// though only an already-observed, non-payload value was ever going to
// be stored. Reuses internal/evidence's own blocklist (see that
// package's redact_export.go) rather than a second, independently
// maintained one.
func redactIfSensitive(name, value string) string {
	if value == "" {
		return value
	}
	if evidence.IsSensitiveFieldName(name) {
		return evidence.RedactedPlaceholder
	}
	return value
}
