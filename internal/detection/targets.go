package detection

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strconv"

	"sakanner/internal/parameters"
	"sakanner/internal/storage"
	"sakanner/pkg/models"
)

// BuildTargets loads a completed scan job's Phase 2 recon output
// (Services, Hosts, HTTPServices, Endpoints, Technologies) plus Phase
// 3.13's normalized input model (Parameters) and turns it into the
// Targets a detector can be run against -- this IS the "target
// selection" the engine performs before running any detector, so the
// engine never blindly runs every detector against every asset (each
// detector's own Metadata/Eligible then further narrows this set; see
// Engine.Run).
//
// One TargetKindHTTPService Target is built per successfully-probed
// HTTPService (its base URL, "/"). One TargetKindEndpoint Target is
// built per discovered Endpoint, plus one additional Target per
// query-location Parameter internal/parameters already discovered and
// persisted for that Endpoint (internal/orchestration.Pipeline runs
// input discovery as part of crawling -- see
// docs/phase-3-13-parameter-discovery.md), plus (Phase 3.19) one
// additional Target per JSON-location, REQUEST_INPUT-provenance
// Parameter, with ParameterLocation set to "body" -- reconciling
// internal/parameters.Location's "json" string with this type's own,
// previously-unused "body" vocabulary value. A JSON parameter whose
// Provenance is "RESPONSE_FIELD" (Phase 3.18 -- a field only ever
// OBSERVED in a response, never confirmed accepted as an input) is
// deliberately EXCLUDED here: it must never automatically become
// something a detector mutates and sends back as if it were a
// confirmed input (see docs/phase-3-19-active-detection.md section 2
// and task section 18's own "response field != request parameter").
// Phase 3.21 adds one additional Target per form-location (POST/
// non-GET form-urlencoded body), REQUEST_INPUT-provenance Parameter,
// with ParameterLocation set to "form" -- and, for a form-SOURCED
// endpoint specifically (query or form location alike), only when the
// form's own action resolved to the SAME origin as this HTTPService
// (see docs/phase-3-21-form-mutation.md section 1 Finding 3 for why: a
// cross-origin form action's host is otherwise indistinguishable from
// this HTTPService's own, which would silently mutate the wrong
// endpoint rather than the form's real one). A parameter whose name
// looks like a CSRF/security token (parameters.IsLikelySecurityToken)
// is never independently promoted to its own Target, but is still
// carried in FormFields so every OTHER field's mutation preserves it.
//
// The IP on every returned Target is the exact IP Phase 2 already
// resolved and scope-validated for that host -- never re-resolved here.
func BuildTargets(ctx context.Context, store storage.Store, scanJobID string) ([]Target, error) {
	services, err := store.Services().ListByScanJob(ctx, scanJobID)
	if err != nil {
		return nil, fmt.Errorf("detection: listing services: %w", err)
	}
	hosts, err := store.Hosts().ListByScanJob(ctx, scanJobID)
	if err != nil {
		return nil, fmt.Errorf("detection: listing hosts: %w", err)
	}
	httpServices, err := store.HTTPServices().ListByScanJob(ctx, scanJobID)
	if err != nil {
		return nil, fmt.Errorf("detection: listing http services: %w", err)
	}
	endpointsList, err := store.Endpoints().ListByScanJob(ctx, scanJobID)
	if err != nil {
		return nil, fmt.Errorf("detection: listing endpoints: %w", err)
	}
	technologies, err := store.Technologies().ListByScanJob(ctx, scanJobID)
	if err != nil {
		return nil, fmt.Errorf("detection: listing technologies: %w", err)
	}
	parametersList, err := store.Parameters().ListByScanJob(ctx, scanJobID)
	if err != nil {
		return nil, fmt.Errorf("detection: listing parameters: %w", err)
	}

	ipByHostID := make(map[string]net.IP, len(hosts))
	for _, h := range hosts {
		ipByHostID[h.ID] = net.ParseIP(h.IPAddress)
	}
	hostIDByServiceID := make(map[string]string, len(services))
	for _, s := range services {
		hostIDByServiceID[s.ID] = s.HostID
	}
	techByHTTPServiceID := make(map[string][]models.Technology, len(technologies))
	for _, t := range technologies {
		techByHTTPServiceID[t.HTTPServiceID] = append(techByHTTPServiceID[t.HTTPServiceID], t)
	}
	endpointsByHTTPServiceID := make(map[string][]models.Endpoint, len(endpointsList))
	for _, e := range endpointsList {
		endpointsByHTTPServiceID[e.HTTPServiceID] = append(endpointsByHTTPServiceID[e.HTTPServiceID], e)
	}
	// Only query-location parameters are relevant to target selection
	// (see doc comment above) -- filtered here, once, rather than
	// inside endpointTargets' own per-endpoint loop.
	queryParamsByEndpointID := make(map[string][]models.Parameter, len(parametersList))
	// Phase 3.19: JSON-body parameters ALSO become Targets, but ONLY
	// when Provenance == "REQUEST_INPUT" -- a field merely OBSERVED in
	// a response (Provenance == "RESPONSE_FIELD", Phase 3.18) must
	// never automatically become something a detector mutates and
	// sends back as if it were a confirmed, accepted input (task
	// section 18's own explicit "response field != request parameter"
	// distinction, still enforced here at the one place JSON
	// parameters are allowed to become active-detection Targets at
	// all). See docs/phase-3-19-active-detection.md section 2.
	jsonParamsByEndpointID := make(map[string][]models.Parameter, len(parametersList))
	// Phase 3.21: form-location (POST/non-GET form-urlencoded body)
	// parameters -- see docs/phase-3-21-form-mutation.md section 5.
	// Provenance-filtered identically to the JSON case above (every
	// form candidate internal/parameters produces is already
	// REQUEST_INPUT, but the filter is kept explicit here rather than
	// assumed, matching the JSON branch's own established discipline).
	formParamsByEndpointID := make(map[string][]models.Parameter, len(parametersList))
	// Phase 3.23: path-location (URL path segment) parameters -- see
	// docs/phase-3-23-path-parameters.md section 5. Provenance-filtered
	// identically to the JSON/form cases above (RESPONSE_FIELD
	// provenance never occurs in practice for a path candidate --
	// internal/parameters.InferPathInputs always sets REQUEST_INPUT --
	// but the filter is kept explicit, matching the established
	// discipline of never assuming a filter is unreachable).
	pathParamsByEndpointID := make(map[string][]models.Parameter, len(parametersList))
	for _, prm := range parametersList {
		switch {
		case prm.Location == "query":
			queryParamsByEndpointID[prm.EndpointID] = append(queryParamsByEndpointID[prm.EndpointID], prm)
		case prm.Location == "json" && prm.Provenance == "REQUEST_INPUT":
			jsonParamsByEndpointID[prm.EndpointID] = append(jsonParamsByEndpointID[prm.EndpointID], prm)
		case prm.Location == "form" && prm.Provenance == "REQUEST_INPUT":
			formParamsByEndpointID[prm.EndpointID] = append(formParamsByEndpointID[prm.EndpointID], prm)
		case prm.Location == "path" && prm.Provenance == "REQUEST_INPUT":
			pathParamsByEndpointID[prm.EndpointID] = append(pathParamsByEndpointID[prm.EndpointID], prm)
		}
	}

	var targets []Target
	for _, svc := range httpServices {
		u, err := url.Parse(svc.URL)
		if err != nil {
			continue // an unparseable stored URL is a data problem for another stage to catch, not fatal to target selection
		}
		ip := ipByHostID[hostIDByServiceID[svc.ServiceID]]
		if ip == nil {
			continue // no resolved IP on record for this service's host -- cannot be dialed safely
		}
		port := portOf(u, svc.Scheme)
		techs := techByHTTPServiceID[svc.ID]

		targets = append(targets, Target{
			Kind:          TargetKindHTTPService,
			ScanJobID:     scanJobID,
			HTTPServiceID: svc.ID,
			Host:          u.Hostname(),
			IP:            ip,
			Port:          port,
			Scheme:        u.Scheme,
			URL:           svc.URL,
			Path:          orSlash(u.Path),
			Technologies:  techs,
		})

		for _, e := range endpointsByHTTPServiceID[svc.ID] {
			targets = append(targets, endpointTargets(scanJobID, svc.ID, e, u.Scheme, u.Hostname(), ip, port, techs, queryParamsByEndpointID[e.ID], jsonParamsByEndpointID[e.ID], formParamsByEndpointID[e.ID], pathParamsByEndpointID[e.ID])...)
		}
	}
	return targets, nil
}

// endpointTargets builds one plain Target for e itself, plus one
// additional Target per already-discovered, already-persisted
// query-location Parameter belonging to e (queryParams -- see
// BuildTargets' doc comment). Deterministically ordered: queryParams
// arrives pre-sorted by Parameters().ListByScanJob's own
// "ORDER BY created_at", which itself reflects internal/parameters.Normalize's
// stable output order.
func endpointTargets(scanJobID, httpServiceID string, e models.Endpoint, scheme, host string, ip net.IP, port int, techs []models.Technology, queryParams, jsonParams, formParams, pathParams []models.Parameter) []Target {
	epPath, query := splitPathQuery(e.Path)

	// Phase 3.22 (docs/phase-3-22-active-detection-coverage.md section
	// 7): a form-sourced endpoint whose action resolved to a DIFFERENT
	// origin than this HTTPService's own is targeted at ITS OWN real
	// destination -- Host/Scheme/Port come from the parsed
	// ActionOrigin, and IP is left nil so mutation.Executor resolves
	// AND scope-validates it FRESH at execution time, via the exact
	// same safedial.Dialer.ResolveInScope path every other component
	// already uses (mutation.Executor.resolveAndValidate, unchanged --
	// this is not a second, independent scope-resolution path). A
	// separately in-scope destination succeeds; an out-of-scope one is
	// refused there, safely, as OutcomeScopeRejected -- never a
	// fabricated finding. A malformed ActionOrigin (should not occur;
	// endpoints.originOf always produces a well-formed value or "")
	// leaves routable=false, falling back to Phase 3.21's original
	// skip behavior for this endpoint's query/form parameter Targets
	// specifically, rather than guessing a host.
	targetScheme, targetHost, targetPort, targetIP := scheme, host, port, ip
	routable := true
	isFormSourced := e.Source == "form"
	if isFormSourced && e.ActionOrigin != "" {
		currentOrigin := scheme + "://" + host + ":" + strconv.Itoa(port)
		if e.ActionOrigin != currentOrigin {
			if u, err := url.Parse(e.ActionOrigin); err == nil && u.Hostname() != "" {
				if p, perr := strconv.Atoi(u.Port()); perr == nil {
					targetScheme, targetHost, targetPort, targetIP = u.Scheme, u.Hostname(), p, nil
				} else {
					routable = false
				}
			} else {
				routable = false
			}
		}
	}

	base := &url.URL{Scheme: targetScheme, Host: net.JoinHostPort(targetHost, strconv.Itoa(targetPort)), Path: epPath, RawQuery: query}

	root := Target{
		Kind:            TargetKindEndpoint,
		ScanJobID:       scanJobID,
		HTTPServiceID:   httpServiceID,
		EndpointID:      e.ID,
		Host:            targetHost,
		IP:              targetIP,
		Port:            targetPort,
		Scheme:          targetScheme,
		URL:             base.String(),
		Path:            epPath,
		Method:          e.Method,
		Technologies:    techs,
		IdentityContext: e.IdentityContext,
	}
	targets := []Target{root}

	if !isFormSourced || routable {
		var queryFormFields map[string]string
		if isFormSourced {
			queryFormFields = fieldValues(queryParams)
		}
		for _, prm := range queryParams {
			if isFormSourced && parameters.IsLikelySecurityToken(prm.Name) {
				continue // preserved via queryFormFields, never independently targeted -- section 7
			}
			t := root
			t.Parameter = prm.Name
			t.ParameterLocation = "query"
			t.FormFields = queryFormFields
			targets = append(targets, t)
		}
	}

	// Phase 3.19: ParameterLocation "body" reconciles
	// internal/parameters.Location's "json" string with
	// detection.Target.ParameterLocation's own, pre-existing
	// documented vocabulary ("query"/"body"/"header"/"cookie") -- see
	// docs/phase-3-19-active-detection.md section 2 finding 5.
	for _, prm := range jsonParams {
		t := root
		t.Parameter = prm.Name
		t.ParameterLocation = "body"
		targets = append(targets, t)
	}

	// Phase 3.21: ParameterLocation "form" -- a POST/non-GET
	// form-urlencoded body parameter, distinct from JSON's "body".
	// Built when routable (same-origin, or a successfully-parsed
	// cross-origin ActionOrigin -- see above); every sibling field's
	// value (including this one's own, harmlessly -- Mutate overwrites
	// it regardless) is carried via FormFields so the baseline request
	// already looks like a complete submission. See
	// docs/phase-3-21-form-mutation.md sections 3 and 5.
	if routable && len(formParams) > 0 {
		formFields := fieldValues(formParams)
		for _, prm := range formParams {
			if parameters.IsLikelySecurityToken(prm.Name) {
				continue
			}
			t := root
			t.Parameter = prm.Name
			t.ParameterLocation = "form"
			t.FormFields = formFields
			targets = append(targets, t)
		}
	}

	// Phase 3.23: ParameterLocation "path" -- a URL path segment. No
	// same-origin gate is needed here (unlike form): mutation.applyPath
	// only ever rewrites req.Path, never Host/Scheme/Port, so a path
	// Target is host-safe by construction -- see
	// docs/phase-3-23-path-parameters.md section 3.1. Each Parameter
	// carries its own PathSegmentIndex, computed once at discovery time
	// by internal/parameters.InferPathInputs.
	for _, prm := range pathParams {
		t := root
		t.Parameter = prm.Name
		t.ParameterLocation = "path"
		t.PathSegmentIndex = prm.PathSegmentIndex
		targets = append(targets, t)
	}
	return targets
}

// fieldValues collapses params into a name->value map for
// Target.FormFields -- a plain map is safe for determinism here
// because every consumer (url.Values.Encode(), inside
// NewMutationRequest) sorts keys internally rather than depending on
// map iteration order (task section 12).
func fieldValues(params []models.Parameter) map[string]string {
	if len(params) == 0 {
		return nil
	}
	out := make(map[string]string, len(params))
	for _, p := range params {
		out[p.Name] = p.Value
	}
	return out
}

func splitPathQuery(pathAndQuery string) (path, query string) {
	u, err := url.Parse(pathAndQuery)
	if err != nil {
		return pathAndQuery, ""
	}
	return u.Path, u.RawQuery
}

func portOf(u *url.URL, scheme string) int {
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			return n
		}
	}
	if scheme == "https" {
		return 443
	}
	return 80
}

func orSlash(path string) string {
	if path == "" {
		return "/"
	}
	return path
}
