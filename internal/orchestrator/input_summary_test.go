package orchestrator

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func manyQueryParamTestServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><body><a href="/search?a=1&b=2&c=3&d=4&e=5">search</a></body></html>`))
	}))
}

// TestResult_InputSummary_PopulatedFromRealCrawl is Phase 3.13's own
// "scan result must expose: inputs discovered, unique endpoints with
// inputs, input discovery warnings" requirement, exercised end to end
// through a real Orchestrator.Run call.
func TestResult_InputSummary_PopulatedFromRealCrawl(t *testing.T) {
	srv := parameterizedTestServer()
	defer srv.Close()

	orch := buildOrchestratorAgainstRealStore(t, srv, true) // crawler enabled
	result, err := orch.Run(context.Background(), Options{Target: "127.0.0.1"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.InputSummary.InputCount == 0 {
		t.Error("InputSummary.InputCount = 0, want at least 1 (the /search?q=hello link)")
	}
	if result.InputSummary.UniqueEndpointsWithInputs == 0 {
		t.Error("InputSummary.UniqueEndpointsWithInputs = 0, want at least 1")
	}
}

// TestResult_InputSummary_Empty_WhenCrawlerDisabled proves the summary
// honestly reflects zero discovery when the crawler (and therefore
// input discovery) never ran, rather than reporting stale or
// fabricated counts.
func TestResult_InputSummary_Empty_WhenCrawlerDisabled(t *testing.T) {
	srv := parameterizedTestServer()
	defer srv.Close()

	orch := buildOrchestratorAgainstRealStore(t, srv, false) // crawler disabled
	result, err := orch.Run(context.Background(), Options{Target: "127.0.0.1"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.InputSummary.InputCount != 0 || result.InputSummary.UniqueEndpointsWithInputs != 0 {
		t.Errorf("InputSummary = %+v, want zero-valued when crawling never ran", result.InputSummary)
	}
}

// TestResult_InputSummary_Warnings_SurfacedFromResourceLimit proves a
// resource-limit warning encountered during input discovery reaches
// the final Result, not just a log line.
func TestResult_InputSummary_Warnings_SurfacedFromResourceLimit(t *testing.T) {
	srv := manyQueryParamTestServer()
	defer srv.Close()

	orch := buildOrchestratorAgainstRealStore(t, srv, true)
	orch.Pipeline.ParameterLimits.MaxInputsPerEndpoint = 2
	result, err := orch.Run(context.Background(), Options{Target: "127.0.0.1"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(result.InputSummary.Warnings) == 0 {
		t.Error("InputSummary.Warnings is empty, want at least one input-limit warning")
	}
}
