package reporting

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"sakanner/internal/storage/sqlite"
	"sakanner/pkg/models"
)

func seededStore(t *testing.T) (*Report, string) {
	t.Helper()
	store, err := sqlite.New(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("sqlite.New: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)

	job := models.ScanJob{ID: "job1", Status: models.ScanJobStatusCompleted, TargetIDs: []string{"t1"}, StartedAt: now, FinishedAt: &now, CreatedAt: now}
	mustCreate(t, store.ScanJobs().Create(ctx, job))

	asset := models.Asset{ID: "a1", ScanJobID: "job1", Name: "www.example.com", Source: "target", CreatedAt: now}
	mustCreate(t, store.Assets().Create(ctx, asset))

	host := models.Host{ID: "h1", ScanJobID: "job1", AssetID: "a1", IPAddress: "203.0.113.5", CreatedAt: now}
	mustCreate(t, store.Hosts().Create(ctx, host))

	dnsRecord := models.DNSRecord{ID: "dr1", ScanJobID: "job1", AssetID: "a1", Type: models.DNSRecordTypeMX, Value: "mail.example.com.", Priority: 10, CreatedAt: now}
	mustCreate(t, store.DNSRecords().Create(ctx, dnsRecord))

	svc := models.Service{ID: "s1", ScanJobID: "job1", HostID: "h1", Port: 443, Protocol: "tcp", CreatedAt: now}
	mustCreate(t, store.Services().Create(ctx, svc))

	httpSvc := models.HTTPService{ID: "hs1", ScanJobID: "job1", ServiceID: "s1", URL: "https://www.example.com/", Scheme: "https", StatusCode: 200, Title: "Example", CreatedAt: now}
	mustCreate(t, store.HTTPServices().Create(ctx, httpSvc))

	tech := models.Technology{ID: "tech1", ScanJobID: "job1", HTTPServiceID: "hs1", Name: "nginx", Category: "web-server", Confidence: 0.9, CreatedAt: now}
	mustCreate(t, store.Technologies().Create(ctx, tech))

	r, err := Build(ctx, store, "job1")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return r, "job1"
}

func mustCreate(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("seed create: %v", err)
	}
}

// TestReport_IncludesDiscoveredParameters is Phase 3.13's own addition:
// Build/JSON/Markdown must all surface discovered inputs, not just
// endpoints.
func TestReport_IncludesDiscoveredParameters(t *testing.T) {
	store, err := sqlite.New(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("sqlite.New: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)
	mustCreate(t, store.ScanJobs().Create(ctx, models.ScanJob{ID: "job1", Status: models.ScanJobStatusCompleted, StartedAt: now, CreatedAt: now}))
	mustCreate(t, store.Assets().Create(ctx, models.Asset{ID: "a1", ScanJobID: "job1", Name: "example.com", Source: "target", CreatedAt: now}))
	mustCreate(t, store.Hosts().Create(ctx, models.Host{ID: "h1", ScanJobID: "job1", AssetID: "a1", IPAddress: "203.0.113.5", CreatedAt: now}))
	mustCreate(t, store.Services().Create(ctx, models.Service{ID: "s1", ScanJobID: "job1", HostID: "h1", Port: 80, Protocol: "tcp", CreatedAt: now}))
	mustCreate(t, store.HTTPServices().Create(ctx, models.HTTPService{ID: "hs1", ScanJobID: "job1", ServiceID: "s1", URL: "http://example.com/", Scheme: "http", StatusCode: 200, CreatedAt: now}))
	mustCreate(t, store.Endpoints().Create(ctx, models.Endpoint{ID: "e1", ScanJobID: "job1", HTTPServiceID: "hs1", Path: "/search?q=test", Method: "GET", Source: "crawl", CreatedAt: now}))
	mustCreate(t, store.Parameters().Create(ctx, models.Parameter{
		ID: "p1", ScanJobID: "job1", EndpointID: "e1", Name: "q", Location: "query", Classification: "PARAMETER",
		Method: "GET", Value: "test", Source: "url_query", CreatedAt: now,
	}))

	r, err := Build(ctx, store, "job1")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(r.Parameters) != 1 || r.Parameters[0].Name != "q" {
		t.Fatalf("Report.Parameters = %+v, want one parameter named q", r.Parameters)
	}

	md := r.Markdown()
	for _, want := range []string{"## Inputs", "/search?q=test", " q ", "query", "PARAMETER"} {
		if !strings.Contains(md, want) {
			t.Errorf("Markdown missing %q:\n%s", want, md)
		}
	}

	b, err := r.JSON()
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	var decoded Report
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(decoded.Parameters) != 1 || decoded.Parameters[0].Name != "q" {
		t.Errorf("decoded Parameters = %+v", decoded.Parameters)
	}
}

func TestBuild_AssemblesAllSections(t *testing.T) {
	r, jobID := seededStore(t)
	if r.Job.ID != jobID {
		t.Errorf("Job.ID = %q, want %q", r.Job.ID, jobID)
	}
	if len(r.Assets) != 1 || len(r.Hosts) != 1 || len(r.DNSRecords) != 1 || len(r.Services) != 1 || len(r.HTTPServices) != 1 || len(r.Technologies) != 1 {
		t.Fatalf("Report = %+v, expected one of each", r)
	}
	if len(r.Findings) != 0 {
		t.Errorf("Findings = %+v, want empty (Phase 1)", r.Findings)
	}
}

func TestJSON_RoundTrips(t *testing.T) {
	r, _ := seededStore(t)
	b, err := r.JSON()
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}

	var decoded Report
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.Job.ID != r.Job.ID {
		t.Errorf("decoded Job.ID = %q, want %q", decoded.Job.ID, r.Job.ID)
	}
	if len(decoded.Technologies) != 1 || decoded.Technologies[0].Name != "nginx" {
		t.Errorf("decoded Technologies = %+v", decoded.Technologies)
	}
}

func TestMarkdown_ContainsExpectedContent(t *testing.T) {
	r, jobID := seededStore(t)
	md := r.Markdown()

	for _, want := range []string{
		jobID,
		"completed",
		"www.example.com",
		"203.0.113.5",
		"443",
		"https://www.example.com/",
		"nginx",
		"mail.example.com.",
		"MX",
		"No findings",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("Markdown output missing %q\n---\n%s", want, md)
		}
	}
}

func TestMarkdown_EmptyReportOmitsSections(t *testing.T) {
	store, err := sqlite.New(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("sqlite.New: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	now := time.Now().UTC()
	job := models.ScanJob{ID: "empty1", Status: models.ScanJobStatusCompleted, StartedAt: now, CreatedAt: now}
	if err := store.ScanJobs().Create(ctx, job); err != nil {
		t.Fatalf("create job: %v", err)
	}

	r, err := Build(ctx, store, "empty1")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	md := r.Markdown()

	if strings.Contains(md, "## Assets") {
		t.Error("expected Assets section to be omitted when there are no assets")
	}
	if strings.Contains(md, "## DNS Records") {
		t.Error("expected DNS Records section to be omitted when there are no dns records")
	}
	if !strings.Contains(md, "No findings") {
		t.Error("expected findings section to explain Phase 1 has no detection")
	}

	// Every list field must serialize as [] when empty, never null --
	// consumers of the JSON report should be able to rely on a
	// consistent array type rather than special-casing an absent list.
	b, err := r.JSON()
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"assets", "hosts", "dns_records", "services", "http_services", "technologies", "endpoints", "findings"} {
		raw, ok := decoded[key]
		if !ok {
			t.Errorf("JSON report missing key %q", key)
			continue
		}
		if string(raw) == "null" {
			t.Errorf("JSON report field %q serialized as null, want [] for an empty list", key)
		}
	}
}
