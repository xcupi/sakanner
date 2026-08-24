package reporting

import (
	"context"
	"strings"
	"testing"
	"time"

	"sakanner/internal/storage/sqlite"
	"sakanner/pkg/models"
)

// A scanned target is untrusted: its HTTP response title and TLS
// certificate fields (which this platform deliberately does not verify)
// can contain arbitrary attacker-chosen content. The Markdown report
// must neutralize that content rather than embedding it raw -- both so
// a malicious "|" or newline can't corrupt the table structure, and so
// embedded HTML/script can't execute if the report is later rendered as
// HTML by some downstream viewer.
func TestMarkdown_NeutralizesMaliciousTargetContent(t *testing.T) {
	store, err := sqlite.New(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("sqlite.New: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	now := time.Now().UTC()

	job := models.ScanJob{ID: "sec1", Status: models.ScanJobStatusCompleted, StartedAt: now, CreatedAt: now}
	if err := store.ScanJobs().Create(ctx, job); err != nil {
		t.Fatalf("create job: %v", err)
	}
	asset := models.Asset{ID: "a1", ScanJobID: "sec1", Name: "evil.test", Source: "target", CreatedAt: now}
	if err := store.Assets().Create(ctx, asset); err != nil {
		t.Fatalf("create asset: %v", err)
	}
	host := models.Host{ID: "h1", ScanJobID: "sec1", AssetID: "a1", IPAddress: "203.0.113.9", CreatedAt: now}
	if err := store.Hosts().Create(ctx, host); err != nil {
		t.Fatalf("create host: %v", err)
	}
	svc := models.Service{ID: "s1", ScanJobID: "sec1", HostID: "h1", Port: 443, Protocol: "tcp", CreatedAt: now}
	if err := store.Services().Create(ctx, svc); err != nil {
		t.Fatalf("create service: %v", err)
	}

	maliciousTitle := "<script>alert('xss')</script> | broken | table\nrow"
	maliciousTLSSubject := "CN=evil|<img src=x onerror=alert(1)>"
	httpSvc := models.HTTPService{
		ID: "hs1", ScanJobID: "sec1", ServiceID: "s1", URL: "https://evil.test/",
		Scheme: "https", StatusCode: 200, Title: maliciousTitle, TLSSubject: maliciousTLSSubject, CreatedAt: now,
	}
	if err := store.HTTPServices().Create(ctx, httpSvc); err != nil {
		t.Fatalf("create http service: %v", err)
	}

	r, err := Build(ctx, store, "sec1")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	md := r.Markdown()

	// No raw script/HTML tags should survive into the output.
	if strings.Contains(md, "<script>") || strings.Contains(md, "<img") {
		t.Errorf("Markdown report contains unescaped HTML from a scanned target:\n%s", md)
	}
	// The escaped forms should be present instead.
	if !strings.Contains(md, "&lt;script&gt;") {
		t.Errorf("expected HTML-escaped script tag in report, got:\n%s", md)
	}

	// The malicious embedded pipe character must not have split the
	// table into extra/misaligned columns -- it must appear escaped.
	if !strings.Contains(md, `\|`) {
		t.Errorf("expected embedded pipe character to be escaped as \\|, got:\n%s", md)
	}

	// The embedded newline inside the title must not have produced a
	// stray, unstructured table row.
	if strings.Contains(md, "table\nrow") {
		t.Errorf("expected embedded newline in title to be flattened, but found it verbatim in:\n%s", md)
	}
}

// TestMarkdown_NeutralizesMaliciousPhase2Content extends
// TestMarkdown_NeutralizesMaliciousTargetContent (written for Phase 1's
// fields) to Phase 2's additions: a DNS TXT record's Value (attacker
// controls arbitrary text there), a crawled Endpoint's Path, and a
// fingerprinted Technology's Version (regex-extracted from
// attacker-controlled response content) are all just as untrusted as
// Title/TLSSubject were, and must be neutralized the same way.
func TestMarkdown_NeutralizesMaliciousPhase2Content(t *testing.T) {
	store, err := sqlite.New(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("sqlite.New: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	now := time.Now().UTC()

	job := models.ScanJob{ID: "sec2", Status: models.ScanJobStatusCompleted, StartedAt: now, CreatedAt: now}
	if err := store.ScanJobs().Create(ctx, job); err != nil {
		t.Fatalf("create job: %v", err)
	}
	asset := models.Asset{ID: "a1", ScanJobID: "sec2", Name: "evil.test", Source: "target", CreatedAt: now}
	if err := store.Assets().Create(ctx, asset); err != nil {
		t.Fatalf("create asset: %v", err)
	}

	maliciousTXT := `<script>alert('txt')</script> | broken`
	dnsRecord := models.DNSRecord{ID: "dr1", ScanJobID: "sec2", AssetID: "a1", Type: models.DNSRecordTypeTXT, Value: maliciousTXT, CreatedAt: now}
	if err := store.DNSRecords().Create(ctx, dnsRecord); err != nil {
		t.Fatalf("create dns record: %v", err)
	}

	host := models.Host{ID: "h1", ScanJobID: "sec2", AssetID: "a1", IPAddress: "203.0.113.9", CreatedAt: now}
	if err := store.Hosts().Create(ctx, host); err != nil {
		t.Fatalf("create host: %v", err)
	}
	svc := models.Service{ID: "s1", ScanJobID: "sec2", HostID: "h1", Port: 443, Protocol: "tcp", CreatedAt: now}
	if err := store.Services().Create(ctx, svc); err != nil {
		t.Fatalf("create service: %v", err)
	}
	httpSvc := models.HTTPService{ID: "hs1", ScanJobID: "sec2", ServiceID: "s1", URL: "https://evil.test/", Scheme: "https", StatusCode: 200, CreatedAt: now}
	if err := store.HTTPServices().Create(ctx, httpSvc); err != nil {
		t.Fatalf("create http service: %v", err)
	}

	maliciousPath := `/<img src=x onerror=alert(1)>|evil`
	endpoint := models.Endpoint{ID: "e1", ScanJobID: "sec2", HTTPServiceID: "hs1", Path: maliciousPath, Method: "GET", Source: "crawl", CreatedAt: now}
	if err := store.Endpoints().Create(ctx, endpoint); err != nil {
		t.Fatalf("create endpoint: %v", err)
	}

	maliciousVersion := `1.0"><script>alert('ver')</script>`
	tech := models.Technology{ID: "t1", ScanJobID: "sec2", HTTPServiceID: "hs1", Name: "nginx", Version: maliciousVersion, Category: "web-server", Confidence: 0.9, Source: "fingerprint", CreatedAt: now}
	if err := store.Technologies().Create(ctx, tech); err != nil {
		t.Fatalf("create technology: %v", err)
	}

	r, err := Build(ctx, store, "sec2")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	md := r.Markdown()

	if strings.Contains(md, "<script>") || strings.Contains(md, "<img") {
		t.Errorf("Markdown report contains unescaped HTML from Phase 2 fields (DNS/Endpoint/Technology):\n%s", md)
	}
	if !strings.Contains(md, "&lt;script&gt;alert(&#39;txt&#39;)") && !strings.Contains(md, "&lt;script&gt;alert('txt')") {
		t.Errorf("expected HTML-escaped TXT record content in report, got:\n%s", md)
	}
	if !strings.Contains(md, `\|evil`) {
		t.Errorf("expected embedded pipe in endpoint path to be escaped, got:\n%s", md)
	}
}
