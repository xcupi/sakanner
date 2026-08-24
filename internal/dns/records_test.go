package dns

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"path/filepath"
	"testing"

	"sakanner/internal/testutil"
	"sakanner/pkg/models"
)

func TestNativeRecordEnumerator_LooksUpAllTypes(t *testing.T) {
	resolver := NewFakeResolver()
	resolver.CNAMEs["www.example.com"] = "example.com."
	resolver.MXs["example.com"] = []*net.MX{{Host: "mail.example.com.", Pref: 10}}
	resolver.TXTs["example.com"] = []string{"v=spf1 -all"}
	resolver.NSs["example.com"] = []*net.NS{{Host: "ns1.example.com."}}

	e := NewNativeRecordEnumerator(resolver)
	if e.Name() != "native" {
		t.Errorf("Name() = %q, want native", e.Name())
	}

	records := e.LookupRecords(context.Background(), "example.com")
	byType := map[models.DNSRecordType][]Record{}
	for _, r := range records {
		byType[r.Type] = append(byType[r.Type], r)
	}
	if len(byType[models.DNSRecordTypeCNAME]) != 0 {
		t.Errorf("expected no CNAME (resolver returns the queried name itself), got %+v", byType[models.DNSRecordTypeCNAME])
	}
	if len(byType[models.DNSRecordTypeMX]) != 1 || byType[models.DNSRecordTypeMX][0].Value != "mail.example.com." || byType[models.DNSRecordTypeMX][0].Priority != 10 {
		t.Errorf("MX = %+v", byType[models.DNSRecordTypeMX])
	}
	if len(byType[models.DNSRecordTypeTXT]) != 1 || byType[models.DNSRecordTypeTXT][0].Value != "v=spf1 -all" {
		t.Errorf("TXT = %+v", byType[models.DNSRecordTypeTXT])
	}
	if len(byType[models.DNSRecordTypeNS]) != 1 || byType[models.DNSRecordTypeNS][0].Value != "ns1.example.com." {
		t.Errorf("NS = %+v", byType[models.DNSRecordTypeNS])
	}
}

func TestDnsxRecordEnumerator_ParsesRecordTypes(t *testing.T) {
	binary := testutil.WriteScript(t, "dnsx", `
echo '{"host":"example.com","cname":["alias.example.com."],"mx":["mail.example.com."],"txt":["v=spf1 -all"],"ns":["ns1.example.com."]}'
exit 0
`)
	e := NewDnsxRecordEnumerator(binary)
	if e.Name() != "dnsx" {
		t.Errorf("Name() = %q, want dnsx", e.Name())
	}

	records := e.LookupRecords(context.Background(), "example.com")
	if len(records) != 4 {
		t.Fatalf("got %d records, want 4: %+v", len(records), records)
	}
	byType := map[models.DNSRecordType]string{}
	for _, r := range records {
		byType[r.Type] = r.Value
	}
	if byType[models.DNSRecordTypeCNAME] != "alias.example.com." {
		t.Errorf("CNAME = %q", byType[models.DNSRecordTypeCNAME])
	}
	if byType[models.DNSRecordTypeMX] != "mail.example.com." {
		t.Errorf("MX = %q", byType[models.DNSRecordTypeMX])
	}
	if byType[models.DNSRecordTypeTXT] != "v=spf1 -all" {
		t.Errorf("TXT = %q", byType[models.DNSRecordTypeTXT])
	}
	if byType[models.DNSRecordTypeNS] != "ns1.example.com." {
		t.Errorf("NS = %q", byType[models.DNSRecordTypeNS])
	}
}

func TestDnsxRecordEnumerator_SkipsSelfReferentialCNAME(t *testing.T) {
	binary := testutil.WriteScript(t, "dnsx", `echo '{"host":"example.com","cname":["example.com."]}'`+"\n")
	e := NewDnsxRecordEnumerator(binary)
	records := e.LookupRecords(context.Background(), "example.com")
	if len(records) != 0 {
		t.Errorf("got %+v, want no records for a self-referential CNAME", records)
	}
}

func TestNewRecordEnumerator_BackendSelection(t *testing.T) {
	resolver := NewFakeResolver()
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))

	e, err := NewRecordEnumerator("native", resolver, logger)
	if err != nil {
		t.Fatalf("NewRecordEnumerator(native): %v", err)
	}
	if e.Name() != "native" {
		t.Errorf("backend=native: Name() = %q, want native", e.Name())
	}

	if _, err := NewRecordEnumerator("not-a-real-backend", resolver, logger); err == nil {
		t.Error("NewRecordEnumerator(garbage backend) = nil error, want an error")
	}
}

func TestNewRecordEnumerator_AutoUsesDnsxWhenPresent(t *testing.T) {
	binary := testutil.WriteScript(t, "dnsx", "exit 0\n")
	t.Setenv("PATH", filepath.Dir(binary))

	resolver := NewFakeResolver()
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))

	e, err := NewRecordEnumerator("auto", resolver, logger)
	if err != nil {
		t.Fatalf("NewRecordEnumerator(auto): %v", err)
	}
	if e.Name() != "dnsx" {
		t.Errorf("Name() = %q, want dnsx when it's present on PATH", e.Name())
	}
}

func TestNewRecordEnumerator_AutoFallsBackWhenDnsxAbsent(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	resolver := NewFakeResolver()
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))

	e, err := NewRecordEnumerator("auto", resolver, logger)
	if err != nil {
		t.Fatalf("NewRecordEnumerator(auto): %v", err)
	}
	if e.Name() != "native" {
		t.Errorf("Name() = %q, want native when dnsx is absent", e.Name())
	}
}
