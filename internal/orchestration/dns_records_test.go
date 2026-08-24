package orchestration

import (
	"context"
	"net"
	"testing"
	"time"

	"sakanner/internal/dns"
	"sakanner/pkg/models"
)

func TestRun_EnumeratesAndPersistsDNSRecords(t *testing.T) {
	p, cleanup := newTestPipeline(t)
	defer cleanup()

	fake := dns.NewFakeResolver()
	fake.Hosts["mail.example.test"] = []net.IP{net.ParseIP("127.0.0.1")}
	fake.CNAMEs["www.example.test"] = "example.test."
	fake.MXs["www.example.test"] = []*net.MX{{Host: "mail.example.test.", Pref: 10}}
	fake.TXTs["www.example.test"] = []string{"v=spf1 -all"}
	fake.NSs["www.example.test"] = []*net.NS{{Host: "ns1.example.test."}}
	p.Resolver = fake

	ctx := context.Background()
	target := models.Target{ID: "t1", Value: "www.example.test", Type: models.TargetTypeHost, CreatedAt: time.Now().UTC()}
	if err := p.Store.Targets().Create(ctx, target); err != nil {
		t.Fatalf("create target: %v", err)
	}
	rule := models.ScopeRule{ID: "r1", Value: "www.example.test", Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow, CreatedAt: time.Now().UTC()}
	if err := p.Store.ScopeRules().Create(ctx, rule); err != nil {
		t.Fatalf("create scope rule: %v", err)
	}

	// www.example.test itself doesn't resolve to an address in the fake
	// resolver's Hosts map, so LookupHost will fail for it -- but DNS
	// record enumeration should still be attempted and persisted (it
	// doesn't depend on host resolution succeeding). Register it so the
	// scan also produces a host/port-scan result, exercising the normal
	// path end-to-end alongside DNS records.
	fake.Hosts["www.example.test"] = []net.IP{net.ParseIP("127.0.0.1")}

	job, err := p.Run(ctx, RunOptions{TargetIDs: []string{"t1"}, Ports: []int{1}})
	if err != nil {
		t.Fatalf("Run: %v (job error: %s)", err, job.Error)
	}
	if job.Status != models.ScanJobStatusCompleted {
		t.Fatalf("job.Status = %s, want completed (error: %s)", job.Status, job.Error)
	}

	records, err := p.Store.DNSRecords().ListByScanJob(ctx, job.ID)
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}

	byType := map[models.DNSRecordType][]models.DNSRecord{}
	for _, r := range records {
		byType[r.Type] = append(byType[r.Type], r)
	}

	if len(byType[models.DNSRecordTypeCNAME]) != 1 || byType[models.DNSRecordTypeCNAME][0].Value != "example.test." {
		t.Errorf("CNAME records = %+v, want [example.test.]", byType[models.DNSRecordTypeCNAME])
	}
	if len(byType[models.DNSRecordTypeMX]) != 1 || byType[models.DNSRecordTypeMX][0].Value != "mail.example.test." || byType[models.DNSRecordTypeMX][0].Priority != 10 {
		t.Errorf("MX records = %+v, want [mail.example.test. priority 10]", byType[models.DNSRecordTypeMX])
	}
	if len(byType[models.DNSRecordTypeTXT]) != 1 || byType[models.DNSRecordTypeTXT][0].Value != "v=spf1 -all" {
		t.Errorf("TXT records = %+v, want [v=spf1 -all]", byType[models.DNSRecordTypeTXT])
	}
	if len(byType[models.DNSRecordTypeNS]) != 1 || byType[models.DNSRecordTypeNS][0].Value != "ns1.example.test." {
		t.Errorf("NS records = %+v, want [ns1.example.test.]", byType[models.DNSRecordTypeNS])
	}
}

func TestRun_DNSRecordEnumerationDisabled_NoRecordsPersisted(t *testing.T) {
	p, cleanup := newTestPipeline(t)
	defer cleanup()
	p.EnumerateDNSRecords = false

	fake := dns.NewFakeResolver()
	fake.Hosts["www.example.test"] = []net.IP{net.ParseIP("127.0.0.1")}
	fake.MXs["www.example.test"] = []*net.MX{{Host: "mail.example.test.", Pref: 10}}
	p.Resolver = fake

	ctx := context.Background()
	target := models.Target{ID: "t1", Value: "www.example.test", Type: models.TargetTypeHost, CreatedAt: time.Now().UTC()}
	if err := p.Store.Targets().Create(ctx, target); err != nil {
		t.Fatalf("create target: %v", err)
	}
	rule := models.ScopeRule{ID: "r1", Value: "www.example.test", Type: models.ScopeRuleExactHost, Action: models.ScopeActionAllow, CreatedAt: time.Now().UTC()}
	if err := p.Store.ScopeRules().Create(ctx, rule); err != nil {
		t.Fatalf("create scope rule: %v", err)
	}

	job, err := p.Run(ctx, RunOptions{TargetIDs: []string{"t1"}, Ports: []int{1}})
	if err != nil {
		t.Fatalf("Run: %v (job error: %s)", err, job.Error)
	}

	records, err := p.Store.DNSRecords().ListByScanJob(ctx, job.ID)
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	if len(records) != 0 {
		t.Errorf("got %d dns records with EnumerateDNSRecords=false, want 0", len(records))
	}
}
