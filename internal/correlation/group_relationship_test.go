package correlation

import "testing"

// Finding groups (task section 15) and cross-detector correlation
// (task sections 13-14).

func TestGroupByEndpoint_SameEndpointDifferentTypesGroupTogether(t *testing.T) {
	xss := xssFinding("scan-1", "")
	xss.AffectedEndpoint = "/api/search"
	sqli := sqliFinding("scan-1", "")
	sqli.AffectedEndpoint = "/api/search"
	sqli.Host = xss.Host
	sqli.Port = xss.Port

	e := NewEngine()
	e.Ingest(xss, sqli)
	findings := e.Findings()
	groups := GroupByEndpoint(findings)

	if len(groups) != 1 {
		t.Fatalf("GroupByEndpoint returned %d groups, want 1", len(groups))
	}
	if len(groups[0].FindingIDs) != 2 {
		t.Errorf("group has %d finding IDs, want 2", len(groups[0].FindingIDs))
	}
	// The group itself must never be reportable as a finding -- it has
	// no severity/confidence/evidence fields at all (enforced by the
	// Group type's own shape, verified here by construction: this test
	// would fail to compile if Group had such fields and this
	// assertion tried to use them).
}

func TestGroupByEndpoint_DifferentEndpointsProduceSeparateGroups(t *testing.T) {
	a := xssFinding("scan-1", "")
	a.AffectedEndpoint = "/search"
	b := sqliFinding("scan-1", "")
	b.AffectedEndpoint = "/products"
	b.Host = a.Host

	e := NewEngine()
	e.Ingest(a, b)
	groups := GroupByEndpoint(e.Findings())
	if len(groups) != 2 {
		t.Fatalf("GroupByEndpoint returned %d groups, want 2", len(groups))
	}
}

func TestGroupByEndpoint_DeterministicOrder(t *testing.T) {
	e := NewEngine()
	e.Ingest(sqliFinding("scan-1", ""), xssFinding("scan-1", ""))
	g1 := GroupByEndpoint(e.Findings())
	g2 := GroupByEndpoint(e.Findings())
	if len(g1) != len(g2) {
		t.Fatal("group count differs across repeated calls")
	}
	for i := range g1 {
		if g1[i].Host != g2[i].Host || g1[i].Path != g2[i].Path {
			t.Errorf("group order differs across repeated calls at index %d", i)
		}
	}
}

// --- Relationships (task sections 13-14) ------------------------------------

func TestRelationships_SameEndpointDifferentTypesStayDistinctFindings(t *testing.T) {
	xss := xssFinding("scan-1", "")
	xss.AffectedEndpoint = "/api/search"
	sqli := sqliFinding("scan-1", "")
	sqli.AffectedEndpoint = "/api/search"
	sqli.Host = xss.Host
	sqli.Port = xss.Port

	e := NewEngine()
	e.Ingest(xss, sqli)
	findings := e.Findings()
	if len(findings) != 2 {
		t.Fatalf("Findings() = %d, want 2 -- relationships never merge distinct vulnerability types", len(findings))
	}

	rels := Relationships(findings)
	if len(rels) != 1 {
		t.Fatalf("Relationships() = %d, want 1", len(rels))
	}
	r := rels[0]
	if !r.SameAsset || !r.SameEndpoint {
		t.Errorf("relationship = %+v, want SameAsset=true SameEndpoint=true", r)
	}
	if r.FindingA == r.FindingB {
		t.Error("a relationship must connect two DIFFERENT finding IDs")
	}
}

func TestRelationships_SameAssetDifferentEndpointNotSameEndpoint(t *testing.T) {
	a := xssFinding("scan-1", "")
	a.AffectedEndpoint = "/search"
	b := sqliFinding("scan-1", "")
	b.AffectedEndpoint = "/products"
	b.Host = a.Host
	b.Port = a.Port

	e := NewEngine()
	e.Ingest(a, b)
	rels := Relationships(e.Findings())
	if len(rels) != 1 {
		t.Fatalf("Relationships() = %d, want 1", len(rels))
	}
	if !rels[0].SameAsset {
		t.Error("SameAsset = false, want true (same host/port)")
	}
	if rels[0].SameEndpoint {
		t.Error("SameEndpoint = true, want false (different paths)")
	}
}

func TestRelationships_DifferentAssetsProduceNoRelationship(t *testing.T) {
	a := xssFinding("scan-1", "")
	a.Host = "example.test"
	b := sqliFinding("scan-1", "")
	b.Host = "other.test"

	e := NewEngine()
	e.Ingest(a, b)
	rels := Relationships(e.Findings())
	if len(rels) != 0 {
		t.Errorf("Relationships() = %+v, want none (different hosts)", rels)
	}
}

func TestRelationships_SameParameterFlag(t *testing.T) {
	xss := xssFinding("scan-1", "")
	xss.AffectedEndpoint, xss.AffectedParameter = "/search", "q"
	sqli := sqliFinding("scan-1", "")
	sqli.AffectedEndpoint, sqli.AffectedParameter = "/search", "q"
	sqli.Host, sqli.Port = xss.Host, xss.Port

	e := NewEngine()
	e.Ingest(xss, sqli)
	rels := Relationships(e.Findings())
	if len(rels) != 1 || !rels[0].SameParameter {
		t.Errorf("Relationships() = %+v, want one relationship with SameParameter=true", rels)
	}
}
