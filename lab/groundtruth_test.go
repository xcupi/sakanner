package lab

import "testing"

func TestLoadGroundTruth_ParsesExpectedShape(t *testing.T) {
	gt, err := LoadGroundTruth()
	if err != nil {
		t.Fatalf("LoadGroundTruth: %v", err)
	}
	if gt.Domain != "scanner.test" {
		t.Errorf("Domain = %q, want scanner.test", gt.Domain)
	}
	if len(gt.Scope.InScope) == 0 {
		t.Error("Scope.InScope is empty")
	}
	if len(gt.Scope.OutOfScope) == 0 {
		t.Error("Scope.OutOfScope is empty")
	}
	for _, host := range gt.Scope.OutOfScope {
		if _, ok := gt.DNS[host]; !ok {
			t.Errorf("out-of-scope host %q has no DNS entry", host)
		}
	}
	for _, host := range gt.Scope.InScope {
		if _, ok := gt.DNS[host]; !ok {
			t.Errorf("in-scope host %q has no DNS entry", host)
		}
	}

	www, ok := gt.DNS["www.scanner.test"]
	if !ok || www.CNAME != "scanner.test" {
		t.Errorf("www.scanner.test DNS entry = %+v, want CNAME scanner.test", www)
	}

	root, ok := gt.Services["scanner.test"]
	if !ok {
		t.Fatal("Services[scanner.test] missing")
	}
	if root.ExpectedTechnology == nil || root.ExpectedTechnology.Name != "nginx" {
		t.Errorf("scanner.test ExpectedTechnology = %+v, want nginx", root.ExpectedTechnology)
	}
	if len(root.LinksToOutOfScope) == 0 {
		t.Error("scanner.test LinksToOutOfScope is empty")
	}

	redirectSvc, ok := gt.Services["redirect.scanner.test"]
	if !ok || len(redirectSvc.Redirects) == 0 {
		t.Errorf("redirect.scanner.test Redirects = %+v, want at least one", redirectSvc.Redirects)
	}
}
