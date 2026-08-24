// Phase 3.10 integration test: runs the REAL Phase 3.1 detection.Engine
// with all six real detectors against the real vuln.scanner.test lab,
// feeds the persisted findings through the REAL Phase 3.8
// correlation.Engine and Phase 3.9 risk engine, and then through the
// NEW Phase 3.10 evidence engine -- verifying every canonical finding,
// of every vulnerability type this project has, receives evidence,
// a reproducibility classification, a summary, and a why-vulnerable
// explanation (task sections 42-43).
package lab

import (
	"context"
	"strings"
	"testing"

	"sakanner/internal/correlation"
	"sakanner/internal/detection"
	"sakanner/internal/evidence"
	"sakanner/internal/risk"
)

func TestPhase3_10_Evidence_RealCanonicalFindingsProduceEvidence(t *testing.T) {
	l := testVulnLab(t)
	store, job, validator := runReconAgainstVulnLab(t, l)

	x := detection.NewExecutor(validator, l.Resolver, detection.ExecutorConfig{Concurrency: 8})
	e := &detection.Engine{Registry: allDetectorsRegistry(t, l), Store: store, Executor: x, Concurrency: 8, Logger: detectionLogger()}

	summary, err := e.Run(context.Background(), detection.RunOptions{ScanJobID: job.ID})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(summary.Errors) != 0 {
		t.Errorf("detector errors during a clean run against the lab: %+v", summary.Errors)
	}

	rawFindings, err := store.Findings().ListByScanJob(context.Background(), job.ID)
	if err != nil {
		t.Fatalf("ListByScanJob: %v", err)
	}
	if len(rawFindings) == 0 {
		t.Fatal("no findings persisted -- test setup problem")
	}

	ce := correlation.NewEngine()
	ce.Ingest(rawFindings...)
	canonical := ce.Findings()
	t.Logf("Correlation: %d raw findings -> %d canonical findings", len(rawFindings), len(canonical))

	assessments := risk.AssessAll(canonical, nil)
	byFinding := make(map[string]risk.Assessment, len(assessments))
	for _, a := range assessments {
		byFinding[a.FindingID] = a
	}

	limits := evidence.DefaultLimits()
	packages := make([]evidence.FindingPackage, 0, len(canonical))
	for _, cf := range canonical {
		pkg := evidence.BuildPackage(cf, byFinding[cf.FindingID], limits)
		packages = append(packages, pkg)
	}

	if len(packages) != len(canonical) {
		t.Fatalf("len(packages) = %d, want %d (evidence building must neither create nor drop findings)", len(packages), len(canonical))
	}

	types := map[string]int{}
	for _, pkg := range packages {
		fid := pkg.Finding.FindingID

		if len(pkg.Evidence) == 0 {
			t.Errorf("%s: no evidence items produced", fid)
		}
		hasVerification := false
		hasReproduction := false
		for _, it := range pkg.Evidence {
			if it.EvidenceID == "" {
				t.Errorf("%s: an evidence item has an empty EvidenceID", fid)
			}
			if it.IntegrityHash == "" {
				t.Errorf("%s: an evidence item has an empty IntegrityHash", fid)
			}
			if it.Type == evidence.EvidenceTypeVerification {
				hasVerification = true
			}
			if it.Type == evidence.EvidenceTypeReproduction {
				hasReproduction = true
			}
		}
		if !hasVerification {
			t.Errorf("%s: no VERIFICATION evidence produced from a real detector finding", fid)
		}
		if !hasReproduction {
			t.Errorf("%s: no REPRODUCTION evidence produced", fid)
		}

		if pkg.Summary == "" {
			t.Errorf("%s: empty Summary", fid)
		}
		if pkg.WhyVulnerable == "" {
			t.Errorf("%s: empty WhyVulnerable", fid)
		}
		if pkg.Reproduction.Level == "" {
			t.Errorf("%s: empty Reproduction.Level", fid)
		}
		if len(pkg.Limitations) == 0 {
			t.Errorf("%s: empty Limitations -- every real finding today lacks a separately-persisted baseline, so this must never be empty (task section 32)", fid)
		}

		types[pkg.Finding.VulnerabilityType]++
	}

	for _, vulnType := range []string{"reflected_xss", "sql_injection", "ssrf", "idor", "path_traversal", "command_injection"} {
		if types[vulnType] == 0 {
			t.Errorf("no evidence package produced for vulnerability type %q", vulnType)
		}
	}

	// Deterministic rebuilding across repeated runs against the SAME
	// canonical set (task sections 19, 39).
	packagesAgain := make([]evidence.FindingPackage, 0, len(canonical))
	for _, cf := range canonical {
		packagesAgain = append(packagesAgain, evidence.BuildPackage(cf, byFinding[cf.FindingID], limits))
	}
	if len(packagesAgain) != len(packages) {
		t.Fatal("repeated BuildPackage runs produced a different length")
	}
	for i := range packages {
		a, b := packages[i], packagesAgain[i]
		if len(a.Evidence) != len(b.Evidence) {
			t.Fatalf("index %d (%s): evidence count differs across repeated runs", i, a.Finding.FindingID)
		}
		for j := range a.Evidence {
			if a.Evidence[j].EvidenceID != b.Evidence[j].EvidenceID {
				t.Errorf("index %d (%s), evidence %d: EvidenceID differs across repeated runs", i, a.Finding.FindingID, j)
			}
			if a.Evidence[j].IntegrityHash != b.Evidence[j].IntegrityHash {
				t.Errorf("index %d (%s), evidence %d: IntegrityHash differs across repeated runs", i, a.Finding.FindingID, j)
			}
		}
		if a.Summary != b.Summary || a.WhyVulnerable != b.WhyVulnerable {
			t.Errorf("index %d (%s): Summary/WhyVulnerable differ across repeated runs", i, a.Finding.FindingID)
		}
	}

	// Scope/secret sanity check against REAL captured evidence (not
	// synthetic fixtures): the IDOR detector's lab probes carry an
	// X-Test-Auth-User identity header, and nothing in this lab ever
	// legitimately emits an Authorization/Cookie header -- if either
	// showed up unredacted here, it would be a real leak, not a test
	// artifact.
	for _, pkg := range packages {
		for _, it := range pkg.Evidence {
			for k, v := range it.Request.Headers {
				lk := strings.ToLower(k)
				if lk == "authorization" || lk == "cookie" || lk == "set-cookie" {
					if v != "<REDACTED>" {
						t.Errorf("%s: header %q = %q, want the redaction placeholder", pkg.Finding.FindingID, k, v)
					}
				}
			}
		}
	}

	t.Logf("Built %d evidence packages across %d vulnerability types", len(packages), len(types))
}
