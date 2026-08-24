package chains

import (
	"time"

	"sakanner/pkg/models"
)

// finding is a small builder for tests -- every field defaults to a
// safe, distinct value, overridable via the with* methods, mirroring
// this session's own established test-fixture-builder pattern.
type findingBuilder struct {
	f models.Finding
}

func newFinding(id, scanID, vulnType string) *findingBuilder {
	return &findingBuilder{f: models.Finding{
		ID: id, ScanID: scanID, VulnerabilityType: vulnType,
		Host: "target.scanner.test", Port: 80, Severity: models.SeverityMedium,
		Confidence: 0.8, FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC(),
	}}
}

func (b *findingBuilder) endpoint(host string, port int, path string) *findingBuilder {
	b.f.Host, b.f.Port, b.f.AffectedEndpoint = host, port, path
	return b
}

func (b *findingBuilder) param(name string) *findingBuilder {
	b.f.AffectedParameter = name
	return b
}

func (b *findingBuilder) url(u string) *findingBuilder {
	b.f.URL = u
	return b
}

func (b *findingBuilder) identity(id string) *findingBuilder {
	b.f.IdentityContext = id
	return b
}

func (b *findingBuilder) severity(s models.Severity) *findingBuilder {
	b.f.Severity = s
	return b
}

func (b *findingBuilder) evidence(content string) *findingBuilder {
	b.f.Evidence = append(b.f.Evidence, models.Evidence{Kind: models.EvidenceKindBaseline, Content: content})
	return b
}

func (b *findingBuilder) build() models.Finding { return b.f }
