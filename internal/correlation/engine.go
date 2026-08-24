package correlation

import (
	"sort"
	"strconv"
	"sync"
	"time"

	"sakanner/pkg/models"
)

// maxEvidenceGroupsPerFinding bounds how many DISTINCT evidence
// signatures (see consolidate.go's evidenceSignature) a single
// identity retains -- task section 9's "prevent unbounded evidence
// growth" and section 31's resource-exhaustion requirement. This is a
// defensive bound against adversarial/malformed input generating many
// distinct-but-tiny evidence sets for the same identity; every
// detector in this project realistically contributes at most a
// handful of distinct signatures per identity (one per confidence
// tier it can produce).
const maxEvidenceGroupsPerFinding = 50

// maxEvidenceItemsPerFinding bounds the final Evidence[] list length
// on an output CanonicalFinding -- task section 9's "number of
// evidence items" limit.
const maxEvidenceItemsPerFinding = 20

// maxEvidenceContentBytes truncates any single evidence item's Content
// -- task section 9's "evidence size" / "response snippets" limit and
// section 30's "extremely long evidence" security requirement. Every
// detector already bounds its own evidence far below this (see each
// Phase 3.x detector's maxBodySample/evidenceFragmentRadius); this is
// a second, independent ceiling enforced here regardless of what a
// detector (or adversarial/malformed input) supplies.
const maxEvidenceContentBytes = 4096

// group is one distinct evidence signature's consolidated state within
// a bucket. confidence/severity are the MIN across every raw finding
// that shared this exact signature (task's "repeated identical
// evidence must not artificially increase confidence/severity") --
// see consolidate.go and docs/phase-3-8-finding-correlation.md
// "Confidence consolidation" for the full two-level rule this
// implements.
type group struct {
	signature   string
	confidence  float64
	severity    models.Severity
	evidence    []EvidenceItem
	title       string
	description string
	remediation string
	detectorID  string
}

// strongerThan defines a deterministic total order over groups, used
// both to pick which group's title/description/remediation represents
// the canonical finding and to decide which group to evict when
// maxEvidenceGroupsPerFinding is exceeded. Higher severity wins, then
// higher confidence, then (for two otherwise-tied groups) the
// LEXICALLY SMALLER signature wins -- an arbitrary but fully
// deterministic final tiebreak, chosen so eviction/selection never
// depends on map iteration or arrival order (see engine_test.go's
// concurrency tests).
func (g *group) strongerThan(o *group) bool {
	if rankOfSeverity(g.severity) != rankOfSeverity(o.severity) {
		return rankOfSeverity(g.severity) > rankOfSeverity(o.severity)
	}
	if g.confidence != o.confidence {
		return g.confidence > o.confidence
	}
	return g.signature < o.signature
}

// bucket accumulates every raw models.Finding sharing one Identity.
type bucket struct {
	identity      Identity
	groups        map[string]*group
	rawInputCount int
	firstSeen     time.Time
	lastSeen      time.Time
}

func newBucket(id Identity) *bucket {
	return &bucket{identity: id, groups: make(map[string]*group)}
}

// ingest folds one raw finding into the bucket -- see the package doc
// comment for why this is order-independent and bounded regardless of
// how many times ingest is called for the same identity.
func (b *bucket) ingest(f models.Finding) {
	sig := evidenceSignature(f.Evidence)
	g := &group{
		signature:   sig,
		confidence:  f.Confidence,
		severity:    f.Severity,
		evidence:    boundedEvidenceItems(f.Evidence),
		title:       f.Title,
		description: f.Description,
		remediation: f.Remediation,
		detectorID:  f.DetectorID,
	}

	if existing, ok := b.groups[sig]; ok {
		existing.confidence = minFloat(existing.confidence, g.confidence)
		existing.severity = minSeverity(existing.severity, g.severity)
		// Title/description/remediation/detectorID for a resubmission
		// of the SAME signature are picked deterministically (lexically
		// smallest Title) rather than "last write wins" (which would be
		// arrival-order-dependent).
		if g.title < existing.title {
			existing.title, existing.description, existing.remediation, existing.detectorID =
				g.title, g.description, g.remediation, g.detectorID
		}
	} else if len(b.groups) < maxEvidenceGroupsPerFinding {
		b.groups[sig] = g
	} else if weakest := findWeakest(b.groups); g.strongerThan(weakest) {
		delete(b.groups, weakest.signature)
		b.groups[sig] = g
	}
	// else: bucket is full and g is not stronger than anything already
	// retained -- discarded. This is the deterministic "retain the
	// strongest evidence" rule task section 9 requires, never random
	// selection.

	b.rawInputCount++
	seen := f.FirstSeen
	if seen.IsZero() {
		seen = f.LastSeen
	}
	if !seen.IsZero() && (b.firstSeen.IsZero() || seen.Before(b.firstSeen)) {
		b.firstSeen = seen
	}
	last := f.LastSeen
	if last.IsZero() {
		last = seen
	}
	if last.After(b.lastSeen) {
		b.lastSeen = last
	}
}

func findWeakest(groups map[string]*group) *group {
	var weakest *group
	for _, g := range groups {
		if weakest == nil || weakest.strongerThan(g) {
			weakest = g
		}
	}
	return weakest
}

func minFloat(a, b float64) float64 {
	if b < a {
		return b
	}
	return a
}

// boundedEvidenceItems converts and deduplicates f's evidence,
// truncating any oversized Content to maxEvidenceContentBytes --
// applied at ingest time so a single malformed/adversarial finding can
// never inflate a bucket's memory footprint before consolidation even
// runs.
func boundedEvidenceItems(evidence []models.Evidence) []EvidenceItem {
	items := evidenceItemsOf(evidence)
	for i := range items {
		if len(items[i].Content) > maxEvidenceContentBytes {
			items[i].Content = items[i].Content[:maxEvidenceContentBytes]
		}
	}
	return dedupeEvidenceItems(items)
}

func dedupeEvidenceItems(items []EvidenceItem) []EvidenceItem {
	seen := make(map[EvidenceItem]bool, len(items))
	out := make([]EvidenceItem, 0, len(items))
	for _, it := range items {
		if seen[it] {
			continue
		}
		seen[it] = true
		out = append(out, it)
	}
	return out
}

// build assembles this bucket's CanonicalFinding -- the consolidation
// step task sections 8, 10, 11, and 12 describe, run once per read
// (Engine.Findings), never incrementally, so it always reflects every
// raw finding ingested so far regardless of insertion order.
func (b *bucket) build() CanonicalFinding {
	severity := models.SeverityInfo
	confidence := 0.0
	var winning *group
	var evidenceUnion []EvidenceItem

	for _, g := range b.groups {
		severity = maxSeverity(severity, g.severity)
		if g.confidence > confidence {
			confidence = g.confidence
		}
		if winning == nil || g.strongerThan(winning) {
			winning = g
		}
		evidenceUnion = append(evidenceUnion, g.evidence...)
	}

	evidence := boundEvidenceForOutput(dedupeEvidenceItems(evidenceUnion))

	status := StatusNew
	if len(b.groups) >= 2 {
		status = StatusConfirmed
	}

	id := b.identity
	cf := CanonicalFinding{
		FindingID:         id.FindingID(),
		ScanID:            id.ScanID,
		VulnerabilityType: id.VulnerabilityType,
		Asset:             Asset{Scheme: id.Scheme, Host: id.Host, Port: id.Port, Path: id.Path},
		HTTP:              HTTPContext{Method: id.Method, Parameter: id.Parameter, Location: id.ParameterLocation},
		Resource:          Resource{Identifier: id.ResourceIdentifier},
		Severity:          severity,
		Confidence:        confidence,
		Status:            status,
		Evidence:          evidence,
		FirstSeen:         b.firstSeen,
		LastSeen:          b.lastSeen,
		Metadata: map[string]string{
			"raw_finding_count":    strconv.Itoa(b.rawInputCount),
			"evidence_group_count": strconv.Itoa(len(b.groups)),
		},
	}
	if winning != nil {
		cf.DetectorID = winning.detectorID
		cf.Title = winning.title
	}
	return cf
}

// boundEvidenceForOutput enforces maxEvidenceItemsPerFinding, keeping
// the STRONGEST items when the union exceeds it (task section 9:
// "retain the strongest/relevant evidence... do not use random
// selection"). "Strongest" is defined deterministically as longer
// Content first (more detail), then Kind, then Content lexically --
// documented explicitly since it's a judgment call, not a value this
// project's models attach to individual evidence items. The final
// output is re-sorted into canonical (Kind, Content) order afterward,
// so truncation never makes the DISPLAYED order depend on this
// selection pass.
func boundEvidenceForOutput(items []EvidenceItem) []EvidenceItem {
	if len(items) <= maxEvidenceItemsPerFinding {
		sortEvidenceItemsCanonical(items)
		return items
	}
	strength := make([]EvidenceItem, len(items))
	copy(strength, items)
	sort.Slice(strength, func(i, j int) bool {
		if len(strength[i].Content) != len(strength[j].Content) {
			return len(strength[i].Content) > len(strength[j].Content)
		}
		if strength[i].Kind != strength[j].Kind {
			return strength[i].Kind < strength[j].Kind
		}
		return strength[i].Content < strength[j].Content
	})
	kept := strength[:maxEvidenceItemsPerFinding]
	sortEvidenceItemsCanonical(kept)
	return kept
}

func sortEvidenceItemsCanonical(items []EvidenceItem) {
	sort.Slice(items, func(i, j int) bool {
		if items[i].Kind != items[j].Kind {
			return items[i].Kind < items[j].Kind
		}
		return items[i].Content < items[j].Content
	})
}

// Engine is the correlation/deduplication layer -- task section 33's
// "clean interface between detectors and the correlation engine."
// Safe for concurrent use: every mutation is serialized by mu, and
// Findings() always recomputes consolidation from the current bucket
// state, so the result is independent of Ingest call order (task
// section 32).
type Engine struct {
	mu      sync.Mutex
	buckets map[string]*bucket
}

// NewEngine returns a ready-to-use, empty Engine.
func NewEngine() *Engine {
	return &Engine{buckets: make(map[string]*bucket)}
}

// IngestResult reports what happened to one raw finding submitted via
// Ingest -- task section 12's per-input status concept
// (StatusNew/StatusDuplicate), never returned as part of the
// CanonicalFinding output set itself.
type IngestResult struct {
	FindingID string
	Status    Status // StatusNew (first time this identity was seen) or StatusDuplicate
}

// Ingest folds findings into the Engine, keyed by their computed
// Identity. It never returns an error: malformed/adversarial input
// (see security_test.go) is handled by computeIdentity/normalization
// without panicking, at worst producing an identity with empty
// components that still deterministically groups identical malformed
// inputs together rather than crashing.
func (e *Engine) Ingest(findings ...models.Finding) []IngestResult {
	e.mu.Lock()
	defer e.mu.Unlock()

	results := make([]IngestResult, len(findings))
	for i, f := range findings {
		id := computeIdentity(f)
		key := id.FindingID()
		b, existed := e.buckets[key]
		if !existed {
			b = newBucket(id)
			e.buckets[key] = b
		}
		b.ingest(f)

		status := StatusNew
		if existed {
			status = StatusDuplicate
		}
		results[i] = IngestResult{FindingID: key, Status: status}
	}
	return results
}

// Findings returns every canonical finding currently held, in
// deterministic order (see ordering.go) -- task section 22.
func (e *Engine) Findings() []CanonicalFinding {
	e.mu.Lock()
	defer e.mu.Unlock()

	out := make([]CanonicalFinding, 0, len(e.buckets))
	for _, b := range e.buckets {
		out = append(out, b.build())
	}
	sortCanonicalFindings(out)
	return out
}

// Len returns how many distinct identities the Engine currently holds
// -- a cheap way to check bucket count without building the full
// CanonicalFinding set (used by performance tests).
func (e *Engine) Len() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.buckets)
}
