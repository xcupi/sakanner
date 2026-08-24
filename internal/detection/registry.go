package detection

import (
	"fmt"
	"sort"
	"sync"
)

// Entry is one Registry row, as returned by List -- a detector's
// Metadata alongside whether the engine will currently run it.
type Entry struct {
	Metadata Metadata
	Enabled  bool
}

// Registry holds every Detector sakanner knows about. It is safe for
// concurrent use.
type Registry struct {
	mu        sync.RWMutex
	detectors map[string]Detector
	enabled   map[string]bool
	order     []string // insertion order, so List/`scanner detectors list` output is stable
}

// NewRegistry returns an empty Registry. A detector only appears in it
// once something explicitly calls Register -- there is no implicit
// population, so an unmodified Phase 3.1 build's registry is empty,
// honestly reflecting that no real detector exists yet.
func NewRegistry() *Registry {
	return &Registry{
		detectors: make(map[string]Detector),
		enabled:   make(map[string]bool),
	}
}

// Register adds d to the registry, enabled by default. It fails if d's
// ID is empty or already registered -- IDs must be unique so a Finding's
// DetectorID unambiguously identifies which detector produced it.
func (r *Registry) Register(d Detector) error {
	if d == nil {
		return fmt.Errorf("detection: cannot register a nil detector")
	}
	id := d.Metadata().ID
	if id == "" {
		return fmt.Errorf("detection: detector has an empty ID")
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.detectors[id]; exists {
		return fmt.Errorf("detection: detector %q is already registered", id)
	}
	r.detectors[id] = d
	r.enabled[id] = true
	r.order = append(r.order, id)
	return nil
}

// Get returns the detector registered under id, if any.
func (r *Registry) Get(id string) (Detector, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	d, ok := r.detectors[id]
	return d, ok
}

// SetEnabled toggles whether id will be run by the Engine, without
// removing it from the registry. It errors if id was never registered.
func (r *Registry) SetEnabled(id string, enabled bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.detectors[id]; !ok {
		return fmt.Errorf("detection: no such detector %q", id)
	}
	r.enabled[id] = enabled
	return nil
}

// Enabled reports whether id is both registered and currently enabled.
func (r *Registry) Enabled(id string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.detectors[id] != nil && r.enabled[id]
}

// List returns every registered detector's Entry, in the order each was
// registered.
func (r *Registry) List() []Entry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Entry, 0, len(r.order))
	for _, id := range r.order {
		out = append(out, Entry{Metadata: r.detectors[id].Metadata(), Enabled: r.enabled[id]})
	}
	return out
}

// Enabled Detectors, in registration order -- what Engine.Run actually
// iterates.
func (r *Registry) enabledDetectors() []Detector {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Detector, 0, len(r.order))
	for _, id := range r.order {
		if r.enabled[id] {
			out = append(out, r.detectors[id])
		}
	}
	// order is already registration order and therefore already
	// deterministic, but sorting by ID additionally makes Engine.Run's
	// detector iteration order independent of registration order too,
	// which keeps dedup/results output byte-identical across two
	// processes that happened to register the same detector set in a
	// different order.
	sort.Slice(out, func(i, j int) bool { return out[i].Metadata().ID < out[j].Metadata().ID })
	return out
}
