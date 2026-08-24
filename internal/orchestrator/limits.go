package orchestrator

import "time"

// Limits bounds resource usage across one Orchestrator's lifetime --
// task section 32. Every field defaults to a positive, safe value (see
// DefaultLimits); a non-positive value anywhere is normalized up to
// that default rather than treated as "unbounded" (task's own "do not
// allow unbounded memory growth").
type Limits struct {
	// MaxConcurrentScans bounds how many Orchestrator.Run calls (against
	// the SAME Orchestrator instance) may execute at once -- task
	// section 31. A caller starting one more concurrent scan than this
	// blocks (bounded queue, task section 33's backpressure
	// requirement) rather than spawning an unbounded goroutine, and
	// unblocks the instant an earlier scan's slot frees up. Respects
	// context cancellation while waiting.
	MaxConcurrentScans int

	// MaxFindings bounds how many canonical findings one scan carries
	// forward into evidence-building and the final result -- applied
	// AFTER Phase 3.9's deterministic risk-based ranking (never
	// reordered, never applied before ranking, so the findings kept are
	// always the highest-priority ones, not an arbitrary prefix of
	// however correlation happened to order them).
	MaxFindings int

	// ScanTimeout bounds one whole scan's wall-clock duration -- task
	// section 14's "overall scan timeout." Zero means "use the caller's
	// own context, no additional bound."
	ScanTimeout time.Duration

	// StageTimeout bounds any ONE stage's wall-clock duration -- task
	// section 14's "stage timeout," applied uniformly to every stage
	// (SCOPE through FINALIZATION). Zero means no per-stage bound beyond
	// whatever ScanTimeout/the caller's own context already impose.
	StageTimeout time.Duration
}

// DefaultLimits returns safe, positive defaults for every field.
func DefaultLimits() Limits {
	return Limits{
		MaxConcurrentScans: 5,
		MaxFindings:        1000,
		ScanTimeout:        0,
		StageTimeout:       0,
	}
}

// normalized returns l with every non-positive bound field replaced by
// DefaultLimits()'s value -- called once, internally, at the start of
// Orchestrator.Run, so a caller-constructed Limits{} zero value behaves
// exactly like DefaultLimits() rather than "unbounded."
func (l Limits) normalized() Limits {
	d := DefaultLimits()
	if l.MaxConcurrentScans <= 0 {
		l.MaxConcurrentScans = d.MaxConcurrentScans
	}
	if l.MaxFindings <= 0 {
		l.MaxFindings = d.MaxFindings
	}
	// ScanTimeout/StageTimeout: 0 legitimately means "no bound," not "use
	// the default" -- a caller who wants a bound sets a positive
	// duration explicitly; there is no sensible universal default
	// duration to substitute silently.
	return l
}
