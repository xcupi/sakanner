package idor

// AuthContext is one synthetic, pre-authenticated identity this
// detector can issue requests as -- "Authorization Context A" /
// "Authorization Context B" in the task's own terminology.
//
// Headers are attached verbatim to every request made "as" this
// context (e.g. {"X-Test-Auth-User": "user-a"} in the Phase 3 Test
// Lab, or in principle {"Authorization": "Bearer <token>"} /
// {"Cookie": "session=<value>"} for a real target) -- this detector
// never establishes, refreshes, or derives credentials itself; it only
// ever attaches whatever was configured. See
// docs/phase-3-5-idor-bola.md "Authentication assumptions" for why
// login/token-acquisition is explicitly out of scope.
//
// OwnsResourceIDs is operator-supplied ground truth: which resource
// identifier VALUES this context is known to own. This is
// configuration-time knowledge, not something the detector infers --
// see docs/phase-3-5-idor-bola.md "Resource ownership" for why: Phase
// 2's recon has no concept of "which identity discovered this link,"
// so there is no automatic way to derive ownership from crawl data
// alone. A resource identifier absent from every configured context's
// OwnsResourceIDs is simply never tested (see Detector.Detect) --
// consistent with the task's explicit instruction to return
// NOT_APPLICABLE rather than guess.
type AuthContext struct {
	ID              string
	Headers         map[string]string
	OwnsResourceIDs map[string]bool
}

// Owns reports whether c is configured as the owner of resource id.
func (c AuthContext) Owns(id string) bool {
	return c.OwnsResourceIDs != nil && c.OwnsResourceIDs[id]
}
