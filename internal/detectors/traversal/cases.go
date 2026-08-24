package traversal

// TraversalCase is one operator-configured (relative traversal path,
// confirmation marker) pair this detector knows to try -- deliberately
// analogous to ssrf.CallbackClient and idor.AuthContext: this detector
// cannot invent knowledge of what a target's protected resource is or
// what content confirms it was actually accessed; that is supplied by
// the operator (in the Phase 3 Test Lab, by the lab's own known
// synthetic fixture).
//
// RelativePath is the CANONICAL, unencoded traversal representation
// (e.g. "../protected/secret-marker.txt") -- the detector derives a
// small, fixed set of alternative encodings from it itself (see
// variants.go); the operator does not need to enumerate encodings.
//
// Marker is a byte sequence that, if found verbatim in a probe's
// response body, constitutes confirmed evidence that the SPECIFIC
// protected resource was returned -- never a real secret. In the lab,
// "PATH_TRAVERSAL_SECRET_MARKER".
type TraversalCase struct {
	RelativePath string
	Marker       string
}
