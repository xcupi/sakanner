package cmdinjection

import "bytes"

// looksAllowed reports whether a response represents genuine access to
// something (2xx status with a non-empty body) as opposed to a denial
// (400/403/404/anything else) or an empty response. Deliberately
// simple and general -- it does not try to parse or understand the
// body's content, only whether the server's own status line indicates
// success. Note that unlike sibling detectors, THIS check does not
// gate confirmation at all (see detector.go's exact-marker-match
// requirement) -- it only gates the legitimate-access reference probe.
func looksAllowed(statusCode int, body []byte) bool {
	return statusCode >= 200 && statusCode < 300 && len(bytes.TrimSpace(body)) > 0
}
