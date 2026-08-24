package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"unicode/utf8"
)

// binaryContentTypePrefixes are Content-Type families this package
// never attempts to render as text -- task section 22.
var binaryContentTypePrefixes = []string{
	"image/", "video/", "audio/", "font/",
	"application/octet-stream", "application/zip", "application/gzip",
	"application/pdf", "application/x-", "application/vnd.",
}

// isBinaryContentType reports whether contentType names a family this
// package treats as binary by declaration, without inspecting any
// bytes.
func isBinaryContentType(contentType string) bool {
	ct := strings.ToLower(contentType)
	for _, prefix := range binaryContentTypePrefixes {
		if strings.HasPrefix(ct, prefix) {
			return true
		}
	}
	return false
}

// looksBinary is the content-based fallback for when Content-Type is
// missing or doesn't name a recognized binary family: a NUL byte or
// invalid UTF-8 anywhere in body is treated as binary -- task section
// 22's "do not blindly convert binary responses to text," applied even
// when the declared type doesn't say so. body is a Go string because
// that is what this project's evidence actually carries
// (ResponseFragment) -- a Go string can losslessly hold arbitrary
// bytes regardless of UTF-8 validity, so no information is lost by the
// time this function sees it.
func looksBinary(body string) bool {
	if len(body) == 0 {
		return false
	}
	if !utf8.ValidString(body) {
		return true
	}
	for i := 0; i < len(body); i++ {
		if body[i] == 0 {
			return true
		}
	}
	return false
}

// samplePrefixHexLen bounds how many raw bytes of a binary response
// are ever hex-encoded into evidence -- small enough to be a safe
// "fingerprint," never enough to reconstruct meaningful binary
// content.
const samplePrefixHexLen = 16

// buildBinarySummary builds a BinarySummary from a response body --
// task section 22. Never stores body as text; SHA256 is computed over
// the FULL body (so two byte-identical binary responses always produce
// the same summary), while SamplePrefixHex is capped at
// samplePrefixHexLen bytes regardless of body size.
func buildBinarySummary(contentType, body string) *BinarySummary {
	sum := sha256.Sum256([]byte(body))
	prefixLen := len(body)
	if prefixLen > samplePrefixHexLen {
		prefixLen = samplePrefixHexLen
	}
	return &BinarySummary{
		ContentType:     contentType,
		SizeBytes:       len(body),
		SHA256:          hex.EncodeToString(sum[:]),
		SamplePrefixHex: hex.EncodeToString([]byte(body[:prefixLen])),
	}
}
