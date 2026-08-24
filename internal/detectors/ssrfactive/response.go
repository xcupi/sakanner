package ssrfactive

import (
	"bytes"

	"sakanner/internal/mutation"
)

// responseContainsMarker reports whether resp's body contains marker
// verbatim -- Mode A's ENTIRE evidence standard. Never true merely
// because the injected URL itself (internalResourceURL) appears in
// the response -- marker is a separate, fixed string the injected URL
// never contains (it identifies the RESOURCE's own content, not the
// payload), so a plain reflection of the payload can never produce a
// false match.
func responseContainsMarker(resp mutation.Response, marker string) bool {
	return marker != "" && bytes.Contains(resp.Body, []byte(marker))
}
