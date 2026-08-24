// Phase 3.29 Server-Side Template Injection (SSTI) Active Detection
// lab fixtures -- the first fixtures for this vulnerability class in
// this codebase (no pre-existing "ssti" detector or fixture family to
// extend). Mirrors every prior "-active" phase's own "fake backend,
// no real dependency" pattern (sqliSimulateQuery, travSynthFS,
// cmdInjectionMatch): sstiSimulateRender recognizes ONLY the 4 fixed
// "NUMBER*NUMBER" delimiter shapes internal/detectors/sstiactive's own
// templateVariants produces, never invoking a real template engine or
// any code-execution capability whatsoever.
package lab

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var sstiTemplatePatterns = []*regexp.Regexp{
	regexp.MustCompile(`\{\{\s*(\d+)\s*\*\s*(\d+)\s*\}\}`),
	regexp.MustCompile(`\$\{\s*(\d+)\s*\*\s*(\d+)\s*\}`),
	regexp.MustCompile(`#\{\s*(\d+)\s*\*\s*(\d+)\s*\}`),
	regexp.MustCompile(`<%=\s*(\d+)\s*\*\s*(\d+)\s*%>`),
}

// sstiSimulateRender is the ONE shared "fake template engine" every
// fixture below reuses -- recognizes ONLY a simple NUMBER*NUMBER
// multiplication inside one of 4 fixed delimiter pairs, computes the
// literal product, and returns it. Anything else is treated as
// ordinary, non-executable text.
func sstiSimulateRender(input string) (rendered string, ok bool) {
	for _, re := range sstiTemplatePatterns {
		if m := re.FindStringSubmatch(input); m != nil {
			a, _ := strconv.Atoi(m[1])
			b, _ := strconv.Atoi(m[2])
			return strconv.Itoa(a * b), true
		}
	}
	return "", false
}

func registerSSTIActive(mux *http.ServeMux) {
	mux.HandleFunc("/ssti/vulnerable", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		w.Header().Set("Content-Type", "text/html")
		if result, ok := sstiSimulateRender(name); ok {
			fmt.Fprintf(w, "<html><body>Hello, %s!</body></html>", result)
			return
		}
		fmt.Fprintf(w, "<html><body>Hello, %s!</body></html>", html.EscapeString(name))
	})

	mux.HandleFunc("/ssti/vulnerable-form", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		name := r.FormValue("name")
		w.Header().Set("Content-Type", "text/html")
		if result, ok := sstiSimulateRender(name); ok {
			fmt.Fprintf(w, "<html><body>Hello, %s!</body></html>", result)
			return
		}
		fmt.Fprintf(w, "<html><body>Hello, %s!</body></html>", html.EscapeString(name))
	})

	mux.HandleFunc("/ssti/vulnerable-json", func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Name string `json:"name"`
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
		if err == nil {
			_ = json.Unmarshal(raw, &payload) // tolerate empty/malformed body -- the JSON baseline probe has none seeded
		}
		w.Header().Set("Content-Type", "text/html")
		if result, ok := sstiSimulateRender(payload.Name); ok {
			fmt.Fprintf(w, "<html><body>Hello, %s!</body></html>", result)
			return
		}
		fmt.Fprintf(w, "<html><body>Hello, %s!</body></html>", html.EscapeString(payload.Name))
	})

	// Path-location: two example links (see harness_vuln.go's index
	// additions) give internal/parameters.InferPathInputs the
	// >=2-distinct-value evidence it requires. No name-heuristic gate
	// applies to sstiactive, so unlike traversal/cmdinjection/open-
	// redirect's own path fixtures, no particular preceding-segment
	// name is required here.
	mux.HandleFunc("/ssti/greet/", func(w http.ResponseWriter, r *http.Request) {
		name, _ := url.PathUnescape(strings.TrimPrefix(r.URL.Path, "/ssti/greet/"))
		w.Header().Set("Content-Type", "text/html")
		if result, ok := sstiSimulateRender(name); ok {
			fmt.Fprintf(w, "<html><body>Hello, %s!</body></html>", result)
			return
		}
		fmt.Fprintf(w, "<html><body>Hello, %s!</body></html>", html.EscapeString(name))
	})

	// --- Negative controls -------------------------------------------

	mux.HandleFunc("/ssti/safe", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body>Hello, %s!</body></html>", html.EscapeString(name))
	})

	mux.HandleFunc("/ssti/generic", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><body>Welcome to the site.</body></html>")
	})
}
