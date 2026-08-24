// Phase 3.26 Command Injection Active Detection lab fixtures.
//
// This file extends vuln.scanner.test (harness_vuln.go) with a
// Windows-cmd.exe-style vulnerable fixture, form/JSON/path-location
// vulnerable fixtures, and a generic-error negative control -- closing
// the gaps registerCommandInjectionAPI (Phase 3.7, query-GET-only,
// Unix-style separators only) left open. It does NOT modify
// registerCommandInjectionAPI or any of its existing seven routes --
// every new fixture here is additive, reusing the SAME
// cmdInjectionLabCommand/cmdInjectionMarkerPrefix safe, lab-only
// protocol (harness_vuln.go), never a real shell of any kind.
package lab

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
)

// cmdInjectionWindowsPattern recognizes "&", "&&", or "|" -- but
// deliberately NOT a bare ";" (real cmd.exe never treats a semicolon
// as a command separator, unlike POSIX shells) -- modeling
// docs/phase-3-26-command-injection-active.md section 10.B's own
// Windows-style grammar. Pure regexp matching against a Go string; no
// shell of any kind is ever invoked.
var cmdInjectionWindowsPattern = regexp.MustCompile(`(?:&{1,2}|\|)\s*` + cmdInjectionLabCommand + `\s+(\S+)`)

// cmdInjectionMatch is the one shared grammar-check helper every new
// fixture below reuses -- returns the matched token and whether the
// grammar matched at all.
func cmdInjectionMatch(pattern *regexp.Regexp, value string) (token string, matched bool) {
	m := pattern.FindStringSubmatch(value)
	if m == nil {
		return "", false
	}
	return m[1], true
}

func registerCommandInjectionActive(mux *http.ServeMux) {
	// B. Vulnerable Windows-style (query, GET) -- same safe protocol,
	// different (cmd.exe-shaped) separator grammar.
	mux.HandleFunc("/api/ping/vulnerable-windows", func(w http.ResponseWriter, r *http.Request) {
		host := r.URL.Query().Get("host")
		w.Header().Set("Content-Type", "text/plain")
		if token, ok := cmdInjectionMatch(cmdInjectionWindowsPattern, host); ok {
			fmt.Fprintf(w, "PING %s: normal response (simulated, no real ping ever executed)\n%s%s", host, cmdInjectionMarkerPrefix, token)
			return
		}
		fmt.Fprintf(w, "PING %s: normal response (simulated, no real ping ever executed)", host)
	})

	// Form-location (Unix-style grammar, same as /api/ping/vulnerable).
	mux.HandleFunc("/api/ping/vulnerable-form", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		host := r.FormValue("host")
		w.Header().Set("Content-Type", "text/plain")
		if token, ok := cmdInjectionMatch(cmdInjectionPattern, host); ok {
			fmt.Fprintf(w, "PING %s: normal response (simulated)\n%s%s", host, cmdInjectionMarkerPrefix, token)
			return
		}
		fmt.Fprintf(w, "PING %s: normal response (simulated)", host)
	})

	// JSON-body-location. Reachable only via a DIRECTLY-persisted
	// Parameter in tests (Location: "json", Provenance:
	// "REQUEST_INPUT"), not through a real crawl -- the crawler cannot
	// yet discover a live JSON REQUEST_INPUT parameter, an honest,
	// pre-existing Phase 3.19 limitation this phase does not close
	// (see docs/phase-3-26-command-injection-active.md and Phase
	// 3.19/3.25's own identical notes). Still a REAL, genuinely
	// vulnerable HTTP endpoint.
	mux.HandleFunc("/api/ping/vulnerable-json", func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Host string `json:"host"`
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
		if err == nil {
			_ = json.Unmarshal(raw, &payload) // tolerate empty/malformed body -- see the baseline-probe note in cmdinjectionactive's own tests
		}
		w.Header().Set("Content-Type", "text/plain")
		if token, ok := cmdInjectionMatch(cmdInjectionPattern, payload.Host); ok {
			fmt.Fprintf(w, "PING %s: normal response (simulated)\n%s%s", payload.Host, cmdInjectionMarkerPrefix, token)
			return
		}
		fmt.Fprintf(w, "PING %s: normal response (simulated)", payload.Host)
	})

	// Path-location -- two example links (see the index page this
	// phase adds to) give internal/parameters.InferPathInputs the
	// >=2-distinct-value evidence it requires.
	mux.HandleFunc("/api/ping/host/", func(w http.ResponseWriter, r *http.Request) {
		host := strings.TrimPrefix(r.URL.Path, "/api/ping/host/")
		w.Header().Set("Content-Type", "text/plain")
		if token, ok := cmdInjectionMatch(cmdInjectionPattern, host); ok {
			fmt.Fprintf(w, "PING %s: normal response (simulated)\n%s%s", host, cmdInjectionMarkerPrefix, token)
			return
		}
		fmt.Fprintf(w, "PING %s: normal response (simulated)", host)
	})

	// F. Generic-error negative control -- ALWAYS a 500, regardless of
	// input, including the baseline itself: the endpoint is never even
	// analyzable enough to probe further (task section 6 item 3).
	mux.HandleFunc("/api/ping/error", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error: something went wrong processing this request"))
	})
}
