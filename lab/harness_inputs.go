// Phase 3.13 Parameter & Input Discovery test fixtures.
//
// This file extends the lab (harness.go/harness_vuln.go) with a
// dedicated fixture app covering every input-discovery scenario task's
// "TEST LAB" section requires: query parameters, duplicate query
// parameters, GET/POST forms, hidden fields, textarea, select, an
// out-of-scope form action, malformed HTML, and a many-field page for
// resource-limit testing. Does not change Start's or
// StartWithVulnerabilities' own behavior -- Phase 1-3.12 tests are
// entirely unaffected by this file's existence (the only harness.go
// edit this phase made was adding this file's own InputsAddr field to
// the Lab struct, mirroring VulnAddr/SSRFInternalAddr's own precedent).
//
// JSON body fixtures are deliberately NOT included here: nothing in the
// live crawl/detection pipeline captures a JSON request body (see
// docs/phase-3-13-parameter-discovery.md "JSON body discovery: an
// honest capability gap") -- internal/parameters/json_test.go's pure
// unit tests (raw bytes in, no live server) are the correct, sufficient
// test surface for JSON discovery, not a live fixture nothing in the
// real pipeline would ever reach anyway.
package lab

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

const ipInputs = "127.0.0.24" // inputs.scanner.test

// StartWithInputFixtures builds and starts everything
// StartWithVulnerabilities does (the vuln lab, itself a superset of the
// base Phase 2 lab), plus this file's own input-discovery fixture app --
// additive, never changes StartWithVulnerabilities'/Start's own
// behavior.
func StartWithInputFixtures(gt *GroundTruth) (*Lab, error) {
	l, err := StartWithVulnerabilities(gt)
	if err != nil {
		return nil, err
	}
	if err := l.startInputFixtures(); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

func (l *Lab) startInputFixtures() error {
	srv, err := newServerOn(ipInputs, inputsAppHandler())
	if err != nil {
		return err
	}
	l.servers = append(l.servers, srv)
	l.InputsAddr = srv.Listener.Addr().String()

	l.Resolver.Hosts["inputs.scanner.test"] = []net.IP{net.ParseIP(ipInputs)}
	return nil
}

func inputsAppHandler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body>
			<a href="/search?q=hello&page=2">search</a>
			<a href="/search?q=hello&page=2">search again (duplicate observation)</a>
			<a href="/dupquery?tag=a&tag=b">dup query</a>
			<a href="/manyinputs">many</a>
			<a href="/external-form">external form</a>
			<a href="/malformed">malformed</a>
			<form action="/login" method="post">
				<input name="username" type="text">
				<input name="password" type="password">
				<input name="csrf_token" type="hidden" value="tok-abc">
				<textarea name="bio">tell us about yourself</textarea>
				<select name="role">
					<option value="user">User</option>
					<option value="admin" selected>Admin</option>
				</select>
			</form>
			<form action="/getform" method="get">
				<input name="filter" type="text" value="active">
			</form>
		</body></html>`)
	})

	leaf := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body>ok</body></html>`)
	}
	mux.HandleFunc("/search", leaf)
	mux.HandleFunc("/dupquery", leaf)
	mux.HandleFunc("/login", leaf)
	mux.HandleFunc("/getform", leaf)

	mux.HandleFunc("/external-form", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// A form whose action points to a host with no scope rule of its
		// own -- task's "FORM ACTION SCOPE": discovering this input must
		// never authorize external.scanner.test as a scan target.
		fmt.Fprint(w, `<html><body>
			<form action="https://external.scanner.test/steal" method="post">
				<input name="data" type="text">
			</form>
		</body></html>`)
	})

	mux.HandleFunc("/manyinputs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		var b strings.Builder
		b.WriteString(`<html><body><form action="/manyinputs-submit" method="post">`)
		for i := 0; i < 30; i++ {
			fmt.Fprintf(&b, `<input name="field%d" type="text">`, i)
		}
		b.WriteString(`</form></body></html>`)
		w.Write([]byte(b.String()))
	})
	mux.HandleFunc("/manyinputs-submit", leaf)

	mux.HandleFunc("/malformed", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// Deliberately unterminated tags/attributes -- task's "malformed
		// HTML" adversarial case: must degrade gracefully, never crash
		// the crawl.
		fmt.Fprint(w, `<html><body><form action="/malformed-submit" method="post"><input name="a" value="unterminated`)
	})
	mux.HandleFunc("/malformed-submit", leaf)

	return mux
}
