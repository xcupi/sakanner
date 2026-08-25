// General web application start-URL/base-path support
// (`scanner scan <target> --start-url ...`), through the real built
// binary. Deliberately not tied to any specific real-world
// application: /app/ here stands in for "any application mounted
// under a base path the site root has no link into," the same role
// lab/harness_auth.go's /subpath-app/* fixture plays at the
// lab-integration level and internal/orchestrator's own
// start_path_test.go plays at the unit level.
package e2e

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const e2eSubpathLoginPageHTML = `<html><body><form action="/app/login" method="post">
  <input type="hidden" name="csrf_token" value="e2e-subpath-fixed-token">
  <input type="text" name="username">
  <input type="password" name="password">
  <input type="submit" name="do_login" value="Log In">
</form></body></html>`

// e2eSubpathApp mirrors lab/harness_auth.go's /subpath-app/* fixture
// (re-declared here rather than imported: this package deliberately
// never depends on the lab package, matching every other e2e file's
// own "plain httptest fixtures only" convention). "/" itself has no
// link into "/app/" at all; "/app/"'s own login processing is gated
// on its submit button's name being present in the POST body, exactly
// like e2eLoginApp's sibling fixtures.
func e2eSubpathApp(username, password string) http.Handler {
	sessions := map[string]string{}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><body>unrelated home page, no link to /app/ at all</body></html>`))
	})
	mux.HandleFunc("/app/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/app/" {
			http.NotFound(w, r)
			return
		}
		c, err := r.Cookie("app_session")
		if err != nil || sessions[c.Value] == "" {
			http.Redirect(w, r, "/app/login", http.StatusFound)
			return
		}
		w.Write([]byte(`<html><body><a href="/app/dashboard">Dashboard</a></body></html>`))
	})
	mux.HandleFunc("/app/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Write([]byte(e2eSubpathLoginPageHTML))
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		if r.FormValue("csrf_token") != "e2e-subpath-fixed-token" {
			http.Error(w, "missing or invalid csrf token", http.StatusBadRequest)
			return
		}
		if r.FormValue("do_login") == "" {
			http.Error(w, "missing submit field", http.StatusBadRequest)
			return
		}
		if r.FormValue("username") != username || r.FormValue("password") != password {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("login failed: invalid credentials"))
			return
		}
		sessions["e2e-subpath-session"] = username
		http.SetCookie(w, &http.Cookie{Name: "app_session", Value: "e2e-subpath-session", Path: "/"})
		http.Redirect(w, r, "/app/dashboard", http.StatusFound)
	})
	mux.HandleFunc("/app/dashboard", func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("app_session")
		if err != nil || sessions[c.Value] == "" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("unauthorized"))
			return
		}
		w.Write([]byte(`<html><body>dashboard, welcome <a href="/app/settings">settings</a></body></html>`))
	})
	mux.HandleFunc("/app/settings", func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("app_session")
		if err != nil || sessions[c.Value] == "" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("unauthorized"))
			return
		}
		w.Write([]byte(`<html><body>settings page -- SETTINGS_PAGE_MARKER</body></html>`))
	})
	return mux
}

// TestScanCmd_StartURL_AuthenticatedCrawlReachesSubpathApp is this
// feature's own vertical slice through the real CLI binary:
// --start-url /app/ combined with --auth-profile authenticates against
// a login form mounted under /app/ (gated on its own named submit
// button, exactly like a real application such as one hosted under
// /DVWA/) and then crawls starting there, reaching /app/dashboard and
// /app/settings -- pages with no link into them from "/" at all.
func TestScanCmd_StartURL_AuthenticatedCrawlReachesSubpathApp(t *testing.T) {
	srv := httptest.NewServer(e2eSubpathApp("alice", "correct-horse-battery-staple"))
	defer srv.Close()
	host, port := e2eSplitHostPort(t, srv)
	loginURL := fmt.Sprintf("http://%s:%s/app/login", host, port)

	t.Setenv("E2E_SUBPATH_USER", "alice")
	t.Setenv("E2E_SUBPATH_PASS", "correct-horse-battery-staple")
	extra := authConfigYAML("app-user", loginURL, "E2E_SUBPATH_USER", "E2E_SUBPATH_PASS") + fmt.Sprintf("ports:\n  default_ports: [%s]\n", port)
	configPath := writeConfig(t, extra)
	c := newCLI(t, buildBinary(t), configPath)
	c.mustRun("scope", "add", host)

	out := c.mustRun("scan", host, "--profile", "web", "--auth-profile", "app-user", "--start-url", "/app/")
	if !strings.Contains(out, "Authentication succeeded for profile \"app-user\"") {
		t.Errorf("output missing authentication success message:\n%s", out)
	}
	if !strings.Contains(out, "Status:                 AUTHENTICATED") {
		t.Errorf("output missing authenticated status in Auth: block:\n%s", out)
	}
	if strings.Contains(out, "Authenticated URLs:      0") {
		t.Errorf("Crawl: block reports zero authenticated URLs -- the authenticated crawl did not actually happen:\n%s", out)
	}

	scanID := extractFullScanID(t, out)
	mdOut := c.mustRun("report", "--scan", scanID, "--format", "markdown")
	if !strings.Contains(mdOut, "/app/dashboard") {
		t.Errorf("report does not list /app/dashboard -- --start-url /app/ did not redirect the crawl's entry point:\n%s", mdOut)
	}
	if !strings.Contains(mdOut, "/app/settings") {
		t.Errorf("report does not list /app/settings -- the authenticated crawl did not follow the dashboard's own link:\n%s", mdOut)
	}
}

// TestScanCmd_StartURL_BarePath_NoAuth_ReachesSubpath proves --start-url
// works standalone, with no authentication involved at all: a plain
// crawl pointed at /app/ still reaches /app/login (the one page an
// unauthenticated visitor can see) even though "/" has no link there.
func TestScanCmd_StartURL_BarePath_NoAuth_ReachesSubpath(t *testing.T) {
	srv := httptest.NewServer(e2eSubpathApp("alice", "correct-horse-battery-staple"))
	defer srv.Close()
	host, port := e2eSplitHostPort(t, srv)

	configPath := writeConfig(t, fmt.Sprintf("ports:\n  default_ports: [%s]\n", port))
	c := newCLI(t, buildBinary(t), configPath)
	c.mustRun("scope", "add", host)

	out := c.mustRun("scan", host, "--profile", "web", "--start-url", "app/")
	scanID := extractFullScanID(t, out)
	mdOut := c.mustRun("report", "--scan", scanID, "--format", "markdown")
	if !strings.Contains(mdOut, "/app/login") {
		t.Errorf("report does not list /app/login -- an unauthenticated crawl starting at \"app/\" (no leading slash) did not reach the subpath app at all:\n%s", mdOut)
	}
}

// TestScanCmd_StartURL_MismatchedHost_RejectedBeforeScan is the
// same-origin pre-flight check: a --start-url naming a DIFFERENT host
// than the scan target must fail fast, before any scan job is created,
// exactly like an unknown --auth-profile or --authz-identity already
// do.
func TestScanCmd_StartURL_MismatchedHost_RejectedBeforeScan(t *testing.T) {
	srv := httptest.NewServer(e2eSubpathApp("alice", "correct-horse-battery-staple"))
	defer srv.Close()
	host, port := e2eSplitHostPort(t, srv)

	configPath := writeConfig(t, fmt.Sprintf("ports:\n  default_ports: [%s]\n", port))
	c := newCLI(t, buildBinary(t), configPath)
	c.mustRun("scope", "add", host)

	out, stderr, err := c.run("scan", host, "--start-url", "http://a-completely-different-host.example/app/")
	if err == nil {
		t.Fatalf("expected an error for a --start-url naming a different host\noutput: %s", out)
	}
	if !strings.Contains(stderr, "does not match the scan target") {
		t.Errorf("stderr missing the same-origin mismatch explanation: %q", stderr)
	}
	if strings.Contains(out, "Scan ID:") {
		t.Fatalf("a scan job was created despite a mismatched --start-url host:\n%s", out)
	}
}
