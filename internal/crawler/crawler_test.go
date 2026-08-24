package crawler

import (
	"context"
	"fmt"
	"net"
	nethttp "net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"sakanner/internal/dns"
	"sakanner/internal/safedial"
	"sakanner/internal/scope"
)

// allowAllValidator lets every check through -- the crawler's safety
// guarantees (dialing only the pre-validated IP, never resolving a new
// host) are already covered by internal/safedial's own tests; these
// tests focus on crawl semantics (link/form/script extraction, depth,
// page-count bounds, same-origin filtering).
type allowAllValidator struct{}

func (allowAllValidator) CheckHost(ctx context.Context, host string) (scope.Decision, error) {
	return scope.Decision{Allowed: true}, nil
}
func (allowAllValidator) CheckIP(ctx context.Context, ip net.IP) (scope.Decision, error) {
	return scope.Decision{Allowed: true}, nil
}
func (allowAllValidator) CheckResolved(ctx context.Context, hostname string, ip net.IP) (scope.Decision, error) {
	return scope.Decision{Allowed: true}, nil
}

func testServerIPPort(t *testing.T, srv *httptest.Server) (net.IP, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		t.Fatalf("parse IP %q", host)
	}
	return ip, port
}

func newTestCrawler() Crawler {
	return NewNativeCrawler(safedial.New(allowAllValidator{}, dns.NewFakeResolver()))
}

func TestCrawl_ExtractsLinksFormsScripts(t *testing.T) {
	mux := nethttp.NewServeMux()
	mux.HandleFunc("/", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte(`<html><body>
			<a href="/page2">Page 2</a>
			<a href="https://external.test/other">External</a>
			<form action="/submit" method="post"></form>
			<script src="/app.js"></script>
		</body></html>`))
	})
	mux.HandleFunc("/page2", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte(`<html><body>page 2</body></html>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	ip, port := testServerIPPort(t, srv)

	c := newTestCrawler()
	pages, err := c.Crawl(context.Background(), ip, port, ip.String(), "http", "/", Options{MaxDepth: 2, MaxPages: 10, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("Crawl: %v", err)
	}

	if len(pages) != 2 {
		t.Fatalf("got %d pages, want 2 (/ and /page2)", len(pages))
	}
	root := pages[0]
	if root.StatusCode != 200 {
		t.Errorf("root.StatusCode = %d, want 200", root.StatusCode)
	}
	if len(root.Links) != 1 {
		t.Fatalf("root.Links = %+v, want exactly 1 (external link must be excluded)", root.Links)
	}
	if len(root.Forms) != 1 || !strings.HasSuffix(root.Forms[0].Action, "/submit") || root.Forms[0].Method != "POST" {
		t.Errorf("root.Forms = %+v, want action ending in /submit, method POST", root.Forms)
	}
	if len(root.Scripts) != 1 {
		t.Fatalf("root.Scripts = %+v, want exactly 1", root.Scripts)
	}
}

func TestCrawl_RespectsMaxPages(t *testing.T) {
	mux := nethttp.NewServeMux()
	// A chain of 10 pages, each linking to the next.
	for i := 0; i < 10; i++ {
		i := i
		path := "/page" + strconv.Itoa(i)
		mux.HandleFunc(path, func(w nethttp.ResponseWriter, r *nethttp.Request) {
			w.Write([]byte(`<html><body><a href="/page` + strconv.Itoa(i+1) + `">next</a></body></html>`))
		})
	}
	mux.HandleFunc("/", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte(`<html><body><a href="/page0">start</a></body></html>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	ip, port := testServerIPPort(t, srv)

	c := newTestCrawler()
	const maxPages = 3
	pages, err := c.Crawl(context.Background(), ip, port, ip.String(), "http", "/", Options{MaxDepth: 20, MaxPages: maxPages, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("Crawl: %v", err)
	}
	if len(pages) > maxPages {
		t.Errorf("got %d pages, want <= %d", len(pages), maxPages)
	}
	if len(pages) == 0 {
		t.Fatal("got 0 pages, want at least 1")
	}
}

func TestCrawl_RespectsMaxDepth(t *testing.T) {
	mux := nethttp.NewServeMux()
	mux.HandleFunc("/", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte(`<html><body><a href="/depth1">d1</a></body></html>`))
	})
	mux.HandleFunc("/depth1", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte(`<html><body><a href="/depth2">d2</a></body></html>`))
	})
	mux.HandleFunc("/depth2", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte(`<html><body>too deep</body></html>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	ip, port := testServerIPPort(t, srv)

	c := newTestCrawler()
	// MaxDepth 1: root (depth 0) + depth1 (depth 1) should be fetched;
	// depth2 (depth 2) should not be queued.
	pages, err := c.Crawl(context.Background(), ip, port, ip.String(), "http", "/", Options{MaxDepth: 1, MaxPages: 10, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("Crawl: %v", err)
	}
	for _, p := range pages {
		if p.URL != "" && strings.Contains(p.URL, "/depth2") {
			t.Errorf("crawled %q, which exceeds MaxDepth=1", p.URL)
		}
	}
	if len(pages) != 2 {
		t.Errorf("got %d pages, want exactly 2 (root + depth1)", len(pages))
	}
}

func TestCrawl_FormActionResolution(t *testing.T) {
	mux := nethttp.NewServeMux()
	mux.HandleFunc("/page/", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte(`<html><body>
			<form action="" method="post"></form>
			<form action="relative-submit" method="post"></form>
			<form action="/absolute-submit" method="get"></form>
		</body></html>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	ip, port := testServerIPPort(t, srv)

	c := newTestCrawler()
	pages, err := c.Crawl(context.Background(), ip, port, ip.String(), "http", "/page/", Options{MaxDepth: 0, MaxPages: 1, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("Crawl: %v", err)
	}
	if len(pages) != 1 || len(pages[0].Forms) != 3 {
		t.Fatalf("got %d pages with forms %+v, want 1 page with 3 forms", len(pages), pages)
	}

	forms := pages[0].Forms
	// An empty action means "submit to the current page" per the HTML
	// spec -- it must resolve to the page's own URL, not an empty string
	// or a bare "/".
	if !strings.HasSuffix(forms[0].Action, "/page/") {
		t.Errorf("empty action resolved to %q, want it to end in /page/ (the current page)", forms[0].Action)
	}
	if !strings.HasSuffix(forms[1].Action, "/page/relative-submit") {
		t.Errorf("relative action resolved to %q, want it to end in /page/relative-submit", forms[1].Action)
	}
	if !strings.HasSuffix(forms[2].Action, "/absolute-submit") {
		t.Errorf("absolute action resolved to %q, want it to end in /absolute-submit", forms[2].Action)
	}
}

func TestCrawl_NonHTMLResponseYieldsNoLinks(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"a href": "/should-not-be-parsed"}`))
	}))
	defer srv.Close()
	ip, port := testServerIPPort(t, srv)

	c := newTestCrawler()
	pages, err := c.Crawl(context.Background(), ip, port, ip.String(), "http", "/", Options{MaxDepth: 2, MaxPages: 10, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("Crawl: %v", err)
	}
	if len(pages) != 1 {
		t.Fatalf("got %d pages, want 1 (JSON body must not be parsed for links)", len(pages))
	}
	if len(pages[0].Links) != 0 {
		t.Errorf("Links = %+v, want empty for a non-HTML response", pages[0].Links)
	}
}

func TestCrawl_RejectsNonHTTPSchemeLinks(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte(`<html><body>
			<a href="javascript:alert(1)">js</a>
			<a href="mailto:test@example.com">mail</a>
			<a href="data:text/html,hi">data</a>
			<a href="#fragment-only">frag</a>
			<a href="/real-page">real</a>
		</body></html>`))
	}))
	defer srv.Close()
	ip, port := testServerIPPort(t, srv)

	c := newTestCrawler()
	pages, err := c.Crawl(context.Background(), ip, port, ip.String(), "http", "/", Options{MaxDepth: 0, MaxPages: 10, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("Crawl: %v", err)
	}
	if len(pages) != 1 {
		t.Fatalf("got %d pages, want 1", len(pages))
	}
	if len(pages[0].Links) != 1 {
		t.Fatalf("Links = %+v, want exactly 1 (only the real http-relative link)", pages[0].Links)
	}
}

func TestCrawl_ContextCancellationStopsPromptly(t *testing.T) {
	mux := nethttp.NewServeMux()
	for i := 0; i < 50; i++ {
		i := i
		mux.HandleFunc("/page"+strconv.Itoa(i), func(w nethttp.ResponseWriter, r *nethttp.Request) {
			w.Write([]byte(`<html><body><a href="/page` + strconv.Itoa(i+1) + `">next</a></body></html>`))
		})
	}
	mux.HandleFunc("/", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte(`<html><body><a href="/page0">start</a></body></html>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	ip, port := testServerIPPort(t, srv)

	c := newTestCrawler()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancelled before crawling starts

	done := make(chan struct{})
	go func() {
		c.Crawl(ctx, ip, port, ip.String(), "http", "/", Options{MaxDepth: 50, MaxPages: 50, Timeout: 5 * time.Second})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Crawl did not return promptly after context cancellation")
	}
}

func TestCrawl_NilIP(t *testing.T) {
	c := newTestCrawler()
	if _, err := c.Crawl(context.Background(), nil, 80, "example.com", "http", "/", Options{MaxPages: 1}); err == nil {
		t.Error("expected error for nil IP")
	}
}

// TestCrawl_JarAndExtraHeadersAttached is Phase 3.14/3.15's
// authenticated-crawling interface (Options.Jar/ExtraHeaders): the
// crawler itself knows nothing about sessions or authentication, only
// that a standard cookie jar/header map (if set) are attached to every
// request it makes.
func TestCrawl_JarAndExtraHeadersAttached(t *testing.T) {
	var gotCookie, gotHeader string
	mux := nethttp.NewServeMux()
	mux.HandleFunc("/", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		if c, err := r.Cookie("session"); err == nil {
			gotCookie = c.Value
		}
		gotHeader = r.Header.Get("X-Custom-Auth")
		w.Write([]byte(`<html><body>ok</body></html>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	ip, port := testServerIPPort(t, srv)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	jar.SetCookies(&url.URL{Scheme: "http", Host: fmt.Sprintf("%s:%d", ip.String(), port)},
		[]*nethttp.Cookie{{Name: "session", Value: "authenticated-session-value"}})

	c := newTestCrawler()
	_, err = c.Crawl(context.Background(), ip, port, ip.String(), "http", "/", Options{
		MaxDepth: 1, MaxPages: 1, Timeout: 5 * time.Second,
		Jar:          jar,
		ExtraHeaders: map[string]string{"X-Custom-Auth": "custom-header-value"},
	})
	if err != nil {
		t.Fatalf("Crawl: %v", err)
	}
	if gotCookie != "authenticated-session-value" {
		t.Errorf("server saw cookie %q, want authenticated-session-value", gotCookie)
	}
	if gotHeader != "custom-header-value" {
		t.Errorf("server saw header %q, want custom-header-value", gotHeader)
	}
}

// TestCrawl_JarSurvivesSameHostRedirect proves the fix for the gap
// Phase 3.15 found in Phase 3.14's original manual-per-request cookie
// attachment: a same-host redirect mid-crawl must still carry the
// session cookie to the redirect target.
func TestCrawl_JarSurvivesSameHostRedirect(t *testing.T) {
	var gotCookie string
	mux := nethttp.NewServeMux()
	mux.HandleFunc("/start", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		nethttp.Redirect(w, r, "/final", nethttp.StatusFound)
	})
	mux.HandleFunc("/final", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		if c, err := r.Cookie("session"); err == nil {
			gotCookie = c.Value
		}
		w.Write([]byte(`<html><body>ok</body></html>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	ip, port := testServerIPPort(t, srv)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	jar.SetCookies(&url.URL{Scheme: "http", Host: fmt.Sprintf("%s:%d", ip.String(), port)},
		[]*nethttp.Cookie{{Name: "session", Value: "survives-redirect"}})

	c := newTestCrawler()
	_, err = c.Crawl(context.Background(), ip, port, ip.String(), "http", "/start", Options{
		MaxDepth: 0, MaxPages: 1, Timeout: 5 * time.Second, Jar: jar,
	})
	if err != nil {
		t.Fatalf("Crawl: %v", err)
	}
	if gotCookie != "survives-redirect" {
		t.Errorf("cookie did not survive a same-host redirect: got %q, want survives-redirect", gotCookie)
	}
}

// newIPServer starts an httptest server bound to a specific loopback IP
// (rather than the default 127.0.0.1 every httptest.NewServer call
// would otherwise share) -- required for a genuine cross-HOST test:
// two httptest.NewServer instances both default to 127.0.0.1, differing
// only by PORT, which is NOT what "a different host" means for
// hostname-based header pinning or cookie domain matching (an earlier
// version of TestCrawl_ExtraHeadersNeverLeakToCrossHostRedirect used
// plain httptest.NewServer for both servers and consequently was never
// actually testing cross-host behavior at all -- both "hosts" resolved
// to the identical hostname "127.0.0.1" -- see
// docs/phase-3-15-authenticated-crawling.md "Why a shared pinned
// transport" for this corrected finding).
func newIPServer(t *testing.T, ip string, handler nethttp.Handler) *httptest.Server {
	t.Helper()
	listener, err := net.Listen("tcp", net.JoinHostPort(ip, "0"))
	if err != nil {
		t.Fatalf("listen on %s: %v", ip, err)
	}
	srv := httptest.NewUnstartedServer(handler)
	srv.Listener.Close()
	srv.Listener = listener
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}

// TestCrawl_ExtraHeadersNeverLeakToCrossHostRedirect is the crawler-level
// proof that a header set for THIS crawl's own host is never forwarded
// to a genuinely DIFFERENT host reached via a same-request redirect.
// net/http's own client already strips manually-set Cookie/Authorization
// headers across a real cross-host redirect (verified independently
// during this phase's development); safedial.PinnedRoundTripper's
// per-hop host check is defense in depth on top of that, and this test
// proves the combination holds for the crawler specifically.
func TestCrawl_ExtraHeadersNeverLeakToCrossHostRedirect(t *testing.T) {
	var evilGotAuth, evilGotCookie string
	evilMux := nethttp.NewServeMux()
	evilMux.HandleFunc("/", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		evilGotAuth = r.Header.Get("Authorization")
		if c, err := r.Cookie("session"); err == nil {
			evilGotCookie = c.Value
		}
		w.Write([]byte("ok"))
	})
	evilSrv := newIPServer(t, "127.0.0.60", evilMux)

	mainMux := nethttp.NewServeMux()
	mainMux.HandleFunc("/start", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		nethttp.Redirect(w, r, fmt.Sprintf("http://%s/", evilSrv.Listener.Addr().String()), nethttp.StatusFound)
	})
	mainSrv := newIPServer(t, "127.0.0.61", mainMux)
	mainIP, mainPort := testServerIPPort(t, mainSrv)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	jar.SetCookies(&url.URL{Scheme: "http", Host: fmt.Sprintf("%s:%d", mainIP.String(), mainPort)},
		[]*nethttp.Cookie{{Name: "session", Value: "must-not-leak"}})

	// allowAllValidator: this test isolates the crawler's own
	// pinning/jar-domain behavior, not scope enforcement (a real,
	// out-of-scope redirect target is separately, unconditionally
	// refused by safedial regardless of this mechanism -- see
	// TestCrawl_OutOfScopeRedirect elsewhere).
	c := NewNativeCrawler(safedial.New(allowAllValidator{}, dns.NewFakeResolver()))
	_, err = c.Crawl(context.Background(), mainIP, mainPort, mainIP.String(), "http", "/start", Options{
		MaxDepth: 0, MaxPages: 1, Timeout: 5 * time.Second, Jar: jar,
		ExtraHeaders: map[string]string{"Authorization": "Bearer must-not-leak-either"},
	})
	if err != nil {
		t.Fatalf("Crawl: %v", err)
	}
	if evilGotAuth != "" {
		t.Fatalf("SECURITY: Authorization header leaked to a cross-host redirect target: %q", evilGotAuth)
	}
	if evilGotCookie != "" {
		t.Fatalf("SECURITY: session cookie leaked to a cross-host redirect target: %q", evilGotCookie)
	}
}

// TestCrawl_NoCookiesOrHeaders_UnaffectedBehavior is a regression guard:
// the zero-value Options (every pre-Phase-3.14 caller) must crawl
// identically to before this field existed.
func TestCrawl_NoCookiesOrHeaders_UnaffectedBehavior(t *testing.T) {
	mux := nethttp.NewServeMux()
	mux.HandleFunc("/", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		if _, err := r.Cookie("session"); err == nil {
			t.Error("no cookie was configured, but the server received one")
		}
		w.Write([]byte(`<html><body>ok</body></html>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	ip, port := testServerIPPort(t, srv)

	c := newTestCrawler()
	pages, err := c.Crawl(context.Background(), ip, port, ip.String(), "http", "/", Options{MaxDepth: 1, MaxPages: 1, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("Crawl: %v", err)
	}
	if len(pages) != 1 {
		t.Fatalf("got %d pages, want 1", len(pages))
	}
}
