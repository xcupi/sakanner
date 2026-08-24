package crawler

import (
	"context"
	nethttp "net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Phase 3.15 task section H/Q's crawler-level adversarial suite:
// encoded/protocol-relative out-of-scope URL bypass attempts, and a
// redirect loop encountered mid-crawl. Task section H's own tests
// (login URL/form action/redirect outside scope) live in
// internal/auth; these test the CRAWLER's own link-following/same-
// origin filter specifically, which is what actually decides whether a
// discovered link is ever fetched at all.

// TestCrawl_ProtocolRelativeLink_NotFollowed is task section H's
// "protocol-relative out-of-scope URLs": "//evil.test/path" resolves
// (per net/url's own reference-resolution rules) to the SAME scheme as
// the current page but a DIFFERENT host -- the crawler's same-origin
// filter must exclude it exactly like an absolute cross-origin link.
func TestCrawl_ProtocolRelativeLink_NotFollowed(t *testing.T) {
	mux := nethttp.NewServeMux()
	mux.HandleFunc("/", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Write([]byte(`<html><body><a href="//evil.test/steal">protocol-relative</a></body></html>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	ip, port := testServerIPPort(t, srv)

	c := newTestCrawler()
	pages, err := c.Crawl(context.Background(), ip, port, ip.String(), "http", "/", Options{MaxDepth: 2, MaxPages: 10, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("Crawl: %v", err)
	}
	if len(pages) != 1 {
		t.Fatalf("got %d pages, want exactly 1 (evil.test must never be fetched): %+v", len(pages), pages)
	}
	if len(pages[0].Links) != 0 {
		t.Errorf("root.Links = %+v, want the protocol-relative external link excluded from further crawling", pages[0].Links)
	}
}

// TestCrawl_UserinfoObfuscatedLink_HostCorrectlyIdentified is task
// section H's "encoded out-of-scope URLs": a classic bypass pattern
// against a NAIVE "does the string contain our domain" check --
// "http://real-looking-host@evil.test/" -- where a naive substring
// check might be fooled by the URL containing the trusted hostname
// textually. net/url correctly parses "evil.test" as the actual Host
// and "real-looking-host" as Userinfo; the crawler's same-origin filter
// compares the PARSED Host, so it is not fooled.
func TestCrawl_UserinfoObfuscatedLink_HostCorrectlyIdentified(t *testing.T) {
	mux := nethttp.NewServeMux()
	mux.HandleFunc("/", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		// The link's own text contains r.Host (the trusted-looking
		// prefix an attacker hopes a naive check matches against),
		// followed by "@evil.test" -- the ACTUAL host per URL syntax.
		w.Write([]byte(`<html><body><a href="http://` + r.Host + `@evil.test/steal">obfuscated</a></body></html>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	ip, port := testServerIPPort(t, srv)

	c := newTestCrawler()
	pages, err := c.Crawl(context.Background(), ip, port, ip.String(), "http", "/", Options{MaxDepth: 2, MaxPages: 10, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("Crawl: %v", err)
	}
	if len(pages) != 1 {
		t.Fatalf("got %d pages, want exactly 1 (the userinfo-obfuscated evil.test link must never be fetched): %+v", len(pages), pages)
	}
	if len(pages[0].Links) != 0 {
		t.Errorf("root.Links = %+v, want the obfuscated external link excluded from further crawling", pages[0].Links)
	}
}

// TestCrawl_RedirectLoop_DoesNotHang is task section Q's "infinite
// authentication redirects" generalized to any redirect loop
// encountered mid-crawl: a page that redirects to itself must not hang
// the crawl -- safedial's own maxRedirects bound (see
// internal/safedial.Dialer.NewClient) truncates the chain.
func TestCrawl_RedirectLoop_DoesNotHang(t *testing.T) {
	mux := nethttp.NewServeMux()
	mux.HandleFunc("/loop", func(w nethttp.ResponseWriter, r *nethttp.Request) {
		nethttp.Redirect(w, r, "/loop", nethttp.StatusFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	ip, port := testServerIPPort(t, srv)

	c := newTestCrawler()
	done := make(chan struct{})
	go func() {
		_, _ = c.Crawl(context.Background(), ip, port, ip.String(), "http", "/loop", Options{MaxDepth: 1, MaxPages: 5, Timeout: 5 * time.Second})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Crawl did not return within 10s against a self-redirecting page -- possible hang on a redirect loop")
	}
}
