package crawler

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"path/filepath"
	"testing"

	"sakanner/internal/dns"
	"sakanner/internal/safedial"
	"sakanner/internal/testutil"
)

func TestKatanaCrawler_ParsesDiscoveredEndpoints(t *testing.T) {
	binary := testutil.WriteScript(t, "katana", `
echo '{"request":{"endpoint":"https://example.com/"},"response":{"status_code":200}}'
echo 'a stray banner line'
echo '{"request":{"endpoint":"https://example.com/about"},"response":{"status_code":200}}'
exit 0
`)
	c := NewKatanaCrawler(binary)
	if c.Name() != "katana" {
		t.Errorf("Name() = %q, want katana", c.Name())
	}

	pages, err := c.Crawl(context.Background(), net.ParseIP("203.0.113.5"), 443, "example.com", "https", "/", Options{MaxDepth: 2, MaxPages: 10})
	if err != nil {
		t.Fatalf("Crawl: %v", err)
	}
	if len(pages) != 2 {
		t.Fatalf("got %d pages, want 2: %+v", len(pages), pages)
	}
	if pages[0].URL != "https://example.com/" || pages[0].StatusCode != 200 {
		t.Errorf("pages[0] = %+v", pages[0])
	}
	if pages[1].URL != "https://example.com/about" {
		t.Errorf("pages[1] = %+v", pages[1])
	}
}

func TestKatanaCrawler_StopsAtMaxPages(t *testing.T) {
	binary := testutil.WriteScript(t, "katana", `
echo '{"request":{"endpoint":"https://example.com/a"},"response":{"status_code":200}}'
echo '{"request":{"endpoint":"https://example.com/b"},"response":{"status_code":200}}'
echo '{"request":{"endpoint":"https://example.com/c"},"response":{"status_code":200}}'
exit 0
`)
	c := NewKatanaCrawler(binary)
	pages, err := c.Crawl(context.Background(), net.ParseIP("203.0.113.5"), 443, "example.com", "https", "/", Options{MaxDepth: 2, MaxPages: 2})
	if err != nil {
		t.Fatalf("Crawl: %v", err)
	}
	if len(pages) != 2 {
		t.Fatalf("got %d pages, want 2 (MaxPages bound): %+v", len(pages), pages)
	}
}

func TestNewCrawlerForBackend_BackendSelection(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	dialer := safedial.New(allowAllValidator{}, dns.NewFakeResolver())

	c, err := NewCrawlerForBackend("native", dialer, logger)
	if err != nil {
		t.Fatalf("NewCrawlerForBackend(native): %v", err)
	}
	if c.Name() != "native" {
		t.Errorf("backend=native: Name() = %q, want native", c.Name())
	}

	if _, err := NewCrawlerForBackend("not-a-real-backend", dialer, logger); err == nil {
		t.Error("NewCrawlerForBackend(garbage backend) = nil error, want an error")
	}
}

func TestNewCrawlerForBackend_AutoUsesKatanaWhenPresent(t *testing.T) {
	binary := testutil.WriteScript(t, "katana", "exit 0\n")
	t.Setenv("PATH", filepath.Dir(binary))

	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	dialer := safedial.New(allowAllValidator{}, dns.NewFakeResolver())

	c, err := NewCrawlerForBackend("auto", dialer, logger)
	if err != nil {
		t.Fatalf("NewCrawlerForBackend(auto): %v", err)
	}
	if c.Name() != "katana" {
		t.Errorf("Name() = %q, want katana when it's present on PATH", c.Name())
	}
}

func TestNewCrawlerForBackend_AutoFallsBackWhenKatanaAbsent(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	dialer := safedial.New(allowAllValidator{}, dns.NewFakeResolver())

	c, err := NewCrawlerForBackend("auto", dialer, logger)
	if err != nil {
		t.Fatalf("NewCrawlerForBackend(auto): %v", err)
	}
	if c.Name() != "native" {
		t.Errorf("Name() = %q, want native when katana is absent", c.Name())
	}
}
