package crawler

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"

	"sakanner/internal/safedial"
	"sakanner/pkg/plugins"
)

// NewCrawlerForBackend selects a Crawler per sakanner's uniform
// auto|native|<tool> backend contract (see pkg/plugins.Resolve): katana
// if backend selects it, the built-in native crawler otherwise. katana
// dials its own sockets from its own process (pkg/plugins' Trust
// boundary), so this stage is sensitive -- Resolve logs accordingly
// whenever katana is actually selected.
func NewCrawlerForBackend(backend string, dialer *safedial.Dialer, logger *slog.Logger) (Crawler, error) {
	decision, err := plugins.Resolve(backend, plugins.Katana, true, logger)
	if err != nil {
		return nil, err
	}
	if decision == plugins.UseTool {
		path, _ := plugins.Detect(plugins.Katana.BinaryName)
		return NewKatanaCrawler(path), nil
	}
	return NewNativeCrawler(dialer), nil
}

type katanaCrawler struct {
	binary string
}

// NewKatanaCrawler returns a Crawler backed by the katana CLI tool
// (found at binary). Unlike the native crawler, katana performs its own
// DNS resolution and dialing for the hostname it's given rather than
// being handed the already-validated literal IP -- the residual
// DNS-rebinding exposure pkg/plugins' package doc documents for any
// dial-performing external tool backend. ip is accepted to satisfy the
// Crawler interface but is not otherwise used.
//
// katana reports each discovered URL as a flat, already-crawled result
// rather than a page-with-outgoing-links graph, so every result here is
// modeled as a Page whose URL is the discovered endpoint with no
// separate Links/Forms/Scripts populated -- endpoints.Normalize will
// record each as a crawl-sourced Endpoint. This is coarser than the
// native crawler's per-origin (link/form/javascript) classification.
func NewKatanaCrawler(binary string) Crawler {
	return &katanaCrawler{binary: binary}
}

func (c *katanaCrawler) Name() string { return "katana" }

// katanaLine models the subset of katana's -json output this package
// reads. Field names follow katana's documented jsonl convention as of
// this writing; verify against the installed katana version if crawling
// silently yields nothing.
type katanaLine struct {
	Request struct {
		Endpoint string `json:"endpoint"`
	} `json:"request"`
	Response struct {
		StatusCode int `json:"status_code"`
	} `json:"response"`
}

var errKatanaMaxPagesReached = errors.New("crawler: reached max pages")

func (c *katanaCrawler) Crawl(ctx context.Context, ip net.IP, port int, hostname, scheme, startPath string, opts Options) ([]Page, error) {
	if opts.MaxPages <= 0 {
		opts.MaxPages = 1
	}
	startURL := fmt.Sprintf("%s://%s:%d%s", scheme, hostname, port, startPath)
	args := []string{"-u", startURL, "-depth", fmt.Sprintf("%d", opts.MaxDepth), "-jc", "-silent", "-json", "-no-color"}

	var pages []Page
	err := plugins.RunJSONLines(ctx, c.binary, args, func(line katanaLine) error {
		if line.Request.Endpoint == "" {
			return nil
		}
		pages = append(pages, Page{URL: line.Request.Endpoint, StatusCode: line.Response.StatusCode})
		if len(pages) >= opts.MaxPages {
			return errKatanaMaxPagesReached
		}
		return nil
	})
	if err != nil && !errors.Is(err, errKatanaMaxPagesReached) {
		return pages, fmt.Errorf("crawler: katana %s: %w", startURL, err)
	}
	return pages, nil
}
