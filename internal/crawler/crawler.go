// Package crawler discovers pages reachable from a starting HTTP(S)
// service by following same-origin links, forms, and script references.
// Crawler is the pluggable interface; NewNativeCrawler is the built-in
// implementation, leaving room for an external tool (e.g. katana) later
// via pkg/plugins without changing callers.
//
// The native crawler deliberately stays within the exact origin
// (scheme+host+port) it started at -- every fetch reuses the same
// already-resolved, already-scope-validated IP via safedial.Dialer, the
// same mechanism internal/http's Prober uses, so crawling introduces no
// new scope-validation surface: it never resolves or dials a different
// host. A link pointing elsewhere is recorded as an external link, not
// followed.
package crawler

import (
	"context"
	"fmt"
	"io"
	"net"
	nethttp "net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/html"

	"sakanner/internal/safedial"
)

// FormField is one named input discovered inside a FormRef -- Phase
// 3.13's extension to form discovery (previously only Action/Method
// were captured). Only fields that represent a meaningful application
// input are collected: submit/button/image/reset controls are
// deliberately excluded (see fieldTypeIsInput), matching task's "do
// not treat submit buttons as vulnerability parameters."
type FormField struct {
	Name  string
	Type  string // text, password, hidden, textarea, select, checkbox, radio, email, number, tel, url, search, date, ... (input type attribute, lowercased; "textarea"/"select" for those elements)
	Value string // the observed/default value already present in the markup -- never a payload (see internal/parameters' doc comment on value handling)
}

// FormRef is a discovered HTML form.
type FormRef struct {
	Action string
	Method string
	Fields []FormField
}

// Page is one fetched page's crawl-relevant content.
type Page struct {
	URL        string
	StatusCode int
	Links      []string // same-origin absolute URLs found via <a href>
	Forms      []FormRef
	Scripts    []string // absolute URLs of <script src="...">

	// ContentType is the response's own Content-Type header, always
	// recorded regardless of what kind of body follows (Phase 3.18) --
	// strictly additive: nothing before Phase 3.18 read this field,
	// because it didn't exist.
	ContentType string
	// ResponseBody is populated ONLY when ContentType indicates JSON
	// (Phase 3.18's live JSON-response capture -- see
	// docs/phase-3-18-api-json-discovery.md section 3 for why a
	// RESPONSE body, never a request body: this crawler never issues
	// anything but GET). Every other content type (HTML, images, other
	// binary) leaves this nil, exactly as every page's body was
	// already discarded unread before Phase 3.18 existed -- no new
	// bandwidth/memory cost for non-JSON responses. Bounded by the
	// same maxCrawlBodySample the HTML parse path already enforces.
	ResponseBody []byte
}

// Options bounds a crawl.
type Options struct {
	MaxDepth int // 0 means only the start page itself
	MaxPages int
	Timeout  time.Duration // per-request timeout

	// Jar/ExtraHeaders, if set, carry session state for this crawl --
	// Phase 3.14/3.15's authenticated-crawling interface (see
	// docs/phase-3-15-authenticated-crawling.md "Session-aware
	// crawler"). This package stays independent from internal/auth: the
	// caller (internal/orchestration.Pipeline) derives these primitive,
	// standard-library values from a Session (Session.JarFor/HeadersFor,
	// both already host-pinned to the session's own host) -- this
	// package accepts and forwards them without knowing what a
	// "session" or "profile" is.
	//
	// Jar is a standard nethttp.CookieJar (not a raw cookie slice, as
	// Phase 3.14 originally used): net/http attaches its cookies to
	// every request AND every redirect hop automatically, and RFC 6265
	// domain matching means it is safe to hand the SAME jar to crawls of
	// different hosts within one scan -- a cookie is only ever released
	// for the domain it was scoped to. This also lets a crawl capture a
	// session-refresh cookie the target sends mid-crawl back into the
	// jar, exactly as a real browser would.
	//
	// ExtraHeaders (Authorization, or a custom header) are attached via
	// safedial.PinnedRoundTripper -- checked per actual outgoing
	// request, including every redirect hop, so a same-crawl redirect
	// to a DIFFERENT host never receives them, matching this crawl's
	// own cookie jar's per-domain isolation. See PinnedRoundTripper's
	// doc comment for exactly what this does and does not add on top of
	// net/http's own (already correct) cross-host redirect behavior.
	Jar          nethttp.CookieJar
	ExtraHeaders map[string]string
}

// Crawler discovers pages starting from one HTTP(S) service.
type Crawler interface {
	Name() string
	// Crawl fetches startPath (relative to scheme://hostname:port) and
	// follows same-origin links breadth-first, bounded by opts. ip must
	// already be scope-validated by the caller, exactly as with
	// internal/http.Prober.
	Crawl(ctx context.Context, ip net.IP, port int, hostname, scheme, startPath string, opts Options) ([]Page, error)
}

type nativeCrawler struct {
	dialer *safedial.Dialer
}

// NewNativeCrawler returns a Crawler built on safedial.Dialer, so every
// fetch it makes goes through the same scope-safe dialing logic as
// internal/http.Prober.
func NewNativeCrawler(dialer *safedial.Dialer) Crawler {
	return &nativeCrawler{dialer: dialer}
}

func (c *nativeCrawler) Name() string { return "native" }

// maxCrawlBodySample bounds how much of each crawled page's body is
// parsed, matching the same rationale as internal/http's body sampling.
const maxCrawlBodySample = 512 * 1024

type queueItem struct {
	path  string
	depth int
}

func (c *nativeCrawler) Crawl(ctx context.Context, ip net.IP, port int, hostname, scheme, startPath string, opts Options) ([]Page, error) {
	if ip == nil {
		return nil, fmt.Errorf("crawler: nil IP")
	}
	if opts.MaxPages <= 0 {
		opts.MaxPages = 1
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}

	origin := fmt.Sprintf("%s:%d", hostname, port)
	client := c.dialer.NewClient(hostname, ip, nil, nil, opts.Timeout, 3)
	if opts.Jar != nil {
		client.Jar = opts.Jar
	}
	if len(opts.ExtraHeaders) > 0 {
		client.Transport = &safedial.PinnedRoundTripper{Base: client.Transport, Headers: opts.ExtraHeaders, PinnedHost: hostname}
	}

	visited := map[string]bool{}
	queue := []queueItem{{path: normalizePath(startPath), depth: 0}}
	var pages []Page

	for len(queue) > 0 && len(pages) < opts.MaxPages {
		if err := ctx.Err(); err != nil {
			return pages, err
		}

		item := queue[0]
		queue = queue[1:]
		if visited[item.path] {
			continue
		}
		visited[item.path] = true

		pageURL := &url.URL{Scheme: scheme, Host: origin, Path: item.path}
		page, links, err := c.fetchAndParse(ctx, client, pageURL)
		if err != nil {
			continue // a single broken/unreachable page doesn't abort the crawl
		}
		pages = append(pages, page)

		if item.depth >= opts.MaxDepth {
			continue
		}
		for _, link := range links {
			if visited[link] || len(queue)+len(pages) >= opts.MaxPages {
				continue
			}
			queue = append(queue, queueItem{path: link, depth: item.depth + 1})
		}
	}

	return pages, nil
}

func (c *nativeCrawler) fetchAndParse(ctx context.Context, client *nethttp.Client, pageURL *url.URL) (Page, []string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	req, err := nethttp.NewRequestWithContext(ctx, nethttp.MethodGet, pageURL.String(), nil)
	if err != nil {
		return Page{}, nil, fmt.Errorf("crawler: build request: %w", err)
	}
	// Cookies/headers are no longer attached here, per-request: they are
	// attached once, at client-construction time in Crawl, via
	// client.Jar (cookies) and PinnedRoundTripper (headers) -- both of
	// which are invoked by net/http itself for EVERY request this
	// client makes, including redirect hops, which a per-request
	// req.AddCookie/req.Header.Set here could not achieve (see
	// Options.Jar's doc comment).
	resp, err := client.Do(req)
	if err != nil {
		return Page{}, nil, fmt.Errorf("crawler: request %s: %w", pageURL, err)
	}
	defer resp.Body.Close()

	ct := resp.Header.Get("Content-Type")
	page := Page{URL: pageURL.String(), StatusCode: resp.StatusCode, ContentType: ct}

	if ct != "" && !strings.Contains(strings.ToLower(ct), "html") {
		// Phase 3.18: a JSON response's body is captured (bounded,
		// exactly like the HTML path below) for live JSON discovery --
		// see docs/phase-3-18-api-json-discovery.md section 3. Every
		// other non-HTML content type is left exactly as before: not
		// read at all.
		if strings.Contains(strings.ToLower(ct), "json") {
			body, err := io.ReadAll(io.LimitReader(resp.Body, maxCrawlBodySample))
			if err == nil {
				page.ResponseBody = body
			}
		}
		return page, nil, nil // non-HTML response: nothing to extract, not an error
	}

	body := io.LimitReader(resp.Body, maxCrawlBodySample)
	links, forms, scripts := extractRefs(body, resp.Request.URL)

	var samePathLinks []string
	for _, link := range links {
		if link.Host != resp.Request.URL.Host {
			continue // external link: recorded nowhere further, not followed
		}
		page.Links = append(page.Links, link.String())
		samePathLinks = append(samePathLinks, normalizePath(link.Path))
	}
	page.Forms = forms
	for _, s := range scripts {
		page.Scripts = append(page.Scripts, s.String())
	}

	return page, samePathLinks, nil
}

// extractRefs walks the parsed HTML tree once, collecting every <a
// href>, <form action>, and <script src> resolved to an absolute URL
// against base. A malformed document (unparseable, or one that yields no
// tokens) simply produces no references rather than an error -- crawling
// a page with slightly invalid HTML should degrade gracefully, not abort
// the crawl.
func extractRefs(body io.Reader, base *url.URL) (links []*url.URL, forms []FormRef, scripts []*url.URL) {
	doc, err := html.Parse(body)
	if err != nil {
		return nil, nil, nil
	}

	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "a":
				if href, ok := attr(n, "href"); ok {
					if u := resolve(base, href); u != nil {
						links = append(links, u)
					}
				}
			case "form":
				// A missing/empty action means "submit to the current
				// page" per the HTML spec -- resolve against base just
				// like links/scripts so FormRef.Action is always a
				// proper absolute URL, never a bare relative fragment or
				// empty string.
				actionAttr, _ := attr(n, "action")
				action := base.String()
				if u := resolve(base, actionAttr); u != nil {
					action = u.String()
				}
				method, ok := attr(n, "method")
				if !ok || method == "" {
					method = "GET"
				}
				forms = append(forms, FormRef{Action: action, Method: strings.ToUpper(method), Fields: extractFormFields(n)})
			case "script":
				if src, ok := attr(n, "src"); ok {
					if u := resolve(base, src); u != nil {
						scripts = append(scripts, u)
					}
				}
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(doc)

	return links, forms, scripts
}

// nonInputControlTypes are <input type="..."> values that submit an
// action rather than carry application data -- excluded from
// discovery entirely, never merely deprioritized, per task's "do not
// treat submit buttons as vulnerability parameters." "file" is also
// excluded: a file upload's meaningful attack surface is its content,
// not a string VALUE this model represents, and this phase explicitly
// does not implement file upload of any kind.
var nonInputControlTypes = map[string]bool{
	"submit": true, "button": true, "image": true, "reset": true, "file": true,
}

// extractFormFields walks a <form> element's own subtree (form is
// itself the root passed in) collecting every named <input>/<select>/
// <textarea> found anywhere beneath it -- a separate, nested walk from
// extractRefs' own top-level one, so a form's fields are always
// associated with exactly the form that contains them regardless of
// arbitrary nesting depth. A field with no "name" attribute is not
// collected: an unnamed control is never actually submitted by a
// browser, so it carries no parameter identity to discover.
func extractFormFields(form *html.Node) []FormField {
	var fields []FormField

	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "input":
				name, ok := attr(n, "name")
				if ok && name != "" {
					typ, _ := attr(n, "type")
					typ = strings.ToLower(strings.TrimSpace(typ))
					if typ == "" {
						typ = "text" // HTML default when the type attribute is omitted
					}
					if !nonInputControlTypes[typ] {
						value, _ := attr(n, "value")
						fields = append(fields, FormField{Name: name, Type: typ, Value: value})
					}
				}
			case "select":
				name, ok := attr(n, "name")
				if ok && name != "" {
					fields = append(fields, FormField{Name: name, Type: "select", Value: selectedOptionValue(n)})
				}
				// Do not recurse into a <select>'s own <option> children --
				// they are never independently-named inputs of their own.
				return
			case "textarea":
				name, ok := attr(n, "name")
				if ok && name != "" {
					fields = append(fields, FormField{Name: name, Type: "textarea", Value: textContent(n)})
				}
				return
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	// Walk the form's CHILDREN, not the form node itself -- form is not
	// itself an <input>/<select>/<textarea>, so starting the switch on
	// it would just fall through uselessly every time.
	for child := form.FirstChild; child != nil; child = child.NextSibling {
		walk(child)
	}
	return fields
}

// selectedOptionValue returns the value a browser would submit for a
// <select> with no JavaScript interaction: the first <option> carrying
// a "selected" attribute, or the first <option> at all if none is
// marked selected (the HTML spec's own default), or "" if the select
// has no options.
func selectedOptionValue(sel *html.Node) string {
	var first, selected *html.Node
	for child := sel.FirstChild; child != nil; child = child.NextSibling {
		if child.Type != html.ElementNode || child.Data != "option" {
			continue
		}
		if first == nil {
			first = child
		}
		if _, ok := attr(child, "selected"); ok {
			selected = child
			break
		}
	}
	target := selected
	if target == nil {
		target = first
	}
	if target == nil {
		return ""
	}
	if v, ok := attr(target, "value"); ok {
		return v
	}
	return textContent(target)
}

// textContent concatenates n's own direct text-node children -- used
// for <textarea>/<option> elements, whose value is their text content
// rather than a "value" attribute.
func textContent(n *html.Node) string {
	var b strings.Builder
	for child := n.FirstChild; child != nil; child = child.NextSibling {
		if child.Type == html.TextNode {
			b.WriteString(child.Data)
		}
	}
	return strings.TrimSpace(b.String())
}

func attr(n *html.Node, name string) (string, bool) {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, name) {
			return a.Val, true
		}
	}
	return "", false
}

// resolve turns a possibly-relative reference into an absolute URL
// against base, rejecting anything that isn't a plausible http(s)-style
// reference (e.g. "javascript:", "mailto:", "data:" URIs).
func resolve(base *url.URL, ref string) *url.URL {
	ref = strings.TrimSpace(ref)
	if ref == "" || strings.HasPrefix(ref, "#") {
		return nil
	}
	if strings.Contains(ref, ":") {
		if u, err := url.Parse(ref); err == nil && u.Scheme != "" && u.Scheme != "http" && u.Scheme != "https" {
			return nil // javascript:, mailto:, data:, tel:, etc.
		}
	}
	u, err := url.Parse(ref)
	if err != nil {
		return nil
	}
	resolved := base.ResolveReference(u)
	if resolved.Scheme != "http" && resolved.Scheme != "https" {
		return nil
	}
	return resolved
}

func normalizePath(p string) string {
	if p == "" {
		return "/"
	}
	return p
}
