package auth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/html"
)

const (
	// maxDiscoveryPages bounds how many pages this package will ever
	// fetch while looking for a login form during ONE authentication
	// attempt: the start page, plus at most this many additional
	// same-origin "login-like" links followed. This is a discovery
	// bound only -- it never itself involves a credential submission
	// (see AutoFormLoginProvider's own doc comment); the single,
	// separate credential-submission step happens at most once,
	// regardless of how many pages discovery examined.
	maxDiscoveryPages = 3
	// maxCandidateLinks bounds how many same-origin "login-like" links
	// found on one page are even scored/considered.
	maxCandidateLinks = 20
)

// loginLinkKeywords are application-agnostic words/phrases commonly
// used for a login page's own link text, URL path, form action, or
// page title -- deliberately generic English login vocabulary, never
// a specific application's own wording or path (task's explicit
// "heuristics must be application-agnostic, do not hardcode
// DVWA/application-specific paths or strings" requirement).
var loginLinkKeywords = []string{
	"log in", "login", "log-in", "sign in", "signin", "sign-in", "log on", "logon",
}

// usernameKeywords are application-agnostic words used to recognize a
// likely username/email field by its name/id/label -- same genericity
// requirement as loginLinkKeywords above.
var usernameKeywords = []string{"user", "email", "e-mail", "login", "account"}

// AutoFormLoginProvider implements Provider for TypeFormLoginAuto:
// discover a conventional username/password HTML login form starting
// from Profile.StartURL, then submit credentials through it via the
// exact same submitCredentials logic FormLoginProvider itself uses
// (formlogin.go) -- discovery only ever determines WHERE and WHAT to
// submit; how a login is submitted, redirects followed, and success
// evaluated is byte-for-byte the same code path form_login already
// uses and has always used.
//
// Bounded, deterministic, single-attempt by construction: discovery
// fetches at most maxDiscoveryPages pages (read-only GETs, never a
// credential), picks exactly one form via scoreForm/
// identifyUsernameField (never tries more than one), and
// submitCredentials is called exactly once regardless of how many
// candidate pages/forms were considered -- this type never retries a
// failed login with a different guess, a different form, or a
// different field, and never sends credentials anywhere until a form
// has been positively identified as password-bearing (task's "do not
// send credentials to a form that is not sufficiently identified as a
// likely authentication form").
type AutoFormLoginProvider struct {
	Profile Profile
}

func (ap *AutoFormLoginProvider) Authenticate(ctx context.Context, deps Dependencies) (*Session, error) {
	p := ap.Profile
	sess := &Session{ProfileName: p.Name, Type: p.Type, Host: p.Host, State: StateAuthenticating, CreatedAt: time.Now().UTC()}

	if p.StartURL == nil {
		return failSession(sess, fmt.Errorf("auth: profile %q has no start_url", p.Name))
	}
	if deps.Dialer == nil {
		return failSession(sess, fmt.Errorf("auth: profile %q: no dialer supplied", p.Name))
	}

	ctx, cancel := context.WithTimeout(ctx, p.Timeout)
	defer cancel()

	client, jar, err := newScopedDiscoveryClient(ctx, deps, p.StartURL, p.Timeout, p.MaxRedirects)
	if err != nil {
		return failSession(sess, fmt.Errorf("auth: profile %q: %w", p.Name, err))
	}

	form, pageURL, err := discoverLoginForm(ctx, client, p.StartURL)
	if err != nil {
		return failSession(sess, fmt.Errorf("auth: profile %q: automatic login-form discovery failed: %w", p.Name, err))
	}
	usernameField, ok := identifyUsernameField(form)
	if !ok {
		return failSession(sess, fmt.Errorf("auth: profile %q: found a likely login form at %s but could not identify a username field", p.Name, pageURL))
	}
	passwordField, ok := identifyPasswordField(form)
	if !ok {
		// Unreachable in practice -- discoverLoginForm only ever
		// returns a form with HasPassword true -- but checked
		// explicitly rather than assumed, matching this file's own
		// "never guess, never submit to an insufficiently-identified
		// form" discipline throughout.
		return failSession(sess, fmt.Errorf("auth: profile %q: found a likely login form at %s but could not identify its password field", p.Name, pageURL))
	}

	actionURL, err := url.Parse(form.Action)
	if err != nil {
		return failSession(sess, fmt.Errorf("auth: profile %q: discovered login form action %q: %w", p.Name, form.Action, err))
	}

	// derived carries the profile's own credentials/timeouts/etc.
	// unchanged, plus exactly what discovery found -- submitCredentials
	// (formlogin.go) neither knows nor cares whether LoginURL/
	// UsernameField/PasswordField were configured or discovered.
	derived := p
	derived.LoginURL = pageURL
	derived.UsernameField = usernameField
	derived.PasswordField = passwordField
	sess.LoginURL = pageURL

	return submitCredentials(ctx, deps, derived, client, jar, pageURL.Hostname(), form, actionURL, sess)
}

// newScopedDiscoveryClient resolves+scope-checks startURL's own host
// and builds the scope-safe, cookie-jar-carrying client every fetch
// during discovery (and, for AutoFormLoginProvider, the eventual
// credential submission too) uses -- the exact same
// ResolveInScope-then-NewClient pattern FormLoginProvider itself
// follows (formlogin.go), shared here so AutoFormLoginProvider.Authenticate
// and the read-only DiscoverOnly preview below can never drift from
// each other on how a discovery client is constructed.
func newScopedDiscoveryClient(ctx context.Context, deps Dependencies, startURL *url.URL, timeout time.Duration, maxRedirects int) (*http.Client, *cookiejar.Jar, error) {
	startIP, err := deps.Dialer.ResolveInScope(ctx, startURL.Hostname())
	if err != nil {
		return nil, nil, fmt.Errorf("start host %q: %w", startURL.Hostname(), err)
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, nil, fmt.Errorf("build cookie jar: %w", err)
	}
	client := deps.Dialer.NewClient(startURL.Hostname(), startIP, nil, nil, timeout, maxRedirects)
	client.Jar = jar
	return client, jar, nil
}

// DiscoveryResult is what "scanner auth discover" reports -- a
// non-secret summary of what automatic login-form discovery found,
// safe to print directly (no credential ever appears in it, since
// DiscoverOnly never reads or submits one).
type DiscoveryResult struct {
	LoginURL      string
	Method        string
	UsernameField string
	PasswordField string
}

// DiscoverOnly runs exactly the discovery phase -- no credential is
// ever read, no form is ever submitted -- so an operator can preview
// what automatic discovery would find (login page, form method,
// username/password field names) before configuring a
// form_login_auto profile or authenticating for real. Reuses the
// identical discoverLoginForm/identifyUsernameField/
// identifyPasswordField logic AutoFormLoginProvider.Authenticate
// itself uses, so a preview can never disagree with what a real
// --identity/--auth-profile authentication attempt would actually do.
// Still scope-checked exactly like every other network-touching path
// in this package (task's "authentication discovery MUST NOT bypass
// scope" applies to the preview command too, not only to a real login).
func DiscoverOnly(ctx context.Context, deps Dependencies, startURL *url.URL, timeout time.Duration, maxRedirects int) (DiscoveryResult, error) {
	if startURL == nil {
		return DiscoveryResult{}, errors.New("start URL is required")
	}
	if deps.Dialer == nil {
		return DiscoveryResult{}, errors.New("no dialer supplied")
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	if maxRedirects <= 0 {
		maxRedirects = DefaultMaxRedirects
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	client, _, err := newScopedDiscoveryClient(ctx, deps, startURL, timeout, maxRedirects)
	if err != nil {
		return DiscoveryResult{}, err
	}

	form, pageURL, err := discoverLoginForm(ctx, client, startURL)
	if err != nil {
		return DiscoveryResult{}, err
	}
	usernameField, ok := identifyUsernameField(form)
	if !ok {
		return DiscoveryResult{}, fmt.Errorf("found a likely login form at %s but could not identify a username field", pageURL)
	}
	passwordField, ok := identifyPasswordField(form)
	if !ok {
		return DiscoveryResult{}, fmt.Errorf("found a likely login form at %s but could not identify its password field", pageURL)
	}
	method := form.Method
	if method == "" {
		method = http.MethodPost
	}
	return DiscoveryResult{
		LoginURL:      pageURL.String(),
		Method:        method,
		UsernameField: usernameField,
		PasswordField: passwordField,
	}, nil
}

// discoverLoginForm fetches startURL, then (only if it has no
// password-bearing form itself) a bounded, same-origin-only set of
// "login-like" links from it, stopping at the first page found to
// have at least one password-bearing form. Never fetches more than
// maxDiscoveryPages pages total. Returns the single best-scoring
// password-bearing form found (see scoreForm) and the URL of the page
// it came from.
func discoverLoginForm(ctx context.Context, client *http.Client, startURL *url.URL) (loginForm, *url.URL, error) {
	visited := make(map[string]bool, maxDiscoveryPages)
	queue := []*url.URL{startURL}

	var bestForm loginForm
	var bestPageURL *url.URL
	bestScore := -1
	pagesFetched := 0

	for len(queue) > 0 && pagesFetched < maxDiscoveryPages {
		pageURL := queue[0]
		queue = queue[1:]
		key := pageURL.String()
		if visited[key] {
			continue
		}
		visited[key] = true
		pagesFetched++

		body, finalURL, doc, fetchErr := fetchAndParse(ctx, client, pageURL)
		if fetchErr != nil {
			continue // this candidate page failed to fetch/parse; try the next one rather than aborting discovery entirely
		}
		_ = body

		for _, f := range parseForms(doc, finalURL) {
			if !f.HasPassword {
				continue
			}
			score := scoreForm(f, doc)
			if score > bestScore {
				bestScore = score
				bestForm = f
				bestPageURL = finalURL
			}
		}
		if bestScore >= 0 {
			// Found at least one password-bearing form -- stop here,
			// deterministically: never keep searching once a viable
			// candidate exists, and never compare candidates found on
			// DIFFERENT pages against each other (only multiple forms
			// on the SAME page are scored against one another).
			break
		}

		if pagesFetched < maxDiscoveryPages {
			for _, link := range findLoginLinks(doc, finalURL, startURL) {
				queue = append(queue, link)
			}
		}
	}

	if bestScore < 0 {
		return loginForm{}, nil, fmt.Errorf("no password-bearing HTML form found within %d page(s) starting from %s", pagesFetched, startURL)
	}
	return bestForm, bestPageURL, nil
}

// fetchAndParse issues one GET through client (which already carries
// the scope-validated, redirect-safe configuration deps.Dialer built)
// and parses the (bounded, readLimited) response body as HTML.
func fetchAndParse(ctx context.Context, client *http.Client, u *url.URL) ([]byte, *url.URL, *html.Node, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, nil, nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, nil, err
	}
	body, err := readLimited(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, nil, nil, err
	}
	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return nil, nil, nil, err
	}
	return body, resp.Request.URL, doc, nil
}

// findLoginLinks returns every same-origin <a href> on doc whose
// visible text or URL path contains a login-related keyword, scored
// (text match weighted higher than a path match) and sorted
// highest-scoring first, capped at maxCandidateLinks. "Same-origin" is
// always relative to origin (the ORIGINAL start_url, fixed for the
// whole discovery run, never a shifting "current page" origin) --
// task's explicit "do not cross origins during authentication
// discovery" requirement, enforced here independently of (in addition
// to) the scope check every dial already performs.
func findLoginLinks(doc *html.Node, base, origin *url.URL) []*url.URL {
	type scoredLink struct {
		url   *url.URL
		score int
	}
	var candidates []scoredLink
	seen := map[string]bool{}

	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "a" {
			if href, ok := attr(n, "href"); ok && href != "" {
				if u, err := url.Parse(href); err == nil {
					resolved := base.ResolveReference(u)
					if sameOrigin(resolved, origin) {
						key := resolved.String()
						if !seen[key] && len(candidates) < maxCandidateLinks {
							seen[key] = true
							if score := scoreLoginLink(resolved, textNodeContent(n)); score > 0 {
								candidates = append(candidates, scoredLink{url: resolved, score: score})
							}
						}
					}
				}
			}
			return // an <a> is never itself a container of another <a> in valid HTML; no need to recurse into it
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(doc)

	sort.SliceStable(candidates, func(i, j int) bool { return candidates[i].score > candidates[j].score })
	out := make([]*url.URL, 0, len(candidates))
	for _, c := range candidates {
		out = append(out, c.url)
	}
	return out
}

func scoreLoginLink(u *url.URL, linkText string) int {
	text := strings.ToLower(linkText)
	path := strings.ToLower(u.Path)
	score := 0
	for _, kw := range loginLinkKeywords {
		if strings.Contains(text, kw) {
			score += 20
		}
		compact := strings.NewReplacer(" ", "", "-", "").Replace(kw)
		if strings.Contains(path, compact) {
			score += 10
		}
	}
	return score
}

func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Hostname(), b.Hostname()) && a.Port() == b.Port()
}

// scoreForm returns how login-like f is -- higher is more likely.
// Only ever called on password-bearing forms (HasPassword is the
// mandatory gate, applied by the caller before scoreForm is reached);
// this score exists only to choose DETERMINISTICALLY among multiple
// password-bearing forms on the SAME page, never to decide whether a
// form is a login form at all.
func scoreForm(f loginForm, doc *html.Node) int {
	score := 10 // baseline: it already passed the HasPassword gate
	action := strings.ToLower(f.Action)
	for _, kw := range loginLinkKeywords {
		if strings.Contains(action, strings.NewReplacer(" ", "", "-", "").Replace(kw)) {
			score += 5
			break
		}
	}
	if title := strings.ToLower(pageTitle(doc)); title != "" {
		for _, kw := range loginLinkKeywords {
			if strings.Contains(title, kw) {
				score += 5
				break
			}
		}
	}
	if _, ok := identifyUsernameField(f); ok {
		// A password field with NO plausible username field alongside
		// it is a weaker candidate (could be a "change password" or
		// PIN-only form) -- still eligible, just ranked lower against
		// a form that also has an identifiable username field.
		score += 20
	}
	return score
}

func pageTitle(doc *html.Node) string {
	var title string
	var walk func(*html.Node) bool
	walk = func(n *html.Node) bool {
		if n.Type == html.ElementNode && n.Data == "title" {
			title = textNodeContent(n)
			return true
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			if walk(child) {
				return true
			}
		}
		return false
	}
	walk(doc)
	return title
}

// identifyUsernameField picks the single most likely username/email
// field among f's own InputMeta -- non-text-like input types (hidden,
// checkbox, password, ...) are never candidates. Deterministic: the
// highest-scoring candidate wins; ties break by document order
// (InputMeta's own order, which mirrors the form's HTML source order,
// so the FIRST such field in the form wins any exact tie -- the same
// "first, not random" determinism principle findLoginForm's own
// existing form-selection already follows).
func identifyUsernameField(f loginForm) (string, bool) {
	bestName := ""
	bestScore := -1
	for _, m := range f.InputMeta {
		if !isTextLikeInputType(m.Type) {
			continue
		}
		score := scoreUsernameCandidate(m)
		if score > bestScore {
			bestScore = score
			bestName = m.Name
		}
	}
	if bestScore < 0 {
		return "", false
	}
	return bestName, true
}

func scoreUsernameCandidate(m inputMeta) int {
	score := 0
	switch m.Autocomplete {
	case "username", "email":
		score += 100
	}
	if m.Type == "email" {
		score += 50
	}
	lowerName := strings.ToLower(m.Name)
	lowerID := strings.ToLower(m.ID)
	lowerLabel := strings.ToLower(m.Label)
	for _, kw := range usernameKeywords {
		if strings.Contains(lowerName, kw) {
			score += 30
			break
		}
	}
	for _, kw := range usernameKeywords {
		if strings.Contains(lowerID, kw) {
			score += 20
			break
		}
	}
	for _, kw := range usernameKeywords {
		if strings.Contains(lowerLabel, kw) {
			score += 20
			break
		}
	}
	if score == 0 {
		// Still a viable plain-text fallback candidate (matches
		// findLoginForm's own "if nothing distinguishes it, still take
		// it" determinism) -- just the lowest-priority one, so any
		// field with an actual matching signal always outranks it.
		score = 1
	}
	return score
}

func identifyPasswordField(f loginForm) (string, bool) {
	for _, m := range f.InputMeta {
		if m.Type == "password" {
			return m.Name, true
		}
	}
	return "", false
}

func isTextLikeInputType(t string) bool {
	switch t {
	case "text", "email", "tel", "search":
		return true
	default:
		return false
	}
}
