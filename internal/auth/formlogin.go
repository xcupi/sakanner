package auth

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"
)

// maxAuthBodySample bounds how much of any login-flow response body is
// read into memory -- task section 15 adversarial scenario 16
// ("extremely large response"), matching the same bounded-read
// convention internal/http.Prober (256KB) and internal/crawler
// (512KB) already established for exactly the same reason.
const maxAuthBodySample = 512 * 1024

// FormLoginProvider implements Provider for TypeFormLogin -- task
// section 4's real, end-to-end login flow: fetch the login page,
// identify its form, submit resolved credentials (preserving any hidden
// fields already present, e.g. a CSRF token), and evaluate whether the
// result actually looks like a successful login rather than assuming
// any non-error HTTP status means success.
type FormLoginProvider struct {
	Profile Profile
}

func (fp *FormLoginProvider) Authenticate(ctx context.Context, deps Dependencies) (*Session, error) {
	p := fp.Profile
	sess := &Session{ProfileName: p.Name, Type: p.Type, Host: p.Host, State: StateAuthenticating, CreatedAt: time.Now().UTC(), LoginURL: p.LoginURL}

	if p.LoginURL == nil {
		return failSession(sess, fmt.Errorf("auth: profile %q has no login_url", p.Name))
	}
	if deps.Dialer == nil {
		return failSession(sess, fmt.Errorf("auth: profile %q: no dialer supplied", p.Name))
	}

	ctx, cancel := context.WithTimeout(ctx, p.Timeout)
	defer cancel()

	// Scope check + resolution for the login host itself (task section
	// 8's "login URL outside scope"): ResolveInScope is the exact same
	// check internal/safedial applies to every other host it ever
	// dials, reused here rather than re-derived.
	loginIP, err := deps.Dialer.ResolveInScope(ctx, p.LoginURL.Hostname())
	if err != nil {
		return failSession(sess, fmt.Errorf("auth: profile %q: login host %q: %w", p.Name, p.LoginURL.Hostname(), err))
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		return failSession(sess, fmt.Errorf("auth: profile %q: build cookie jar: %w", p.Name, err))
	}
	client := deps.Dialer.NewClient(p.LoginURL.Hostname(), loginIP, nil, nil, p.Timeout, p.MaxRedirects)
	client.Jar = jar

	// 1. Fetch the login page.
	getReq, err := http.NewRequestWithContext(ctx, http.MethodGet, p.LoginURL.String(), nil)
	if err != nil {
		return failSession(sess, fmt.Errorf("auth: profile %q: build login page request: %w", p.Name, err))
	}
	getResp, err := client.Do(getReq)
	if err != nil {
		return failSession(sess, fmt.Errorf("auth: profile %q: fetch login page: %w", p.Name, err))
	}
	pageBody, readErr := readLimited(getResp.Body)
	getResp.Body.Close()
	if readErr != nil {
		return failSession(sess, fmt.Errorf("auth: profile %q: read login page: %w", p.Name, readErr))
	}

	// 2-3. Identify the login form and its username/password fields.
	form, err := findLoginForm(pageBody, getResp.Request.URL)
	if err != nil {
		return failSession(sess, fmt.Errorf("auth: profile %q: %w", p.Name, err))
	}
	actionURL, err := url.Parse(form.Action)
	if err != nil {
		return failSession(sess, fmt.Errorf("auth: profile %q: login form action %q: %w", p.Name, form.Action, err))
	}

	// Explicit, fast, clearly-worded scope check on the form's action
	// host BEFORE submitting anything (task section 8's "form action
	// outside scope") -- defense in depth on top of the dial-level
	// check dialValidated performs anyway for any host other than the
	// one this client was built for (see safedial's package doc): this
	// check exists so an out-of-scope form action fails with a message
	// naming the actual problem, not a generic dial error.
	if !strings.EqualFold(actionURL.Hostname(), p.LoginURL.Hostname()) {
		decision, decErr := deps.Validator.CheckHost(ctx, actionURL.Hostname())
		if decErr != nil || !decision.Allowed {
			return failSession(sess, fmt.Errorf("auth: profile %q: login form action host %q is out of scope", p.Name, actionURL.Hostname()))
		}
	}

	// 4-5. Submit credentials -- every hidden/pre-filled field the form
	// carried is preserved (form.Fields already holds them), with only
	// the username/password fields (and any operator-configured
	// ExtraFields) overwritten.
	submission := make(map[string]string, len(form.Fields)+2+len(p.ExtraFields))
	for k, v := range form.Fields {
		submission[k] = v
	}
	submission[p.UsernameField] = p.Username
	submission[p.PasswordField] = p.Password
	for k, v := range p.ExtraFields {
		submission[k] = v
	}
	values := url.Values{}
	for k, v := range submission {
		values.Set(k, v)
	}

	method := form.Method
	if method == "" {
		method = http.MethodPost
	}
	var postReq *http.Request
	if method == http.MethodGet {
		actionURL.RawQuery = values.Encode()
		postReq, err = http.NewRequestWithContext(ctx, http.MethodGet, actionURL.String(), nil)
	} else {
		postReq, err = http.NewRequestWithContext(ctx, method, actionURL.String(), strings.NewReader(values.Encode()))
		if postReq != nil {
			postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}
	if err != nil {
		return failSession(sess, fmt.Errorf("auth: profile %q: build login submission request: %w", p.Name, err))
	}

	// 6-7. Submit and follow redirects -- client.CheckRedirect (set by
	// dialer.NewClient) already re-validates scope on every hop, so a
	// redirect to an out-of-scope host is truncated, not followed (task
	// section 8's "redirect outside scope" / "malicious redirect").
	postResp, err := client.Do(postReq)
	if err != nil {
		return failSession(sess, fmt.Errorf("auth: profile %q: submit login form: %w", p.Name, err))
	}
	postBody, readErr := readLimited(postResp.Body)
	postResp.Body.Close()
	if readErr != nil {
		return failSession(sess, fmt.Errorf("auth: profile %q: read login response: %w", p.Name, readErr))
	}

	// 8. Validate whether authentication actually succeeded.
	ok, reason := evaluateSuccess(p, postResp, postBody, jar)
	if !ok {
		return failSession(sess, fmt.Errorf("auth: profile %q: authentication failed: %s", p.Name, reason))
	}

	// 9. Create the authenticated session context.
	sess.State = StateAuthenticated
	sess.Jar = jar
	return sess, nil
}

// evaluateSuccess implements task section 4's "must NOT blindly assume
// HTTP 200 means login succeeded." When the operator has configured an
// explicit indicator, it alone governs. With no indicators configured
// at all, a conservative default heuristic applies: a non-error status
// AND at least one cookie actually established for the login host (a
// real session-based login always leaves SOME session state behind;
// an application that just always returns 200 regardless of
// credentials fails this check, catching exactly the trap task section
// 4 names).
func evaluateSuccess(p Profile, resp *http.Response, body []byte, jar *cookiejar.Jar) (bool, string) {
	if p.FailureTextContains != "" && bytes.Contains(body, []byte(p.FailureTextContains)) {
		return false, "response contained the configured failure indicator"
	}
	hasExplicitSuccessIndicator := p.SuccessURLContains != "" || p.SuccessTextContains != ""
	if p.SuccessURLContains != "" && !strings.Contains(resp.Request.URL.String(), p.SuccessURLContains) {
		return false, "final response URL did not contain the configured success indicator"
	}
	if p.SuccessTextContains != "" && !bytes.Contains(body, []byte(p.SuccessTextContains)) {
		return false, "response body did not contain the configured success indicator"
	}
	if hasExplicitSuccessIndicator {
		return true, ""
	}

	if resp.StatusCode >= 400 {
		return false, fmt.Sprintf("login response status %d", resp.StatusCode)
	}
	cookies := jar.Cookies(&url.URL{Scheme: "https", Host: p.LoginURL.Hostname(), Path: "/"})
	if len(cookies) == 0 {
		return false, "no session cookie was established and no success/failure indicator is configured"
	}
	return true, ""
}

// readLimited reads at most maxAuthBodySample bytes -- callers ignore
// io.EOF's absence deliberately: a truncated read of an oversized
// response is not itself an error (task's "extremely large response"
// case must degrade gracefully, not fail the whole login attempt).
func readLimited(r io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, maxAuthBodySample))
	if err != nil {
		return nil, err
	}
	return body, nil
}
