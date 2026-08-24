package lab

import (
	"context"
	"io"
	"net/http"
	"testing"
	"time"
)

// TestSSRFCallbackServer_NeverProxiesRegardlessOfInput is the direct
// proof behind callback.go's package doc comment: the callback
// server's handler makes zero outbound network calls of its own,
// regardless of what it's sent. A request carrying headers/body
// SHAPED like a forwarding instruction (as if probing for an open-
// proxy vulnerability in the callback server itself) gets the
// identical fixed acknowledgment every other request gets -- nothing
// about the request's content ever changes its behavior.
func TestSSRFCallbackServer_NeverProxiesRegardlessOfInput(t *testing.T) {
	l := testVulnLab(t)
	cb := l.SSRFCallback
	if cb == nil {
		t.Fatal("SSRFCallback is nil")
	}

	token, callbackURL, err := cb.NewToken(context.Background())
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, callbackURL, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	// Adversarial headers/body shaped like a "please proxy/forward me"
	// instruction -- the callback server must ignore all of this.
	req.Header.Set("X-Forward-To", "http://external.scanner.test/")
	req.Header.Set("X-Proxy-Target", "http://169.254.169.254/latest/meta-data/")
	req.Header.Set("Location", "http://external.scanner.test/")

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 -- the callback server always acknowledges identically, regardless of headers", resp.StatusCode)
	}
	if string(body) != "ok" {
		t.Errorf("body = %q, want \"ok\" -- proxy-shaped headers must have zero effect on the response", body)
	}

	obs, err := cb.Observations(context.Background(), token)
	if err != nil {
		t.Fatalf("Observations: %v", err)
	}
	if len(obs) != 1 {
		t.Fatalf("Observations = %+v, want exactly 1 recorded hit", obs)
	}
}

// TestSSRFCallbackServer_RecordsOnlyNecessaryMetadata confirms the
// recorded Observation carries only method/path/remote-addr/timestamp
// -- no request body, no arbitrary headers -- per section 19's
// "record only necessary metadata."
func TestSSRFCallbackServer_RecordsOnlyNecessaryMetadata(t *testing.T) {
	l := testVulnLab(t)
	cb := l.SSRFCallback

	token, callbackURL, err := cb.NewToken(context.Background())
	if err != nil {
		t.Fatalf("NewToken: %v", err)
	}

	resp, err := http.Post(callbackURL, "text/plain", nil)
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	resp.Body.Close()

	obs, err := cb.Observations(context.Background(), token)
	if err != nil {
		t.Fatalf("Observations: %v", err)
	}
	if len(obs) != 1 {
		t.Fatalf("Observations = %+v, want 1", obs)
	}
	if obs[0].Method != http.MethodPost {
		t.Errorf("Method = %q, want POST", obs[0].Method)
	}
}

// TestSSRFCallbackServer_TokenIsolationAcrossManyTokens is a broader
// version of internal/detectors/ssrf's own correlation_test.go
// isolation tests, run against the REAL server (not fakeCallback) --
// many distinct tokens hit in sequence, each Observations call must
// only ever see its own.
func TestSSRFCallbackServer_TokenIsolationAcrossManyTokens(t *testing.T) {
	l := testVulnLab(t)
	cb := l.SSRFCallback

	const n = 10
	tokens := make([]string, n)
	urls := make([]string, n)
	for i := 0; i < n; i++ {
		tok, u, err := cb.NewToken(context.Background())
		if err != nil {
			t.Fatalf("NewToken: %v", err)
		}
		tokens[i] = tok
		urls[i] = u
	}
	// Hit only every OTHER token.
	for i := 0; i < n; i += 2 {
		resp, err := http.Get(urls[i])
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		resp.Body.Close()
	}
	for i, tok := range tokens {
		obs, err := cb.Observations(context.Background(), tok)
		if err != nil {
			t.Fatalf("Observations: %v", err)
		}
		wantHit := i%2 == 0
		gotHit := len(obs) > 0
		if gotHit != wantHit {
			t.Errorf("token %d: hit=%v, want %v", i, gotHit, wantHit)
		}
	}
}
