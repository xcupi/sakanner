package lab

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"
)

func testLab(t *testing.T) *Lab {
	t.Helper()
	gt, err := LoadGroundTruth()
	if err != nil {
		t.Fatalf("LoadGroundTruth: %v", err)
	}
	l, err := Start(gt)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(l.Close)
	return l
}

func dial(t *testing.T, host string, l *Lab) net.IP {
	t.Helper()
	ips, err := l.Resolver.LookupHost(context.Background(), host)
	if err != nil {
		t.Fatalf("LookupHost(%s): %v", host, err)
	}
	if len(ips) == 0 {
		t.Fatalf("LookupHost(%s) returned no addresses", host)
	}
	return ips[0]
}

func httpGet(t *testing.T, url string) *http.Response {
	t.Helper()
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec
	}
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	return resp
}

func TestLab_AllServicesStartAndRespond(t *testing.T) {
	l := testLab(t)

	cases := []struct {
		host     string
		wantBody string
	}{
		{"scanner.test", "scanner.test"},
		{"www.scanner.test", "scanner.test"},
		{"api.scanner.test", "api.scanner.test"},
		{"static.scanner.test", "generic lab page"},
		{"js.scanner.test", "js.scanner.test"},
	}
	for _, tc := range cases {
		ip := dial(t, tc.host, l)
		resp := httpGet(t, fmt.Sprintf("http://%s/", net.JoinHostPort(ip.String(), portFor(t, l, tc.host))))
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s: status = %d, want 200", tc.host, resp.StatusCode)
		}
	}
}

// portFor resolves which port a lab hostname's HTTP service is actually
// listening on, by asking the lab directly rather than hardcoding one --
// mirrors how the real lab integration test discovers ports (see
// lab_test.go), since httptest servers bind an OS-assigned port.
func portFor(t *testing.T, l *Lab, host string) string {
	t.Helper()
	switch host {
	case "redirect.scanner.test":
		return portOf(l.RedirectHTTPAddr)
	}
	for _, s := range l.servers {
		tcpAddr, ok := s.Listener.Addr().(*net.TCPAddr)
		if !ok {
			continue
		}
		ip := dial(t, host, l)
		if tcpAddr.IP.Equal(ip) {
			return fmt.Sprintf("%d", tcpAddr.Port)
		}
	}
	t.Fatalf("no server found for host %s", host)
	return ""
}

func TestLab_RefusePortRefusesConnections(t *testing.T) {
	l := testLab(t)
	ip := dial(t, "refuse.scanner.test", l)

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip.String(), fmt.Sprintf("%d", refusePort)), 2*time.Second)
	if err == nil {
		conn.Close()
		t.Fatal("expected connection refused, got a successful connection")
	}
}

func TestLab_SlowEndpointExceedsShortTimeout(t *testing.T) {
	l := testLab(t)
	ip := dial(t, "slow.scanner.test", l)

	client := &http.Client{Timeout: 200 * time.Millisecond}
	_, err := client.Get(fmt.Sprintf("http://%s/", net.JoinHostPort(ip.String(), portFor(t, l, "slow.scanner.test"))))
	if err == nil {
		t.Fatal("expected a client timeout against the slow endpoint")
	}
}

// TestLab_RedirectChainHTTPToHTTPS checks only the harness's own
// behavior (the Location header it hands back), not whether a generic
// HTTP client can follow it -- "redirect.scanner.test" isn't a real DNS
// name, so a plain client (using the system resolver) can't dial it.
// Actually following this redirect end to end, through sakanner's own
// resolve-validate-dial-by-IP path via the lab's FakeResolver, is what
// lab_test.go's full pipeline test verifies.
func TestLab_RedirectChainHTTPToHTTPS(t *testing.T) {
	l := testLab(t)

	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get(fmt.Sprintf("http://%s/", l.RedirectHTTPAddr))
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMovedPermanently {
		t.Errorf("status = %d, want 301", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	wantPrefix := fmt.Sprintf("https://redirect.scanner.test:%s/secure", portOf(l.RedirectHTTPSAddr))
	if loc != wantPrefix {
		t.Errorf("Location = %q, want %q", loc, wantPrefix)
	}
}

func TestLab_LoopIsTruncatedByClient(t *testing.T) {
	l := testLab(t)

	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	resp, err := client.Get(fmt.Sprintf("http://%s/loop", l.RedirectHTTPAddr))
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want 302 (truncated, not followed forever)", resp.StatusCode)
	}
}

func TestLab_StatusCodeScenarios(t *testing.T) {
	l := testLab(t)

	for path, want := range map[string]int{
		"/missing":   http.StatusNotFound,
		"/forbidden": http.StatusForbidden,
		"/error":     http.StatusInternalServerError,
	} {
		resp := httpGet(t, fmt.Sprintf("http://%s%s", l.RedirectHTTPAddr, path))
		defer resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("%s: status = %d, want %d", path, resp.StatusCode, want)
		}
	}
}
