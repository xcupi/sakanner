package lab

import (
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"time"

	"sakanner/internal/dns"
)

// discardLogger silences the noise every lab HTTP(S) server would
// otherwise print: sakanner's Prober always tries HTTPS before HTTP for
// any port (see internal/http.Prober.Probe), so every plain-HTTP lab
// service logs a "TLS handshake error" for that attempt -- harmless and
// expected, not a lab failure, but noisy in test output.
var discardLogger = log.New(io.Discard, "", 0)

// Fixed loopback addresses, one per lab hostname (except the CNAMEs,
// which share their target's address, and the two out-of-scope hosts,
// which share an RFC 5737 TEST-NET-3 address). Every hostname needing
// its own address gets one because sakanner's port scanner applies the
// SAME port list to every resolved host -- two hostnames sharing one IP
// would see each other's open ports, contaminating results across
// services that should be independent. The entire 127.0.0.0/8 range is
// loopback (net.IP.IsLoopback treats it as reserved, same as 127.0.0.1),
// so AllowReservedRanges must be set for lab scans, exactly as the rest
// of this codebase's test suite already does for 127.0.0.1.
const (
	ipScanner  = "127.0.0.11" // scanner.test, www.scanner.test (CNAME)
	ipAPI      = "127.0.0.12" // api.scanner.test
	ipStatic   = "127.0.0.13" // static.scanner.test
	ipRedirect = "127.0.0.14" // redirect.scanner.test
	ipJS       = "127.0.0.15" // js.scanner.test
	ipSlow     = "127.0.0.16" // slow.scanner.test
	ipRefuse   = "127.0.0.17" // refuse.scanner.test
	ipAltPort  = "127.0.0.18" // altport.scanner.test
	ipIPv6     = "::1"        // ipv6.scanner.test

	// ipExternal/ipOther use RFC 5737 TEST-NET-3, reserved for
	// documentation -- guaranteed to never route to a real host, so even
	// a scope-enforcement bug that let the scanner attempt a dial here
	// would just time out against a documentation-only network rather
	// than touching a real third party.
	ipExternal = "203.0.113.99" // external.scanner.test, admin.scanner.test (CNAME)
	ipOther    = "203.0.113.98" // another-test.local
)

// refusePort is a fixed TCP port on ipRefuse guaranteed to have nothing
// listening -- chosen well above the ephemeral port range Linux assigns
// by default, to avoid the OS itself reusing it for another connection
// mid-test. Start verifies it's actually free before relying on it.
const refusePort = 19999

// altPort is a fixed, non-standard port for altport.scanner.test.
// Ground truth requires this port to NOT be in sakanner's default port
// list; unlike refusePort, something legitimately listens here.
const altPort = 18099

// SlowResponseDelay is how long slow.scanner.test's handler sleeps
// before responding. Lab tests must configure a shorter HTTP timeout
// than this so the "does a slow target hang the scan" scenario is
// actually exercised deterministically rather than depending on how
// fast the machine running the test happens to be.
const SlowResponseDelay = 3 * time.Second

//go:embed fixtures/scanner-test-index.html
var scannerIndexHTML []byte

//go:embed fixtures/generic-page.html
var genericPageHTML []byte

//go:embed fixtures/app.js
var appJS []byte

//go:embed fixtures/api-index.html
var apiIndexHTML []byte

//go:embed fixtures/js-index.html
var jsIndexHTML []byte

var _ embed.FS // (fixtures/ also referenced directly by the Docker profile; see lab/nginx, lab/apache)

// Lab is a running instance of the Phase 2 Test Laboratory: a set of
// real local HTTP(S)/TCP listeners plus a dns.FakeResolver, all built
// from GroundTruth so tests assert against one source of truth. Every
// server is plain Go net/http(s) -- the same httptest pattern already
// used throughout this codebase's test suite -- so the lab needs nothing
// beyond the Go toolchain: no Docker, no root, no system DNS changes.
type Lab struct {
	GT       *GroundTruth
	Resolver *dns.FakeResolver

	// RedirectHTTPAddr/RedirectHTTPSAddr are redirect.scanner.test's two
	// listener addresses -- exposed directly (rather than only through
	// Resolver) because the redirect/status-code scenarios are tested by
	// dialing specific sub-paths directly with internal/safedial, not
	// through the standard root-path-only probe/crawl flow. See
	// docs/phase-2-test-lab.md "Known limitations".
	RedirectHTTPAddr  string
	RedirectHTTPSAddr string

	// VulnAddr/SSRFInternalAddr are set only when StartWithVulnerabilities
	// (harness_vuln.go, Phase 3) is used instead of plain Start -- empty
	// otherwise. Exposed the same way RedirectHTTPAddr is, for tests that
	// need the literal address rather than going through Resolver.
	VulnAddr         string
	SSRFInternalAddr string

	// FormSecondHostAddr is second-service.scanner.test's own listener
	// address -- Phase 3.22's genuinely SEPARATE, SEPARATELY-IN-SCOPE
	// second host, proving docs/phase-3-22-active-detection-coverage.md
	// section 7's resolution positively (a cross-origin form action
	// that IS in scope reaches its real destination), not merely its
	// negative/exclusion case (already covered since Phase 3.21). Set
	// only when StartWithVulnerabilities is used.
	FormSecondHostAddr string

	// SSRFCallback is set only when StartWithVulnerabilities is used --
	// nil otherwise. Phase 3.4's out-of-band callback recorder (see
	// callback.go); tests that construct a real ssrf.Detector pass this
	// directly as its CallbackClient.
	SSRFCallback *SSRFCallbackServer

	// InputsAddr is set only when StartWithInputFixtures
	// (harness_inputs.go, Phase 3.13) is used -- empty otherwise.
	InputsAddr string

	// AuthAddr is set only when StartWithAuthFixtures
	// (harness_auth.go, Phase 3.14) is used -- empty otherwise.
	AuthAddr string

	servers []*httptest.Server
	lock    net.Listener // the cross-process setup lock; see labLockAddr
}

// labLockAddr is a fixed, otherwise-unused loopback port used purely
// as a cross-process advisory lock, not a lab service. altPort (18099)
// below is a genuinely fixed, hardcoded port -- unlike every other lab
// server, which binds an OS-assigned ephemeral port -- so at most ONE
// lab instance can exist system-wide at any moment, across every
// process, not just within one. That constraint was always true but
// went untriggered until Phase 3.11.2, when tests/e2e started
// importing and starting this same lab for its own CLI integration
// tests: `go test ./...` runs separate packages' test binaries in
// parallel by default, so lab's own suite and tests/e2e's can
// now genuinely call Start/StartWithVulnerabilities at the same
// wall-clock instant from two different OS processes, both racing to
// bind :18099. A plain net.Listen on a well-known port is a standard,
// dependency-free way to implement a systemwide mutex here: the first
// process to successfully bind labLockAddr holds the "lock" until it
// closes that listener (in Close()); everyone else's own bind attempt
// fails and retries until it's free.
const labLockAddr = "127.0.0.1:18999"

func acquireLabLock() (net.Listener, error) {
	deadline := time.Now().Add(60 * time.Second)
	for {
		ln, err := net.Listen("tcp", labLockAddr)
		if err == nil {
			return ln, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("lab: timed out waiting for the cross-process lab setup lock on %s: %w", labLockAddr, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// Start builds and starts every lab service, and a dns.FakeResolver
// populated to match. Callers must defer Close(). Acquires the
// cross-process lab lock (see labLockAddr) for the duration of setup,
// transferring it to the returned Lab for Close() to release --
// startLocked itself is unchanged from before that lock existed.
func Start(gt *GroundTruth) (*Lab, error) {
	lock, err := acquireLabLock()
	if err != nil {
		return nil, err
	}
	l, err := startLocked(gt)
	if err != nil {
		lock.Close()
		return nil, err
	}
	l.lock = lock
	return l, nil
}

func startLocked(gt *GroundTruth) (*Lab, error) {
	l := &Lab{GT: gt, Resolver: dns.NewFakeResolver()}

	if err := checkPortFree(ipRefuse, refusePort); err != nil {
		return nil, fmt.Errorf("lab: refuse port %d on %s is not free: %w", refusePort, ipRefuse, err)
	}

	scannerSrv, err := newServerOn(ipScanner, scannerTestHandler())
	if err != nil {
		return nil, err
	}
	l.servers = append(l.servers, scannerSrv)

	apiSrv, err := newServerOn(ipAPI, apiHandler())
	if err != nil {
		return nil, err
	}
	l.servers = append(l.servers, apiSrv)

	staticSrv, err := newServerOn(ipStatic, staticHandler())
	if err != nil {
		return nil, err
	}
	l.servers = append(l.servers, staticSrv)

	jsSrv, err := newServerOn(ipJS, jsAppHandler())
	if err != nil {
		return nil, err
	}
	l.servers = append(l.servers, jsSrv)

	slowSrv, err := newServerOn(ipSlow, slowHandler())
	if err != nil {
		return nil, err
	}
	l.servers = append(l.servers, slowSrv)

	altSrv, err := newServerOnPort(ipAltPort, altPort, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(genericPageHTML)
	}))
	if err != nil {
		return nil, err
	}
	l.servers = append(l.servers, altSrv)

	// redirect.scanner.test needs its HTTPS address known before its
	// HTTP handler can be built (the HTTP->HTTPS redirect's Location
	// header must name the actual HTTPS port).
	redirectTLSSrv, err := newTLSServerOn(ipRedirect, redirectSecureHandler())
	if err != nil {
		return nil, err
	}
	l.servers = append(l.servers, redirectTLSSrv)
	l.RedirectHTTPSAddr = redirectTLSSrv.Listener.Addr().String()

	redirectHTTPSrv, err := newServerOn(ipRedirect, redirectHTTPHandler(l.RedirectHTTPSAddr))
	if err != nil {
		return nil, err
	}
	l.servers = append(l.servers, redirectHTTPSrv)
	l.RedirectHTTPAddr = redirectHTTPSrv.Listener.Addr().String()

	if ipv6Srv, err := newServerOn(ipIPv6, ipv6Handler()); err == nil {
		l.servers = append(l.servers, ipv6Srv)
	}
	// An IPv6-unavailable sandbox is not a lab failure -- IPv6 coverage
	// is explicitly best-effort (see ground-truth.yaml). If binding
	// failed, ipv6.scanner.test simply won't resolve to anything the
	// FakeResolver has an entry for below, and lab tests skip it.

	l.wireResolver(scannerSrv, apiSrv, staticSrv, jsSrv, slowSrv, altSrv, ipv6Bound(l.servers))

	return l, nil
}

// Close stops every server the lab started.
func (l *Lab) Close() {
	for _, s := range l.servers {
		s.Close()
	}
	// The cross-process setup lock (labLockAddr) is held for the lab's
	// ENTIRE lifetime, not just its setup phase: altPort (18099) stays
	// bound by an actual service listener the whole time a Lab is
	// running, so a second process's own lab could never bind it
	// anyway until this one fully closes -- releasing the lock any
	// earlier would let a second process pass the lock check and then
	// still fail on the real port collision moments later.
	if l.lock != nil {
		l.lock.Close()
	}
}

// Ports returns every port a lab service is reachable on, plus
// refusePort (which nothing listens on, by design) -- the full list a
// port scan must be given to discover every lab service, since each
// hostname's httptest.Server binds an OS-assigned port rather than a
// fixed one (see the package doc for why fixed ports aren't used here).
func (l *Lab) Ports() []int {
	seen := map[int]bool{refusePort: true}
	ports := []int{refusePort}
	for _, s := range l.servers {
		tcpAddr, ok := s.Listener.Addr().(*net.TCPAddr)
		if !ok || seen[tcpAddr.Port] {
			continue
		}
		seen[tcpAddr.Port] = true
		ports = append(ports, tcpAddr.Port)
	}
	return ports
}

func ipv6Bound(servers []*httptest.Server) bool {
	for _, s := range servers {
		if s.Listener != nil {
			if tcpAddr, ok := s.Listener.Addr().(*net.TCPAddr); ok && tcpAddr.IP.Equal(net.ParseIP(ipIPv6)) {
				return true
			}
		}
	}
	return false
}

func (l *Lab) wireResolver(scannerSrv, apiSrv, staticSrv, jsSrv, slowSrv, altSrv *httptest.Server, ipv6Available bool) {
	r := l.Resolver

	set := func(host, ip string) { r.Hosts[host] = []net.IP{net.ParseIP(ip)} }

	set("scanner.test", ipScanner)
	set("www.scanner.test", ipScanner) // CNAME target resolves to the same address
	r.CNAMEs["www.scanner.test"] = "scanner.test."

	set("api.scanner.test", ipAPI)
	set("static.scanner.test", ipStatic)
	set("redirect.scanner.test", ipRedirect)
	set("js.scanner.test", ipJS)
	set("slow.scanner.test", ipSlow)
	set("refuse.scanner.test", ipRefuse)
	set("altport.scanner.test", ipAltPort)

	set("admin.scanner.test", ipExternal) // CNAME target resolves to the (out-of-scope) address
	r.CNAMEs["admin.scanner.test"] = "external.scanner.test."
	set("external.scanner.test", ipExternal)
	set("another-test.local", ipOther)

	if ipv6Available {
		set("ipv6.scanner.test", ipIPv6)
	}
}

func checkPortFree(ip string, port int) error {
	l, err := net.Listen("tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return err
	}
	return l.Close()
}

func newServerOn(ip string, handler http.Handler) (*httptest.Server, error) {
	return newServerOnPort(ip, 0, handler)
}

func newServerOnPort(ip string, port int, handler http.Handler) (*httptest.Server, error) {
	listener, err := net.Listen("tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return nil, fmt.Errorf("lab: listen on %s:%d: %w", ip, port, err)
	}
	srv := httptest.NewUnstartedServer(handler)
	srv.Listener.Close()
	srv.Listener = listener
	srv.Config.ErrorLog = discardLogger
	srv.Start()
	return srv, nil
}

func newTLSServerOn(ip string, handler http.Handler) (*httptest.Server, error) {
	listener, err := net.Listen("tcp", net.JoinHostPort(ip, "0"))
	if err != nil {
		return nil, fmt.Errorf("lab: listen on %s: %w", ip, err)
	}
	srv := httptest.NewUnstartedServer(handler)
	srv.Listener.Close()
	srv.Listener = listener
	srv.Config.ErrorLog = discardLogger
	srv.StartTLS()
	return srv, nil
}

// --- Handlers ---------------------------------------------------------

func scannerTestHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.25.3")
		w.Write(scannerIndexHTML)
	})
	mux.HandleFunc("/about", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.25.3")
		w.Write(genericPageHTML)
	})
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.25.3")
		w.Write(genericPageHTML)
	})
	mux.HandleFunc("/contact", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.25.3")
		w.Write(genericPageHTML)
	})
	mux.HandleFunc("/static/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write(appJS)
	})
	return mux
}

func apiHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.58 (Ubuntu)")
		w.Write(apiIndexHTML)
	})
	mux.HandleFunc("/items", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.58 (Ubuntu)")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"items": []string{"book-1", "book-2"}})
	})
	mux.HandleFunc("/users/42", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.58 (Ubuntu)")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"id": 42})
	})
	return mux
}

func staticHandler() http.Handler {
	// Deliberately sets no Server header at all -- the negative
	// fingerprinting case (no technology detected).
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(genericPageHTML)
	})
}

func jsAppHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write(jsIndexHTML)
	})
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Write(appJS)
	})
	return mux
}

func slowHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(SlowResponseDelay)
		w.Write(genericPageHTML)
	})
}

func ipv6Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(genericPageHTML)
	})
}

// redirectHTTPHandler serves redirect.scanner.test's plaintext port.
// httpsAddr is that hostname's already-started HTTPS listener address,
// captured by Start before this handler is built.
func redirectHTTPHandler(httpsAddr string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, fmt.Sprintf("https://redirect.scanner.test:%s/secure", portOf(httpsAddr)), http.StatusMovedPermanently)
	})
	mux.HandleFunc("/multi", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/multi/2", http.StatusFound)
	})
	mux.HandleFunc("/multi/2", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/multi/done", http.StatusFound)
	})
	mux.HandleFunc("/multi/done", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("done"))
	})
	mux.HandleFunc("/loop", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/loop", http.StatusFound)
	})
	mux.HandleFunc("/external-redirect", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://external.scanner.test/", http.StatusFound)
	})
	mux.HandleFunc("/missing", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	mux.HandleFunc("/forbidden", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	})
	mux.HandleFunc("/error", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	})
	return mux
}

func redirectSecureHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("secure root"))
	})
	mux.HandleFunc("/secure", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("secure page"))
	})
	return mux
}

func portOf(addr string) string {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	return port
}
