package main

import (
	"fmt"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/time/rate"

	"sakanner/internal/auth"
	"sakanner/internal/detection"
	"sakanner/internal/dns"
	"sakanner/internal/evidence"
	"sakanner/internal/fingerprint"
	httpstage "sakanner/internal/http"
	"sakanner/internal/mutation"
	"sakanner/internal/orchestration"
	"sakanner/internal/orchestrator"
	"sakanner/internal/parameters"
	"sakanner/internal/policy"
	"sakanner/internal/safedial"
	"sakanner/internal/scope"
	"sakanner/pkg/models"
)

// buildPipeline constructs the shared internal/orchestration.Pipeline
// both scan paths below use -- the exact same field-by-field wiring
// this command has used since Phase 1, factored out once so the new
// full-pipeline path (task section 45) and the original recon-only
// `--target <id>` path share one construction, never two independently
// drifting copies.
func buildPipeline(a *app, portList []int) *orchestration.Pipeline {
	cfg := a.cfg
	return &orchestration.Pipeline{
		Store:               a.store,
		Resolver:            dns.New(cfg.DNS.Timeout),
		Fingerprinter:       fingerprint.NewMatcher(fingerprint.DefaultSignatures()),
		Wordlist:            cfg.Discovery.Wordlist,
		DefaultPorts:        cfg.Ports.DefaultPorts,
		PortDialTimeout:     cfg.Ports.DialTimeout,
		HTTPConfig:          httpstage.Config{Timeout: cfg.HTTP.Timeout, MaxRedirects: cfg.HTTP.MaxRedirects},
		PortLimiter:         rate.NewLimiter(rate.Limit(cfg.RateLimit.PortsPerSecond), int(cfg.RateLimit.PortsPerSecond)+1),
		HTTPLimiter:         rate.NewLimiter(rate.Limit(cfg.RateLimit.HTTPPerSecond), int(cfg.RateLimit.HTTPPerSecond)+1),
		Concurrency:         orchestration.Concurrency{DNSWorkers: cfg.Concurrency.DNSWorkers, PortWorkers: cfg.Concurrency.PortWorkers, HTTPWorkers: cfg.Concurrency.HTTPWorkers},
		AllowReservedRanges: cfg.Scope.AllowReservedRanges,
		MaxCIDRHosts:        256,
		EnumerateDNSRecords: cfg.DNS.EnumerateRecords,
		CrawlEnabled:        cfg.Crawler.Enabled,
		CrawlMaxDepth:       cfg.Crawler.MaxDepth,
		CrawlMaxPages:       cfg.Crawler.MaxPages,
		DiscoveryBackend:    cfg.Tools.Subfinder,
		DNSBackend:          cfg.Tools.Dnsx,
		PortsBackend:        cfg.Tools.Naabu,
		HTTPBackend:         cfg.Tools.Httpx,
		CrawlBackend:        cfg.Tools.Katana,
		Logger:              a.logger,
	}
}

func newScanCmd(a *app) *cobra.Command {
	var targetIDs []string
	var portList []int
	var scanTimeout time.Duration
	var profileFlag string
	var authProfileFlag string
	var identityFlag string
	var authzIdentityFlag string

	cmd := &cobra.Command{
		Use:   "scan [target]",
		Short: "Run a scan (full pipeline), or recon-only against registered --target IDs",
		Long: `Run a scan.

Two invocation forms:
  scanner scan <target>            full pipeline: scope check, recon,
                                    crawling (if enabled), vulnerability
                                    detection, correlation, risk
                                    scoring, evidence collection
  scanner scan --target <id> ...   LEGACY recon-only path against an
                                    already-registered target (see
                                    "scanner target --help") -- never
                                    runs detection/correlation/risk/
                                    evidence, and --profile has no
                                    effect on it

Profiles:
  recon (default)   recon only -- crawler and detection both disabled
  web               bounded crawling + vulnerability detection
  deep              deeper (still bounded) crawling + vulnerability detection

Select with --profile; see "scanner profiles list"/"show <name>" for
each profile's exact settings. The default is "recon" deliberately: a
plain "scanner scan <target>" with no flags has always been
recon-only, so adding profiles must not make it more active by
default. An explicit --profile always wins over both the recon
default and a "crawler.enabled: true" config setting.

Detection coverage (profile "web"/"deep" only -- moot under "recon",
where detection is off by policy):
  Enabled by default:    XSS (reflected), SQL injection, command
                          injection, SSTI -- each via two independent
                          detectors (a heuristic one and a stronger,
                          mutation-based "-active" one)
  Registered, disabled:  SSRF, path traversal, open redirect -- each
                          needs operator-supplied configuration this
                          build does not ship (e.g. an out-of-band
                          callback service for SSRF)
  Conditional:            IDOR/BOLA (idor-active) -- disabled unless
                          --authz-identity is also supplied

Run "scanner detectors list" for the exact, current registry. Every
enabled detector tests query, form, and path-parameter inputs alike.
JSON request-body inputs are supported by the mutation engine but not
yet discovered by the live crawler (which only ever observes JSON in
a RESPONSE body); header/cookie inputs are not yet discovered or
tested at all. See docs/phase-3-29-active-detection-coverage-review.md
section 3 for the full input/mutation coverage matrix.

The scan output's "Inputs:"/"Detection:" blocks always explain what
actually happened for that specific run -- see "scanner inputs
<scan-id>" for the full discovered-input list.

Authentication (see docs/phase-3-14-authentication.md,
docs/phase-3-16-multi-identity.md, docs/phase-3-24-authorization.md):
  --auth-profile <name>    authenticate using a configured profile --
                            see "scanner auth profiles list"
  --identity <name>        authenticate as a configured identity
                            instead (mutually exclusive with
                            --auth-profile) -- see "scanner identities
                            list"
  --authz-identity <name>  authenticate a SECOND identity to enable
                            horizontal authorization (IDOR/BOLA)
                            testing against --identity's baseline
                            (requires --identity)

Authentication is entirely opt-in (omit all three flags to scan
unauthenticated, exactly as before) and a strict pre-flight step: an
invalid profile/identity or a failed login fails the command
immediately (exit code 5), before any scan job is created. When
authentication succeeds and crawling is enabled, the crawler carries
the session's cookies/headers to every same-origin request for that
session's own host. Authenticated crawling NEVER expands scope --
every request, authenticated or not, passes the same scope check.

See also:
  scanner profiles show <name>   one profile's exact settings
  scanner detectors list         which detectors are registered/enabled
  scanner auth profiles list     configured authentication profiles
  scanner identities list        configured identities
  scanner status <scan-id>       a finished scan's result counts
  scanner findings --scan <id>   a finished scan's findings
  scanner chains --scan <id>     related-finding chains
  scanner report --scan <id>     a full report (JSON or Markdown)`,
		Example: `  scanner scan 203.0.113.10 --profile web
  scanner scan example.com --profile deep --auth-profile lab-login
  scanner scan example.com --profile web --identity account-a
  scanner scan example.com --profile web --identity account-a --authz-identity account-b`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 1 {
				return runFullScan(a, cmd, args[0], portList, scanTimeout, profileFlag, authProfileFlag, identityFlag, authzIdentityFlag)
			}

			// Original, unchanged recon-only path (Phase 1): operates on
			// already-registered target IDs via --target, never touches
			// detection/correlation/risk/evidence at all, never consults
			// --profile.
			if len(targetIDs) == 0 {
				return missingArgError(cmd, "a target argument, or at least one --target <id>",
					[]string{
						"scanner scan example.com --profile web",
						"scanner target list                       # to find a registered --target <id>",
						"scanner scan --target <id>",
					})
			}
			pipeline := buildPipeline(a, portList)
			job, runErr := pipeline.Run(cmd.Context(), orchestration.RunOptions{TargetIDs: targetIDs, Ports: portList})

			fmt.Fprintf(cmd.OutOrStdout(), "scan %s finished with status %s\n", job.ID, job.Status)
			if job.Error != "" {
				fmt.Fprintf(cmd.OutOrStdout(), "error: %s\n", job.Error)
			}
			return runErr
		},
	}

	cmd.Flags().StringSliceVar(&targetIDs, "target", nil, "target ID to scan (repeatable) -- recon only, no detection/correlation/risk/evidence")
	cmd.Flags().IntSliceVar(&portList, "ports", nil, "ports to scan, comma-separated (overrides config default)")
	cmd.Flags().DurationVar(&scanTimeout, "timeout", 0, "overall scan timeout for the full-pipeline path (0 = use the selected profile's own timeout)")
	cmd.Flags().StringVar(&profileFlag, "profile", "", `scan profile: "recon" (default), "web", or "deep" -- see "scanner profiles list"`)
	_ = cmd.RegisterFlagCompletionFunc("profile", profileNameCompletion)
	cmd.Flags().StringVar(&authProfileFlag, "auth-profile", "", `authenticate before scanning using this authentication profile -- see "scanner auth profiles list"`)
	cmd.Flags().StringVar(&identityFlag, "identity", "", `authenticate before scanning as this configured identity -- see "scanner identities list" (mutually exclusive with --auth-profile)`)
	cmd.MarkFlagsMutuallyExclusive("auth-profile", "identity")
	cmd.Flags().StringVar(&authzIdentityFlag, "authz-identity", "", `authenticate a SECOND configured identity and enable horizontal authorization (IDOR/BOLA) testing against --identity's own baseline -- see "scanner identities list" (requires --identity)`)
	return cmd
}

// runFullScan implements task section 45's `scanner scan <target>`:
// the complete pipeline (scope -> recon -> discovery -> detection ->
// verification -> correlation -> risk -> evidence -> finalization) via
// internal/orchestrator.Orchestrator, from a single raw target string.
//
// Phase 3.12: profileFlag is resolved to an internal/policy.EffectivePolicy
// FIRST, before anything else touches the network, storage, or even
// constructs a Pipeline/Orchestrator -- an unknown --profile value
// fails right here (task's "no network activity, no scan job created
// if possible" for an invalid profile).
//
// Phase 3.14: authProfileFlag, if non-empty, is resolved and
// AUTHENTICATED next -- still strictly before an Orchestrator is built
// or a scan job created (task section 12's identical requirement,
// applied to authentication profiles). Authentication is a pre-flight
// step performed entirely OUTSIDE internal/orchestrator (see
// orchestrator.Options.AuthSession's doc comment for why): its result
// is either a ready-to-use *auth.Session threaded into Options, or a
// clean, distinct failure (exitAuthFailed) with no scan job ever
// created -- exactly mirroring how an invalid --profile is handled two
// lines above.
func runFullScan(a *app, cmd *cobra.Command, target string, portList []int, scanTimeout time.Duration, profileFlag, authProfileFlag, identityFlag, authzIdentityFlag string) error {
	cfg := a.cfg

	// Phase 3.24: validated before ANYTHING else touches the network --
	// the same "invalid options fail before network activity" discipline
	// --profile/--auth-profile/--identity already follow two checks
	// below. See docs/phase-3-24-authorization.md section 6.
	if authzIdentityFlag != "" {
		if identityFlag == "" {
			return &exitCodeErr{code: exitAuthFailed, err: fmt.Errorf("--authz-identity requires --identity (the baseline identity authorization tests are compared against)")}
		}
		if authzIdentityFlag == identityFlag {
			return &exitCodeErr{code: exitAuthFailed, err: fmt.Errorf("--authz-identity (%q) must name a DIFFERENT identity than --identity (%q)", authzIdentityFlag, identityFlag)}
		}
		if _, err := findIdentityConfig(a.cfg, authzIdentityFlag); err != nil {
			return &exitCodeErr{code: exitAuthFailed, err: err}
		}
	}

	eff, err := policy.Resolve(profileFlag, policy.ConfigView{
		CrawlerEnabled:  cfg.Crawler.Enabled,
		CrawlerMaxDepth: cfg.Crawler.MaxDepth,
		CrawlerMaxPages: cfg.Crawler.MaxPages,
	})
	if err != nil {
		return &exitCodeErr{code: exitGenericError, err: err}
	}

	var authSession *auth.Session
	switch {
	case identityFlag != "":
		// Phase 3.16: --identity resolves to a configured Identity ->
		// its (possibly credential-overridden) auth Profile, and tags
		// the resulting Session with IdentityName -- see
		// authenticateForIdentity's own doc comment. --auth-profile and
		// --identity are mutually exclusive (enforced by
		// MarkFlagsMutuallyExclusive above), so this branch and the one
		// below never both run.
		authSession, err = authenticateForIdentity(cmd, a, identityFlag)
		if err != nil {
			return err // already wrapped in *exitCodeErr by authenticateForIdentity
		}
	case authProfileFlag != "":
		authSession, err = authenticateForScan(cmd, a, authProfileFlag)
		if err != nil {
			return err // already wrapped in *exitCodeErr by authenticateForScan
		}
	}

	// Phase 3.24: the SECOND identity, authenticated the exact same way
	// (authenticateForIdentity, unchanged) as a fully independent
	// session -- never sharing a cookie jar, header map, or credential
	// with authSession above. See docs/phase-3-24-authorization.md
	// section 6.
	var authzSession *auth.Session
	var authzExecutor *detection.Executor
	if authzIdentityFlag != "" {
		authzSession, err = authenticateForIdentity(cmd, a, authzIdentityFlag)
		if err != nil {
			return err // already wrapped in *exitCodeErr by authenticateForIdentity
		}
		authzExecutor, err = buildAuthzExecutor(cmd, a, authzSession)
		if err != nil {
			return &exitCodeErr{code: exitGenericError, err: err}
		}
	}

	limits := orchestrator.DefaultLimits()
	limits.StageTimeout = eff.StageTimeout
	limits.ScanTimeout = eff.ScanTimeout
	if scanTimeout > 0 {
		// An explicit --timeout always overrides the resolved profile's
		// own default -- the same "an explicit, narrower operator
		// choice wins" precedent --profile itself follows relative to
		// config (see policy.Resolve's doc comment).
		limits.ScanTimeout = scanTimeout
	}

	detectionRegistry := productionRegistry()
	if authzExecutor != nil {
		detectionRegistry = productionRegistryWithAuthz(authzExecutor, authzIdentityFlag)
	}

	orch := &orchestrator.Orchestrator{
		Store:             a.store,
		Pipeline:          buildPipeline(a, portList),
		DetectionRegistry: detectionRegistry,
		DetectionExecutorConfig: detection.ExecutorConfig{
			Concurrency:  cfg.Detection.Workers,
			Limiter:      rate.NewLimiter(rate.Limit(cfg.Detection.RequestsPerSecond), int(cfg.Detection.RequestsPerSecond)+1),
			Timeout:      cfg.Detection.Timeout,
			MaxRedirects: cfg.Detection.MaxRedirects,
			UserAgent:    cfg.Detection.UserAgent,
			MaxRequests:  cfg.Detection.MaxRequestsPerRun,
		},
		DetectionConcurrency: eff.DetectionConcurrency,
		EvidenceLimits:       evidence.DefaultLimits(),
		Logger:               a.logger,
		Limits:               limits,
	}

	result, runErr := orch.Run(cmd.Context(), orchestrator.Options{
		Target:            target,
		Ports:             portList,
		ProfileLabel:      eff.ProfileName,
		DetectionDisabled: !eff.DetectionEnabled,
		CrawlOverride: &orchestrator.CrawlSettings{
			Enabled: eff.CrawlEnabled, MaxDepth: eff.CrawlMaxDepth, MaxPages: eff.CrawlMaxPages,
			ParameterLimits: parameters.Limits{MaxInputsPerEndpoint: eff.MaxInputsPerEndpoint, MaxTotalInputs: eff.MaxTotalInputs},
		},
		AuthSession: authSession,
	})
	printScanResult(cmd, result)

	switch result.Status {
	case orchestrator.StatusFailed:
		return &exitCodeErr{code: exitScanFailed, err: runErr}
	case orchestrator.StatusCancelled:
		return &exitCodeErr{code: exitScanCancelled, err: runErr}
	}
	return nil
}

// authenticateForScan resolves authProfileName against the loaded
// config and performs the login/setup flow -- task section 12's
// "invalid authentication profile must fail before network activity,
// create no scan job, return deterministic error, return correct exit
// code" plus section 8's "enforce scope before every authentication-
// related network request."
func authenticateForScan(cmd *cobra.Command, a *app, authProfileName string) (*auth.Session, error) {
	pc, err := auth.FindProfileConfig(authProfileConfigs(a.cfg), authProfileName)
	if err != nil {
		return nil, &exitCodeErr{code: exitAuthFailed, err: err}
	}
	profile, err := auth.ResolveProfile(pc)
	if err != nil {
		return nil, &exitCodeErr{code: exitAuthFailed, err: fmt.Errorf("auth profile %q: %w", authProfileName, err)}
	}
	return performAuthentication(cmd, a, profile, fmt.Sprintf("profile %q", profile.Name))
}

// authenticateForIdentity resolves identityName against the loaded
// config's "identities" list and performs the login/setup flow --
// Phase 3.16's own entry point, mirroring authenticateForScan's exact
// pre-flight contract (fail before network activity, no scan job on
// failure). A disabled identity fails immediately, before even
// resolving its auth profile -- task section 9's IDENTITY_DISABLED
// state is checked structurally, never authenticated against. On
// success (or failure -- Provider.Authenticate always returns a
// non-nil Session either way, see its own doc comment), the returned
// Session's IdentityName is set to identityName: this is the ONE place
// in the entire codebase a Session's IdentityName is ever populated --
// internal/auth itself never sets it (see Session.IdentityName's doc
// comment).
func authenticateForIdentity(cmd *cobra.Command, a *app, identityName string) (*auth.Session, error) {
	ic, err := findIdentityConfig(a.cfg, identityName)
	if err != nil {
		return nil, &exitCodeErr{code: exitAuthFailed, err: err}
	}
	if ic.Disabled {
		return nil, &exitCodeErr{code: exitAuthFailed, err: fmt.Errorf("identity %q is disabled (identities[%s].disabled = true)", identityName, identityName)}
	}
	profile, err := auth.ResolveIdentityProfile(ic, authProfileConfigs(a.cfg))
	if err != nil {
		return nil, &exitCodeErr{code: exitAuthFailed, err: err}
	}
	sess, authErr := performAuthentication(cmd, a, profile, fmt.Sprintf("identity %q (auth profile %q)", identityName, ic.AuthProfile))
	if sess != nil {
		sess.IdentityName = identityName
	}
	return sess, authErr
}

// performAuthentication is the ONE place this codebase actually
// performs a login/setup network attempt -- shared by both the bare
// --auth-profile path (Phase 3.14/3.15, unchanged) and the --identity
// path (Phase 3.16), so the two never independently drift. The
// scope.Validator/safedial.Dialer built here are constructed from the
// SAME currently-persisted scope rules (a.store.ScopeRules().List) the
// orchestrator's own SCOPE stage would separately load moments later
// for the scan itself -- one source of truth, no separate
// authentication-only scope mechanism. label is used only for the
// printed progress messages (never a secret).
func performAuthentication(cmd *cobra.Command, a *app, profile auth.Profile, label string) (*auth.Session, error) {
	rules, err := a.store.ScopeRules().List(cmd.Context())
	if err != nil {
		return nil, &exitCodeErr{code: exitGenericError, err: fmt.Errorf("loading scope rules for authentication: %w", err)}
	}
	validator := scope.NewValidator(rules, a.cfg.Scope.AllowReservedRanges)
	dialer := safedial.New(validator, dns.New(a.cfg.DNS.Timeout))

	provider, err := auth.NewProvider(profile)
	if err != nil {
		return nil, &exitCodeErr{code: exitAuthFailed, err: err}
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Authenticating with %s (host: %s)...\n", label, profile.Host)
	sess, authErr := provider.Authenticate(cmd.Context(), auth.Dependencies{Dialer: dialer, Validator: validator})
	if authErr != nil {
		fmt.Fprintf(cmd.OutOrStdout(), "Authentication FAILED for %s: %v\n", label, authErr)
		return sess, &exitCodeErr{code: exitAuthFailed, err: authErr}
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Authentication succeeded for %s.\n", label)
	return sess, nil
}

// buildAuthzExecutor builds a FRESH, fully independent
// *detection.Executor for the Phase 3.24 compare identity's own
// session -- mirroring internal/orchestrator.buildDetectionExecutor's
// exact construction (same scope-rule source, same
// detection.NewExecutorWithSession call, same
// session.JarFor(session.Host)/HeadersFor(session.Host) host-pinning),
// duplicated rather than shared because this executor must exist
// BEFORE the Orchestrator/registry are constructed (idoractive needs
// it at Registry-construction time, via New() -- see
// productionRegistryWithAuthz), whereas buildDetectionExecutor itself
// runs INSIDE Orchestrator.Run, too late for that. A separate
// detection.ExecutorConfig (with its own rate.Limiter instance, since
// rate.Limiter is not safe to share across independent Executors) is
// built from the SAME cfg.Detection.* settings runFullScan's own
// primary DetectionExecutorConfig below uses, so both identities'
// executors are bounded identically. See
// docs/phase-3-24-authorization.md section 1.3.
func buildAuthzExecutor(cmd *cobra.Command, a *app, session *auth.Session) (*detection.Executor, error) {
	cfg := a.cfg
	rules, err := a.store.ScopeRules().List(cmd.Context())
	if err != nil {
		return nil, fmt.Errorf("loading scope rules for authorization testing: %w", err)
	}
	validator := scope.NewValidator(rules, cfg.Scope.AllowReservedRanges)
	resolver := dns.New(cfg.DNS.Timeout)
	execCfg := detection.ExecutorConfig{
		Concurrency:  cfg.Detection.Workers,
		Limiter:      rate.NewLimiter(rate.Limit(cfg.Detection.RequestsPerSecond), int(cfg.Detection.RequestsPerSecond)+1),
		Timeout:      cfg.Detection.Timeout,
		MaxRedirects: cfg.Detection.MaxRedirects,
		UserAgent:    cfg.Detection.UserAgent,
		MaxRequests:  cfg.Detection.MaxRequestsPerRun,
	}
	sessCtx := mutation.SessionContext{
		Jar: session.JarFor(session.Host), Headers: session.HeadersFor(session.Host),
		PinnedHost: session.Host, IdentityContext: session.IdentityName,
	}
	return detection.NewExecutorWithSession(validator, resolver, execCfg, sessCtx), nil
}

func yesNo(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}

func printScanResult(cmd *cobra.Command, result orchestrator.Result) {
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "Scan ID:  %s\n", result.ScanID)
	fmt.Fprintf(out, "Target:   %s\n", result.Target)
	if result.Profile != "" {
		// Task's "Profile: field in scan output" -- empty only for a
		// Result built without Options.ProfileLabel (no caller in this
		// codebase does that anymore, but a future direct
		// Orchestrator.Run caller might, so this stays conditional
		// rather than printing a misleading blank profile name).
		fmt.Fprintf(out, "Profile:  %s\n", result.Profile)
	}
	fmt.Fprintf(out, "Status:   %s\n", result.Status)
	fmt.Fprintf(out, "Duration: %s\n", result.Duration.Round(time.Millisecond))

	// Phase 3.14 task section 7's explicit CLI requirement: distinguish
	// "scan completed without authentication" (AuthState ==
	// UNAUTHENTICATED, the default) from "authentication was attempted
	// and failed" (AUTHENTICATION_FAILED -- though in practice
	// runFullScan never reaches orch.Run at all in that case, since
	// authenticateForScan fails the command first; this branch exists
	// for any OTHER caller of the orchestrator that might reach this
	// state) from "authenticated scan completed successfully"
	// (AUTHENTICATED). Always shown once a profile was involved.
	if result.AuthProfile != "" {
		fmt.Fprintln(out, "\nAuth:")
		// Phase 3.16 task section 6's example format: "Identity:" is
		// shown ONLY when a --identity was used (never for a bare
		// --auth-profile scan, matching task section 2's "do not
		// collapse these concepts" -- Profile always names the
		// underlying auth profile; Identity names the configured
		// identity, and is empty when there wasn't one).
		if result.Identity != "" {
			fmt.Fprintf(out, "  Identity:               %s\n", result.Identity)
		}
		fmt.Fprintf(out, "  Profile:                %s\n", result.AuthProfile)
		fmt.Fprintf(out, "  Status:                 %s\n", result.AuthState)
		// Phase 3.15 task section N's example format.
		fmt.Fprintf(out, "  Authenticated Requests: %d\n", result.AuthenticatedRequests)
		fmt.Fprintf(out, "  Session Expired:        %s\n", yesNo(result.SessionExpired))
	}

	// Phase 3.15 task section N/8: "clearly distinguish authenticated
	// vs unauthenticated discovered resources" -- shown whenever
	// crawling actually happened (public or authenticated), mirroring
	// the Inputs:/Detection: blocks' own "always shown when relevant"
	// precedent. Silent (not printed) only when nothing was crawled at
	// all (e.g. the recon profile), matching how those blocks handle
	// their own "nothing to report" case by printing zeros rather than
	// omitting the section -- CrawlSummary is the one exception,
	// because unlike Inputs/Detection it has no policy-vs-target
	// distinction worth explaining, so an all-zero block would only add
	// noise to a recon-profile scan's output.
	cs := result.CrawlSummary
	if cs.PublicURLs > 0 || cs.AuthenticatedURLs > 0 {
		fmt.Fprintln(out, "\nCrawl:")
		fmt.Fprintf(out, "  Public URLs:             %d\n", cs.PublicURLs)
		fmt.Fprintf(out, "  Authenticated URLs:      %d\n", cs.AuthenticatedURLs)
		fmt.Fprintf(out, "  Authenticated Endpoints: %d\n", cs.AuthenticatedEndpoints)
	}

	// Phase 3.13 task's "scan result must expose: inputs discovered,
	// unique endpoints with inputs, input discovery warnings." Always
	// shown (matching the Detection block's own "always shown"
	// precedent below) so a scan with zero inputs (e.g. the recon
	// profile, or a target with nothing crawlable) is legible as "zero,
	// by policy or by evidence" rather than a silently absent section.
	is := result.InputSummary
	fmt.Fprintln(out, "\nInputs:")
	fmt.Fprintf(out, "  Discovered: %d\n", is.InputCount)
	fmt.Fprintf(out, "  Unique endpoints with inputs: %d\n", is.UniqueEndpointsWithInputs)
	if len(is.Warnings) > 0 {
		fmt.Fprintln(out, "  Warnings:")
		for _, w := range is.Warnings {
			fmt.Fprintf(out, "    - %s\n", w)
		}
	}

	// Detection readiness (Phase 3.11.2 task section 2, extended by
	// Phase 3.12): always shown, so "Findings: (none)" is never the
	// only signal an operator has for judging whether detection
	// actually ran -- see the Findings section below, which explicitly
	// cross-references this block.
	//
	// "Policy enabled" (Phase 3.12) answers a DIFFERENT question than
	// "Enabled" (Phase 3.11.2, unchanged below): "Policy enabled" is
	// whether the active scan profile permits detection to run at all;
	// "Enabled" is how many REGISTERED detectors are individually
	// enabled in the registry. A recon-profile scan shows
	// "Policy enabled: false" with "Enabled: 0" underneath it (detection
	// never ran, so the registry's own per-detector enablement is moot);
	// a web/deep-profile scan shows "Policy enabled: true" with
	// "Enabled: <N>" reflecting the registry as it always has.
	ds := result.DetectorSummary
	fmt.Fprintln(out, "\nDetection:")
	fmt.Fprintf(out, "  Policy enabled: %v\n", ds.State != orchestrator.DetectionStateDisabledByProfile)
	if ds.State == orchestrator.DetectionStateDisabledByProfile {
		fmt.Fprintln(out, "  Reason: profile disables vulnerability detection")
	}
	fmt.Fprintf(out, "  Registered: %d\n", ds.DetectorsRegistered)
	fmt.Fprintf(out, "  Enabled: %d\n", ds.DetectorsEnabled)
	fmt.Fprintf(out, "  Eligible targets: %d\n", ds.EligibleTargets)
	fmt.Fprintf(out, "  Detector runs: %d\n", ds.DetectorRuns)
	fmt.Fprintf(out, "  Raw findings: %d\n", ds.RawFindingsCreated)
	fmt.Fprintf(out, "  Canonical findings: %d\n", ds.CanonicalFindings)
	// Phase 3.19 task section 12: RequestsIssued was already computed
	// (Executor.RequestCount(), summed across Do and, since this phase,
	// ExecuteMutation) but never printed -- observability before/after
	// active detection multiplies request volume, with no secret ever
	// exposed (a plain integer).
	fmt.Fprintf(out, "  Requests issued: %d\n", ds.RequestsIssued)

	if len(result.Errors) > 0 {
		fmt.Fprintln(out, "\nErrors/Warnings:")
		for _, e := range result.Errors {
			fmt.Fprintf(out, "  [%s] %s: %s\n", e.Category, e.Stage, e.Message)
		}
	}

	fmt.Fprintln(out, "\nFindings:")
	if len(result.Findings) == 0 {
		// Task section 4: "no findings" must never read as "all
		// detectors executed and found nothing" unless that's actually
		// true -- the wording here depends on ds.State (task section
		// 5's 3 states), not just on the findings list being empty.
		switch ds.State {
		case orchestrator.DetectionStateExecuted:
			fmt.Fprintln(out, "  (none -- detectors executed, no vulnerabilities found)")
		case orchestrator.DetectionStateFailed:
			fmt.Fprintln(out, "  (none -- detection did not complete; see Errors/Warnings above)")
		case orchestrator.DetectionStateDisabledByProfile:
			fmt.Fprintln(out, "  (none -- vulnerability detection is disabled by the active scan profile; see Detection summary above)")
		default: // DetectionStateNotRun, or a scan that never reached DETECTION at all
			fmt.Fprintln(out, "  (none -- no vulnerability detectors were executed; see Detection summary above)")
		}
		return
	}

	for _, severity := range []models.Severity{models.SeverityCritical, models.SeverityHigh, models.SeverityMedium, models.SeverityLow, models.SeverityInfo} {
		var matching []int
		for i, pkg := range result.Findings {
			if pkg.Finding.Severity == severity {
				matching = append(matching, i)
			}
		}
		if len(matching) == 0 {
			continue
		}
		fmt.Fprintf(out, "%s:\n", severityLabel(severity))
		w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "  ID\tTYPE\tURL\tPARAMETER\tSEVERITY\tCONFIDENCE\tRISK\tPRIORITY")
		for _, i := range matching {
			pkg := result.Findings[i]
			url := fmt.Sprintf("%s://%s:%d%s", pkg.Finding.Asset.Scheme, pkg.Finding.Asset.Host, pkg.Finding.Asset.Port, pkg.Finding.Asset.Path)
			fmt.Fprintf(w, "  %s\t%s\t%s\t%s\t%s\t%.0f%%\t%d\t%s\n",
				pkg.Finding.FindingID, pkg.Finding.VulnerabilityType, url, pkg.Finding.HTTP.Parameter,
				pkg.Finding.Severity, pkg.Finding.Confidence*100, pkg.Risk.RiskScore, pkg.Risk.Priority)
		}
		w.Flush()
	}

	fmt.Fprintf(out, "\nSummary: %d total (critical=%d high=%d medium=%d low=%d info=%d)\n",
		result.Summary.Total, result.Summary.Critical, result.Summary.High, result.Summary.Medium, result.Summary.Low, result.Summary.Info)
}

func severityLabel(s models.Severity) string {
	switch s {
	case models.SeverityCritical:
		return "CRITICAL"
	case models.SeverityHigh:
		return "HIGH"
	case models.SeverityMedium:
		return "MEDIUM"
	case models.SeverityLow:
		return "LOW"
	default:
		return "INFO"
	}
}
