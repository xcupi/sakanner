# Phase 2 PARTIAL Items — Review

This document reviews every item the Phase 2 acceptance test
(`docs/phase-2-acceptance-test.md`) flagged as incomplete coverage. No
code was changed to produce this document — it is analysis only, per
the request.

## Correction to the acceptance report's count

Before reviewing, a correction: the acceptance report's Summary section
says **"PARTIAL: 5"** and, two lines above that, **"4 items... marked
PARTIAL"** — those two counts already disagree with each other, and
neither matches the actual data. Re-checking the report line by line:

- Exactly **3 table rows** are literally tagged `PARTIAL`: Section 3
  (DNS record-level dedup), Section 6 (ASP.NET/Express framework
  detection), Section 7 (duplicate JavaScript references).
- Section 18's external-tool-argument-parsing item was tagged
  **`PASS, with one residual risk noted as reviewed-not-executed`** in
  its own table row — not `PARTIAL` — but the Summary's prose swept it
  into the PARTIAL tally anyway when naming examples.

So there are **4 distinct items** worth reviewing, not 5. There is no
missing fifth item being silently dropped here — the "5" in the prior
report was a counting error made while writing that summary, not a
reference to real, distinct content. I'm flagging this directly rather
than padding this document to force a count of five. The 4 real items
are reviewed in full below, including the Section 18 item, since it's
clearly relevant to this review even though its original label was
technically "PASS with a caveat" rather than "PARTIAL."

---

## Item 1: DNS record-level deduplication

### 1. Test/requirement
Section 3 (DNS Discovery), "Deduplication" checklist row: *"a name
queried twice in one job would produce two DNSRecord rows"* should not
happen.

### 2. Why it is PARTIAL
The acceptance-testing pass fixed a *different, broader* bug — the same
**hostname** being discovered via two sources (explicit target +
subdomain enumeration) creating two separate `Asset` rows, which as a
side effect caused DNS record enumeration to run twice for that host
(Finding #2 in the acceptance report). That fix closes the *reproduced*
scenario, but no test verifies the narrower, still-open case: **a single
DNS lookup returning the same record value more than once.**

I re-checked this while writing this review (not assumed):

- `internal/storage/migrations/0003_dns_records.sql` defines no `UNIQUE`
  constraint on `(asset_id, type, value)` — only a primary key on `id`
  and a non-unique index on `scan_job_id`.
- `dnsRecordRepo.Create` (`internal/storage/sqlite/repos.go:434`) is an
  unconditional `INSERT`, with no existence check beforehand.
- `dnsxRecordEnumerator.LookupRecords` (`internal/dns/records.go`)
  appends every value from `line.MX`/`line.TXT`/`line.NS` verbatim, with
  no dedup of the tool's own output.

So: if a DNS server actually has a duplicate record in its zone (this
happens in practice — misconfigured zones, or an external tool merging
results from multiple resolvers with overlapping answers), sakanner will
persist the duplicate as two identical `DNSRecord` rows.

### 3. What functionality is currently missing
A dedup check — either a `UNIQUE(scan_job_id, asset_id, type, value)`
constraint at the schema level, or an equivalent check in
`persistAssetHostsAndDNSRecords`'s record-persisting loop
(`internal/orchestration/pipeline.go`) — before inserting a `DNSRecord`.

### 4. Is the gap intentional?
No. It's an oversight, not a decision. The asset-level fix addressed the
bug that was actually reproduced during acceptance testing; auditing
whether the *same* class of gap existed one layer deeper (at the record
level) wasn't done at the time.

### 5. Required for the Phase 2 specification?
Partially. The original Phase 2 build request's DNS section explicitly
lists "deduplication" as a thing to verify, so this is a named
acceptance-test concern. But the project's own architecture (from the
Phase 1 planning session) already designates **dedup as a dedicated
future-phase pipeline stage** (`internal/correlation`,
`internal/findings` — currently doc-only stubs — are literally where
system-wide result deduplication/correlation is planned to live). That
makes this specific gap read more like "the future dedup phase hasn't
started yet" than "Phase 2 shipped something broken."

### 6. Risk if left unresolved
**Low.** Impact is cosmetic/report-noise (a duplicate line in a DNS
records table), not a correctness or security issue. It doesn't affect
scope enforcement, doesn't cause incorrect scan results (both rows would
have identical, correct content), and DNS record counts per asset are
small enough that this can't meaningfully bloat storage or a report.

### 7. Recommendation: **DEFER TO FUTURE PHASE**
Low risk, not safety-critical, and the project's own roadmap already
plans a dedicated dedup/correlation phase that is the natural home for
this class of fix — doing it piecemeal now (one `UNIQUE` constraint at a
time, stage by stage) risks a worse outcome than doing it once,
systematically, when `internal/correlation`/`internal/findings` are
actually built out.

---

## Item 2: Framework detection (ASP.NET/Express) through a full pipeline run

### 1. Test/requirement
Section 6 (Technology Fingerprinting), "Framework detection" — verify
detection is backed by evidence from an actual target response, not just
that a signature exists.

### 2. Why it is PARTIAL
During acceptance testing, one new end-to-end test was written
(`TestRun_CMSDetectionEndToEnd`, serving a real WordPress-shaped page
through a full `Pipeline.Run` and confirming the persisted `Technology`
row). The equivalent test was **not** written for the `ASP.NET` and
`Express` signatures in `fingerprint.DefaultSignatures()` — they remain
verified only by `internal/fingerprint/fingerprint_test.go`'s
header-matching unit tests (which call `Identify()` directly with a
constructed `http.Header`, never through a live server or the pipeline).

### 3. What functionality is currently missing
An integration test (or Test Lab fixture) that serves
`X-Powered-By: ASP.NET` / `X-AspNet-Version: ...` or
`X-Powered-By: Express` through a real `httptest` server, runs it
through `Pipeline.Run`, and asserts the persisted `Technology` row —
mirroring the WordPress test exactly.

### 4. Is the gap intentional?
No. During acceptance testing, CMS detection was judged the
higher-value gap to close (WordPress/Drupal detection uses a different
matching mode — `BodyPattern` + a version-extraction regex against page
content — than ASP.NET/Express's `HeaderMatches`, so closing the CMS gap
also incidentally proves the *other* matching mode works end-to-end).
Framework detection was left as a residual, lower-priority gap under
time pressure, not excluded on purpose.

### 5. Required for the Phase 2 specification?
**Yes**, more directly than Item 1. "Framework detection" is explicitly
named in both the original Phase 2 build request and the acceptance
test's Section 6 checklist, and the `ASP.NET`/`Express` signatures are
already shipped, working code (not a stub) — this gap is purely in
*verification depth* of an already-implemented, already-named Phase 2
capability, not a missing feature.

### 6. Risk if left unresolved
**Low.** `ASP.NET`/`Express` use `HeaderMatches` — the exact same
matching mechanism already proven end-to-end for `nginx` and `Apache`
(both real Test Lab fixtures, both passing). The fetch → fingerprint →
persist wiring is shared, untouched-by-signature-specifics code. The
realistic residual risk is narrow: a typo in one of these two specific
regex patterns that only an end-to-end run — not the unit test, which
uses the same constructed header the pattern was written against — would
catch. `internal/fingerprint/fingerprint_test.go`'s
`TestDefaultSignatures_HeaderMatches` already exercises the same regex
patterns directly, further narrowing what an integration test would add.

### 7. Recommendation: **FIX BEFORE PHASE 3**
Cheap and mechanical — it's a direct copy of the exact pattern already
used for `TestRun_CMSDetectionEndToEnd` (serve two headers through an
`httptest` server, run the pipeline, assert the `Technology` row), no
design decisions required, and it closes a named Phase 2 checklist item
completely rather than leaving it partially verified. Unlike Item 1,
there's no future-phase dependency blocking this — it's purely
unfinished verification of already-shipped code.

---

## Item 3: Duplicate JavaScript reference deduplication

### 1. Test/requirement
Section 7 (JavaScript Discovery), "Duplicate references" — the original
Phase 2 request explicitly asks to verify "duplicate references" and
"normalization and deduplication" for JS discovery specifically.

### 2. Why it is PARTIAL
No Test Lab fixture has two identical `<script src="...">` tags on one
page (or the same script referenced from two different crawled pages),
so this exact scenario was never exercised, even though the general
"two identical links dedup to one endpoint" case *was* proven (Section
8/9, `scanner.test`'s duplicated `/about` link).

### 3. What functionality is currently missing
Not an implementation gap — a **test** gap. Re-reading the relevant code
for this review (not assumed) confirms both halves of this concern are
already implemented:

- **Fetch-side dedup:** `discoverJavaScriptTechnologies`
  (`internal/orchestration/pipeline.go:729`) keeps a `seen map[string]bool`
  keyed by `scriptURL`, checked before every fetch, across all pages in
  one crawl — so the same script URL is fetched and fingerprinted at
  most once per scan, regardless of how many times it's referenced.
- **Endpoint-record dedup:** `endpoints.Normalize`'s `add()` closure
  (`internal/endpoints/endpoints.go:41`) applies the same
  `seen[(path,method,source)]` check uniformly to `SourceJavaScript`
  entries as it does to links/forms/crawled pages.

What's missing is a test that actually exercises this with a genuine
duplicate-script fixture, per the instruction not to assume a feature
works because the code exists.

### 4. Is the gap intentional?
No — straightforward oversight in fixture design; the Test Lab's
`scanner.test` page has exactly one `<script src>` tag, so this path was
never reached.

### 5. Required for the Phase 2 specification?
**Yes**, explicitly — the original Phase 2 request's JavaScript-discovery
section names "duplicate references" and "normalization and
deduplication" directly, more explicitly than either Item 1 or Item 2.

### 6. Risk if left unresolved
**Low**, for the same reason as Item 2: the dedup logic for both the
fetch path and the persisted-endpoint path is shared, generic code
already proven correct for the analogous link/form cases. There is no
JS-specific branch in either dedup mechanism that could plausibly behave
differently for scripts than for links.

### 7. Recommendation: **FIX BEFORE PHASE 3**
Same reasoning as Item 2: cheap (extend one Test Lab fixture with a
duplicate `<script src>` tag, or add a focused unit test against
`endpoints.Normalize` and `discoverJavaScriptTechnologies` directly),
explicitly named in the original spec, and removes any remaining doubt
about a capability that's very likely already correct. No future-phase
dependency blocks this.

---

## Item 4: External tool argument-parsing safety, verified against a real binary

### 1. Test/requirement
Section 18 (Security Review), "unsafe external tool execution" —
whether a target-derived value (e.g., a hostname reported by subfinder)
that happens to look like a CLI flag (starts with `-`) could be
misinterpreted as a flag by the *external tool's own* argument parser
when passed as an adjacent argv element (e.g.,
`["-u", "-o=/tmp/evil", ...]`), rather than being consumed as that
flag's value.

### 2. Why it is PARTIAL (labeled "PASS, with one residual risk" in the report)
This was reviewed by code inspection and general reasoning about argv
conventions, but — unlike Item 4's neighbors — **it cannot be resolved
by writing more Go tests.** It requires an actual `naabu`/`httpx`/
`katana`/`subfinder`/`dnsx` binary (or the Docker Compose profile that
would run one) to observe how *that specific tool's* argument parser
really behaves. Neither is available: no external recon tools are
installed, and Docker is not installed on this machine (documented
already in `docs/phase-2-test-lab.md`).

### 3. What functionality is currently missing
Not a missing feature — a missing **empirical verification**. What's
architecturally true and already confirmed:
- Every external-tool argv is built via `exec.CommandContext(ctx, binary, args...)`
  (`pkg/plugins/exec.go`) — never a shell, so classic shell injection is
  categorically not possible.
- Adjacent flag-value pairs (`"-u", target`) are how virtually every CLI
  parser, including Go's `flag`/`pflag` and the `goflags` library the
  ProjectDiscovery tools use, associates a value with its flag,
  regardless of what the value's content looks like.

What's unverified is whether that general rule actually holds for these
five specific tools' specific parsers, in practice — that requires
running them, not reading their source.

### 4. Is the gap intentional?
No — purely an environmental constraint (no Docker, no tools installed),
not a scoping decision.

### 5. Required for the Phase 2 specification?
Indirectly. It's not one of the named A–F external-tool test conditions
in the original request (installed/missing/valid/malformed/timeout/
non-zero-exit), but it falls under the security-review section's
"unsafe external tool execution" checklist item, which *is* explicitly
requested.

### 6. Risk if left unresolved
**Low-to-moderate, and bounded.** Even in the worst case (a real tool's
parser did misinterpret a flag-like hostname), the blast radius is
contained to that external process behaving unexpectedly — it does
**not** touch sakanner's own scope-enforcement guarantee. The
dial-performing tools (naabu/httpx/katana) are already documented as
carrying reduced scope-revalidation assurance whenever selected (a
`WARN`-level log fires every time), and this specific risk would at most
compound that already-disclosed, already-accepted trust boundary — it
wouldn't create a new one. It's also a narrow trigger condition: a
subfinder/dnsx result would need to report a name starting with `-`,
which is not typical DNS-tool output.

### 7. Recommendation: **DEFER TO FUTURE PHASE**
The verification itself genuinely can't be completed with code changes
alone — it needs either the operator's permission to install one real
tool (or Docker) in an environment where that's appropriate, which is
outside this review's scope to decide unilaterally. That said, a cheap,
low-risk **hardening** measure is available independent of ever proving
exploitability: reject or `--`-terminate argv values that begin with `-`
before they reach any external-tool invocation. That's a legitimate
candidate for a small, self-contained fix if the team wants
defense-in-depth regardless of whether real-world exploitability is ever
confirmed — but it's a distinct, optional hardening decision from "close
this PARTIAL," and shouldn't be bundled into resolving the verification
gap itself. Recommending DEFER for the verification; noting the
hardening option separately for the team's discretion.

---

## Summary

| # | Item | Required by spec? | Risk | Recommendation |
|---|---|---|---|---|
| 1 | DNS record-level dedup | Named, but overlaps a planned future dedup/correlation phase | Low | **DEFER TO FUTURE PHASE** |
| 2 | ASP.NET/Express framework detection, full pipeline | Yes, named and already-implemented | Low | **FIX BEFORE PHASE 3** |
| 3 | Duplicate JS reference dedup | Yes, explicitly named | Low | **FIX BEFORE PHASE 3** |
| 4 | External tool argv-parsing vs. a real binary | Indirectly (security review) | Low-moderate, bounded | **DEFER TO FUTURE PHASE** (verification blocked on environment; optional hardening available separately) |

No code was changed while producing this review, per the request.
