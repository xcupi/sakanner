package reporting

import (
	"fmt"
	"html"
	"strings"

	"sakanner/pkg/models"
)

// mdEscape neutralizes a value before it's embedded in a Markdown table
// cell. Fields like HTTP response titles, TLS certificate subject/issuer
// strings, and response headers originate from the scanned target, which
// this platform explicitly does not trust (TLS certificates aren't even
// verified, by design, so their fields can contain arbitrary attacker
// content). Without escaping, such a value could break the table's row
// structure (embedded "|" or newlines) or, if the report is later
// rendered as HTML by some downstream viewer, inject markup/script that
// executes in the analyst's browser -- Markdown permits raw inline HTML
// by default. html.EscapeString neutralizes that; the pipe/newline
// replacements keep the table itself well-formed.
func mdEscape(s string) string {
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "|", "\\|")
	return html.EscapeString(s)
}

// Markdown renders r as a human-readable Markdown summary.
func (r *Report) Markdown() string {
	var b strings.Builder

	fmt.Fprintf(&b, "# Scan Report: %s\n\n", r.Job.ID)
	fmt.Fprintf(&b, "- **Status:** %s\n", r.Job.Status)
	fmt.Fprintf(&b, "- **Started:** %s\n", r.Job.StartedAt.Format("2006-01-02 15:04:05 MST"))
	if r.Job.FinishedAt != nil {
		fmt.Fprintf(&b, "- **Finished:** %s\n", r.Job.FinishedAt.Format("2006-01-02 15:04:05 MST"))
	}
	if r.Job.Error != "" {
		fmt.Fprintf(&b, "- **Error:** %s\n", r.Job.Error)
	}
	fmt.Fprintf(&b, "- **Targets:** %s\n\n", strings.Join(r.Job.TargetIDs, ", "))

	fmt.Fprintf(&b, "## Summary\n\n")
	fmt.Fprintf(&b, "| Assets | Hosts | DNS Records | Services | HTTP Services | Technologies | Endpoints | Inputs | Findings |\n")
	fmt.Fprintf(&b, "|---|---|---|---|---|---|---|---|---|\n")
	fmt.Fprintf(&b, "| %d | %d | %d | %d | %d | %d | %d | %d | %d |\n\n",
		len(r.Assets), len(r.Hosts), len(r.DNSRecords), len(r.Services), len(r.HTTPServices), len(r.Technologies), len(r.Endpoints), len(r.Parameters), len(r.Findings))

	writeAssetsSection(&b, r)
	writeDNSRecordsSection(&b, r)
	writeServicesSection(&b, r)
	writeHTTPSection(&b, r)
	writeTechnologiesSection(&b, r)
	writeEndpointsSection(&b, r)
	writeParametersSection(&b, r)
	writeFindingsSection(&b, r)

	return b.String()
}

func writeAssetsSection(b *strings.Builder, r *Report) {
	if len(r.Assets) == 0 {
		return
	}
	fmt.Fprintf(b, "## Assets\n\n")
	fmt.Fprintf(b, "| Name | Source | IPs |\n|---|---|---|\n")
	hostsByAsset := map[string][]string{}
	for _, h := range r.Hosts {
		hostsByAsset[h.AssetID] = append(hostsByAsset[h.AssetID], h.IPAddress)
	}
	for _, a := range r.Assets {
		fmt.Fprintf(b, "| %s | %s | %s |\n", mdEscape(a.Name), mdEscape(a.Source), strings.Join(hostsByAsset[a.ID], ", "))
	}
	b.WriteString("\n")
}

func writeDNSRecordsSection(b *strings.Builder, r *Report) {
	if len(r.DNSRecords) == 0 {
		return
	}
	nameByAsset := map[string]string{}
	for _, a := range r.Assets {
		nameByAsset[a.ID] = a.Name
	}

	fmt.Fprintf(b, "## DNS Records\n\n")
	fmt.Fprintf(b, "| Asset | Type | Value | Priority |\n|---|---|---|---|\n")
	for _, dr := range r.DNSRecords {
		priority := ""
		if dr.Priority != 0 {
			priority = fmt.Sprintf("%d", dr.Priority)
		}
		fmt.Fprintf(b, "| %s | %s | %s | %s |\n", mdEscape(nameByAsset[dr.AssetID]), dr.Type, mdEscape(dr.Value), priority)
	}
	b.WriteString("\n")
}

func writeServicesSection(b *strings.Builder, r *Report) {
	if len(r.Services) == 0 {
		return
	}
	ipByHost := map[string]string{}
	for _, h := range r.Hosts {
		ipByHost[h.ID] = h.IPAddress
	}

	fmt.Fprintf(b, "## Open Services\n\n")
	fmt.Fprintf(b, "| Host | Port | Protocol |\n|---|---|---|\n")
	for _, s := range r.Services {
		fmt.Fprintf(b, "| %s | %d | %s |\n", ipByHost[s.HostID], s.Port, s.Protocol)
	}
	b.WriteString("\n")
}

func writeHTTPSection(b *strings.Builder, r *Report) {
	if len(r.HTTPServices) == 0 {
		return
	}
	fmt.Fprintf(b, "## HTTP Services\n\n")
	fmt.Fprintf(b, "| URL | Status | Title | TLS | Redirects |\n|---|---|---|---|---|\n")
	for _, h := range r.HTTPServices {
		fmt.Fprintf(b, "| %s | %d | %s | %s | %s |\n",
			mdEscape(h.URL), h.StatusCode, mdEscape(h.Title), mdEscape(tlsSummary(h)), redirectSummary(h))
	}
	b.WriteString("\n")
}

func tlsSummary(h models.HTTPService) string {
	if h.TLSSubject == "" {
		return ""
	}
	s := h.TLSVersion
	if h.TLSSelfSigned {
		if s != "" {
			s += ", "
		}
		s += "self-signed"
	}
	if s == "" {
		s = h.TLSSubject
	}
	return s
}

func redirectSummary(h models.HTTPService) string {
	if len(h.RedirectChain) == 0 {
		return ""
	}
	return fmt.Sprintf("%d hop(s)", len(h.RedirectChain))
}

func writeTechnologiesSection(b *strings.Builder, r *Report) {
	if len(r.Technologies) == 0 {
		return
	}
	urlByHTTPService := map[string]string{}
	for _, h := range r.HTTPServices {
		urlByHTTPService[h.ID] = h.URL
	}

	fmt.Fprintf(b, "## Technologies\n\n")
	fmt.Fprintf(b, "| URL | Technology | Version | Category | Confidence | Source |\n|---|---|---|---|---|---|\n")
	for _, t := range r.Technologies {
		fmt.Fprintf(b, "| %s | %s | %s | %s | %.0f%% | %s |\n",
			mdEscape(urlByHTTPService[t.HTTPServiceID]), mdEscape(t.Name), mdEscape(t.Version), mdEscape(t.Category), t.Confidence*100, mdEscape(t.Source))
	}
	b.WriteString("\n")
}

func writeEndpointsSection(b *strings.Builder, r *Report) {
	if len(r.Endpoints) == 0 {
		return
	}
	urlByHTTPService := map[string]string{}
	for _, h := range r.HTTPServices {
		urlByHTTPService[h.ID] = h.URL
	}

	fmt.Fprintf(b, "## Endpoints\n\n")
	fmt.Fprintf(b, "| Service | Method | Path | Source |\n|---|---|---|---|\n")
	for _, e := range r.Endpoints {
		fmt.Fprintf(b, "| %s | %s | %s | %s |\n", mdEscape(urlByHTTPService[e.HTTPServiceID]), mdEscape(e.Method), mdEscape(e.Path), mdEscape(e.Source))
	}
	b.WriteString("\n")
}

// writeParametersSection renders Phase 3.13's discovered inputs.
// Values are already redacted at discovery time
// (internal/parameters.redactIfSensitive, reusing
// internal/evidence.IsSensitiveFieldName's own blocklist) -- mdEscape
// here guards against the value breaking table structure or carrying
// injected markup, not against secret exposure, which is handled
// upstream.
func writeParametersSection(b *strings.Builder, r *Report) {
	if len(r.Parameters) == 0 {
		return
	}
	pathByEndpoint := map[string]string{}
	for _, e := range r.Endpoints {
		pathByEndpoint[e.ID] = e.Path
	}

	fmt.Fprintf(b, "## Inputs\n\n")
	fmt.Fprintf(b, "| Endpoint | Method | Name | Location | Classification | Value |\n|---|---|---|---|---|---|\n")
	for _, p := range r.Parameters {
		fmt.Fprintf(b, "| %s | %s | %s | %s | %s | %s |\n",
			mdEscape(pathByEndpoint[p.EndpointID]), mdEscape(p.Method), mdEscape(p.Name), mdEscape(p.Location), mdEscape(p.Classification), mdEscape(p.Value))
	}
	b.WriteString("\n")
}

func writeFindingsSection(b *strings.Builder, r *Report) {
	fmt.Fprintf(b, "## Findings\n\n")
	if len(r.Findings) == 0 {
		b.WriteString("No findings (no vulnerability detectors are registered -- see docs/phase-3-1-detection-engine.md).\n\n")
		return
	}
	fmt.Fprintf(b, "| Severity | Detector | Title | Host | Endpoint | Confidence | Status |\n|---|---|---|---|---|---|---|\n")
	for _, f := range r.Findings {
		fmt.Fprintf(b, "| %s | %s | %s | %s | %s | %.0f%% | %s |\n",
			severityLabel(f.Severity), mdEscape(f.DetectorID), mdEscape(f.Title), mdEscape(f.Host), mdEscape(f.AffectedEndpoint), f.Confidence*100, f.ValidationStatus)
	}
	b.WriteString("\n")
}

func severityLabel(s models.Severity) string {
	if s == "" {
		return "unknown"
	}
	return string(s)
}
