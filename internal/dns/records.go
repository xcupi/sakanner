package dns

import (
	"context"
	"log/slog"
	"strings"
	"sync"

	"sakanner/pkg/models"
	"sakanner/pkg/plugins"
)

// Record is one DNS record discovered for a name, independent of which
// RecordEnumerator produced it.
type Record struct {
	Type     models.DNSRecordType
	Value    string
	Priority int
}

// RecordEnumerator looks up CNAME/MX/TXT/NS records for a name.
// LookupRecords is best-effort: an individual record type simply not
// existing, or the whole lookup failing, yields fewer (or zero) results
// rather than an error -- most hosts have no MX/TXT/NS of their own, and
// that is the overwhelmingly common case, not a failure.
type RecordEnumerator interface {
	Name() string
	LookupRecords(ctx context.Context, name string) []Record
}

// NewRecordEnumerator selects a RecordEnumerator per sakanner's uniform
// auto|native|<tool> backend contract (see pkg/plugins.Resolve): dnsx if
// backend selects it, the built-in resolver-backed enumerator otherwise.
// Like subfinder, dnsx only performs DNS lookups -- it never dials the
// target itself -- so this stage is not "sensitive" in the
// pkg/plugins.Resolve sense.
func NewRecordEnumerator(backend string, resolver Resolver, logger *slog.Logger) (RecordEnumerator, error) {
	decision, err := plugins.Resolve(backend, plugins.Dnsx, false, logger)
	if err != nil {
		return nil, err
	}
	if decision == plugins.UseTool {
		path, _ := plugins.Detect(plugins.Dnsx.BinaryName)
		return NewDnsxRecordEnumerator(path), nil
	}
	return NewNativeRecordEnumerator(resolver), nil
}

type nativeRecordEnumerator struct {
	resolver Resolver
}

// NewNativeRecordEnumerator returns a RecordEnumerator backed by resolver,
// looking up CNAME/MX/TXT/NS concurrently for each call.
func NewNativeRecordEnumerator(resolver Resolver) RecordEnumerator {
	return &nativeRecordEnumerator{resolver: resolver}
}

func (e *nativeRecordEnumerator) Name() string { return "native" }

func (e *nativeRecordEnumerator) LookupRecords(ctx context.Context, name string) []Record {
	var (
		mu  sync.Mutex
		out []Record
		wg  sync.WaitGroup
	)
	add := func(r Record) {
		mu.Lock()
		out = append(out, r)
		mu.Unlock()
	}

	wg.Add(4)
	go func() {
		defer wg.Done()
		cname, err := e.resolver.LookupCNAME(ctx, name)
		if err != nil || cname == "" {
			return
		}
		// A resolver with no real CNAME record still returns a
		// "canonical name" equal to the queried name itself; only record
		// an actual redirection.
		if strings.EqualFold(strings.TrimSuffix(cname, "."), strings.TrimSuffix(name, ".")) {
			return
		}
		add(Record{Type: models.DNSRecordTypeCNAME, Value: cname})
	}()
	go func() {
		defer wg.Done()
		mxs, err := e.resolver.LookupMX(ctx, name)
		if err != nil {
			return
		}
		for _, mx := range mxs {
			add(Record{Type: models.DNSRecordTypeMX, Value: mx.Host, Priority: int(mx.Pref)})
		}
	}()
	go func() {
		defer wg.Done()
		txts, err := e.resolver.LookupTXT(ctx, name)
		if err != nil {
			return
		}
		for _, txt := range txts {
			add(Record{Type: models.DNSRecordTypeTXT, Value: txt})
		}
	}()
	go func() {
		defer wg.Done()
		nss, err := e.resolver.LookupNS(ctx, name)
		if err != nil {
			return
		}
		for _, ns := range nss {
			add(Record{Type: models.DNSRecordTypeNS, Value: ns.Host})
		}
	}()
	wg.Wait()

	return out
}

type dnsxRecordEnumerator struct {
	binary string
}

// NewDnsxRecordEnumerator returns a RecordEnumerator backed by the dnsx
// CLI tool (found at binary).
func NewDnsxRecordEnumerator(binary string) RecordEnumerator {
	return &dnsxRecordEnumerator{binary: binary}
}

func (e *dnsxRecordEnumerator) Name() string { return "dnsx" }

// dnsxLine models the subset of dnsx's -json output this package reads:
// one object per queried host, with a string slice per requested record
// type present when non-empty.
type dnsxLine struct {
	Host  string   `json:"host"`
	CNAME []string `json:"cname"`
	MX    []string `json:"mx"`
	TXT   []string `json:"txt"`
	NS    []string `json:"ns"`
}

func (e *dnsxRecordEnumerator) LookupRecords(ctx context.Context, name string) []Record {
	var out []Record
	_ = plugins.RunJSONLines(ctx, e.binary, []string{"-d", name, "-silent", "-json", "-cname", "-mx", "-txt", "-ns"}, func(line dnsxLine) error {
		for _, v := range line.CNAME {
			if strings.EqualFold(strings.TrimSuffix(v, "."), strings.TrimSuffix(name, ".")) {
				continue
			}
			out = append(out, Record{Type: models.DNSRecordTypeCNAME, Value: v})
		}
		for _, v := range line.MX {
			out = append(out, Record{Type: models.DNSRecordTypeMX, Value: v})
		}
		for _, v := range line.TXT {
			out = append(out, Record{Type: models.DNSRecordTypeTXT, Value: v})
		}
		for _, v := range line.NS {
			out = append(out, Record{Type: models.DNSRecordTypeNS, Value: v})
		}
		return nil
	})
	// A failed/erroring subprocess run simply yields whatever (if
	// anything) was decoded before the failure -- LookupRecords has no
	// error return, matching the native path's best-effort semantics.
	return out
}
