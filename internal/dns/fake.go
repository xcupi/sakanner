package dns

import (
	"context"
	"fmt"
	"net"
)

// FakeResolver is a Resolver backed by in-memory maps, for use in tests
// of packages that depend on dns.Resolver without touching the network.
type FakeResolver struct {
	Hosts  map[string][]net.IP
	CNAMEs map[string]string
	MXs    map[string][]*net.MX
	TXTs   map[string][]string
	NSs    map[string][]*net.NS
}

// NewFakeResolver returns an empty FakeResolver ready to have its maps
// populated by the caller.
func NewFakeResolver() *FakeResolver {
	return &FakeResolver{
		Hosts:  map[string][]net.IP{},
		CNAMEs: map[string]string{},
		MXs:    map[string][]*net.MX{},
		TXTs:   map[string][]string{},
		NSs:    map[string][]*net.NS{},
	}
}

func (f *FakeResolver) LookupHost(ctx context.Context, host string) ([]net.IP, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ips, ok := f.Hosts[host]
	if !ok {
		return nil, fmt.Errorf("dns: fake: no such host %q", host)
	}
	return ips, nil
}

func (f *FakeResolver) LookupCNAME(ctx context.Context, host string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if c, ok := f.CNAMEs[host]; ok {
		return c, nil
	}
	return host + ".", nil
}

func (f *FakeResolver) LookupMX(ctx context.Context, host string) ([]*net.MX, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return f.MXs[host], nil
}

func (f *FakeResolver) LookupTXT(ctx context.Context, host string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return f.TXTs[host], nil
}

func (f *FakeResolver) LookupNS(ctx context.Context, host string) ([]*net.NS, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return f.NSs[host], nil
}
