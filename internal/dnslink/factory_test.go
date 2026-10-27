package dnslink

import (
	"context"
	"strings"
	"testing"

	"github.com/libdns/libdns"
)

// fakeProvider implements the libdns getter/setter pair for handler tests.
type fakeProvider struct {
	setZone    string
	setRecords []libdns.Record
	listResult []libdns.Record
	err        error
}

func (f *fakeProvider) GetRecords(_ context.Context, _ string) ([]libdns.Record, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.listResult, nil
}

func (f *fakeProvider) SetRecords(_ context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.setZone = zone
	f.setRecords = recs
	return recs, nil
}

func fakeFactory(fake *fakeProvider) *Factory {
	return NewFactory(map[string]Builder{
		"fake": func(_ map[string]string) (Provider, error) {
			return fake, nil
		},
	})
}

func TestDefaultFactoryProviders(t *testing.T) {
	want := []string{
		"cloudflare", "digitalocean", "dnsimple", "gandi", "godaddy",
		"hetzner", "linode", "namecheap", "ovh", "porkbun", "route53",
	}
	got := DefaultFactory().Providers()
	if len(got) != len(want) {
		t.Fatalf("providers = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("providers = %v, want %v", got, want)
		}
	}
}

func TestFactoryUnknownProvider(t *testing.T) {
	_, err := DefaultFactory().Build("nosuchprovider", nil)
	if err == nil || !strings.Contains(err.Error(), "unknown provider") {
		t.Fatalf("expected unknown provider error, got %v", err)
	}
}

// TestFactoryBuildsEveryProvider constructs every real provider with the
// minimal documented credentials. Constructors must not touch the network:
// they only fill a struct (clients are built lazily on first use).
func TestFactoryBuildsEveryProvider(t *testing.T) {
	cases := map[string]map[string]string{
		"cloudflare":   {"apiToken": "x"},
		"route53":      {},
		"godaddy":      {"apiToken": "x"},
		"namecheap":    {"apiKey": "x", "user": "u"},
		"porkbun":      {"apiKey": "x", "apiSecretKey": "y"},
		"hetzner":      {"authApiToken": "x"},
		"digitalocean": {"apiToken": "x"},
		"ovh":          {"applicationKey": "x", "applicationSecret": "y", "consumerKey": "z"},
		"gandi":        {"bearerToken": "x"},
		"linode":       {"apiToken": "x"},
		"dnsimple":     {"apiAccessToken": "x", "accountId": "1"},
	}
	factory := DefaultFactory()
	for name, creds := range cases {
		provider, err := factory.Build(name, creds)
		if err != nil {
			t.Errorf("build %s: %v", name, err)
			continue
		}
		if provider == nil {
			t.Errorf("build %s: nil provider", name)
		}
	}
}

func TestFactoryMissingCredential(t *testing.T) {
	_, err := DefaultFactory().Build("cloudflare", map[string]string{})
	if err == nil || !strings.Contains(err.Error(), "apiToken") {
		t.Fatalf("expected missing apiToken error, got %v", err)
	}
	// The error must name the field but never carry a credential value.
	_, err = DefaultFactory().Build("porkbun", map[string]string{"apiKey": "sekrit-value"})
	if err == nil || !strings.Contains(err.Error(), "apiSecretKey") {
		t.Fatalf("expected missing apiSecretKey error, got %v", err)
	}
	if strings.Contains(err.Error(), "sekrit-value") {
		t.Fatalf("error leaked a credential value: %v", err)
	}
}
