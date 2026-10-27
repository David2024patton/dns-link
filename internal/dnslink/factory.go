// Package dnslink is the core of the dns-link service: a tiny HTTP API that
// writes and lists DNS records at a caller's own DNS provider through the
// libdns provider packages.
//
// Credentials arrive per request and are used only to construct the
// provider client for that single call. They are never stored, logged, or
// persisted anywhere in this package.
package dnslink

import (
	"fmt"
	"sort"

	"github.com/libdns/cloudflare"
	"github.com/libdns/digitalocean"
	"github.com/libdns/dnsimple"
	"github.com/libdns/gandi"
	"github.com/libdns/godaddy"
	"github.com/libdns/hetzner"
	"github.com/libdns/libdns"
	"github.com/libdns/linode"
	"github.com/libdns/namecheap"
	"github.com/libdns/ovh"
	"github.com/libdns/porkbun"
	"github.com/libdns/route53"
)

// Provider is the slice of libdns behavior this service needs: read a zone
// and set records in it.
type Provider interface {
	libdns.RecordGetter
	libdns.RecordSetter
}

// Builder constructs a provider client from per-request credentials.
// Credential keys are the documented per-provider fields (see README.md).
type Builder func(creds map[string]string) (Provider, error)

// Factory builds provider clients by name. It exists so handlers can be
// tested against a fake provider: tests register their own builders.
type Factory struct {
	builders map[string]Builder
}

// NewFactory returns a Factory over the given builders.
func NewFactory(builders map[string]Builder) *Factory {
	return &Factory{builders: builders}
}

// Build returns the provider client for name, or an error naming the
// problem (unknown provider, or a missing required credential field).
// The error never contains credential values.
func (f *Factory) Build(name string, creds map[string]string) (Provider, error) {
	builder, ok := f.builders[name]
	if !ok {
		return nil, fmt.Errorf("unknown provider %q", name)
	}
	return builder(creds)
}

// Providers returns the sorted names of the providers this factory knows.
func (f *Factory) Providers() []string {
	names := make([]string, 0, len(f.builders))
	for name := range f.builders {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// cred returns the first non-empty credential value among keys, so a
// provider can document one canonical field name and still accept the
// natural alias callers tend to send (for example "apiToken").
func cred(creds map[string]string, keys ...string) string {
	for _, key := range keys {
		if v := creds[key]; v != "" {
			return v
		}
	}
	return ""
}

// requireCred is cred plus a hard failure when every key is empty: failing
// here gives the caller a precise "you forgot field X" error instead of a
// confusing provider-side authentication failure.
func requireCred(provider string, creds map[string]string, keys ...string) (string, error) {
	if v := cred(creds, keys...); v != "" {
		return v, nil
	}
	return "", fmt.Errorf("provider %s requires credential field %q", provider, keys[0])
}

// DefaultFactory returns the factory with every provider package compiled
// into this build.
func DefaultFactory() *Factory {
	return NewFactory(map[string]Builder{
		"cloudflare": func(creds map[string]string) (Provider, error) {
			token, err := requireCred("cloudflare", creds, "apiToken")
			if err != nil {
				return nil, err
			}
			return &cloudflare.Provider{
				APIToken:  token,
				ZoneToken: cred(creds, "zoneToken"),
			}, nil
		},
		"route53": func(creds map[string]string) (Provider, error) {
			// Every field is optional: with none given, the AWS SDK
			// default credential chain applies.
			return &route53.Provider{
				Region:          cred(creds, "region"),
				Profile:         cred(creds, "profile"),
				AccessKeyId:     cred(creds, "accessKeyId"),
				SecretAccessKey: cred(creds, "secretAccessKey"),
				SessionToken:    cred(creds, "sessionToken"),
			}, nil
		},
		"godaddy": func(creds map[string]string) (Provider, error) {
			token, err := requireCred("godaddy", creds, "apiToken")
			if err != nil {
				return nil, err
			}
			return &godaddy.Provider{APIToken: token}, nil
		},
		"namecheap": func(creds map[string]string) (Provider, error) {
			apiKey, err := requireCred("namecheap", creds, "apiKey")
			if err != nil {
				return nil, err
			}
			user, err := requireCred("namecheap", creds, "user")
			if err != nil {
				return nil, err
			}
			return &namecheap.Provider{
				APIKey:      apiKey,
				User:        user,
				APIEndpoint: cred(creds, "apiEndpoint"),
				ClientIP:    cred(creds, "clientIp"),
			}, nil
		},
		"porkbun": func(creds map[string]string) (Provider, error) {
			apiKey, err := requireCred("porkbun", creds, "apiKey")
			if err != nil {
				return nil, err
			}
			secret, err := requireCred("porkbun", creds, "apiSecretKey")
			if err != nil {
				return nil, err
			}
			return &porkbun.Provider{APIKey: apiKey, APISecretKey: secret}, nil
		},
		"hetzner": func(creds map[string]string) (Provider, error) {
			token, err := requireCred("hetzner", creds, "authApiToken", "apiToken")
			if err != nil {
				return nil, err
			}
			return &hetzner.Provider{AuthAPIToken: token}, nil
		},
		"digitalocean": func(creds map[string]string) (Provider, error) {
			token, err := requireCred("digitalocean", creds, "apiToken")
			if err != nil {
				return nil, err
			}
			return &digitalocean.Provider{APIToken: token}, nil
		},
		"ovh": func(creds map[string]string) (Provider, error) {
			appKey, err := requireCred("ovh", creds, "applicationKey")
			if err != nil {
				return nil, err
			}
			appSecret, err := requireCred("ovh", creds, "applicationSecret")
			if err != nil {
				return nil, err
			}
			consumerKey, err := requireCred("ovh", creds, "consumerKey")
			if err != nil {
				return nil, err
			}
			return &ovh.Provider{
				Endpoint:          cred(creds, "endpoint"),
				ApplicationKey:    appKey,
				ApplicationSecret: appSecret,
				ConsumerKey:       consumerKey,
			}, nil
		},
		"gandi": func(creds map[string]string) (Provider, error) {
			token, err := requireCred("gandi", creds, "bearerToken", "apiToken")
			if err != nil {
				return nil, err
			}
			return &gandi.Provider{
				BearerToken: token,
				SharingId:   cred(creds, "sharingId"),
			}, nil
		},
		"linode": func(creds map[string]string) (Provider, error) {
			token, err := requireCred("linode", creds, "apiToken")
			if err != nil {
				return nil, err
			}
			return &linode.Provider{
				APIToken:   token,
				APIURL:     cred(creds, "apiUrl"),
				APIVersion: cred(creds, "apiVersion"),
			}, nil
		},
		"dnsimple": func(creds map[string]string) (Provider, error) {
			token, err := requireCred("dnsimple", creds, "apiAccessToken", "apiToken")
			if err != nil {
				return nil, err
			}
			accountID, err := requireCred("dnsimple", creds, "accountId")
			if err != nil {
				return nil, err
			}
			return &dnsimple.Provider{
				APIAccessToken: token,
				AccountID:      accountID,
				APIURL:         cred(creds, "apiUrl"),
			}, nil
		},
	})
}
