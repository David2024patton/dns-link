# dns-link

A tiny DNS record service built on [libdns](https://github.com/libdns/libdns).
It exists for one job: let the Dokploy MCP gateways link a tenant's own
domain to their application in a single flow. The gateway's `link-domain`
tool calls this service to write the DNS A record at the tenant's provider,
then attaches the domain in Dokploy itself.

One provider interface, one package per DNS host. Adding a provider is one
new entry in the factory, nothing else changes.

## Providers in this build

cloudflare, route53, godaddy, namecheap, porkbun, hetzner, digitalocean,
ovh, gandi, linode, dnsimple.

**vultr is intentionally not included:** `github.com/libdns/vultr` v1.0.0
(the only release, and current master) is still written against the
pre-1.0 libdns API where `Record` was a struct; it does not compile against
libdns v1. It can be added the day the package is ported.

## HTTP API

JSON in, JSON out. Port 8080 (override with `PORT`).

### `GET /health`

No auth (liveness only, returns no data).

```json
{"status":"ok"}
```

### `POST /v1/records/set`

Writes (creates or replaces) a single record via libdns `SetRecords`.

```json
{
  "provider": "cloudflare",
  "zone": "example.com",
  "type": "A",
  "name": "app",
  "value": "107.90.116.157",
  "ttl": 300,
  "credentials": {"apiToken": "..."}
}
```

`ttl` is optional, in seconds. Success: `200` with
`{"ok":true,"provider":...,"zone":...,"records":[...]}`.
Validation problems: `400`. Provider-side failures (bad credentials,
provider outage): `502` with the provider's error in `{"error": "..."}`.

### `POST /v1/records/list`

Lists a zone's records via libdns `GetRecords`.

```json
{"provider": "cloudflare", "zone": "example.com", "credentials": {"apiToken": "..."}}
```

Success: `200` with `{"ok":true,"provider":...,"zone":...,"records":[{"name","type","value","ttl"}]}`.

## Auth: the shared token

Every `/v1/*` call must carry the header:

```
X-DNS-Link-Token: <token>
```

The token comes from the `DNS_LINK_TOKEN` environment variable and is
compared in constant time. **If `DNS_LINK_TOKEN` is unset, the service
refuses to start.** Missing or wrong token: `401`.

The gateways hold the same token in their own environment; it is a
service-to-service door key, not a user credential.

## Credentials: per request, nothing at rest

DNS provider credentials travel inside each request's `credentials` object
and are used only to build that call's provider client. They are **never
stored, logged, or persisted** — not in a database, not in a file, not in
the structured logs (which carry provider, zone, type, name, and outcome
only). The tenant's agent presents them on every call, the same way the
gateways treat Dokploy API keys.

Credential fields per provider (all values are strings):

| provider | required | optional |
| --- | --- | --- |
| cloudflare | `apiToken` (scoped token, Zone.DNS write) | `zoneToken` |
| route53 | none (AWS default chain applies) | `accessKeyId`, `secretAccessKey`, `sessionToken`, `region`, `profile` |
| godaddy | `apiToken` (the `key:secret` pair as one string) | |
| namecheap | `apiKey`, `user` | `apiEndpoint`, `clientIp` |
| porkbun | `apiKey`, `apiSecretKey` | |
| hetzner | `authApiToken` | |
| digitalocean | `apiToken` | |
| ovh | `applicationKey`, `applicationSecret`, `consumerKey` | `endpoint` |
| gandi | `bearerToken` | `sharingId` |
| linode | `apiToken` | `apiUrl`, `apiVersion` |
| dnsimple | `apiAccessToken`, `accountId` | `apiUrl` |

## Run it

```sh
DNS_LINK_TOKEN=<random-long-token> go run .
curl localhost:8080/health
```

## Build / deploy

```sh
docker build -t dns-link .
docker run -e DNS_LINK_TOKEN=<random-long-token> -p 8080:8080 dns-link
```

In production it runs as a Dokploy application next to the gateways and is
reached over the internal container network; it has no public domain.

## Tests

```sh
go test ./...
go vet ./...
```

Handler tests run against a fake provider implementing the libdns
interfaces; the factory is swappable by construction.
