# TODO

- [ ] Add vultr when github.com/libdns/vultr is ported to the libdns v1 API.
- [ ] Add more libdns providers as tenants need them (one factory entry each):
      candidates include cloudns, dnsmadeeasy, duckdns, inwx, mitosys.
- [ ] Consider a `/v1/records/delete` endpoint if a tenant unlink flow is
      ever wanted in the gateways. Deliberately absent in v1: the gateway
      tool only links.
- [ ] Optional: report the resolved provider package versions at startup in
      the structured log for support.
