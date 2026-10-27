// dns-link is a tiny DNS record service for the Dokploy MCP gateways.
//
// It writes and lists DNS records at a caller's own DNS provider (through
// libdns) so a gateway tool can link a tenant's domain to their app in one
// flow: write the A record, then attach the domain in Dokploy.
//
// Fail-closed by design: without DNS_LINK_TOKEN in the environment the
// process refuses to start, and every /v1/* route requires that token in
// the X-DNS-Link-Token header. Provider credentials arrive per request and
// are never stored, logged, or persisted.
package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/David2024patton/dns-link/internal/dnslink"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	token := os.Getenv("DNS_LINK_TOKEN")
	if token == "" {
		fmt.Fprintln(os.Stderr, "dns-link: DNS_LINK_TOKEN is not set; refusing to start")
		os.Exit(1)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	server := dnslink.NewServer(dnslink.DefaultFactory(), token, logger)
	httpServer := &http.Server{
		Addr:              ":" + port,
		Handler:           server.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	logger.Info("dns-link listening", "port", port, "providers", dnslink.DefaultFactory().Providers())
	if err := httpServer.ListenAndServe(); err != nil {
		fmt.Fprintf(os.Stderr, "dns-link: server error: %v\n", err)
		os.Exit(1)
	}
}
