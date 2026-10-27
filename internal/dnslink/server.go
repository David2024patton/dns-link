package dnslink

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/libdns/libdns"
)

// providerTimeout bounds a single provider API call so a hung provider
// cannot pin a request forever.
const providerTimeout = 60 * time.Second

// Server is the dns-link HTTP API. The shared token is the only gate: it is
// compared in constant time, and the service refuses to start without one
// (enforced in main). Credentials for DNS providers arrive inside each
// request body and are never stored or logged.
type Server struct {
	factory *Factory
	token   string
	logger  *slog.Logger
}

// NewServer builds a Server. The token must be non-empty.
func NewServer(factory *Factory, token string, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{factory: factory, token: token, logger: logger}
}

// Handler returns the HTTP routes: /health is open (liveness only, no
// data), everything under /v1/ requires the shared token header.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.Handle("POST /v1/records/set", s.auth(http.HandlerFunc(s.handleSet)))
	mux.Handle("POST /v1/records/list", s.auth(http.HandlerFunc(s.handleList)))
	return mux
}

// auth requires the X-DNS-Link-Token header to match the configured token.
func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("X-DNS-Link-Token")
		if len(got) != len(s.token) || subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) != 1 {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next.ServeHTTP(w, r)
	})
}

type setRequest struct {
	Provider    string         `json:"provider"`
	Zone        string         `json:"zone"`
	Type        string         `json:"type"`
	Name        string         `json:"name"`
	Value       string         `json:"value"`
	TTL         *int64         `json:"ttl"` // seconds, optional
	Credentials map[string]any `json:"credentials"`
}

type listRequest struct {
	Provider    string         `json:"provider"`
	Zone        string         `json:"zone"`
	Credentials map[string]any `json:"credentials"`
}

// recordJSON is the wire shape of one DNS record. TTL is whole seconds.
type recordJSON struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
	TTL   int64  `json:"ttl"`
}

func toRecordJSON(rec libdns.Record) recordJSON {
	rr := rec.RR()
	return recordJSON{
		Name:  rr.Name,
		Type:  rr.Type,
		Value: rr.Data,
		TTL:   int64(rr.TTL / time.Second),
	}
}

func (s *Server) handleSet(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	var req setRequest
	if err := decodeBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validateSet(req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	provider, err := s.buildProvider(req.Provider, req.Credentials)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	rec := libdns.RR{
		Name: req.Name,
		Type: strings.ToUpper(req.Type),
		Data: req.Value,
	}
	if req.TTL != nil {
		rec.TTL = time.Duration(*req.TTL) * time.Second
	}

	ctx, cancel := context.WithTimeout(r.Context(), providerTimeout)
	defer cancel()
	set, err := provider.SetRecords(ctx, req.Zone, []libdns.Record{rec})
	outcome := "ok"
	if err != nil {
		outcome = "provider_error"
		s.logger.Info("records/set",
			"provider", req.Provider, "zone", req.Zone, "type", rec.Type, "name", req.Name,
			"outcome", outcome, "duration_ms", time.Since(start).Milliseconds())
		writeError(w, http.StatusBadGateway, fmt.Sprintf("provider %s: %v", req.Provider, err))
		return
	}
	s.logger.Info("records/set",
		"provider", req.Provider, "zone", req.Zone, "type", rec.Type, "name", req.Name,
		"outcome", outcome, "duration_ms", time.Since(start).Milliseconds())

	out := make([]recordJSON, 0, len(set))
	for _, rec := range set {
		out = append(out, toRecordJSON(rec))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"provider": req.Provider,
		"zone":     req.Zone,
		"records":  out,
	})
}

func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	var req listRequest
	if err := decodeBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(req.Provider) == "" {
		writeError(w, http.StatusBadRequest, "provider is required")
		return
	}
	if strings.TrimSpace(req.Zone) == "" {
		writeError(w, http.StatusBadRequest, "zone is required")
		return
	}
	provider, err := s.buildProvider(req.Provider, req.Credentials)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), providerTimeout)
	defer cancel()
	recs, err := provider.GetRecords(ctx, req.Zone)
	outcome := "ok"
	if err != nil {
		outcome = "provider_error"
		s.logger.Info("records/list",
			"provider", req.Provider, "zone", req.Zone,
			"outcome", outcome, "duration_ms", time.Since(start).Milliseconds())
		writeError(w, http.StatusBadGateway, fmt.Sprintf("provider %s: %v", req.Provider, err))
		return
	}
	s.logger.Info("records/list",
		"provider", req.Provider, "zone", req.Zone,
		"outcome", outcome, "count", len(recs), "duration_ms", time.Since(start).Milliseconds())

	out := make([]recordJSON, 0, len(recs))
	for _, rec := range recs {
		out = append(out, toRecordJSON(rec))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"provider": req.Provider,
		"zone":     req.Zone,
		"records":  out,
	})
}

// buildProvider converts the request's credential object (string values
// only; tokens are strings at every provider) and builds the client.
func (s *Server) buildProvider(name string, raw map[string]any) (Provider, error) {
	creds := make(map[string]string, len(raw))
	for key, value := range raw {
		str, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("credential field %q must be a string", key)
		}
		creds[key] = str
	}
	return s.factory.Build(name, creds)
}

func validateSet(req setRequest) error {
	switch {
	case strings.TrimSpace(req.Provider) == "":
		return fmt.Errorf("provider is required")
	case strings.TrimSpace(req.Zone) == "":
		return fmt.Errorf("zone is required")
	case strings.TrimSpace(req.Type) == "":
		return fmt.Errorf("type is required")
	case strings.TrimSpace(req.Name) == "":
		return fmt.Errorf("name is required")
	case req.Value == "":
		return fmt.Errorf("value is required")
	case req.TTL != nil && *req.TTL < 0:
		return fmt.Errorf("ttl must not be negative")
	}
	return nil
}

func decodeBody(r *http.Request, dst any) error {
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("could not read body: %v", err)
	}
	if err := json.Unmarshal(body, dst); err != nil {
		return fmt.Errorf("invalid JSON body: %v", err)
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
