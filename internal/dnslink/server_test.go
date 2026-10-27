package dnslink

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/libdns/libdns"
)

const testToken = "test-shared-token"

func testServer(fake *fakeProvider) *httptest.Server {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	return httptest.NewServer(NewServer(fakeFactory(fake), testToken, logger).Handler())
}

func post(t *testing.T, url, token, body string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBufferString(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("X-DNS-Link-Token", token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestHealthIsOpen(t *testing.T) {
	srv := testServer(&fakeProvider{})
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health status = %d, want 200", resp.StatusCode)
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out["status"] != "ok" {
		t.Fatalf("health body = %v", out)
	}
}

func TestAuthMiddleware(t *testing.T) {
	srv := testServer(&fakeProvider{})
	defer srv.Close()
	body := `{"provider":"fake","zone":"example.com","type":"A","name":"app","value":"107.90.116.157","credentials":{}}`

	status, _ := post(t, srv.URL+"/v1/records/set", "", body)
	if status != http.StatusUnauthorized {
		t.Fatalf("missing token: status = %d, want 401", status)
	}
	status, _ = post(t, srv.URL+"/v1/records/set", "wrong-token-value", body)
	if status != http.StatusUnauthorized {
		t.Fatalf("wrong token: status = %d, want 401", status)
	}
	status, out := post(t, srv.URL+"/v1/records/set", testToken, body)
	if status != http.StatusOK {
		t.Fatalf("correct token: status = %d, want 200 (body %v)", status, out)
	}
}

func TestSetRecordHappyPath(t *testing.T) {
	fake := &fakeProvider{}
	srv := testServer(fake)
	defer srv.Close()

	status, out := post(t, srv.URL+"/v1/records/set", testToken,
		`{"provider":"fake","zone":"example.com","type":"a","name":"app","value":"107.90.116.157","ttl":300,"credentials":{"apiToken":"x"}}`)
	if status != http.StatusOK {
		t.Fatalf("status = %d, body %v", status, out)
	}
	if fake.setZone != "example.com" {
		t.Fatalf("provider zone = %q", fake.setZone)
	}
	if len(fake.setRecords) != 1 {
		t.Fatalf("provider got %d records, want 1", len(fake.setRecords))
	}
	rr := fake.setRecords[0].RR()
	if rr.Name != "app" || rr.Type != "A" || rr.Data != "107.90.116.157" {
		t.Fatalf("record = %+v", rr)
	}
	if rr.TTL != 300*time.Second {
		t.Fatalf("ttl = %v, want 300s", rr.TTL)
	}
	if out["ok"] != true {
		t.Fatalf("body = %v", out)
	}
}

func TestSetValidation(t *testing.T) {
	srv := testServer(&fakeProvider{})
	defer srv.Close()
	cases := map[string]string{
		"missing provider": `{"zone":"example.com","type":"A","name":"app","value":"1.2.3.4"}`,
		"missing zone":     `{"provider":"fake","type":"A","name":"app","value":"1.2.3.4"}`,
		"missing type":     `{"provider":"fake","zone":"example.com","name":"app","value":"1.2.3.4"}`,
		"missing name":     `{"provider":"fake","zone":"example.com","type":"A","value":"1.2.3.4"}`,
		"missing value":    `{"provider":"fake","zone":"example.com","type":"A","name":"app"}`,
		"unknown provider": `{"provider":"nope","zone":"example.com","type":"A","name":"app","value":"1.2.3.4"}`,
		"bad json":         `{"provider":`,
		"nonstring cred":   `{"provider":"fake","zone":"example.com","type":"A","name":"app","value":"1.2.3.4","credentials":{"apiToken":42}}`,
	}
	for name, body := range cases {
		status, out := post(t, srv.URL+"/v1/records/set", testToken, body)
		if status != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400 (body %v)", name, status, out)
		}
		if _, ok := out["error"]; !ok {
			t.Errorf("%s: body has no error field: %v", name, out)
		}
	}
}

func TestSetProviderErrorIs502(t *testing.T) {
	fake := &fakeProvider{err: errors.New("upstream said no")}
	srv := testServer(fake)
	defer srv.Close()
	status, out := post(t, srv.URL+"/v1/records/set", testToken,
		`{"provider":"fake","zone":"example.com","type":"A","name":"app","value":"1.2.3.4","credentials":{}}`)
	if status != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", status)
	}
	errText, _ := out["error"].(string)
	if !strings.Contains(errText, "upstream said no") {
		t.Fatalf("error = %q, want the provider error surfaced", errText)
	}
}

func TestListRecords(t *testing.T) {
	fake := &fakeProvider{listResult: []libdns.Record{
		libdns.RR{Name: "app", Type: "A", Data: "107.90.116.157", TTL: 300 * time.Second},
		libdns.RR{Name: "@", Type: "MX", Data: "10 mail.example.com", TTL: 3600 * time.Second},
	}}
	srv := testServer(fake)
	defer srv.Close()

	status, out := post(t, srv.URL+"/v1/records/list", testToken,
		`{"provider":"fake","zone":"example.com","credentials":{}}`)
	if status != http.StatusOK {
		t.Fatalf("status = %d, body %v", status, out)
	}
	records, ok := out["records"].([]any)
	if !ok || len(records) != 2 {
		t.Fatalf("records = %v", out["records"])
	}
	first, _ := records[0].(map[string]any)
	if first["name"] != "app" || first["type"] != "A" || first["value"] != "107.90.116.157" {
		t.Fatalf("first record = %v", first)
	}
	if first["ttl"] != float64(300) {
		t.Fatalf("first ttl = %v, want 300", first["ttl"])
	}
}
