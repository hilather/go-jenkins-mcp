package auth

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// Regression (RFC 8707 §6): the login flow sends resource=<jenkinsAudience>
// so the issued access token is audience-scoped, but the refresh path sent
// only grant_type/refresh_token/client_id — an IdP that honors the refresh-time
// resource parameter could mint a default-audience token the MCP then presents
// to Jenkins. The refresh exchange now carries the configured audience.
func TestDoRefreshTokenExchange_SendsResourceIndicator(t *testing.T) {
	t.Parallel()
	var gotForm url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotForm, _ = url.ParseQuery(string(body))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at-2","token_type":"Bearer","expires_in":3600}`))
	}))
	defer srv.Close()

	_, err := doRefreshTokenExchange(context.Background(), srv.Client(), srv.URL,
		"jenkins-mcp", "rt-1", time.Now(), "api://jenkins-api")
	if err != nil {
		t.Fatal(err)
	}
	if got := gotForm.Get("resource"); got != "api://jenkins-api" {
		t.Fatalf("resource param = %q, want api://jenkins-api", got)
	}
	if gotForm.Get("grant_type") != "refresh_token" || gotForm.Get("refresh_token") != "rt-1" {
		t.Fatalf("base form fields broken: %v", gotForm)
	}
}

// No audience configured → no resource param (unchanged behavior).
func TestDoRefreshTokenExchange_NoResourceWhenUnset(t *testing.T) {
	t.Parallel()
	var gotForm url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotForm, _ = url.ParseQuery(string(body))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at-2","token_type":"Bearer","expires_in":3600}`))
	}))
	defer srv.Close()

	if _, err := doRefreshTokenExchange(context.Background(), srv.Client(), srv.URL,
		"jenkins-mcp", "rt-1", time.Now(), ""); err != nil {
		t.Fatal(err)
	}
	if _, present := gotForm["resource"]; present {
		t.Fatalf("resource must be omitted when no audience configured: %v", gotForm)
	}
}
