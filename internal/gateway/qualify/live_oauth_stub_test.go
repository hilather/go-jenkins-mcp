//go:build live_oauth

package qualify_test

import (
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// Opt-in residual pin against testdata/oauth-lab (HOST-012…015).
//
//	make live-oauth-up
//	go test -tags=live_oauth ./internal/gateway/qualify/ -count=1
//
// Skips when the lab is not reachable so accidental -tags=live_oauth without
// compose does not fail CI. Default `go test` / `make test` never include this
// file (build tag). Not a production Entra / AgentCore pin — see
// docs/gateway/qualification.md §7.

func TestLiveOAuth_LabReachableOrSkip(t *testing.T) {
	// Loopback mock-token (HOST-015) is the Mode C residual peer.
	base := strings.TrimSpace(os.Getenv("OAUTH_LAB_TOKEN_URL"))
	if base == "" {
		port := strings.TrimSpace(os.Getenv("OAUTH_TOKEN_PORT"))
		if port == "" {
			port = "18083"
		}
		base = "http://127.0.0.1:" + port
	}
	base = strings.TrimRight(base, "/")
	health := base + "/healthz"

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(health)
	if err != nil {
		t.Skipf("oauth-lab not up (%s): %v — run: make live-oauth-up", health, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Skipf("oauth-lab healthz status %d at %s — run: make live-oauth-up", resp.StatusCode, health)
	}
	t.Logf("oauth-lab mock-token healthy at %s (residual live pin only; not Entra)", health)
}

func TestLiveOAuth_MockOIDCHealthOrSkip(t *testing.T) {
	port := strings.TrimSpace(os.Getenv("OAUTH_OIDC_PORT"))
	if port == "" {
		port = "18081"
	}
	health := "http://127.0.0.1:" + port + "/healthz"
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(health)
	if err != nil {
		t.Skipf("oauth-lab mock-oidc not up (%s): %v", health, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Skipf("mock-oidc healthz status %d", resp.StatusCode)
	}
	t.Logf("oauth-lab mock-oidc healthy at %s", health)
}

func TestLiveOAuth_MockRSHealthOrSkip(t *testing.T) {
	port := strings.TrimSpace(os.Getenv("OAUTH_RS_PORT"))
	if port == "" {
		port = "18082"
	}
	health := "http://127.0.0.1:" + port + "/healthz"
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(health)
	if err != nil {
		t.Skipf("oauth-lab mock-rs not up (%s): %v", health, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Skipf("mock-rs healthz status %d", resp.StatusCode)
	}
	t.Logf("oauth-lab mock-rs healthy at %s (not jwt-auth-filter production pin)", health)
}
