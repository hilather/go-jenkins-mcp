package auth_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/auth"
	"github.com/hilather/go-jenkins-mcp/internal/profile"
)

// JAS-001: pure helper rejects co-hosted AS / issuer URLs.
func TestRejectJenkinsAsAuthorizationServer(t *testing.T) {
	t.Parallel()
	jenkins := "https://jenkins.example.com"
	cases := []struct {
		name    string
		as      string
		wantErr bool
	}{
		{"external_entra", "https://login.microsoftonline.com/tenant/v2.0", false},
		{"same_origin_root", "https://jenkins.example.com", true},
		{"same_host_path", "https://jenkins.example.com/oauth/authorize", true},
		{"same_host_case", "https://Jenkins.Example.COM/as", true},
		{"same_host_http_scheme", "http://jenkins.example.com/token", true},
		{"different_host", "https://idp.example.com", false},
		{"empty_as_ok", "", false},
		{"port_differs", "https://jenkins.example.com:8443", false}, // different host:port form
		{"explicit_default_port_same", "https://jenkins.example.com:443", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := auth.RejectJenkinsAsAuthorizationServer(jenkins, tc.as)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected reject")
				}
				if apperr.CodeOf(err) != apperr.CodeInvalidArgument {
					t.Fatalf("code: %v", apperr.CodeOf(err))
				}
				msg := strings.ToLower(err.Error())
				if !strings.Contains(msg, "jenkins") {
					t.Fatalf("expected jenkins wording: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Regression: empty jenkins with non-empty AS fails closed.
func TestRejectJenkinsAsAuthorizationServer_EmptyJenkins(t *testing.T) {
	t.Parallel()
	err := auth.RejectJenkinsAsAuthorizationServer("", "https://login.example.com")
	if err == nil {
		t.Fatal("expected fail closed without jenkins URL")
	}
}

// Profile-layer host check stays aligned with the canonical auth helper
// (profile cannot import auth; both enforce JAS-001 / ADR 0003).
func TestRejectJenkinsAS_ProfileParity(t *testing.T) {
	t.Parallel()
	pairs := []struct {
		jenkins, as string
	}{
		{"https://jenkins.example.com", "https://jenkins.example.com"},
		{"https://jenkins.example.com/", "https://jenkins.example.com/oauth/token"},
		{"https://jenkins.example.com", "https://login.microsoftonline.com/t/v2.0"},
		{"https://ci.corp.example", "https://ci.corp.example:443/jwks"},
	}
	for _, p := range pairs {
		authErr := auth.RejectJenkinsAsAuthorizationServer(p.jenkins, p.as)
		// profile API is (candidate, jenkins) — opposite argument order.
		profErr := profile.RejectJenkinsHostAsASEndpoint(p.as, p.jenkins)
		authReject := authErr != nil
		profReject := profErr != nil
		if authReject != profReject {
			t.Fatalf("parity mismatch jenkins=%q as=%q auth=%v profile=%v",
				p.jenkins, p.as, authErr, profErr)
		}
	}
}

// Contract: JAS-001 doc states default no-go and the stock-Jenkins prohibition.
func TestJASNoGoDocPresent(t *testing.T) {
	t.Parallel()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "docs", "auth", "jas-no-go.md")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("jas-no-go.md missing: %v", err)
	}
	lower := strings.ToLower(string(data))
	required := []string{
		"no-go",
		"threat model",
		"token minting",
		"session fixation",
		"csrf",
		"privilege escalation",
		"shared identity",
		"pkce",
		"jwks",
		"stock jenkins",
		"must never",
		"agentcore",
		"rejectjenkinsasauthorizationserver",
		"jas-002",
		"default no-go",
	}
	for _, want := range required {
		if !strings.Contains(lower, strings.ToLower(want)) {
			t.Errorf("jas-no-go.md missing required language %q", want)
		}
	}
}
