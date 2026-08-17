package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/profile"
)

// Regression (AUD-001): emitLoginAudit and the login_success / login_fail
// catalog event types existed but were never wired — runAPITokenLogin /
// runOIDCLogin never called them, so operators auditing login activity found
// an empty trail. Login now emits login_success / login_fail.
func TestLoginEmitsAuditEvents(t *testing.T) {
	withTestXDG(t)

	// Failure path first: unreachable Jenkins → verify fails → login_fail.
	p := &profile.Profile{
		ConfigVersion: profile.CurrentConfigVersion,
		ID:            "corp",
		JenkinsURL:    "http://127.0.0.1:1", // nothing listening
		AuthMethod:    profile.AuthMethodAPIToken,
		Username:      "alice",
	}
	store, err := profileStore()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(p); err != nil {
		t.Fatal(err)
	}
	t.Setenv("JENKINS_MCP_LOGIN_USER", "alice")
	t.Setenv("JENKINS_MCP_LOGIN_TOKEN", "token-value-1")

	if err := runLogin([]string{"--profile", "corp"}); err == nil {
		t.Fatal("login against unreachable Jenkins must fail")
	}
	auditFile := filepath.Join(os.Getenv("XDG_DATA_HOME"), "jenkins-mcp", "profiles", "corp", "audit", "audit.jsonl")
	data, err := os.ReadFile(auditFile)
	if err != nil {
		t.Fatalf("login_fail audit missing (file): %v", err)
	}
	if !strings.Contains(string(data), "login_fail") {
		t.Fatalf("login_fail event missing: %s", data)
	}
	if strings.Contains(string(data), "token-value-1") {
		t.Fatal("audit leaked the token")
	}

	// Success path: whoAmI-verified login → login_success.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"alice","fullName":"Alice","anonymous":false,"authenticated":true}`))
	}))
	defer srv.Close()
	p2 := &profile.Profile{
		ConfigVersion: profile.CurrentConfigVersion,
		ID:            "corp2",
		JenkinsURL:    srv.URL,
		AuthMethod:    profile.AuthMethodAPIToken,
		Username:      "alice",
	}
	if err := store.Save(p2); err != nil {
		t.Fatal(err)
	}
	if err := runLogin([]string{"--profile", "corp2"}); err != nil {
		t.Fatalf("login against whoAmI fixture: %v", err)
	}
	auditFile2 := filepath.Join(os.Getenv("XDG_DATA_HOME"), "jenkins-mcp", "profiles", "corp2", "audit", "audit.jsonl")
	data2, err := os.ReadFile(auditFile2)
	if err != nil {
		t.Fatalf("login_success audit missing (file): %v", err)
	}
	if !strings.Contains(string(data2), "login_success") {
		t.Fatalf("login_success event missing: %s", data2)
	}
}
