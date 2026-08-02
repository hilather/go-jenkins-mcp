package gateway_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/gateway"
)

// OAUTH-010 / GWY-001: progressive consent residual honesty (env/static, secret-free).
func TestProgressiveConsentResidual(t *testing.T) {
	t.Parallel()
	const canary = "CANARY_consent_residual_token_xyz789"
	pc := gateway.NewProgressiveConsentResidual()
	if pc.Browser3LOAutomated {
		t.Fatal("browser 3LO must not claim automated")
	}
	if !pc.MetadataPathDoneStar {
		t.Fatal("metadata path must be Done*")
	}
	if !pc.ProcessLocalConsentMetadataStore {
		t.Fatal("process-local consent metadata store must be Done*")
	}
	if pc.DurableConsentSessionStore || pc.MultiReplicaConsentCorrelation {
		t.Fatal("AgentCore durable vault / multi-replica must stay residual false")
	}
	if !pc.LastConsentWouldApply {
		t.Fatal("last_consent_would_apply marker")
	}
	if !strings.Contains(pc.ResidualNote, "OAUTH-010") {
		t.Fatalf("note: %q", pc.ResidualNote)
	}
	if !strings.Contains(strings.ToLower(pc.ResidualNote), "not automated") {
		t.Fatalf("want browser not automated: %q", pc.ResidualNote)
	}
	if !strings.Contains(pc.ResidualNote, "Done*") {
		t.Fatalf("want Done* metadata path: %q", pc.ResidualNote)
	}
	if !strings.Contains(strings.ToLower(pc.ResidualNote), "process-local") {
		t.Fatalf("want process-local store honesty: %q", pc.ResidualNote)
	}
	if !strings.Contains(strings.ToLower(pc.ResidualNote), "not multi-replica") {
		t.Fatalf("want not multi-replica honesty: %q", pc.ResidualNote)
	}
	// StatusMap / JSON secret-free.
	sm := pc.StatusMap()
	if sm["process_local_consent_metadata_store"] != true {
		t.Fatalf("StatusMap process_local: %+v", sm)
	}
	// Consent store honesty parity (HOST-007 SPA progressive_consent nest).
	if sm["stores_tokens"] != false {
		t.Fatalf("stores_tokens must be false: %+v", sm)
	}
	if sm["multi_replica_shared"] != false {
		t.Fatalf("multi_replica_shared must be false: %+v", sm)
	}
	raw, err := json.Marshal(sm)
	if err != nil {
		t.Fatal(err)
	}
	blob := string(raw) + " " + pc.ResidualNote + " " + pc.Surfaces
	for _, bad := range []string{canary, "access_token=", "refresh_token=", "client_secret=", "Authorization: Bearer"} {
		if strings.Contains(blob, bad) {
			t.Fatalf("canary/marker %q in residual surfaces", bad)
		}
	}
}

// Regression: ConsentRequired progressive helpers + Error() stay metadata-only.
func TestConsentRequired_ProgressiveHelpersCanary(t *testing.T) {
	t.Parallel()
	const (
		canary  = "access_token_must_never_appear_in_consent_xyz"
		authURL = "https://login.microsoftonline.com/t/oauth2/v2.0/authorize?client_id=public&state=canary-test"
		sessID  = "sess-canary-progress-1"
	)
	err := gateway.NewConsentRequired(gateway.ConsentInfo{
		AuthorizationURL: authURL,
		SessionID:        sessID,
		Provider:         "agentcore",
	})
	cr, ok := gateway.AsConsentRequired(err)
	if !ok || cr == nil {
		t.Fatalf("AsConsentRequired: %v", err)
	}
	if cr.ConsentAuthorizationURL() != authURL || cr.ConsentSessionID() != sessID {
		t.Fatalf("helpers: %+v", cr.Info)
	}
	// Log-safe Error(): no full query dump, no canary.
	if strings.Contains(err.Error(), "state=canary-test") {
		t.Fatalf("Error() dumped authorize state: %q", err.Error())
	}
	blob := err.Error() + " " + cr.Info.String() + " " + fmt.Sprint(cr.Info.StatusMap())
	for _, bad := range []string{canary, "access_token=", "refresh_token=", "client_secret="} {
		if strings.Contains(blob, bad) {
			t.Fatalf("surface contained %q: %q", bad, blob)
		}
	}
	// StatusMap never exposes full URL (has_authorization_url bool only).
	sm := cr.Info.StatusMap()
	if sm["has_authorization_url"] != true || sm["has_session_id"] != true {
		t.Fatalf("StatusMap: %+v", sm)
	}
	if _, ok := sm["authorization_url"]; ok {
		t.Fatal("StatusMap must not embed full authorization_url")
	}
}
