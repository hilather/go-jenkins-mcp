package qualify_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/gateway/qualify"
)

func TestRunOffline_AllPass(t *testing.T) {
	t.Parallel()
	sum := qualify.RunOffline(context.Background())
	if !sum.OK || sum.Failed != 0 {
		b, _ := json.MarshalIndent(sum, "", "  ")
		t.Fatalf("offline qualify failed:\n%s", b)
	}
	if sum.Suite != "offline" {
		t.Fatalf("suite %q", sum.Suite)
	}
	if sum.Passed < 20 {
		t.Fatalf("expected >= 20 cases (incl. mode A/B/C + HOST-011 + OAUTH-009/010 + progressive consent + residual-status honesty), got %d", sum.Passed)
	}
	// Residuals must document live AgentCore gap and offline vault/IdP/mode matrix Done*.
	foundLive := false
	foundOfflineDone := false
	foundOAuthLab := false
	foundProgressiveConsent := false
	foundResidualStatusHonesty := false
	for _, r := range sum.Residuals {
		low := strings.ToLower(r)
		if strings.Contains(low, "agentcore") || strings.Contains(low, "live") {
			foundLive = true
		}
		if strings.Contains(low, "vault hit/miss") && strings.Contains(low, "done") {
			foundOfflineDone = true
		}
		if strings.Contains(low, "oauth-lab") || strings.Contains(low, "live-oauth") {
			foundOAuthLab = true
		}
		if strings.Contains(low, "progressive consent") &&
			strings.Contains(low, "not automated") {
			foundProgressiveConsent = true
		}
		if strings.Contains(low, "residual-status") &&
			strings.Contains(low, "honesty") &&
			strings.Contains(low, "done") {
			foundResidualStatusHonesty = true
		}
	}
	if !foundLive {
		t.Fatal("expected live AgentCore residual note")
	}
	if !foundOfflineDone {
		t.Fatal("expected residual noting offline vault hit/miss Done*")
	}
	if !foundOAuthLab {
		t.Fatal("expected residual noting oauth-lab / live-oauth opt-in")
	}
	if !foundProgressiveConsent {
		t.Fatal("expected residual noting progressive consent UX (browser 3LO not automated)")
	}
	if !foundResidualStatusHonesty {
		t.Fatal("expected residual noting gateway residual-status offline honesty Done*")
	}
	// JSON summary must never include canary token.
	raw, err := json.Marshal(sum)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), qualify.CanaryToken) {
		t.Fatal("canary token in JSON summary")
	}
}

func TestRunOffline_SecurityCaseNames(t *testing.T) {
	t.Parallel()
	sum := qualify.RunOffline(context.Background())
	want := map[string]bool{
		"jenkins_as_as_rejected":                  false,
		"wrong_audience_rejected":                 false,
		"wrong_subject_binding_rejected":          false,
		"subject_binding_contracts":               false,
		"token_never_in_errors":                   false,
		"consent_url_has_no_token":                false,
		"cross_user_cache_isolation":              false,
		"vault_hit_miss":                          false,
		"idp_outage_chaos":                        false,
		"jwks_key_rotation_lite":                  false,
		"mode_a_vault_obtain_basic":               false,
		"mode_b_jwt_vault_bearer":                 false,
		"mode_c_agentcore_live_matrix":            false,
		"host011_no_silent_fallthrough":           false,
		"oauth009_offline_bearer_matrix":          false,
		"oauth010_mode_c_offline_matrix":          false,
		"progressive_consent_residual":            false,
		"gateway_residual_status_offline_honesty": false,
		"concurrent_obtain_stub_under_budget":     false,
		"fail_closed_obtain_latency":              false,
	}
	for _, c := range sum.Cases {
		if _, ok := want[c.Name]; ok {
			want[c.Name] = true
			if !c.Passed {
				t.Errorf("case %s failed: %s", c.Name, c.Detail)
			}
		}
	}
	for name, seen := range want {
		if !seen {
			t.Errorf("missing case %s", name)
		}
	}
}
