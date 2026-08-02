package auth_test

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/auth"
)

func TestExtractGroups_DefaultClaimNames(t *testing.T) {
	t.Parallel()
	claims := map[string]any{
		"sub":    "user-a",
		"groups": []any{"g-ops", "g-dev", "g-ops"},
		"roles":  []string{"reader"},
	}
	res, err := auth.ExtractGroups(claims, auth.DefaultGroupClaimConfig())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Groups) != 3 {
		t.Fatalf("want 3 unique groups, got %v", res.Groups)
	}
	// Order: groups claim first, then roles.
	if res.Groups[0] != "g-ops" || res.Groups[1] != "g-dev" || res.Groups[2] != "reader" {
		t.Fatalf("order: %v", res.Groups)
	}
	if len(res.SourceClaims) != 2 {
		t.Fatalf("sources: %v", res.SourceClaims)
	}
}

func TestExtractGroups_ConfigurableClaimNames(t *testing.T) {
	t.Parallel()
	cfg := auth.GroupClaimConfig{ClaimNames: []string{"member_of"}, MaxGroups: 64}
	claims := map[string]any{
		"groups":    []string{"ignored"},
		"member_of": []string{"team-x"},
	}
	res, err := auth.ExtractGroups(claims, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Groups) != 1 || res.Groups[0] != "team-x" {
		t.Fatalf("%v", res.Groups)
	}
}

func TestExtractGroups_OverageTruncateResidual(t *testing.T) {
	t.Parallel()
	groups := make([]string, auth.MaxStoredGroups+5)
	for i := range groups {
		groups[i] = "group-" + itoa(i)
	}
	cfg := auth.GroupClaimConfig{ClaimNames: []string{"groups"}, FailOnOverage: false}
	res, err := auth.ExtractGroups(map[string]any{"groups": groups}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Truncated || len(res.Groups) != auth.MaxStoredGroups {
		t.Fatalf("truncated=%v n=%d residual=%q", res.Truncated, len(res.Groups), res.ResidualNote)
	}
	if !strings.Contains(res.ResidualNote, "group_overage_truncated") {
		t.Fatalf("residual: %q", res.ResidualNote)
	}
	// Hard cap: never store more than MaxStoredGroups.
	if len(res.Groups) > auth.MaxStoredGroups {
		t.Fatal("cap violated")
	}
}

func TestExtractGroups_OverageFailClosed(t *testing.T) {
	t.Parallel()
	groups := make([]string, auth.MaxStoredGroups+1)
	for i := range groups {
		groups[i] = "g" + itoa(i)
	}
	cfg := auth.GroupClaimConfig{ClaimNames: []string{"groups"}, FailOnOverage: true}
	_, err := auth.ExtractGroups(map[string]any{"groups": groups}, cfg)
	if err == nil || apperr.CodeOf(err) != apperr.CodeAuthentication {
		t.Fatalf("got %v", err)
	}
}

func TestExtractGroups_EntraOverageReference_FailClosed(t *testing.T) {
	t.Parallel()
	// Entra overage: groups claim is a reference object, not a list — fail closed
	// even when roles are present (roles ≠ full directory group membership).
	claims := map[string]any{
		"groups": map[string]any{
			"src":      []string{"src1"},
			"endpoint": "https://graph.microsoft.com/v1.0/users/me/getMemberGroups",
		},
		"roles": []string{"App.Reader"},
	}
	_, err := auth.ExtractGroups(claims, auth.DefaultGroupClaimConfig())
	if err == nil || apperr.CodeOf(err) != apperr.CodeAuthentication {
		t.Fatalf("want auth fail closed, got %v", err)
	}
	if !strings.Contains(err.Error(), "overage") {
		t.Fatalf("want overage wording: %v", err)
	}
	// Must not invent membership from the Graph endpoint URL or roles alone.
	if strings.Contains(err.Error(), "App.Reader") {
		t.Fatalf("must not leak role invent path: %v", err)
	}
	if strings.Contains(err.Error(), "graph.microsoft.com") {
		t.Fatalf("must not echo graph endpoint in error: %v", err)
	}
}

func TestExtractGroups_EntraClaimNamesOverage_FailClosed(t *testing.T) {
	t.Parallel()
	// Classic Entra distributed claim: _claim_names.groups + _claim_sources, no groups array.
	claims := map[string]any{
		"sub": "user-overage",
		"_claim_names": map[string]any{
			"groups": "src1",
		},
		"_claim_sources": map[string]any{
			"src1": map[string]any{
				"endpoint": "https://graph.microsoft.com/v1.0/users/uid/getMemberObjects",
			},
		},
		// roles alone must not substitute for full groups membership under overage.
		"roles": []string{"App.Reader"},
	}
	_, err := auth.ExtractGroups(claims, auth.DefaultGroupClaimConfig())
	if err == nil || apperr.CodeOf(err) != apperr.CodeAuthentication {
		t.Fatalf("want auth fail closed on claim_names overage, got %v", err)
	}
	if !strings.Contains(err.Error(), auth.IncompleteGroupOverageMessage) &&
		!strings.Contains(err.Error(), "overage") {
		t.Fatalf("want incomplete overage message: %v", err)
	}
	// Secret / endpoint canary: no Graph URL or invented groups in error.
	if strings.Contains(err.Error(), "graph.microsoft.com") ||
		strings.Contains(err.Error(), "getMemberObjects") {
		t.Fatalf("must not echo claim_sources endpoint: %v", err)
	}
	if err := auth.CheckIncompleteGroupOverage(claims); err == nil {
		t.Fatal("CheckIncompleteGroupOverage must fail")
	}
	// No markers → OK.
	if err := auth.CheckIncompleteGroupOverage(map[string]any{"groups": []string{"g1"}}); err != nil {
		t.Fatal(err)
	}
}

func TestExtractGroups_EntraOverageHybrid_GroupsPresentOK(t *testing.T) {
	t.Parallel()
	// Hybrid: concrete groups array present alongside overage markers — keep path.
	claims := map[string]any{
		"sub":    "user-hybrid",
		"groups": []any{"g-ops", "g-dev"},
		"roles":  []string{"reader"},
		"_claim_names": map[string]any{
			"groups": "src1",
		},
		"_claim_sources": map[string]any{
			"src1": map[string]any{
				"endpoint": "https://graph.microsoft.com/v1.0/users/uid/getMemberObjects",
			},
		},
	}
	res, err := auth.ExtractGroups(claims, auth.DefaultGroupClaimConfig())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Groups) != 3 {
		t.Fatalf("want concrete groups+roles, got %v", res.Groups)
	}
	if res.Groups[0] != "g-ops" || res.Groups[1] != "g-dev" || res.Groups[2] != "reader" {
		t.Fatalf("order: %v", res.Groups)
	}
	if !strings.Contains(res.ResidualNote, "group_overage_hybrid") {
		t.Fatalf("want hybrid residual note: %q", res.ResidualNote)
	}
	// Residual must not invent extra Graph memberships.
	for _, g := range res.Groups {
		if strings.Contains(g, "graph") || strings.Contains(g, "src1") {
			t.Fatalf("invented membership: %v", res.Groups)
		}
	}
}

func TestExtractGroupsFromJWT(t *testing.T) {
	t.Parallel()
	payload := map[string]any{
		"sub":    "alice-sub",
		"aud":    "api://jenkins-api",
		"groups": []string{"g1", "g2"},
	}
	jwt := fakeJWT(t, payload)
	res, err := auth.ExtractGroupsFromJWT(jwt, auth.DefaultGroupClaimConfig())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Groups) != 2 {
		t.Fatalf("%v", res.Groups)
	}
	claims, err := auth.ParseJWTPayload(jwt)
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.ValidateAudienceClaim(claims, "api://jenkins-api"); err != nil {
		t.Fatal(err)
	}
	if err := auth.ValidateSubjectClaim(claims, "alice-sub"); err != nil {
		t.Fatal(err)
	}
	if err := auth.ValidateAudienceClaim(claims, "api://wrong"); err == nil {
		t.Fatal("wrong audience must fail")
	}
	if err := auth.ValidateSubjectClaim(claims, "other"); err == nil {
		t.Fatal("wrong subject must fail")
	}
}

func TestBoundGroups(t *testing.T) {
	t.Parallel()
	res, err := auth.BoundGroups([]string{" a ", "a", "b", ""}, 64, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Groups) != 2 {
		t.Fatalf("%v", res.Groups)
	}
}

func TestExtractGroups_MaxNameLengthFailClosed(t *testing.T) {
	t.Parallel()
	// Regression: oversize group names must not be accepted (or truncated into collisions).
	longName := strings.Repeat("g", auth.MaxGroupNameBytes+1)
	cfg := auth.DefaultGroupClaimConfig()
	_, err := auth.ExtractGroups(map[string]any{"groups": []string{"ok", longName}}, cfg)
	if err == nil || apperr.CodeOf(err) != apperr.CodeAuthentication {
		t.Fatalf("want auth fail closed, got %v", err)
	}
	// Exact bound is accepted.
	exact := strings.Repeat("x", auth.MaxGroupNameBytes)
	res, err := auth.ExtractGroups(map[string]any{"groups": []string{exact}}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Groups) != 1 || res.Groups[0] != exact {
		t.Fatalf("%v", res.Groups)
	}
	// BoundGroups path too.
	_, err = auth.BoundGroups([]string{longName}, 64, false)
	if err == nil {
		t.Fatal("BoundGroups must fail closed on oversize name")
	}
}

func fakeJWT(t *testing.T, payload map[string]any) string {
	t.Helper()
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	body := base64.RawURLEncoding.EncodeToString(b)
	return hdr + "." + body + ".sig"
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	pos := len(b)
	n := i
	for n > 0 {
		pos--
		b[pos] = byte('0' + n%10)
		n /= 10
	}
	return string(b[pos:])
}
