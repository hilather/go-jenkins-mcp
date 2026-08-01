package auth_test

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/auth"
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

func TestExtractGroups_EntraOverageReference(t *testing.T) {
	t.Parallel()
	// Entra overage: groups claim is a reference object, not a list.
	claims := map[string]any{
		"groups": map[string]any{
			"src":      []string{"src1"},
			"endpoint": "https://graph.microsoft.com/v1.0/users/me/getMemberGroups",
		},
		"roles": []string{"App.Reader"},
	}
	res, err := auth.ExtractGroups(claims, auth.DefaultGroupClaimConfig())
	if err != nil {
		t.Fatal(err)
	}
	// Must not invent directory membership from the reference.
	if len(res.Groups) != 1 || res.Groups[0] != "App.Reader" {
		t.Fatalf("groups: %v", res.Groups)
	}
	if !strings.Contains(res.ResidualNote, "group_overage_reference") {
		t.Fatalf("residual: %q", res.ResidualNote)
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
