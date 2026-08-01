package auth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// MaxStoredGroups is the hard cap on group/role claims retained for policy
// binding (OAUTH-006). Excess groups are truncated (with residual note) or
// rejected when FailOnOverage is set — overage must never silently broaden access.
const MaxStoredGroups = 64

// MaxGroupNameBytes is the hard cap on a single group/role claim name length
// (OAUTH-006). Oversize names fail closed (never truncated into colliding short forms).
const MaxGroupNameBytes = 256

// DefaultGroupClaimNames are the claim keys inspected for groups/roles when
// the profile does not override GroupClaimNames.
var DefaultGroupClaimNames = []string{"groups", "roles"}

// GroupClaimConfig controls extraction of group/role claims from ID or access
// token claim maps (OAUTH-006 MVP). Pure offline logic — no network.
type GroupClaimConfig struct {
	// ClaimNames is the ordered list of JWT claim keys to read (e.g. groups, roles).
	// Empty → DefaultGroupClaimNames.
	ClaimNames []string
	// MaxGroups caps stored groups (0 → MaxStoredGroups).
	MaxGroups int
	// FailOnOverage fails closed when the unique group set exceeds MaxGroups.
	// When false, groups are truncated and ResidualNote is set.
	FailOnOverage bool
}

// DefaultGroupClaimConfig returns production-leaning defaults.
func DefaultGroupClaimConfig() GroupClaimConfig {
	return GroupClaimConfig{
		ClaimNames:    append([]string(nil), DefaultGroupClaimNames...),
		MaxGroups:     MaxStoredGroups,
		FailOnOverage: false, // truncate + residual; gateway bind may still fail-closed
	}
}

// GroupExtractResult is the bounded group list for policy subject binding.
// Never includes raw tokens.
type GroupExtractResult struct {
	// Groups is the deduped, ordered, capped group/role id list.
	Groups []string
	// Truncated is true when input exceeded MaxGroups and was cut.
	Truncated bool
	// ResidualNote is a non-secret operator note when Truncated (or empty).
	ResidualNote string
	// SourceClaims lists claim names that contributed at least one group.
	SourceClaims []string
}

// IncompleteGroupOverageMessage is the non-secret fail-closed reason when Entra
// group overage markers appear without a concrete groups claim array.
// Membership is never invented (Microsoft Graph expansion remains residual).
const IncompleteGroupOverageMessage = "entra group overage without full groups claim; membership not invented"

// CheckIncompleteGroupOverage fails closed when the JWT claim map has Entra-style
// group overage markers (_claim_names.groups, groups-as-reference-object) without
// a concrete groups string list. Hybrid tokens that still embed a full groups
// array are accepted (markers ignored for membership). Never invents membership
// and never calls Microsoft Graph (OAUTH-006 / OAUTH-010 residual).
//
// Used by ExtractGroups and ValidateAccessToken so gateway bind /
// PolicySubjectFromHTTPInbound / multi-user JWT subject paths fail closed
// under RequireVerified rather than binding empty groups.
func CheckIncompleteGroupOverage(claims map[string]any) error {
	if claims == nil {
		return nil
	}
	if !hasGroupOverageMarkers(claims) {
		return nil
	}
	if hasConcreteGroupsArray(claims) {
		// Hybrid: concrete groups present — keep current path (no Graph).
		return nil
	}
	return apperr.New(apperr.CodeAuthentication, IncompleteGroupOverageMessage)
}

// hasGroupOverageMarkers reports Entra distributed-claim / overage indicators
// for directory group membership (not app-role lists alone).
func hasGroupOverageMarkers(claims map[string]any) bool {
	if claims == nil {
		return false
	}
	// Top-level _claim_names.groups → full groups omitted; Graph endpoint in _claim_sources.
	if hasClaimNamesGroupKey(claims["_claim_names"]) {
		return true
	}
	// groups claim itself is a reference object (src / endpoint / _claim_sources).
	if raw, ok := claims["groups"]; ok && raw != nil && isOverageReference(raw) {
		return true
	}
	// _claim_sources present with no concrete groups and groups key absent is only
	// treated as group overage when _claim_names already pointed at groups (above)
	// or groups is a reference object. Bare _claim_sources for other claims is ignored.
	return false
}

// hasClaimNamesGroupKey reports whether _claim_names maps the groups claim to a source id.
func hasClaimNamesGroupKey(v any) bool {
	switch m := v.(type) {
	case map[string]any:
		if _, ok := m["groups"]; ok {
			return true
		}
	case map[string]string:
		if _, ok := m["groups"]; ok {
			return true
		}
	}
	return false
}

// hasConcreteGroupsArray reports whether claims["groups"] is a string list
// (possibly empty). Map/object overage shapes are not concrete membership.
func hasConcreteGroupsArray(claims map[string]any) bool {
	if claims == nil {
		return false
	}
	raw, ok := claims["groups"]
	if !ok || raw == nil {
		return false
	}
	if isOverageReference(raw) {
		return false
	}
	_, err := coerceStringList(raw)
	return err == nil
}

// ExtractGroups reads group/role claims from a decoded JWT claim map.
// Supports string, []string, and []any of strings.
//
// Entra group overage without a full groups array fails closed (never invents
// membership; no Graph expansion). When a concrete groups array is present,
// overage markers are ignored for membership extraction. Non-groups claim
// keys that are overage reference objects are skipped with ResidualNote.
func ExtractGroups(claims map[string]any, cfg GroupClaimConfig) (GroupExtractResult, error) {
	if claims == nil {
		return GroupExtractResult{}, nil
	}
	// OAUTH-006: Entra overage-only → fail closed (gateway RequireVerified path).
	if err := CheckIncompleteGroupOverage(claims); err != nil {
		return GroupExtractResult{}, err
	}
	names := cfg.ClaimNames
	if len(names) == 0 {
		names = DefaultGroupClaimNames
	}
	max := cfg.MaxGroups
	if max <= 0 {
		max = MaxStoredGroups
	}

	var collected []string
	var sources []string
	sourceSeen := map[string]struct{}{}
	var overageRefs []string

	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		raw, ok := claims[name]
		if !ok || raw == nil {
			continue
		}
		// Entra group overage: claim may be a reference object, not a list.
		// Incomplete groups overage already failed above; remaining refs are
		// non-groups claim keys (or hybrid residual) — do not invent membership.
		if isOverageReference(raw) {
			overageRefs = append(overageRefs, name)
			continue
		}
		gs, err := coerceStringList(raw)
		if err != nil {
			return GroupExtractResult{}, apperr.New(apperr.CodeAuthentication,
				fmt.Sprintf("group claim %q has unsupported shape", name))
		}
		if len(gs) == 0 {
			continue
		}
		if _, seen := sourceSeen[name]; !seen {
			sourceSeen[name] = struct{}{}
			sources = append(sources, name)
		}
		collected = append(collected, gs...)
	}

	out, truncated, err := boundGroupList(collected, max, cfg.FailOnOverage)
	if err != nil {
		return GroupExtractResult{}, err
	}

	res := GroupExtractResult{
		Groups:       out,
		Truncated:    truncated,
		SourceClaims: sources,
	}
	if truncated {
		res.ResidualNote = fmt.Sprintf(
			"group_overage_truncated: stored_groups capped at %d; excess ignored (cannot broaden access)",
			max)
	}
	if len(overageRefs) > 0 {
		note := "group_overage_reference: claim(s) " + strings.Join(overageRefs, ",") +
			" are directory overage references (not expanded); membership not invented"
		if res.ResidualNote != "" {
			res.ResidualNote = res.ResidualNote + "; " + note
		} else {
			res.ResidualNote = note
		}
	}
	// Hybrid residual: overage markers present but concrete groups used.
	if hasGroupOverageMarkers(claims) && hasConcreteGroupsArray(claims) {
		note := "group_overage_hybrid: _claim_names/_claim_sources or ref ignored; concrete groups claim used (no graph expansion)"
		if res.ResidualNote != "" {
			res.ResidualNote = res.ResidualNote + "; " + note
		} else {
			res.ResidualNote = note
		}
	}
	return res, nil
}

// isOverageReference detects Entra-style group overage payload shapes that are
// not concrete group id lists (e.g. map with _claim_sources / src / endpoint).
func isOverageReference(v any) bool {
	m, ok := v.(map[string]any)
	if !ok {
		return false
	}
	if _, ok := m["src"]; ok {
		return true
	}
	if _, ok := m["_claim_sources"]; ok {
		return true
	}
	if _, ok := m["endpoint"]; ok {
		return true
	}
	return false
}

func coerceStringList(v any) ([]string, error) {
	switch t := v.(type) {
	case string:
		s := strings.TrimSpace(t)
		if s == "" {
			return nil, nil
		}
		return []string{s}, nil
	case []string:
		return t, nil
	case []any:
		out := make([]string, 0, len(t))
		for _, el := range t {
			switch e := el.(type) {
			case string:
				out = append(out, e)
			default:
				return nil, fmt.Errorf("non-string element")
			}
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unsupported type %T", v)
	}
}

// boundGroupList dedupes, trims, enforces max name length, then caps count.
// Overage cannot broaden access. Oversize names fail closed (never truncated).
func boundGroupList(in []string, max int, failOnOverage bool) ([]string, bool, error) {
	if max <= 0 {
		max = MaxStoredGroups
	}
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, g := range in {
		g = strings.TrimSpace(g)
		if g == "" {
			continue
		}
		if len(g) > MaxGroupNameBytes {
			return nil, false, apperr.New(apperr.CodeAuthentication,
				fmt.Sprintf("group name exceeds length bound of %d bytes", MaxGroupNameBytes))
		}
		if _, ok := seen[g]; ok {
			continue
		}
		seen[g] = struct{}{}
		out = append(out, g)
	}
	if len(out) <= max {
		return out, false, nil
	}
	if failOnOverage {
		return nil, false, apperr.New(apperr.CodeAuthentication,
			fmt.Sprintf("group list exceeds bound of %d", max))
	}
	return out[:max], true, nil
}

// BoundGroups is a convenience for callers that already hold a string slice
// (gateway inbound claims, tests).
func BoundGroups(in []string, max int, failOnOverage bool) (GroupExtractResult, error) {
	if max <= 0 {
		max = MaxStoredGroups
	}
	out, truncated, err := boundGroupList(in, max, failOnOverage)
	if err != nil {
		return GroupExtractResult{}, err
	}
	res := GroupExtractResult{Groups: out, Truncated: truncated}
	if truncated {
		res.ResidualNote = fmt.Sprintf(
			"group_overage_truncated: stored_groups capped at %d; excess ignored (cannot broaden access)",
			max)
	}
	return res, nil
}

// ParseJWTPayload decodes the payload segment of a compact JWT without
// verifying the signature. Use only after signature validation in production
// paths; tests and offline claim extract may use it on fixture tokens.
// Never logs or returns the full raw token.
func ParseJWTPayload(jwt string) (map[string]any, error) {
	parts := strings.Split(strings.TrimSpace(jwt), ".")
	if len(parts) != 3 {
		return nil, apperr.New(apperr.CodeAuthentication, "jwt must have three segments")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// Some fixtures pad; try standard raw with padding restore.
		payload, err = base64.URLEncoding.DecodeString(padB64(parts[1]))
		if err != nil {
			return nil, apperr.New(apperr.CodeAuthentication, "jwt payload is not valid base64url")
		}
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, apperr.New(apperr.CodeAuthentication, "jwt payload is not valid JSON")
	}
	return claims, nil
}

func padB64(s string) string {
	switch len(s) % 4 {
	case 2:
		return s + "=="
	case 3:
		return s + "="
	default:
		return s
	}
}

// ExtractGroupsFromJWT parses a compact JWT payload and extracts groups.
// Payload-only: callers must already have validated the JWT via ValidateAccessToken
// (signature, iss/aud/exp, ID-token rejection). Never use this on untrusted raw
// tokens without that prior check (serve path: GroupsFromValidatedToken).
func ExtractGroupsFromJWT(jwt string, cfg GroupClaimConfig) (GroupExtractResult, error) {
	claims, err := ParseJWTPayload(jwt)
	if err != nil {
		return GroupExtractResult{}, err
	}
	return ExtractGroups(claims, cfg)
}

// ValidateAudienceClaim fails closed when aud is missing or does not match
// expected (exact string or membership in aud array). Empty expected is invalid.
func ValidateAudienceClaim(claims map[string]any, expected string) error {
	expected = strings.TrimSpace(expected)
	if expected == "" {
		return apperr.New(apperr.CodeInvalidArgument, "expected audience is required")
	}
	if claims == nil {
		return apperr.New(apperr.CodeAuthentication, "token claims are missing")
	}
	raw, ok := claims["aud"]
	if !ok || raw == nil {
		return apperr.New(apperr.CodeAuthentication, "token audience claim is missing")
	}
	switch t := raw.(type) {
	case string:
		if strings.TrimSpace(t) != expected {
			return apperr.New(apperr.CodeAuthentication, "token audience does not match expected resource")
		}
	case []any:
		for _, el := range t {
			s, ok := el.(string)
			if ok && strings.TrimSpace(s) == expected {
				return nil
			}
		}
		return apperr.New(apperr.CodeAuthentication, "token audience does not match expected resource")
	case []string:
		for _, s := range t {
			if strings.TrimSpace(s) == expected {
				return nil
			}
		}
		return apperr.New(apperr.CodeAuthentication, "token audience does not match expected resource")
	default:
		return apperr.New(apperr.CodeAuthentication, "token audience claim has unsupported shape")
	}
	return nil
}

// ValidateSubjectClaim fails closed when sub is missing or does not match expected.
func ValidateSubjectClaim(claims map[string]any, expectedSub string) error {
	expectedSub = strings.TrimSpace(expectedSub)
	if expectedSub == "" {
		return apperr.New(apperr.CodeInvalidArgument, "expected subject is required")
	}
	if claims == nil {
		return apperr.New(apperr.CodeAuthentication, "token claims are missing")
	}
	raw, ok := claims["sub"]
	if !ok {
		return apperr.New(apperr.CodeAuthentication, "token subject claim is missing")
	}
	sub, ok := raw.(string)
	if !ok || strings.TrimSpace(sub) == "" {
		return apperr.New(apperr.CodeAuthentication, "token subject claim is invalid")
	}
	if strings.TrimSpace(sub) != expectedSub {
		return apperr.New(apperr.CodeAuthentication, "token subject does not match bound identity")
	}
	return nil
}

// ClaimString returns a trimmed string claim or empty.
func ClaimString(claims map[string]any, key string) string {
	if claims == nil {
		return ""
	}
	raw, ok := claims[key]
	if !ok {
		return ""
	}
	s, ok := raw.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(s)
}
