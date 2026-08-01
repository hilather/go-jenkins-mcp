package gateway

import (
	"strings"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/audit"
	"github.com/simonfxr/go-jenkins-mcp/internal/contracts"
)

// SubjectInvalidateResult is a secret-free outcome of process-local subject
// cache invalidation (GWY-002 / HOST-003 force re-auth residual lite).
// Never includes tokens, vault material, or Authorization headers.
type SubjectInvalidateResult struct {
	// SubjectKey is the operator-supplied or composed tenant|subject|profile key.
	// Safe to echo when the operator just typed it; prefer SubjectKeyHash in
	// multi-tenant logs/audit.
	SubjectKey string
	// SubjectKeyHash is audit.HashOpaque(SubjectKey) for correlation (never raw
	// inventory dumps in aggregated telemetry).
	SubjectKeyHash string
	// PrincipalCleared is true when PrincipalStore.Delete succeeded for SubjectKey
	// (entry may or may not have existed). False when principals was nil or
	// Delete returned an error (e.g. FilePrincipalCache IO/corrupt/save — row may
	// remain on disk). Never claim cleared without durable success.
	PrincipalCleared bool
	// TokenCacheCleared is true when at least one token-cache delete path ran
	// successfully (exact CacheKey and/or subject-namespace purge).
	TokenCacheCleared bool
	// TokenCacheEntriesDeleted is the number of token entries removed when known
	// (subject-namespace purge); -1 when unknown / exact Delete only.
	TokenCacheEntriesDeleted int
	// TokenCacheNote is residual honesty about token cache scope (memory vs file,
	// multi-pod, serve-process).
	TokenCacheNote string
	// ResidualNote is multi-process / multi-pod / live-revocation honesty.
	// May include principal Delete failure residual when PrincipalCleared is false
	// due to durable store IO.
	ResidualNote string
}

// subjectInvalidateResidualNote is the stable offline honesty sentence.
const subjectInvalidateResidualNote = "force re-auth residual lite (GWY-002/HOST-003): PrincipalCache + optional TokenCache only — not live Entra/AgentCore revocation, not multi-pod fan-out; CLI principal clear is process-local unless serve shares FilePrincipalCache via JENKINS_MCP_GATEWAY_PRINCIPAL_CACHE_PATH (and FileTokenCache via JENKINS_MCP_GATEWAY_TOKEN_CACHE_PATH)"

// InvalidateSubjectLocal clears process-local multi-user caches for a validated
// caller so the next Obtain / Binding path re-fetches (logout / revoke companion).
//
//   - principals: PrincipalStore.Delete(SubjectKey(caller)); nil → skip principal;
//     Delete error → PrincipalCleared=false (FilePrincipalCache durability honesty)
//   - tokens: prefer DeleteBySubjectKey when available (all workloads); else
//     TokenCache.Delete(caller.CacheKey()); nil → residual note only
//
// Secret-free: never logs or returns token bytes. Safe for tests and CLI.
func InvalidateSubjectLocal(caller Caller, principals PrincipalStore, tokens TokenCache) SubjectInvalidateResult {
	sk := SubjectKey(caller)
	res := SubjectInvalidateResult{
		SubjectKey:               sk,
		SubjectKeyHash:           audit.HashOpaque(sk),
		TokenCacheEntriesDeleted: -1,
		ResidualNote:             subjectInvalidateResidualNote,
	}
	if sk == "" {
		res.TokenCacheNote = "invalid or empty subject key; nothing cleared"
		return res
	}

	if principals != nil {
		if err := principals.Delete(sk); err != nil {
			// FilePrincipalCache IO/corrupt/save — do not claim cleared (parity with
			// FileTokenCache DeleteBySubjectKey -1 honesty).
			res.PrincipalCleared = false
			res.ResidualNote = subjectInvalidateResidualNote + "; principal Delete failed (IO/corrupt residual); principal may remain on disk"
		} else {
			res.PrincipalCleared = true
		}
	}

	if tokens == nil {
		res.TokenCacheNote = "token_cache not provided (serve process-local MemoryTokenCache residual; optional same-host FileTokenCache via JENKINS_MCP_GATEWAY_TOKEN_CACHE_PATH)"
		return res
	}

	// Prefer subject-namespace purge (all workloads for tenant|user|profile).
	if d, ok := tokens.(interface{ DeleteBySubjectKey(string) int }); ok {
		n := d.DeleteBySubjectKey(sk)
		if n < 0 {
			// FileTokenCache IO/corrupt/save failure — do not claim cleared.
			res.TokenCacheCleared = false
			res.TokenCacheEntriesDeleted = -1
			res.TokenCacheNote = "token_cache subject-namespace purge failed (IO/corrupt residual); tokens may remain on disk"
			return res
		}
		res.TokenCacheCleared = true
		res.TokenCacheEntriesDeleted = n
		res.TokenCacheNote = "token_cache subject-namespace deleted (process/file local; multi-pod external residual)"
		return res
	}

	// Fallback: exact CacheKey delete when caller has minimum binding fields.
	if caller.CacheKey().Valid() {
		tokens.Delete(caller.CacheKey())
		res.TokenCacheCleared = true
		res.TokenCacheEntriesDeleted = -1
		res.TokenCacheNote = "token_cache exact CacheKey deleted (workload-scoped; multi-pod residual)"
		return res
	}

	res.TokenCacheNote = "token_cache present but caller CacheKey invalid; no token entry deleted"
	return res
}

// InvalidateSubjectKeyLocal clears caches for an explicit subjectKey
// (tenant|subject|profile). Optional workload is used only for exact CacheKey
// fallback when the cache does not support DeleteBySubjectKey.
// Fail closed on empty/invalid subjectKey.
func InvalidateSubjectKeyLocal(subjectKey, workload string, principals PrincipalStore, tokens TokenCache) (SubjectInvalidateResult, error) {
	sk := strings.TrimSpace(subjectKey)
	if err := ValidateSubjectKey(sk); err != nil {
		return SubjectInvalidateResult{}, err
	}
	tenant, subject, profile, err := SplitSubjectKey(sk)
	if err != nil {
		return SubjectInvalidateResult{}, err
	}
	caller := Caller{
		Tenant:     tenant,
		Subject:    subject,
		ProfileID:  contracts.ProfileID(profile),
		WorkloadID: strings.TrimSpace(workload),
	}
	return InvalidateSubjectLocal(caller, principals, tokens), nil
}

// SplitSubjectKey parses tenant|subject|profile (exactly three pipe-separated
// fields). Subject must be non-empty. Fail closed on malformed keys.
func SplitSubjectKey(subjectKey string) (tenant, subject, profile string, err error) {
	k := strings.TrimSpace(subjectKey)
	if k == "" {
		return "", "", "", apperr.New(apperr.CodeInvalidArgument, "gateway subject key is required")
	}
	parts := strings.Split(k, "|")
	if len(parts) != 3 {
		return "", "", "", apperr.New(apperr.CodeInvalidArgument,
			"gateway subject key must be tenant|subject|profile (exactly three fields)")
	}
	tenant = strings.TrimSpace(parts[0])
	subject = strings.TrimSpace(parts[1])
	profile = strings.TrimSpace(parts[2])
	if subject == "" {
		return "", "", "", apperr.New(apperr.CodeInvalidArgument, "gateway subject key subject field is required")
	}
	return tenant, subject, profile, nil
}

// StatusMap is secret-free JSON for CLI / doctor (never tokens).
func (r SubjectInvalidateResult) StatusMap() map[string]any {
	return map[string]any{
		"subject_key":                 r.SubjectKey,
		"subject_key_hash":            r.SubjectKeyHash,
		"principal_cleared":           r.PrincipalCleared,
		"token_cache_cleared":         r.TokenCacheCleared,
		"token_cache_entries_deleted": r.TokenCacheEntriesDeleted,
		"token_cache_note":            r.TokenCacheNote,
		"residual_note":               r.ResidualNote,
		"cleared": map[string]any{
			"principal":   r.PrincipalCleared,
			"token_cache": r.TokenCacheCleared,
		},
	}
}
