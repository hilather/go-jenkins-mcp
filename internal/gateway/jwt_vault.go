package gateway

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"sync"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// JWTVault stores per-subject Jenkins-audience access tokens for Mode B
// (jwt_rs_bearer / HOST-010 offline lab foundation).
//
// subjectKey is derived from gateway binding via SubjectKey(caller) — never
// from MCP tool arguments (GWY-002). Implementations must never log token
// values; errors must not embed secrets.
//
// Tokens stored here are presented to Jenkins as Authorization: Bearer
// (HTTPAuthSchemeBearer). They must be **access tokens** with Jenkins API
// audience — **never ID tokens** (OIDC id_token is not a Jenkins API credential).
// Live jwt-auth-filter / IdP issuance pin remains OAUTH-009 residual.
type JWTVault interface {
	// Get returns the access token for subjectKey.
	// ok=false with err=nil means not found (caller maps to fail-closed Obtain).
	Get(ctx context.Context, subjectKey string) (token string, ok bool, err error)
	// Put stores or replaces the access token for subjectKey.
	// Callers must supply Jenkins-audience access tokens only (never ID tokens).
	Put(ctx context.Context, subjectKey, token string) error
	// Delete removes the entry for subjectKey. Missing entries are success.
	Delete(ctx context.Context, subjectKey string) error
}

// MemoryJWTVault is a process-memory JWTVault for tests and unit labs.
// Not durable across restarts; never multi-replica storage.
type MemoryJWTVault struct {
	mu      sync.RWMutex
	entries map[string]string
}

// NewMemoryJWTVault constructs an empty memory JWT vault.
func NewMemoryJWTVault() *MemoryJWTVault {
	return &MemoryJWTVault{entries: make(map[string]string)}
}

// Get implements JWTVault.
func (v *MemoryJWTVault) Get(ctx context.Context, subjectKey string) (string, bool, error) {
	if err := ctx.Err(); err != nil {
		return "", false, apperr.Wrap(apperr.CodeCancelled, "gateway jwt vault get cancelled", err)
	}
	if err := ValidateSubjectKey(subjectKey); err != nil {
		return "", false, err
	}
	if v == nil {
		return "", false, nil
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	tok, ok := v.entries[strings.TrimSpace(subjectKey)]
	if !ok {
		return "", false, nil
	}
	return tok, true, nil
}

// Put implements JWTVault.
func (v *MemoryJWTVault) Put(ctx context.Context, subjectKey, token string) error {
	if err := ctx.Err(); err != nil {
		return apperr.Wrap(apperr.CodeCancelled, "gateway jwt vault put cancelled", err)
	}
	if err := ValidateSubjectKey(subjectKey); err != nil {
		return err
	}
	tok := strings.TrimSpace(token)
	if tok == "" {
		return apperr.New(apperr.CodeInvalidArgument, "gateway jwt vault access token is required")
	}
	if err := rejectIDTokenAsAPICredential(tok); err != nil {
		return err
	}
	if v == nil {
		return apperr.New(apperr.CodeInternal, "gateway jwt vault is nil")
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.entries == nil {
		v.entries = make(map[string]string)
	}
	v.entries[strings.TrimSpace(subjectKey)] = tok
	return nil
}

// Delete implements JWTVault.
func (v *MemoryJWTVault) Delete(ctx context.Context, subjectKey string) error {
	if err := ctx.Err(); err != nil {
		return apperr.Wrap(apperr.CodeCancelled, "gateway jwt vault delete cancelled", err)
	}
	if err := ValidateSubjectKey(subjectKey); err != nil {
		return err
	}
	if v == nil {
		return nil
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	delete(v.entries, strings.TrimSpace(subjectKey))
	return nil
}

// Len returns the number of stored subjects (tests / status only; no secrets).
func (v *MemoryJWTVault) Len() int {
	if v == nil {
		return 0
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	return len(v.entries)
}

// ListSubjectKeys returns subject keys only (no tokens). Sorted for stable
// admin/status output. Never includes secrets.
func (v *MemoryJWTVault) ListSubjectKeys(ctx context.Context) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, apperr.Wrap(apperr.CodeCancelled, "gateway jwt vault list cancelled", err)
	}
	if v == nil {
		return nil, nil
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	out := make([]string, 0, len(v.entries))
	for k := range v.entries {
		out = append(out, k)
	}
	sortSubjectKeys(out)
	return out, nil
}

// rejectIDTokenAsAPICredential is a best-effort fail-closed guard: JWT-shaped
// material whose payload claims token_use/typ of id_token is rejected.
// Opaque lab tokens pass through. Never logs the token.
func rejectIDTokenAsAPICredential(token string) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" {
		return nil
	}
	payload, err := decodeJWTPayloadSegment(parts[1])
	if err != nil || payload == "" {
		return nil
	}
	// id_token must never be used as Jenkins API credential (HOST-010).
	// Parse the payload as JSON first: the previous substring match was
	// bypassable by valid JSON whitespace ("token_use" : "id_token").
	var claims struct {
		TokenUse string `json:"token_use"`
		Typ      string `json:"typ"`
	}
	if err := json.Unmarshal([]byte(payload), &claims); err == nil {
		if strings.EqualFold(strings.TrimSpace(claims.TokenUse), "id_token") ||
			strings.EqualFold(strings.TrimSpace(claims.Typ), "id_token") {
			return apperr.New(apperr.CodeInvalidArgument,
				"id_token cannot be used as jenkins api credential; store access tokens only")
		}
		return nil
	}
	// Backstop for non-JSON payloads (should not happen for JWT): substring scan.
	pl := strings.ToLower(payload)
	if strings.Contains(pl, `"token_use":"id_token"`) ||
		strings.Contains(pl, `"token_use": "id_token"`) ||
		strings.Contains(pl, `"typ":"id_token"`) ||
		strings.Contains(pl, `"typ": "id_token"`) {
		return apperr.New(apperr.CodeInvalidArgument,
			"id_token cannot be used as jenkins api credential; store access tokens only")
	}
	return nil
}

func decodeJWTPayloadSegment(seg string) (string, error) {
	seg = strings.TrimSpace(seg)
	if m := len(seg) % 4; m != 0 {
		seg += strings.Repeat("=", 4-m)
	}
	raw, err := base64.URLEncoding.DecodeString(seg)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}
