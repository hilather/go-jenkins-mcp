package auth

import (
	"context"
	"strings"
	"sync"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/keyring"
)

// TokenStore persists OIDC TokenBundle material per profile (OAUTH-004).
// Implementations must never log token bytes. Profile JSON is not a store.
// OAUTH-002 browser login writes via Set after code exchange.
type TokenStore interface {
	// Get loads the durable bundle for profileID.
	Get(ctx context.Context, profileID string) (TokenBundle, error)
	// Set replaces the durable bundle atomically (whole-blob write).
	Set(ctx context.Context, profileID string, bundle TokenBundle) error
	// Delete removes durable material. Missing entries are success.
	Delete(ctx context.Context, profileID string) error
	// Has reports presence without returning material.
	Has(ctx context.Context, profileID string) (bool, error)
}

// KeyringTokenStore implements TokenStore using the OS credential store
// (method=oidc_tokens). Suitable for OAUTH-002/004/007.
type KeyringTokenStore struct {
	Keyring *keyring.Store
}

// NewKeyringTokenStore wraps a keyring.Store. kr must not be nil.
func NewKeyringTokenStore(kr *keyring.Store) *KeyringTokenStore {
	if kr == nil {
		panic("auth: nil keyring for TokenStore")
	}
	return &KeyringTokenStore{Keyring: kr}
}

// Get implements TokenStore.
func (s *KeyringTokenStore) Get(ctx context.Context, profileID string) (TokenBundle, error) {
	if err := ctx.Err(); err != nil {
		return TokenBundle{}, apperr.Wrap(apperr.CodeCancelled, "token store get cancelled", err)
	}
	if s == nil || s.Keyring == nil {
		return TokenBundle{}, apperr.New(apperr.CodeInternal, "token store is not configured")
	}
	profileID = strings.TrimSpace(profileID)
	if profileID == "" {
		return TokenBundle{}, apperr.New(apperr.CodeInvalidArgument, "profile id is required")
	}
	raw, err := s.Keyring.GetOIDCTokens(profileID)
	if err != nil {
		return TokenBundle{}, err
	}
	return UnmarshalTokenBundle([]byte(raw))
}

// Set implements TokenStore.
func (s *KeyringTokenStore) Set(ctx context.Context, profileID string, bundle TokenBundle) error {
	if err := ctx.Err(); err != nil {
		return apperr.Wrap(apperr.CodeCancelled, "token store set cancelled", err)
	}
	if s == nil || s.Keyring == nil {
		return apperr.New(apperr.CodeInternal, "token store is not configured")
	}
	profileID = strings.TrimSpace(profileID)
	if profileID == "" {
		return apperr.New(apperr.CodeInvalidArgument, "profile id is required")
	}
	raw, err := bundle.MarshalKeyring()
	if err != nil {
		return err
	}
	return s.Keyring.SetOIDCTokens(profileID, string(raw))
}

// Delete implements TokenStore.
func (s *KeyringTokenStore) Delete(ctx context.Context, profileID string) error {
	if err := ctx.Err(); err != nil {
		return apperr.Wrap(apperr.CodeCancelled, "token store delete cancelled", err)
	}
	if s == nil || s.Keyring == nil {
		return apperr.New(apperr.CodeInternal, "token store is not configured")
	}
	profileID = strings.TrimSpace(profileID)
	if profileID == "" {
		return apperr.New(apperr.CodeInvalidArgument, "profile id is required")
	}
	return s.Keyring.DeleteOIDCTokens(profileID)
}

// Has implements TokenStore.
func (s *KeyringTokenStore) Has(ctx context.Context, profileID string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, apperr.Wrap(apperr.CodeCancelled, "token store has cancelled", err)
	}
	if s == nil || s.Keyring == nil {
		return false, apperr.New(apperr.CodeInternal, "token store is not configured")
	}
	return s.Keyring.HasOIDCTokens(strings.TrimSpace(profileID))
}

// MemoryTokenStore is an in-process TokenStore for unit tests.
// It is never the production default. Safe for concurrent use.
type MemoryTokenStore struct {
	mu sync.Mutex
	// data is profileID → raw keyring JSON (same encoding as KeyringTokenStore).
	data map[string][]byte
}

// NewMemoryTokenStore returns an empty memory token store.
func NewMemoryTokenStore() *MemoryTokenStore {
	return &MemoryTokenStore{data: make(map[string][]byte)}
}

// Get implements TokenStore.
func (s *MemoryTokenStore) Get(ctx context.Context, profileID string) (TokenBundle, error) {
	if err := ctx.Err(); err != nil {
		return TokenBundle{}, apperr.Wrap(apperr.CodeCancelled, "token store get cancelled", err)
	}
	if s == nil {
		return TokenBundle{}, apperr.New(apperr.CodeInternal, "token store is not configured")
	}
	profileID = strings.TrimSpace(profileID)
	s.mu.Lock()
	raw, ok := s.data[profileID]
	var cp []byte
	if ok {
		cp = make([]byte, len(raw))
		copy(cp, raw)
	}
	s.mu.Unlock()
	if !ok {
		return TokenBundle{}, apperr.New(apperr.CodeAuthentication, "no oidc tokens stored for this profile")
	}
	return UnmarshalTokenBundle(cp)
}

// Set implements TokenStore.
func (s *MemoryTokenStore) Set(ctx context.Context, profileID string, bundle TokenBundle) error {
	if err := ctx.Err(); err != nil {
		return apperr.Wrap(apperr.CodeCancelled, "token store set cancelled", err)
	}
	if s == nil {
		return apperr.New(apperr.CodeInternal, "token store is not configured")
	}
	profileID = strings.TrimSpace(profileID)
	if profileID == "" {
		return apperr.New(apperr.CodeInvalidArgument, "profile id is required")
	}
	raw, err := bundle.MarshalKeyring()
	if err != nil {
		return err
	}
	cp := make([]byte, len(raw))
	copy(cp, raw)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data == nil {
		s.data = make(map[string][]byte)
	}
	s.data[profileID] = cp
	return nil
}

// Delete implements TokenStore.
func (s *MemoryTokenStore) Delete(ctx context.Context, profileID string) error {
	if err := ctx.Err(); err != nil {
		return apperr.Wrap(apperr.CodeCancelled, "token store delete cancelled", err)
	}
	if s == nil {
		return apperr.New(apperr.CodeInternal, "token store is not configured")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, strings.TrimSpace(profileID))
	return nil
}

// Has implements TokenStore.
func (s *MemoryTokenStore) Has(ctx context.Context, profileID string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, apperr.Wrap(apperr.CodeCancelled, "token store has cancelled", err)
	}
	if s == nil {
		return false, apperr.New(apperr.CodeInternal, "token store is not configured")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.data[strings.TrimSpace(profileID)]
	return ok, nil
}
