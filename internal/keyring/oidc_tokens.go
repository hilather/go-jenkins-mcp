package keyring

import (
	"fmt"
	"strings"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// MethodOIDCTokens is the keyring method namespace for OIDC token blobs (OAUTH-004).
// Distinct from api_token and cache_aead. Profile JSON must never hold this material.
const MethodOIDCTokens = "oidc_tokens"

// OIDCTokensAccountKey builds the backend user key for a profile OIDC token blob.
// It never includes secret material — only profile id and method.
func OIDCTokensAccountKey(profileID string) string {
	return fmt.Sprintf("profile=%s;method=%s",
		strings.TrimSpace(profileID), MethodOIDCTokens)
}

// SetOIDCTokens stores or replaces the opaque OIDC token blob for a profile.
// blob is typically JSON from auth.TokenBundle; never logged.
func (s *Store) SetOIDCTokens(profileID string, blob string) error {
	if err := validateOIDCTokensRef(profileID); err != nil {
		return err
	}
	if strings.TrimSpace(blob) == "" {
		return apperr.New(apperr.CodeInvalidArgument, "oidc token blob is required")
	}
	err := s.Backend.Set(s.service(), OIDCTokensAccountKey(profileID), blob)
	if err != nil {
		return mapStoreErr(err, "store oidc tokens")
	}
	return nil
}

// GetOIDCTokens loads the OIDC token blob for a profile.
func (s *Store) GetOIDCTokens(profileID string) (string, error) {
	if err := validateOIDCTokensRef(profileID); err != nil {
		return "", err
	}
	v, err := s.Backend.Get(s.service(), OIDCTokensAccountKey(profileID))
	if err != nil {
		return "", mapOIDCTokensErr(err)
	}
	if strings.TrimSpace(v) == "" {
		// Empty entry is unusable — treat as missing, not a secret leak path.
		return "", apperr.New(apperr.CodeAuthentication, "no oidc tokens stored for this profile")
	}
	return v, nil
}

// DeleteOIDCTokens removes the OIDC token blob for a profile. Missing is success.
func (s *Store) DeleteOIDCTokens(profileID string) error {
	if err := validateOIDCTokensRef(profileID); err != nil {
		return err
	}
	err := s.Backend.Delete(s.service(), OIDCTokensAccountKey(profileID))
	if err == nil || err == ErrNotFound {
		return nil
	}
	return mapStoreErr(err, "delete oidc tokens")
}

// HasOIDCTokens reports whether a blob is present (does not return material).
func (s *Store) HasOIDCTokens(profileID string) (bool, error) {
	_, err := s.GetOIDCTokens(profileID)
	if err == nil {
		return true, nil
	}
	switch apperr.CodeOf(err) {
	case apperr.CodeAuthentication:
		return false, nil
	case apperr.CodeCorruptCache:
		// Corrupt entry exists — present for diagnostics; Get surfaces the error.
		return true, nil
	default:
		return false, err
	}
}

func validateOIDCTokensRef(profileID string) error {
	if strings.TrimSpace(profileID) == "" {
		return apperr.New(apperr.CodeInvalidArgument, "profile id is required for oidc tokens")
	}
	return nil
}

func mapOIDCTokensErr(err error) error {
	if err == nil {
		return nil
	}
	if err == ErrNotFound {
		return apperr.New(apperr.CodeAuthentication, "no oidc tokens stored for this profile")
	}
	if err == ErrUnavailable || err == ErrUnsupported {
		return apperr.Wrap(apperr.CodeAuthentication,
			"secret service unavailable (unlock session keyring or install Secret Service); headless file backend is disabled by default",
			err)
	}
	return apperr.Wrap(apperr.CodeInternal, "load oidc tokens failed", err)
}
