package keyring

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// MethodCacheAEAD is the keyring method namespace for ARC-009 cache encryption keys.
// Raw key material is never written to profile JSON or pack manifests.
const MethodCacheAEAD = "cache_aead"

// CacheKeyAccountKey builds the backend user key for a profile cache key version.
// It never includes secret material — only profile id and version.
func CacheKeyAccountKey(profileID string, version int) string {
	return fmt.Sprintf("profile=%s;method=%s;version=%d",
		strings.TrimSpace(profileID), MethodCacheAEAD, version)
}

// SetCacheKey stores or replaces a 32-byte AES-256 cache key for profile/version.
// Material is base64-encoded for the backend string API; never logged.
func (s *Store) SetCacheKey(profileID string, version int, material []byte) error {
	if err := validateCacheKeyRef(profileID, version); err != nil {
		return err
	}
	if len(material) != 32 {
		return apperr.New(apperr.CodeInvalidArgument, "cache key must be 32 bytes")
	}
	// Encode so backends that expect printable secrets stay happy.
	enc := base64.StdEncoding.EncodeToString(material)
	err := s.Backend.Set(s.service(), CacheKeyAccountKey(profileID, version), enc)
	if err != nil {
		return mapStoreErr(err, "store cache key")
	}
	return nil
}

// GetCacheKey loads the 32-byte AES-256 cache key for profile/version.
func (s *Store) GetCacheKey(profileID string, version int) ([]byte, error) {
	if err := validateCacheKeyRef(profileID, version); err != nil {
		return nil, err
	}
	v, err := s.Backend.Get(s.service(), CacheKeyAccountKey(profileID, version))
	if err != nil {
		return nil, mapCacheKeyErr(err)
	}
	mat, err := base64.StdEncoding.DecodeString(v)
	if err != nil || len(mat) != 32 {
		// Corrupt keyring entry — fail closed without echoing value.
		return nil, apperr.New(apperr.CodeCorruptCache, "cache key entry is corrupt or wrong size")
	}
	return mat, nil
}

// DeleteCacheKey removes the cache key for profile/version. Missing is success.
func (s *Store) DeleteCacheKey(profileID string, version int) error {
	if err := validateCacheKeyRef(profileID, version); err != nil {
		return err
	}
	err := s.Backend.Delete(s.service(), CacheKeyAccountKey(profileID, version))
	if err == nil || err == ErrNotFound {
		return nil
	}
	return mapStoreErr(err, "delete cache key")
}

// HasCacheKey reports whether a key is present (does not return material).
func (s *Store) HasCacheKey(profileID string, version int) (bool, error) {
	_, err := s.GetCacheKey(profileID, version)
	if err == nil {
		return true, nil
	}
	// Missing key / unavailable secret service → not present (caller may fail closed later).
	switch apperr.CodeOf(err) {
	case apperr.CodeAuthentication:
		return false, nil
	case apperr.CodeCorruptCache:
		// Entry exists but is unusable — treat as present for status, surface on Get.
		return true, nil
	default:
		return false, err
	}
}

func validateCacheKeyRef(profileID string, version int) error {
	if strings.TrimSpace(profileID) == "" {
		return apperr.New(apperr.CodeInvalidArgument, "profile id is required for cache key")
	}
	if version < 1 {
		return apperr.New(apperr.CodeInvalidArgument, "cache key version must be >= 1")
	}
	return nil
}

func mapCacheKeyErr(err error) error {
	if err == nil {
		return nil
	}
	if err == ErrNotFound {
		return apperr.New(apperr.CodeAuthentication, "no cache encryption key stored for this profile/version")
	}
	if err == ErrUnavailable || err == ErrUnsupported {
		return apperr.Wrap(apperr.CodeAuthentication,
			"secret service unavailable (unlock session keyring or install Secret Service); headless file backend is disabled by default",
			err)
	}
	return apperr.Wrap(apperr.CodeInternal, "load cache key failed", err)
}
