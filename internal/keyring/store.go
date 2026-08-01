package keyring

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// DefaultService is the application namespace in the OS secret store.
const DefaultService = "go-jenkins-mcp"

// Store is a namespaced credential API over a Backend.
// Namespace: application + profile + origin + method + account.
type Store struct {
	Backend Backend
	// Service is the keyring service/application id (default DefaultService).
	Service string
}

// NewStore wraps a Backend. backend must not be nil.
func NewStore(backend Backend) *Store {
	if backend == nil {
		panic("keyring: nil backend")
	}
	return &Store{Backend: backend, Service: DefaultService}
}

// Default returns a Store using the OS Secret Service backend.
// Headless environments without Secret Service fail closed on Get/Set/Delete.
func Default() *Store {
	return NewStore(NewSecretService())
}

// CredentialRef identifies a stored secret without holding the secret value.
type CredentialRef struct {
	ProfileID string
	Origin    string // normalized scheme://host[:port]
	Method    string // e.g. api_token
	Account   string // Jenkins username / account identity
}

// AccountKey builds the backend user key. It never includes the secret.
func AccountKey(ref CredentialRef) string {
	origin := strings.TrimSpace(strings.ToLower(ref.Origin))
	// Ensure origin is not a full URL with path/userinfo if callers pass one.
	if u, err := url.Parse(origin); err == nil && u.Host != "" {
		origin = strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
	}
	return fmt.Sprintf("profile=%s;origin=%s;method=%s;account=%s",
		strings.TrimSpace(ref.ProfileID),
		origin,
		strings.TrimSpace(ref.Method),
		strings.TrimSpace(ref.Account),
	)
}

func (s *Store) service() string {
	if s.Service == "" {
		return DefaultService
	}
	return s.Service
}

// SetSecret stores or replaces an opaque secret for ref. Secret is never logged.
// Used for API tokens (method=api_token) and OIDC blobs (method=oidc; OAUTH-002/004).
func (s *Store) SetSecret(ref CredentialRef, secret string) error {
	if err := validateRef(ref); err != nil {
		return err
	}
	if strings.TrimSpace(secret) == "" {
		return apperr.New(apperr.CodeInvalidArgument, "secret value is required")
	}
	err := s.Backend.Set(s.service(), AccountKey(ref), secret)
	if err != nil {
		return mapStoreErr(err, "store credential")
	}
	return nil
}

// GetSecret loads the opaque secret for ref.
func (s *Store) GetSecret(ref CredentialRef) (string, error) {
	if err := validateRef(ref); err != nil {
		return "", err
	}
	v, err := s.Backend.Get(s.service(), AccountKey(ref))
	if err != nil {
		return "", mapStoreErr(err, "load credential")
	}
	return v, nil
}

// DeleteSecret removes the secret for ref. Missing entries are success.
func (s *Store) DeleteSecret(ref CredentialRef) error {
	if err := validateRef(ref); err != nil {
		return err
	}
	err := s.Backend.Delete(s.service(), AccountKey(ref))
	if err == nil || err == ErrNotFound {
		return nil
	}
	return mapStoreErr(err, "delete credential")
}

// SetAPIToken stores or replaces the API token for ref. Token is never logged.
func (s *Store) SetAPIToken(ref CredentialRef, token string) error {
	if strings.TrimSpace(token) == "" {
		return apperr.New(apperr.CodeInvalidArgument, "api token is required")
	}
	return s.SetSecret(ref, token)
}

// GetAPIToken loads the API token for ref.
func (s *Store) GetAPIToken(ref CredentialRef) (string, error) {
	return s.GetSecret(ref)
}

// DeleteAPIToken removes the API token for ref. Missing entries are success.
func (s *Store) DeleteAPIToken(ref CredentialRef) error {
	return s.DeleteSecret(ref)
}

func validateRef(ref CredentialRef) error {
	if strings.TrimSpace(ref.ProfileID) == "" {
		return apperr.New(apperr.CodeInvalidArgument, "profile id is required for keyring entry")
	}
	if strings.TrimSpace(ref.Origin) == "" {
		return apperr.New(apperr.CodeInvalidArgument, "origin is required for keyring entry")
	}
	if strings.TrimSpace(ref.Method) == "" {
		return apperr.New(apperr.CodeInvalidArgument, "auth method is required for keyring entry")
	}
	if strings.TrimSpace(ref.Account) == "" {
		return apperr.New(apperr.CodeInvalidArgument, "account is required for keyring entry")
	}
	return nil
}

// mapStoreErr converts backend errors to apperr without embedding secrets.
// err.Error() from our backends is secret-free; still avoid concatenating values.
func mapStoreErr(err error, op string) error {
	if err == nil {
		return nil
	}
	if err == ErrNotFound {
		return apperr.New(apperr.CodeAuthentication, "no credential stored for this profile")
	}
	if err == ErrUnavailable || err == ErrUnsupported {
		return apperr.Wrap(apperr.CodeAuthentication,
			"secret service unavailable (unlock session keyring or install Secret Service); headless file backend is disabled by default",
			err)
	}
	// Generic safe message — do not include err text in model-visible path.
	return apperr.Wrap(apperr.CodeInternal, op+" failed", err)
}
