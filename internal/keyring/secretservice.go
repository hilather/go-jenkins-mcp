package keyring

import (
	"errors"
	"strings"

	gokeyring "github.com/zalando/go-keyring"
)

// SecretService is the Linux backend using org.freedesktop.secrets via
// github.com/zalando/go-keyring. Product support is Rocky/Ubuntu only (ADR 0008);
// macOS and Windows secret stores are out of scope.
type SecretService struct{}

// NewSecretService returns the OS secret-service backend.
func NewSecretService() *SecretService {
	return &SecretService{}
}

// Set implements Backend.
func (s *SecretService) Set(service, user, password string) error {
	err := gokeyring.Set(service, user, password)
	if err != nil {
		return mapKeyringErr(err)
	}
	return nil
}

// Get implements Backend.
func (s *SecretService) Get(service, user string) (string, error) {
	v, err := gokeyring.Get(service, user)
	if err != nil {
		return "", mapKeyringErr(err)
	}
	return v, nil
}

// Delete implements Backend.
func (s *SecretService) Delete(service, user string) error {
	err := gokeyring.Delete(service, user)
	if err != nil {
		return mapKeyringErr(err)
	}
	return nil
}

// mapKeyringErr converts zalando/go-keyring errors into secret-free sentinels.
// The underlying error message may contain user/service labels but must not
// include the password; we still avoid wrapping raw strings into public messages.
func mapKeyringErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, gokeyring.ErrNotFound) {
		return ErrNotFound
	}
	// go-keyring returns plain errors for dbus/unavailable cases.
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "not found"),
		strings.Contains(msg, "cannot find"),
		strings.Contains(msg, "no such"):
		return ErrNotFound
	case strings.Contains(msg, "could not connect"),
		strings.Contains(msg, "dbus"),
		strings.Contains(msg, "secret service"),
		strings.Contains(msg, "no secret"),
		strings.Contains(msg, "unable to open"),
		strings.Contains(msg, "cannot autolaunch"),
		strings.Contains(msg, "not available"),
		strings.Contains(msg, "unsupported"):
		return ErrUnavailable
	default:
		// Fail closed: treat unknown OS keyring failures as unavailable rather
		// than inventing a success path. Do not embed err text (may be noisy).
		return ErrUnavailable
	}
}
