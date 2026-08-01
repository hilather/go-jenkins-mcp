package keyring

import (
	"errors"
)

// Backend is a low-level secret storage adapter.
// Implementations must never log password values.
type Backend interface {
	// Set stores or replaces password for (service, user).
	Set(service, user, password string) error
	// Get returns the password for (service, user).
	// ErrNotFound when missing.
	Get(service, user string) (string, error)
	// Delete removes the password for (service, user).
	// ErrNotFound when missing is acceptable as success or returned — Store normalizes.
	Delete(service, user string) error
}

// Sentinel errors (secret-free).
var (
	// ErrNotFound indicates no credential for the key.
	ErrNotFound = errors.New("keyring: credential not found")
	// ErrUnavailable indicates the OS secret service is missing, locked, or unusable.
	ErrUnavailable = errors.New("keyring: secret service unavailable")
	// ErrUnsupported indicates the backend is not supported on this platform.
	ErrUnsupported = errors.New("keyring: backend unsupported on this platform")
)
