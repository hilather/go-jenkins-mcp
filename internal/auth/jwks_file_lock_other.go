//go:build !unix

package auth

import (
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// withJWKSFileLock is a no-op on non-unix (Windows is out of platform matrix).
// Process-local mutex still serializes within one process. Multi-process same
// file safety is Tier-1 Linux (unix flock) only — HOST-001/HOST-008 residual
// honesty. Public JWKS keys only (never secrets).
func withJWKSFileLock(cachePath string, fn func() error) error {
	if strings.TrimSpace(cachePath) == "" {
		return apperr.New(apperr.CodeInternal, "jwks cache path is required for flock")
	}
	if fn == nil {
		return nil
	}
	return fn()
}
