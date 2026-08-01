//go:build !unix

package gateway

import "github.com/simonfxr/go-jenkins-mcp/internal/apperr"

// withVaultFileLock is a no-op on non-unix (Windows is out of platform matrix).
// Process-local mutex still serializes within one process. Multi-process same
// file safety is Tier-1 Linux (unix flock) only — HOST-008 residual honesty.
func withVaultFileLock(vaultPath string, fn func() error) error {
	if vaultPath == "" {
		return apperr.New(apperr.CodeInternal, "gateway vault path is required for flock")
	}
	if fn == nil {
		return nil
	}
	return fn()
}
