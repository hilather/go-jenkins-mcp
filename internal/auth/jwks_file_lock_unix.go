//go:build unix

package auth

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// withJWKSFileLock serializes multi-process access to a shared JWKS cache path
// via a sibling lock file (path+".lock") and syscall.Flock (LOCK_EX).
//
// HOST-001 / HOST-008 Done* lite: same-host multi-process share of public JWKS
// only. Flock on a dedicated lock file remains valid across temp+rename of the
// JSON payload. Not multi-pod / multi-host HA without a shared filesystem.
//
// Lock file mode 0600; never logs JWKS key material.
func withJWKSFileLock(cachePath string, fn func() error) error {
	if strings.TrimSpace(cachePath) == "" {
		return apperr.New(apperr.CodeInternal, "jwks cache path is required for flock")
	}
	dir := filepath.Dir(cachePath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return apperr.Wrap(apperr.CodeInternal, "jwks cache lock directory create failed", err)
	}
	lockPath := cachePath + ".lock"
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return apperr.Wrap(apperr.CodeInternal, "jwks cache lock open failed", err)
	}
	_ = f.Chmod(0o600)

	if err := jwksFlockExclusive(f); err != nil {
		_ = f.Close()
		return err
	}
	defer func() {
		_ = jwksFlockUnlock(f)
		_ = f.Close()
	}()
	return fn()
}

func jwksFlockExclusive(f *os.File) error {
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
		if err == nil {
			return nil
		}
		if err == syscall.EINTR {
			continue
		}
		return apperr.Wrap(apperr.CodeInternal, "jwks cache flock exclusive failed", err)
	}
}

func jwksFlockUnlock(f *os.File) error {
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		if err == nil {
			return nil
		}
		if err == syscall.EINTR {
			continue
		}
		return err
	}
}
