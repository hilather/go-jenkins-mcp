//go:build unix

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// withVaultFileLock serializes multi-process access to a shared vault file via
// a sibling lock file (path+".lock") and syscall.Flock (LOCK_EX).
//
// HOST-008 Done* lite: process-local mutex alone does not protect concurrent
// File*Vault instances or CLI + serve on the same path. Flock on a dedicated
// lock file (not the vault inode) remains valid across temp+rename of the
// vault JSON. Not multi-pod / multi-host HA (shared filesystem required).
//
// Lock file mode 0600; never logs vault contents.
func withVaultFileLock(vaultPath string, fn func() error) error {
	if strings.TrimSpace(vaultPath) == "" {
		return apperr.New(apperr.CodeInternal, "gateway vault path is required for flock")
	}
	dir := filepath.Dir(vaultPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return apperr.Wrap(apperr.CodeInternal, "gateway vault lock directory create failed", err)
	}
	lockPath := vaultPath + ".lock"
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return apperr.Wrap(apperr.CodeInternal, "gateway vault lock open failed", err)
	}
	// Re-assert mode (existing lock file may have looser perms from older labs).
	_ = f.Chmod(0o600)

	if err := flockExclusive(f); err != nil {
		_ = f.Close()
		return err
	}
	// Unlock then close; ignore unlock errors after successful fn (best-effort).
	defer func() {
		_ = flockUnlock(f)
		_ = f.Close()
	}()
	return fn()
}

func flockExclusive(f *os.File) error {
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
		if err == nil {
			return nil
		}
		if err == syscall.EINTR {
			continue
		}
		return apperr.Wrap(apperr.CodeInternal, "gateway vault flock exclusive failed", err)
	}
}

func flockUnlock(f *os.File) error {
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
