//go:build unix

package gateway_test

import (
	"os"
	"syscall"
	"testing"
	"time"
)

// holdVaultLockFor acquires exclusive flock on path+".lock" and holds it for d.
func holdVaultLockFor(t *testing.T, vaultPath string, d time.Duration) {
	t.Helper()
	lockPath := vaultPath + ".lock"
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatalf("flock: %v", err)
	}
	time.Sleep(d)
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}

// tryFlockHeld returns true when another process holds exclusive lock on lockPath.
func tryFlockHeld(t *testing.T, lockPath string) bool {
	t.Helper()
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return false
	}
	defer f.Close()
	err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err == nil {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		return false // we got the lock → not held by child
	}
	// EWOULDBLOCK / EAGAIN → held
	return true
}
