//go:build !unix

package gateway_test

import (
	"testing"
	"time"
)

func holdVaultLockFor(t *testing.T, vaultPath string, d time.Duration) {
	t.Helper()
	t.Skip("flock hold helper is unix-only")
}

func tryFlockHeld(t *testing.T, lockPath string) bool {
	t.Helper()
	return false
}
