package fleet

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/hilather/go-jenkins-mcp/internal/config"
)

const (
	installIDFileName = "installation_id"
	installIDDirName  = "telemetry"
	filePerm          = 0o600
	dirPerm           = 0o700
)

// InstallIDPath returns the path for the pseudonymous installation id file
// under XDG data: $XDG_DATA_HOME/jenkins-mcp/telemetry/installation_id
func InstallIDPath(paths config.Paths) string {
	return filepath.Join(paths.DataDir, installIDDirName, installIDFileName)
}

// TelemetryDir returns $XDG_DATA_HOME/jenkins-mcp/telemetry
func TelemetryDir(paths config.Paths) string {
	return filepath.Join(paths.DataDir, installIDDirName)
}

// LoadOrCreateInstallationID returns a stable random UUID (RFC 4122-ish v4).
// It is not a secret and is not derived from hostname. Stored once on first use.
func LoadOrCreateInstallationID(paths config.Paths) (string, error) {
	path := InstallIDPath(paths)
	if b, err := os.ReadFile(path); err == nil {
		id := strings.TrimSpace(string(b))
		if isValidInstallID(id) {
			return id, nil
		}
		// Corrupt file: regenerate (best-effort).
	}
	id, err := newRandomInstallID()
	if err != nil {
		return "", err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return "", fmt.Errorf("fleet: create telemetry dir: %w", err)
	}
	_ = os.Chmod(dir, dirPerm)
	// Unpredictable O_EXCL temp in the same directory: two processes
	// first-running at once must not interleave writes to a shared <path>.tmp
	// (which could publish one id while the other process returns its own).
	tmp, err := os.CreateTemp(dir, ".installation_id-*.tmp")
	if err != nil {
		return "", fmt.Errorf("fleet: stage installation_id: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename
	if _, err := tmp.WriteString(id + "\n"); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("fleet: write installation_id: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("fleet: write installation_id: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		// Race: another process may have created it.
		if b, rerr := os.ReadFile(path); rerr == nil {
			existing := strings.TrimSpace(string(b))
			if isValidInstallID(existing) {
				return existing, nil
			}
		}
		return "", fmt.Errorf("fleet: rename installation_id: %w", err)
	}
	return id, nil
}

func newRandomInstallID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("fleet: random install id: %w", err)
	}
	// RFC 4122 version 4 / variant bits.
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hex.EncodeToString(b[0:4]),
		hex.EncodeToString(b[4:6]),
		hex.EncodeToString(b[6:8]),
		hex.EncodeToString(b[8:10]),
		hex.EncodeToString(b[10:16]),
	), nil
}

func isValidInstallID(id string) bool {
	// Accept 36-char UUID form only (no free-form hostnames).
	if len(id) != 36 {
		return false
	}
	for i, c := range id {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return false
			}
		}
	}
	return true
}

// installIDCache avoids repeated disk reads in a single process.
var (
	installIDMu    sync.Mutex
	installIDCache string
)

// CachedInstallationID loads once per process (tests may call ResetInstallIDCache).
func CachedInstallationID(paths config.Paths) (string, error) {
	installIDMu.Lock()
	defer installIDMu.Unlock()
	if installIDCache != "" {
		return installIDCache, nil
	}
	id, err := LoadOrCreateInstallationID(paths)
	if err != nil {
		return "", err
	}
	installIDCache = id
	return id, nil
}

// ResetInstallIDCache clears the process cache (tests only).
func ResetInstallIDCache() {
	installIDMu.Lock()
	installIDCache = ""
	installIDMu.Unlock()
}
