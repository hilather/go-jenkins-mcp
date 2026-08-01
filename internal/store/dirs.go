package store

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// DirPerm is the mode for per-user data directories (owner rwx only).
const DirPerm fs.FileMode = 0o700

// EnsureDir creates path (and parents) with DirPerm and validates ownership/mode.
// If the directory already exists, it is re-chmod'd toward DirPerm when possible
// and then validated. World- or group-writable directories fail closed.
func EnsureDir(path string) error {
	path, err := cleanDataPath(path)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(path, DirPerm); err != nil {
		return apperr.Wrap(apperr.CodeInternal, "failed to create data directory", err)
	}
	// Force owner-only even when umask left group bits set.
	if err := os.Chmod(path, DirPerm); err != nil {
		return apperr.Wrap(apperr.CodeInternal, "failed to set data directory mode", err)
	}
	return ValidateDir(path)
}

// ValidateDir checks that path is a directory suitable for private cache data:
// not a symlink, not world/group-writable, and owned by the current user when
// the platform exposes ownership (Unix).
func ValidateDir(path string) error {
	path, err := cleanDataPath(path)
	if err != nil {
		return err
	}
	fi, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return apperr.Wrap(apperr.CodeNotFound, "data directory does not exist", err)
		}
		return apperr.Wrap(apperr.CodeInternal, "failed to stat data directory", err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return apperr.New(apperr.CodeCorruptCache,
			"data directory must not be a symbolic link")
	}
	if !fi.IsDir() {
		return apperr.New(apperr.CodeCorruptCache, "data path is not a directory")
	}
	perm := fi.Mode().Perm()
	// Reject group/other write (world-writable is a subset).
	if perm&0o022 != 0 {
		return apperr.New(apperr.CodeCorruptCache,
			fmt.Sprintf("data directory mode %04o is group/world-writable; require 0700", perm))
	}
	// Prefer strict 0700 for new trees; allow stricter (e.g. 0500) but not looser.
	if perm&0o077 != 0 {
		return apperr.New(apperr.CodeCorruptCache,
			fmt.Sprintf("data directory mode %04o is group/other-accessible; require 0700", perm))
	}
	if err := validateDirOwner(path, fi); err != nil {
		return err
	}
	return nil
}

// EnsureProfileDataDir ensures the per-profile data root under dataRoot
// (typically config.Paths.ProfileDataDir(id)) exists with secure permissions.
// profileID must be a non-empty safe token (no path separators or "..").
func EnsureProfileDataDir(dataRoot string, profileID string) (string, error) {
	profileID = strings.TrimSpace(profileID)
	if profileID == "" {
		return "", apperr.New(apperr.CodeInvalidArgument, "profile id is required")
	}
	if err := validateProfileIDForPath(profileID); err != nil {
		return "", err
	}
	// dataRoot is the full profile data path (already includes profile id when
	// produced by config.Paths.ProfileDataDir). When callers pass the app data
	// root + id separately, join; when they pass ProfileDataDir, use as-is.
	// Convention: EnsureProfileDataDir(paths.ProfileDataDir(id), id) or
	// EnsureProfileDataDir(paths.DataDir, id) — we accept either by checking
	// whether dataRoot already ends with the profile id segment.
	path := resolveProfileDataPath(dataRoot, profileID)
	if err := EnsureDir(path); err != nil {
		return "", err
	}
	return path, nil
}

// resolveProfileDataPath returns the absolute profile data directory.
// If dataRoot already ends with profileID (as ProfileDataDir does), it is used
// directly; otherwise profileID is joined under dataRoot.
func resolveProfileDataPath(dataRoot, profileID string) string {
	clean := filepath.Clean(dataRoot)
	if filepath.Base(clean) == profileID {
		return clean
	}
	return filepath.Join(clean, profileID)
}

func validateProfileIDForPath(id string) error {
	if strings.Contains(id, string(filepath.Separator)) || strings.Contains(id, "/") || strings.Contains(id, "\\") {
		return apperr.New(apperr.CodeInvalidArgument, "profile id must not contain path separators")
	}
	if id == "." || id == ".." || strings.Contains(id, "..") {
		return apperr.New(apperr.CodeInvalidArgument, "profile id must not contain path traversal")
	}
	return nil
}

func cleanDataPath(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", apperr.New(apperr.CodeInvalidArgument, "data directory path is required")
	}
	if !filepath.IsAbs(path) {
		return "", apperr.New(apperr.CodeInvalidArgument, "data directory path must be absolute")
	}
	clean := filepath.Clean(path)
	// Reject ".." segments that Clean could not fully resolve away from root.
	// Clean already collapses ".." but we still refuse relative components that
	// would escape if joined incorrectly.
	if strings.Contains(clean, ".."+string(filepath.Separator)) || strings.HasSuffix(clean, string(filepath.Separator)+"..") {
		return "", apperr.New(apperr.CodeInvalidArgument, "data directory path must not traverse")
	}
	return clean, nil
}
