package update

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/config"
)

// VerifyLKGOptions controls on-disk re-verify of the last-known-good artifact.
// LKG stores only a basename (no full path); ArtifactPath or SearchDirs resolve the file.
type VerifyLKGOptions struct {
	// LKGPath is the last_known_good.json path. Empty ⇒ DefaultLKGPath(Paths).
	LKGPath string
	// ArtifactPath when set is the exact local file to hash (operator --file).
	// Takes precedence over SearchDirs.
	ArtifactPath string
	// SearchDirs are directories tried as filepath.Join(dir, LKG.PathBasename)
	// when ArtifactPath is empty. Empty ⇒ UpdateDataDir only.
	SearchDirs []string
	// Paths optional for default LKG / download dir resolution.
	Paths *config.Paths
}

// VerifyLKGResult is a secret-free integrity report for the LKG artifact on disk.
// Never includes full home paths, URLs, tokens, or private keys.
type VerifyLKGResult struct {
	// Schema identifies the CLI/report shape (stable for operators/scripts).
	Schema string `json:"schema,omitempty"`
	// OK is true only when LKG is present, the artifact is found, and sha256 matches.
	OK bool `json:"ok"`
	// LKGPresent is false when no last_known_good record exists.
	LKGPresent bool `json:"lkg_present"`
	// Version / Channel from the LKG record when present.
	Version string `json:"version,omitempty"`
	Channel string `json:"channel,omitempty"`
	// PathBasename is the LKG-recorded basename only (never a directory).
	PathBasename string `json:"path_basename,omitempty"`
	// ExpectedSHA256 is the LKG artifact_sha256 (lowercase hex).
	ExpectedSHA256 string `json:"expected_sha256,omitempty"`
	// ActualSHA256 is the computed content hash when the file was readable.
	ActualSHA256 string `json:"actual_sha256,omitempty"`
	// SHAMatch is true when actual equals expected (case-insensitive).
	SHAMatch bool `json:"sha_match"`
	// ArtifactFound is true when a local file was located and opened.
	ArtifactFound bool `json:"artifact_found"`
	// Reason is a secret-free failure or skip explanation.
	Reason string `json:"reason,omitempty"`
	// Residual notes that LKG is metadata only (not installed binary).
	Residual string `json:"residual,omitempty"`
}

// ResidualLKGIntegrity is the fixed residual honesty note for verify-lkg, doctor,
// and offline security self-check (UPD-001). LKG is last verified download
// metadata only — not an installed binary; install/rollback is operator-owned.
// Never auto-installs or swaps the running binary.
const ResidualLKGIntegrity = "LKG is last verified download metadata only — not an installed binary. " +
	"On-disk re-verify proves the staged artifact still matches LKG sha256; install/rollback is operator-owned."

// LKGResidualNote returns ResidualLKGIntegrity (stable accessor for diagnostics).
func LKGResidualNote() string { return ResidualLKGIntegrity }

// FileSHA256 returns the lowercase hex SHA-256 of the file at path.
// Streams the file (no unbounded ReadAll). Fail closed on open/read errors.
func FileSHA256(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", apperr.New(apperr.CodeInvalidArgument, "file path is empty")
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", apperr.New(apperr.CodeNotFound,
				fmt.Sprintf("file not found: %s", sanitizePath(path)))
		}
		return "", apperr.Wrap(apperr.CodeInternal,
			fmt.Sprintf("open file failed: %s", sanitizePath(path)), err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return "", apperr.Wrap(apperr.CodeInternal,
			fmt.Sprintf("stat file failed: %s", sanitizePath(path)), err)
	}
	if st.IsDir() {
		return "", apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("path is a directory: %s", sanitizePath(path)))
	}
	// Bound read the same way as download (fail closed on absurd size).
	if st.Size() > DefaultMaxArtifactBytes {
		return "", apperr.New(apperr.CodeQuota,
			fmt.Sprintf("file exceeds max artifact bytes %d", DefaultMaxArtifactBytes))
	}
	h := sha256.New()
	limited := io.LimitReader(f, DefaultMaxArtifactBytes+1)
	n, err := io.Copy(h, limited)
	if err != nil {
		return "", apperr.Wrap(apperr.CodeInternal,
			fmt.Sprintf("read file failed: %s", sanitizePath(path)), err)
	}
	if n > DefaultMaxArtifactBytes {
		return "", apperr.New(apperr.CodeQuota,
			fmt.Sprintf("file exceeds max artifact bytes %d", DefaultMaxArtifactBytes))
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// VerifyLKG loads the LKG record and re-hashes the local artifact against
// ArtifactSHA256. Fail-closed integrity outcomes set OK=false with Reason;
// corrupt LKG returns an error. Missing LKG returns a result with LKGPresent=false
// (callers choose fail vs skip).
func VerifyLKG(opts VerifyLKGOptions) (*VerifyLKGResult, error) {
	res := &VerifyLKGResult{
		Schema:   "jenkins-mcp.update.verify-lkg.v1",
		Residual: ResidualLKGIntegrity,
	}

	lkgPath := strings.TrimSpace(opts.LKGPath)
	if lkgPath == "" {
		p, err := DefaultLKGPath(opts.Paths)
		if err != nil {
			return nil, err
		}
		lkgPath = p
	}

	rec, err := LoadLKG(lkgPath)
	if err != nil {
		return nil, err
	}
	if rec == nil {
		res.OK = false
		res.LKGPresent = false
		res.Reason = "no last-known-good record (run update download after signed verify)"
		return res, nil
	}

	res.LKGPresent = true
	res.Version = rec.Version
	res.Channel = rec.Channel
	res.PathBasename = rec.PathBasename
	res.ExpectedSHA256 = strings.ToLower(strings.TrimSpace(rec.ArtifactSHA256))

	// Empty / invalid sha should never pass Validate, but fail closed defensively.
	if res.ExpectedSHA256 == "" {
		res.OK = false
		res.Reason = "LKG artifact_sha256 is empty (fail closed)"
		return res, nil
	}
	if len(res.ExpectedSHA256) != 64 || !isHex(res.ExpectedSHA256) {
		res.OK = false
		res.Reason = "LKG artifact_sha256 is invalid (fail closed)"
		return res, nil
	}

	artPath, locateReason, err := resolveLKGArtifact(rec, opts)
	if err != nil {
		return nil, err
	}
	if artPath == "" {
		res.OK = false
		res.ArtifactFound = false
		res.SHAMatch = false
		res.Reason = locateReason
		return res, nil
	}

	actual, err := FileSHA256(artPath)
	if err != nil {
		// Missing / unreadable after resolve: fail closed as not found.
		res.OK = false
		res.ArtifactFound = false
		res.SHAMatch = false
		res.Reason = apperr.ModelMessage(err)
		return res, nil
	}
	res.ArtifactFound = true
	res.ActualSHA256 = actual
	res.SHAMatch = strings.EqualFold(actual, res.ExpectedSHA256)
	if !res.SHAMatch {
		res.OK = false
		res.Reason = "artifact sha256 mismatch (fail closed; refuse trust of on-disk file)"
		return res, nil
	}
	res.OK = true
	res.Reason = "artifact sha256 matches LKG"
	return res, nil
}

// resolveLKGArtifact returns the local path to hash, or ("", reason, nil) when
// the file cannot be located. Errors are for invalid operator input only.
func resolveLKGArtifact(rec *LKGRecord, opts VerifyLKGOptions) (path string, reason string, err error) {
	if explicit := strings.TrimSpace(opts.ArtifactPath); explicit != "" {
		// Operator-provided path: must be a regular file (not a directory).
		st, statErr := os.Stat(explicit)
		if statErr != nil {
			if os.IsNotExist(statErr) {
				return "", fmt.Sprintf("artifact file not found: %s", sanitizePath(explicit)), nil
			}
			return "", "", apperr.Wrap(apperr.CodeInternal,
				fmt.Sprintf("artifact path unreadable: %s", sanitizePath(explicit)), statErr)
		}
		if st.IsDir() {
			return "", fmt.Sprintf("artifact path is a directory: %s", sanitizePath(explicit)), nil
		}
		return explicit, "", nil
	}

	base := strings.TrimSpace(rec.PathBasename)
	if base == "" {
		return "", "LKG path_basename is empty; pass --file PATH to the staged artifact", nil
	}
	// Defense: never join if basename is path-like (Validate should have refused).
	if base != filepath.Base(base) || strings.Contains(base, "://") {
		return "", "LKG path_basename is invalid (fail closed)", nil
	}

	dirs := opts.SearchDirs
	if len(dirs) == 0 {
		var resolved config.Paths
		if opts.Paths != nil {
			resolved = *opts.Paths
		} else {
			r, rerr := config.Resolve()
			if rerr != nil {
				return "", "", apperr.Wrap(apperr.CodeInternal, "resolve config paths for LKG artifact search", rerr)
			}
			resolved = r
		}
		dirs = []string{resolved.UpdateDataDir()}
	}

	tried := 0
	for _, dir := range dirs {
		dir = strings.TrimSpace(dir)
		if dir == "" {
			continue
		}
		tried++
		candidate := filepath.Join(dir, base)
		st, statErr := os.Stat(candidate)
		if statErr != nil {
			continue
		}
		if st.IsDir() {
			continue
		}
		return candidate, "", nil
	}
	if tried == 0 {
		return "", "no download search directories available; pass --file PATH", nil
	}
	return "", fmt.Sprintf(
		"LKG artifact %s not found under download dir(s); pass --file PATH if staged elsewhere",
		base), nil
}
