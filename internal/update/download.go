package update

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// Default max artifact size for download (512 MiB). Prevents unbounded disk fill.
const DefaultMaxArtifactBytes int64 = 512 << 20

// DownloadOptions controls optional explicit artifact download (never auto-install).
type DownloadOptions struct {
	// Manifest must already be signature-verified (SignatureState=verified).
	Manifest *Manifest
	// RequireVerified when true (default for CLI) refuses unverified_pilot manifests.
	RequireVerified bool
	// SignatureState from VerifyManifest; must be verified when RequireVerified.
	SignatureState string
	// GOOS/GOARCH select the artifact key (default: runtime via caller).
	GOOS   string
	GOARCH string
	// OutDir is the destination directory (must be writable). Empty ⇒ os.TempDir().
	OutDir string
	// HTTPClient optional; nil uses a 2-minute timeout client.
	HTTPClient *http.Client
	// MaxBytes caps download size; 0 ⇒ DefaultMaxArtifactBytes.
	MaxBytes int64
	// UserAgent set on the request when non-empty.
	UserAgent string
	// CurrentVersion is the running binary version for downgrade preflight.
	// Empty skips version compare (bootstrap / tests that set SkipPreflight).
	CurrentVersion string
	// ChannelPin when non-empty must match manifest.Channel (preflight).
	ChannelPin string
	// AllowDowngrade opts in to accepting remote version < current (default false).
	AllowDowngrade bool
	// SkipPreflight disables PreflightAccept (tests only). Prefer full preflight.
	SkipPreflight bool
}

// DownloadResult is secret-free download outcome. AutoInstall is always false.
type DownloadResult struct {
	Path           string `json:"path"`
	SHA256         string `json:"sha256"`
	BytesWritten   int64  `json:"bytes_written"`
	Platform       string `json:"platform"`
	Version        string `json:"version"`
	Channel        string `json:"channel"`
	AutoInstall    bool   `json:"auto_install"` // always false
	NextSteps      string `json:"next_steps"`
	SignatureState string `json:"signature_state"`
}

// DownloadArtifact streams the platform artifact to OutDir after checksum verify.
// It never executes, chmods for install, or replaces the running binary.
// Preflight (channel pin, downgrade policy, free space) runs before network I/O
// unless SkipPreflight is set.
func DownloadArtifact(opts DownloadOptions) (*DownloadResult, error) {
	m := opts.Manifest
	if m == nil {
		return nil, apperr.New(apperr.CodeInvalidArgument, "update manifest is nil")
	}
	sigState := strings.TrimSpace(opts.SignatureState)
	if opts.RequireVerified && sigState != SigStateVerified {
		return nil, apperr.New(apperr.CodePolicyDenial,
			"update download requires a verified signed manifest (signature_state=verified)")
	}
	if sigState == "" {
		sigState = SigStateAbsent
	}

	goos := strings.TrimSpace(opts.GOOS)
	goarch := strings.TrimSpace(opts.GOARCH)
	if goos == "" || goarch == "" {
		return nil, apperr.New(apperr.CodeInvalidArgument, "GOOS and GOARCH are required for download")
	}
	plat := PlatformKey(goos, goarch)
	art, ok := m.ArtifactFor(goos, goarch)
	if !ok {
		return nil, apperr.New(apperr.CodeNotFound,
			fmt.Sprintf("no update artifact for platform %s", plat))
	}
	art.URL = strings.TrimSpace(art.URL)
	art.SHA256 = strings.ToLower(strings.TrimSpace(art.SHA256))
	art.Filename = strings.TrimSpace(art.Filename)
	if !strings.HasPrefix(art.URL, "https://") && !strings.HasPrefix(art.URL, "http://") {
		return nil, apperr.New(apperr.CodeInvalidArgument,
			"artifact URL must be http(s)")
	}

	outDir := strings.TrimSpace(opts.OutDir)
	if outDir == "" {
		outDir = os.TempDir()
	}
	if !opts.SkipPreflight {
		if err := PreflightAccept(PreflightOptions{
			Manifest:       m,
			CurrentVersion: opts.CurrentVersion,
			ChannelPin:     opts.ChannelPin,
			AllowDowngrade: opts.AllowDowngrade,
			GOOS:           goos,
			GOARCH:         goarch,
			OutDir:         outDir,
			MaxBytes:       opts.MaxBytes,
		}); err != nil {
			return nil, err
		}
	} else if err := preflightOutDir(outDir, art.Size); err != nil {
		// Still enforce free-space / writability when preflight is skipped for version tests.
		return nil, err
	}

	name := art.Filename
	if name == "" {
		name = filepath.Base(art.URL)
		if name == "" || name == "." || name == "/" {
			name = fmt.Sprintf("jenkins-mcp_%s_%s_%s.bin", m.Version, goos, goarch)
		}
	}
	// Prevent path traversal in filename from manifest.
	name = filepath.Base(name)
	if name == "." || name == string(filepath.Separator) {
		return nil, apperr.New(apperr.CodeInvalidArgument, "artifact filename is invalid")
	}
	dest := filepath.Join(outDir, name)
	// Refuse overwrite of existing files (operator must clean or pick another outdir).
	if _, err := os.Stat(dest); err == nil {
		return nil, apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("destination already exists: %s (refuse overwrite)", filepath.Base(dest)))
	} else if err != nil && !os.IsNotExist(err) {
		return nil, apperr.Wrap(apperr.CodeInternal, "destination stat failed", err)
	}

	maxBytes := opts.MaxBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxArtifactBytes
	}
	if art.Size > 0 && art.Size > maxBytes {
		return nil, apperr.New(apperr.CodeQuota,
			fmt.Sprintf("artifact declared size %d exceeds max download bytes %d", art.Size, maxBytes))
	}

	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Minute}
	}
	req, err := http.NewRequest(http.MethodGet, art.URL, nil)
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeInvalidArgument, "invalid artifact URL", err)
	}
	if opts.UserAgent != "" {
		req.Header.Set("User-Agent", opts.UserAgent)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeUpstreamProtocol, "artifact download failed", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, apperr.New(apperr.CodeUpstreamProtocol,
			fmt.Sprintf("artifact download HTTP %d", resp.StatusCode))
	}

	// Write to temp then rename after checksum OK.
	tmp, err := os.CreateTemp(outDir, ".jenkins-mcp-update-*.part")
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeInternal, "create temp download file failed", err)
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		_ = tmp.Close()
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	h := sha256.New()
	limited := io.LimitReader(resp.Body, maxBytes+1)
	n, err := io.Copy(io.MultiWriter(tmp, h), limited)
	if err != nil {
		return nil, wrapDiskOrIO(err, "artifact write failed")
	}
	if n > maxBytes {
		return nil, apperr.New(apperr.CodeQuota,
			fmt.Sprintf("artifact exceeded max download bytes %d", maxBytes))
	}
	if art.Size > 0 && n != art.Size {
		return nil, apperr.New(apperr.CodeUpstreamProtocol,
			fmt.Sprintf("artifact size mismatch: got %d want %d", n, art.Size))
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(sum, art.SHA256) {
		return nil, apperr.New(apperr.CodePolicyDenial,
			"artifact sha256 mismatch (fail closed; refuse install)")
	}
	if err := tmp.Close(); err != nil {
		return nil, wrapDiskOrIO(err, "artifact close failed")
	}
	if err := os.Rename(tmpPath, dest); err != nil {
		// Cross-device fallback: copy.
		if err2 := copyFile(tmpPath, dest); err2 != nil {
			return nil, wrapDiskOrIO(err2, "artifact finalize failed")
		}
		_ = os.Remove(tmpPath)
	}
	cleanup = false

	return &DownloadResult{
		Path:           dest,
		SHA256:         sum,
		BytesWritten:   n,
		Platform:       plat,
		Version:        m.Version,
		Channel:        m.Channel,
		AutoInstall:    false,
		SignatureState: sigState,
		NextSteps: "Artifact downloaded and checksum-verified only — not installed. " +
			"Prefer enterprise package manager (dnf/apt) or: inspect the archive, " +
			"install via org process, then re-run jenkins-mcp doctor / pilot-check. " +
			"Rollback/install remains residual (operator-owned).",
	}, nil
}

// preflightOutDir ensures outDir exists and is writable; optional size hint.
func preflightOutDir(outDir string, sizeHint int64) error {
	st, err := os.Stat(outDir)
	if err != nil {
		if os.IsNotExist(err) {
			if mkErr := os.MkdirAll(outDir, 0o755); mkErr != nil {
				return wrapDiskOrIO(mkErr, "update outdir not creatable")
			}
			st, err = os.Stat(outDir)
			if err != nil {
				return wrapDiskOrIO(err, "update outdir unreadable after create")
			}
		} else {
			return wrapDiskOrIO(err, "update outdir unreadable")
		}
	}
	if !st.IsDir() {
		return apperr.New(apperr.CodeInvalidArgument, "update outdir is not a directory")
	}
	// Probe writability with a temp file.
	f, err := os.CreateTemp(outDir, ".jenkins-mcp-write-probe-*")
	if err != nil {
		return wrapDiskOrIO(err, "update outdir is not writable")
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)

	// Optional free-space check when size is known (best-effort; ENOSPC still handled on write).
	if sizeHint > 0 {
		if free, ok := freeBytes(outDir); ok && free < sizeHint {
			return apperr.New(apperr.CodeQuota,
				fmt.Sprintf("insufficient disk space in outdir (need ~%d bytes)", sizeHint))
		}
	}
	return nil
}

func wrapDiskOrIO(err error, msg string) error {
	if err == nil {
		return nil
	}
	// Map common disk failures to quota / internal without leaking paths with secrets.
	s := strings.ToLower(err.Error())
	if strings.Contains(s, "no space") || strings.Contains(s, "enospc") {
		return apperr.Wrap(apperr.CodeQuota, msg+": disk full", err)
	}
	if strings.Contains(s, "permission denied") || strings.Contains(s, "read-only") {
		return apperr.Wrap(apperr.CodePolicyDenial, msg+": not writable", err)
	}
	return apperr.Wrap(apperr.CodeInternal, msg, err)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		_ = os.Remove(dst)
		return err
	}
	return out.Close()
}
