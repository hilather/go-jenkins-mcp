package update

import (
	"fmt"
	"os"
	"strings"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// EnvUpdateAllowDowngrade opts in to accepting manifests / downloads whose
// version is lower than the running binary. Must be exactly "1".
//
// Default (unset or any other value): fail-closed — only equal or newer versions
// are accepted for download. update-check may still report that the current
// binary is ahead of the manifest (compare_result=older) without downloading.
const EnvUpdateAllowDowngrade = "JENKINS_MCP_UPDATE_ALLOW_DOWNGRADE"

// AllowDowngradeFromEnviron reports whether JENKINS_MCP_UPDATE_ALLOW_DOWNGRADE=1.
func AllowDowngradeFromEnviron() bool {
	return strings.TrimSpace(os.Getenv(EnvUpdateAllowDowngrade)) == "1"
}

// PreflightOptions controls accept-time checks before a download is started.
// Channel pin and structure/signature checks remain the responsibility of
// VerifyManifest; this layer covers version-downgrade, platform artifact
// presence, free-space, and outdir writability.
type PreflightOptions struct {
	// Manifest must already be signature-verified for download accept.
	Manifest *Manifest
	// CurrentVersion is the running binary version (for downgrade policy).
	CurrentVersion string
	// ChannelPin when non-empty must match manifest.Channel (case-insensitive).
	// Prefer verifying channel in VerifyManifest; this is a second line for download.
	ChannelPin string
	// AllowDowngrade when true permits remote version < current.
	// Default false = fail-closed (equal/newer only).
	AllowDowngrade bool
	// GOOS/GOARCH select the artifact (required for free-space size hint).
	GOOS   string
	GOARCH string
	// OutDir is the destination directory; empty skips outdir/free-space checks.
	OutDir string
	// MaxBytes optional download cap; 0 ⇒ DefaultMaxArtifactBytes for size check.
	MaxBytes int64
	// SkipFreeSpace when true skips the free-bytes check (tests only).
	SkipFreeSpace bool
}

// PreflightAccept rejects manifests that fail download accept policy.
// Call after VerifyManifest and before DownloadArtifact.
//
// Rules (fail closed unless noted):
//   - Manifest non-nil and structurally valid for download (v2 + artifacts preferred;
//     v1 without artifacts is rejected for download).
//   - Channel pin match when ChannelPin is set.
//   - Version compare: reject remote < current unless AllowDowngrade.
//     Unknown version compare is rejected for download (fail closed).
//   - Platform artifact present when GOOS/GOARCH set.
//   - Declared size within MaxBytes when both known.
//   - OutDir writable + free space when OutDir non-empty (reuses preflightOutDir).
func PreflightAccept(opts PreflightOptions) error {
	m := opts.Manifest
	if m == nil {
		return apperr.New(apperr.CodeInvalidArgument, "update preflight: manifest is nil")
	}
	if err := m.ValidateStructure(); err != nil {
		return err
	}

	if pin := strings.TrimSpace(opts.ChannelPin); pin != "" {
		if m.Channel != "" && !strings.EqualFold(m.Channel, pin) {
			return apperr.New(apperr.CodeNotFound,
				fmt.Sprintf("update preflight: manifest channel %q does not match pin %q", m.Channel, pin))
		}
	}

	if err := CheckDowngradePolicy(opts.CurrentVersion, m.Version, opts.AllowDowngrade); err != nil {
		return err
	}

	goos := strings.TrimSpace(opts.GOOS)
	goarch := strings.TrimSpace(opts.GOARCH)
	var sizeHint int64
	if goos != "" && goarch != "" {
		art, ok := m.ArtifactFor(goos, goarch)
		if !ok {
			return apperr.New(apperr.CodeNotFound,
				fmt.Sprintf("update preflight: no artifact for platform %s", PlatformKey(goos, goarch)))
		}
		sizeHint = art.Size
		maxBytes := opts.MaxBytes
		if maxBytes <= 0 {
			maxBytes = DefaultMaxArtifactBytes
		}
		if sizeHint > 0 && sizeHint > maxBytes {
			return apperr.New(apperr.CodeQuota,
				fmt.Sprintf("update preflight: artifact declared size %d exceeds max download bytes %d",
					sizeHint, maxBytes))
		}
		// Artifact must have http(s) URL and sha256 (ValidateStructure already for v2).
		url := strings.TrimSpace(art.URL)
		if !strings.HasPrefix(url, "https://") && !strings.HasPrefix(url, "http://") {
			return apperr.New(apperr.CodeInvalidArgument,
				"update preflight: artifact URL must be http(s)")
		}
		// Refuse credential-looking userinfo in artifact URL (never store; reject accept).
		if strings.Contains(url, "@") {
			// http://user:pass@host/… — fail closed for download accept.
			if i := strings.Index(url, "://"); i >= 0 {
				rest := url[i+3:]
				if j := strings.Index(rest, "/"); j >= 0 {
					rest = rest[:j]
				}
				if strings.Contains(rest, "@") {
					return apperr.New(apperr.CodePolicyDenial,
						"update preflight: artifact URL must not contain credentials (userinfo)")
				}
			}
		}
	}

	outDir := strings.TrimSpace(opts.OutDir)
	if outDir != "" {
		if opts.SkipFreeSpace {
			// Still check writability without free-space.
			if err := preflightOutDirWritable(outDir); err != nil {
				return err
			}
		} else {
			if err := preflightOutDir(outDir, sizeHint); err != nil {
				return err
			}
		}
	}
	return nil
}

// CheckDowngradePolicy enforces equal/newer-only by default.
//
//	current vs remote via CompareVersions(current, remote):
//	  "newer"  → remote > current → OK
//	  "same"   → OK
//	  "older"  → remote < current → reject unless allowDowngrade
//	  "unknown"→ reject for download accept (fail closed)
func CheckDowngradePolicy(current, remote string, allowDowngrade bool) error {
	cur := strings.TrimSpace(current)
	rem := strings.TrimSpace(remote)
	if rem == "" {
		return apperr.New(apperr.CodeInvalidArgument, "update preflight: remote version is empty")
	}
	// Unknown current (dev builds): allow equal/newer remote but still reject when
	// both parseable and remote is older. Empty current ⇒ skip compare (bootstrap).
	if cur == "" || cur == "dev" || cur == "unknown" {
		return nil
	}
	switch CompareVersions(cur, rem) {
	case "newer", "same":
		return nil
	case "older":
		if allowDowngrade {
			return nil
		}
		return apperr.New(apperr.CodePolicyDenial,
			fmt.Sprintf("update downgrade rejected: manifest %s < current %s (set %s=1 to allow)",
				rem, cur, EnvUpdateAllowDowngrade))
	default:
		return apperr.New(apperr.CodePolicyDenial,
			fmt.Sprintf("update preflight: cannot compare current %q to manifest %q (fail closed)",
				cur, rem))
	}
}

// preflightOutDirWritable is free-space-free writability probe (tests / residual).
func preflightOutDirWritable(outDir string) error {
	return preflightOutDir(outDir, 0)
}
