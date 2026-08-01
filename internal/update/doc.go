// Package update implements signed release-manifest verification and optional
// artifact download for UPD-001 (managed update lifecycle).
//
// Design (see docs/release/update.md and docs/packaging.md):
//
//   - Prefer enterprise package managers (RPM/DEB/repos) for install/rollback.
//   - Manifest schema v2 is Ed25519-signed over a canonical JSON body that
//     excludes the signatures field (same envelope idea as policy bundles,
//     without importing package policy to avoid coupling).
//   - Trusted public keys live under XDG …/jenkins-mcp/update/trusted_keys/ or
//     JENKINS_MCP_UPDATE_TRUSTED_KEYS (file or directory).
//   - When trusted keys are configured, unsigned or tampered manifests fail closed.
//   - When no keys are configured, unsigned manifests are accepted only with
//     JENKINS_MCP_UPDATE_ALLOW_UNSIGNED=1 (signature_state=unverified_pilot).
//   - Download verifies artifact SHA-256 from a verified signed manifest and
//     never executes or installs the binary.
//   - Download preflight (fail closed): channel pin, equal/newer version only
//     (opt-in downgrade via JENKINS_MCP_UPDATE_ALLOW_DOWNGRADE=1), free space,
//     writable outdir. No credential-bearing artifact URLs.
//   - Last-known-good (LKG) secret-free JSON is written under XDG data after a
//     successful verified download (version, channel, sha256, basename, key ids).
//   - VerifyLKG re-hashes the staged artifact (basename under UpdateDataDir or
//     an explicit path) against LKG.ArtifactSHA256 and fails closed on missing
//     file, empty sha, or mismatch.
//
// Residuals: automatic install, binary rollback/swap, and storage migration
// preflight beyond download path checks remain out of scope for this MVP slice.
// Install and rollback stay operator / package-manager owned.
package update
