# Signed update lifecycle (UPD-001)

| Field | Value |
|-------|--------|
| **Task** | UPD-001 (MVP beyond lite + Wave 20 polish) |
| **Package** | `internal/update` |
| **CLI** | `update-check`, `update verify-manifest`, `update download`, `update show-lkg`, `update verify-lkg` |
| **Prefer** | Enterprise package managers (RPM/DEB/repos) for install and rollback |

## Goals

- Fail closed on **unsigned or tampered** update metadata when trusted keys are configured.
- Optional **explicit** artifact download with **SHA-256** verification only.
- **Never** auto-download, auto-install, or replace the running binary.
- Keep pilot residual path for unsigned metadata behind an explicit env gate.
- **Last-known-good (LKG)** secret-free record after successful verified download.
- **Download preflight**: channel pin, equal/newer version only (downgrade opt-in), free space.

## Residual (install / rollback still operator-owned)

| Residual | Notes |
|----------|--------|
| Automatic install / binary swap | Operator or package manager only — CLI never executes the artifact |
| Rollback of previous binary | Prefer package manager history / OS snapshots; LKG is metadata only, not a restore path |
| Storage/config migrations gated on update | Migrations run on process start of installed version, not via this CLI |
| Multi-sig / HSM-backed release keys | Org-owned; CLI verifies Ed25519 public keys only |
| Emergency adapter disable | Documented under policy/adapter allowlists (separate from update) |

---

## Manifest schema

### Schema v2 (signed — preferred)

Canonical signing body is JSON of all fields **except** `signatures` (Go struct field order via `encoding/json`).

```json
{
  "schema_version": 2,
  "channel": "stable",
  "version": "1.2.3",
  "commit": "abc1234",
  "changelog_url": "https://releases.example.corp/jenkins-mcp/changelog/1.2.3",
  "issued_at": "2026-08-01T00:00:00Z",
  "not_after": "2027-08-01T00:00:00Z",
  "min_schema": 2,
  "min_app_version": "1.0.0",
  "artifacts": {
    "linux/amd64": {
      "url": "https://releases.example.corp/jenkins-mcp_1.2.3_linux_amd64.tar.gz",
      "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      "size": 12345678,
      "filename": "jenkins-mcp_1.2.3_linux_amd64.tar.gz"
    }
  },
  "notes": "optional non-secret publisher note",
  "signatures": [
    {
      "alg": "ed25519",
      "key_id": "corp-update-2026",
      "signature": "<base64 raw 64-byte Ed25519 signature>"
    }
  ]
}
```

| Field | Rules |
|-------|--------|
| `schema_version` | `2` for signed artifacts |
| `channel` | `stable` or `beta` (CLI pin must match) |
| `version` | Semver-ish dotted numeric; used for compare |
| `not_after` | RFC3339; inclusive expiry (valid while `now <= not_after`) |
| `min_schema` | Client rejects if greater than supported schema |
| `min_app_version` | Client rejects if running version is lower |
| `artifacts` | Map key `GOOS/GOARCH` (e.g. `linux/amd64`); each needs `url` + 64-hex `sha256` |
| `signatures` | At least one trusted `key_id` must verify when keys are configured |

### Schema v1 (lite — unsigned pilot only)

```json
{
  "schema_version": 1,
  "channel": "stable",
  "latest": {
    "version": "1.2.3",
    "commit": "abc1234",
    "changelog_url": "https://…",
    "published_at": "2026-08-01T00:00:00Z"
  }
}
```

Accepted only when **no** trusted update keys are configured **and**
`JENKINS_MCP_UPDATE_ALLOW_UNSIGNED=1` → `signature_state=unverified_pilot`.

---

## Trusted keys

| Item | Value |
|------|--------|
| Default dir | `$XDG_CONFIG_HOME/jenkins-mcp/update/trusted_keys/` |
| Env override | `JENKINS_MCP_UPDATE_TRUSTED_KEYS` (file or directory) |
| Formats | Same as policy keys: PEM `PUBLIC KEY`, base64 32-byte raw, or JSON trust store |
| Layout | Directory: `<key_id>.pub` / `<key_id>.pem` per key |

**Private keys never** ship in the product tree or trusted-key stores.

---

## Verification policy (fail closed)

| Situation | Result |
|-----------|--------|
| Trusted keys present + valid signature | `signature_state=verified` |
| Trusted keys present + unsigned / wrong / tampered | Reject |
| Trusted keys present + expired `not_after` | Reject |
| No keys + signed manifest | Reject (cannot verify; configure keys) |
| No keys + unsigned + `JENKINS_MCP_UPDATE_ALLOW_UNSIGNED=1` | `unverified_pilot` |
| No keys + unsigned + allow flag unset | Reject |
| Channel pin mismatch (`--channel`) | Reject |
| `min_schema` / `min_app_version` too high | Reject |

Signature material and private keys never appear in errors, logs, or MCP output.

---

## Download preflight (accept policy)

Applied after signature verify and **before** network artifact I/O (`PreflightAccept` / `DownloadArtifact`).

| Check | Default | Opt-in |
|-------|---------|--------|
| Channel pin (`--channel`) | Must match manifest channel | — |
| Version vs current binary | **Equal or newer only** (fail closed on downgrade) | `JENKINS_MCP_UPDATE_ALLOW_DOWNGRADE=1` |
| Unknown version compare | Reject for download | — |
| Artifact URL | `http(s)` only; **no userinfo credentials** | — |
| Outdir | Creatable + writable (probe file) | — |
| Free space | Declared `size` vs available bytes (Unix best-effort) | — |
| Max size | Default 512 MiB | — |
| Overwrite | Refuse existing destination filename | — |
| SHA-256 | Mismatch → delete partial; fail closed | — |

`update-check` may still report `compare_result=older` (current ahead of manifest) without downloading. Downgrade policy blocks **download accept** only unless the env opt-in is set.

---

## Last-known-good (LKG)

After a **successful** verified download, the CLI writes a secret-free JSON record:

| Item | Value |
|------|--------|
| Default path | `$XDG_DATA_HOME/jenkins-mcp/update/last_known_good.json` |
| Env override | `JENKINS_MCP_UPDATE_LKG_PATH` |
| Fields | `version`, `channel`, `artifact_sha256`, `path_basename`, `timestamp`, `signature_key_ids`, `platform` |
| Never stored | URLs (credential-bearing or otherwise), full paths, private keys, signature blobs |

LKG is **download metadata only** — it does **not** install, swap, or restore a binary. Use `update-check --json` (fields `lkg_*`, `compare_lkg`) or `update show-lkg` to inspect.

### On-disk re-verify

`update verify-lkg` proves the **local staged artifact still matches** `artifact_sha256` recorded in LKG (integrity residual after download).

| Item | Behavior |
|------|----------|
| CLI | `jenkins-mcp update verify-lkg [--json] [--file PATH]` |
| Default path | `$XDG_DATA_HOME/jenkins-mcp/update/<path_basename>` (LKG basename under update data dir) |
| `--file` | Explicit staged artifact when download used a custom `--outdir` |
| Fail closed | Missing LKG, missing file, empty/invalid sha, or hash mismatch → non-zero exit |
| Output | Secret-free: `ok`, `sha_match`, `version`, `path_basename`, expected/actual sha256 (no tokens/URLs/full home paths) |
| Doctor | Check `update_lkg`: **skip** if no LKG; **warn** if LKG present but artifact missing/mismatch when resolvable; **ok** on match |
| Security self-check | Offline item `update_lkg_residual` (UPD-001): proves LKG residual honesty (`ResidualLKGIntegrity` — metadata only, not auto-install; install/rollback operator-owned) without network or real artifacts |

---

## CLI

```bash
# Metadata check (no download). Requires network only when manifest URL is set.
export JENKINS_MCP_UPDATE_MANIFEST_URL=https://releases.example.corp/jenkins-mcp/stable.json
# Production: install public keys under update/trusted_keys/
jenkins-mcp update-check --channel stable --json
# JSON includes current_version, latest_version, lkg_* triad when LKG exists

# Offline verify a local manifest file
jenkins-mcp update verify-manifest --file /tmp/stable.json --keys /etc/jenkins-mcp/update/trusted_keys --json

# Optional explicit download AFTER signed verify (never installs; records LKG)
jenkins-mcp update download --channel stable --outdir /var/tmp/jenkins-mcp-updates --json

# Inspect last-known-good (offline)
jenkins-mcp update show-lkg --json

# Re-verify staged artifact still matches LKG sha256 (fail closed)
jenkins-mcp update verify-lkg --json
# When download used a custom outdir:
jenkins-mcp update verify-lkg --json --file /var/tmp/jenkins-mcp-updates/jenkins-mcp_….tar.gz
```

| Command | Behavior |
|---------|----------|
| `update-check` | Fetch + verify manifest; report current vs latest vs LKG; `auto_download=false` |
| `update verify-manifest` | Local file crypto/structure checks |
| `update download` | Requires trusted keys + verified signature; preflight; streams artifact; verifies SHA-256; writes LKG; prints path + next steps |
| `update show-lkg` | Offline read of LKG record (or absent) |
| `update verify-lkg` | Re-hash staged artifact vs LKG sha256; fail closed on missing/mismatch |

---

## Operator workflow (recommended)

1. Prefer **signed RPM/DEB** from org repos (`dnf` / `apt`).
2. Optionally run `update-check` for awareness / changelog URL / LKG triad.
3. If using portable tarball: `update download` → `update verify-lkg` (or `--file` if custom outdir) → inspect staged file + LKG → install via org process → `doctor` / `pilot-check`.
4. Rollback via package manager or previous artifact — not an in-process swap; LKG does not restore binaries.

---

## Publisher notes (org CI)

1. Build artifacts with `make package`; record SHA-256 in the v2 manifest.
2. Sign canonical body with Ed25519 offline/HSM; attach `signatures[]`.
3. Publish manifest over HTTPS; distribute public key PEM to hosts.
4. Pin channel (`stable` vs `beta`) in fleet config.

---

## Tests (evidence)

```bash
export PATH="$HOME/.local/go/bin:$PATH"
go test ./internal/update/ ./cmd/jenkins-mcp/ -count=1
```

Coverage includes: valid sign/verify, tamper, expired, unsigned with/without keys, checksum mismatch, download without auto-install, unwritable outdir, LKG store/load (secret-free), LKG on-disk re-verify (match/mismatch/missing/explicit `--file`), downgrade reject/opt-in, channel pin preflight, free-space reject, credential URL reject.
