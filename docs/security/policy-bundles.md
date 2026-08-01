# Signed enterprise policy bundles (MGR-001)

**Task:** MGR-001  
**Related:** CFG-002, POL-002, ADR 0012, [`../policy-rbac.md`](../policy-rbac.md), package `internal/policy`

## Purpose

Security can centrally **constrain** (never elevate) MCP behavior: force read-only,
deny tools, lower result budgets. Signed bundles prove integrity and freshness
using **Ed25519** public keys distributed out-of-band. Bundles are **secret-free**
— no credentials, tokens, or private keys.

## Bundle format (`overlay.bundle.json`)

Versioned **envelope** (not a signature field on the plain overlay).

### Single-sig (MVP, default)

```json
{
  "schema_version": 1,
  "alg": "ed25519",
  "key_id": "corp-policy-2026",
  "issued_at": "2026-08-01T00:00:00Z",
  "not_after": "2027-08-01T00:00:00Z",
  "min_version": 1,
  "bundle_seq": 42,
  "overlay": {
    "version": 1,
    "force_read_only": true,
    "mode": "pilot",
    "deny_tools": ["jenkins_get_build_logs"],
    "max_result_bytes": 65536
  },
  "signature": "<base64 raw Ed25519 signature>"
}
```

### Multi-sig lite (optional dual-control)

Optional `signatures[]` array for dual-control / multi-party publish. Same
canonical body as single-sig; signature fields are never part of the signed
payload. When `signatures` is present and non-empty, verification uses that
array (not top-level `signature`).

```json
{
  "schema_version": 1,
  "alg": "ed25519",
  "key_id": "corp-policy-a",
  "issued_at": "2026-08-01T00:00:00Z",
  "not_after": "2027-08-01T00:00:00Z",
  "min_version": 1,
  "bundle_seq": 42,
  "overlay": {
    "version": 1,
    "force_read_only": true,
    "mode": "pilot"
  },
  "signatures": [
    {"key_id": "corp-policy-a", "signature": "<base64>"},
    {"key_id": "corp-policy-b", "signature": "<base64>"}
  ]
}
```

| Field | Meaning |
|-------|---------|
| `schema_version` | Envelope schema; must be `1` |
| `alg` | Only `ed25519` in MVP |
| `key_id` | Primary key id (always part of the **signed** body; required) |
| `issued_at` | Optional RFC3339 |
| `not_after` | Optional RFC3339; exclusive after this instant → reject |
| `min_version` | Minimum client **overlay** schema (`version` field); client too old → reject |
| `bundle_seq` | Monotonic ≥ 1; used for **rollback / downgrade** detection |
| `overlay` | Same schema as CFG-002 plain overlay (**no** nested `signature`) |
| `signature` | MVP single-sig: base64 of 64-byte Ed25519 over **canonical signing JSON** |
| `signatures` | Multi-sig lite (optional): `[{key_id, signature}, …]` — when non-empty, multi-sig path |

### Canonical signing payload

Signature covers `encoding/json` of the envelope **without** the `signature`
or `signatures` fields (fixed Go struct field order). Nested `overlay.signature`
is always cleared before signing/verifying. Multi-sig signers all sign the
**same** body.

### Multi-sig verification (Done\* lite)

`Ed25519SignatureVerifier` behavior:

| Envelope shape | Path |
|----------------|------|
| `signatures` present and non-empty | Multi-sig: verify **each** entry against `TrustedKeySet`; require ≥ `MinSignatures` valid **distinct** `key_id`s |
| Only top-level `signature` (+ `key_id`) | Existing single-sig path (unchanged) |

- **`MinSignatures`** (field on `Ed25519SignatureVerifier`): default **1** when 0/unset; set to **2** for dual-control (2-of-N distinct trusted keys).
- Fail closed: unknown `key_id`, invalid signature, or fewer than `MinSignatures` distinct valid keys.
- Duplicate `key_id`s count once toward the threshold.
- Top-level `key_id` remains required (signed body); top-level `signature` is optional when `signatures[]` is non-empty.
- Full cryptographic threshold schemes (e.g. true *t*-of-*n* secret sharing / BLS-style aggregates) are **not** implemented — residual below.

### Plain overlays (pilot)

Unsigned `overlay.json` remains valid when **no** trusted keys are configured
(`signature_state=unverified_pilot`). When trusted keys are present, plain
unsigned files are **rejected**. Signed envelopes always require trusted keys.

## Trusted public keys

| Source | Path / env |
|--------|------------|
| Default dir | `$XDG_CONFIG_HOME/jenkins-mcp/policy/trusted_keys/` |
| Override | `JENKINS_MCP_POLICY_TRUSTED_KEYS` → file or directory |

### Directory layout

- Files named `<key_id>.pub` / `<key_id>.pem` / `<key_id>`
- Content: PKIX PEM `PUBLIC KEY`, or raw/base64 32-byte Ed25519 public key
- Optional JSON trust store file:

```json
{
  "keys": [
    {
      "key_id": "corp-policy-2026",
      "alg": "ed25519",
      "public_key": "<base64 32-byte pubkey>"
    }
  ]
}
```

**Private keys are never accepted** in the trust store. Key material must not
appear in logs, MCP results, doctor output, or support bundles (only `key_id`).

## Fail-closed rules (safe mode)

| Condition | Behavior |
|-----------|----------|
| Invalid JSON / schema / overlay fields | Load error — process must not start with partial policy |
| Unknown `key_id` (single-sig or any multi-sig entry) | Reject |
| Bad signature / tamper | Reject |
| Multi-sig: distinct valid keys &lt; `MinSignatures` | Reject |
| `not_after` expired | Reject |
| `min_version` > client overlay schema | Reject |
| `bundle_seq` **&lt;** last-good seq | Reject (**downgrade / rollback**) |
| Same `bundle_seq`, different content hash | Reject |
| Signed envelope without trusted keys | Reject |
| Trusted keys configured + plain unsigned file | Reject |
| `JENKINS_MCP_POLICY_REQUIRED=1` + missing file | Reject |
| `JENKINS_MCP_POLICY_REQUIRED=1` + no keys + unsigned | Reject (staging stub requires non-empty signature field) |

Absent file + not required → no overlay (pilot continues).

### Last-good cache

Path: `$XDG_CACHE_HOME/jenkins-mcp/policy/last_good.json`

Secret-free record: `bundle_seq`, `content_hash` (sha256 of signing payload),
`key_id`, `loaded_at`. Used only for rollback detection. Corrupt cache → fail
closed (remove file to re-bootstrap after intentional reset).

### Key rotation and emergency replacement

1. Distribute new public key under a new `key_id` (both keys trusted during window).
2. Publish a new bundle with **higher** `bundle_seq` signed by the new key.
3. Optionally remove the old public key after fleet absorption.

Emergency deny policy: publish higher `bundle_seq` with stricter `deny_tools` /
`force_read_only: true`. Lower `bundle_seq` is always rejected once last-good is set.

## Load path (`serve` / `LoadFromEnviron`)

1. Resolve path: `JENKINS_MCP_POLICY_FILE` → else prefer
   `policy/overlay.bundle.json` if present → else `policy/overlay.json`.
2. If trusted keys present → `Ed25519SignatureVerifier` with last-good cache;
   `RequireSigned=true`.
3. Else if `JENKINS_MCP_POLICY_REQUIRED` → staging `RequiringSignatureVerifier`.
4. Else → `NopSignatureVerifier` (pilot; `unverified_pilot`).

After a successful initial load, `serve` wraps the evaluator in
`ReloadableDenyOnly` (Wave 24): path mtime is checked on `Evaluate` (min 5s
interval); corrupt/signature-fail reloads keep last-good. Wave 25 hot-applies
`force_read_only` (`DynamicForce`) and sets `max_result_bytes` within serve-bootstrap ceiling (Wave 31/37)
(`LiveHardMax`) on successful reload. Bootstrap ceiling is default 1 MiB or
`--hard-max-bytes` / `JENKINS_MCP_HARD_MAX_BYTES` (flag wins); overlay cannot raise
above it. See
[`../policy-rbac.md`](../policy-rbac.md#hot-reload-wave-24--wave-25-hot-apply).
Wave 28: `deny_tools` ListTools discovery is live-filtered without restart.

## CLI

```bash
# Verify a bundle (or plain pilot overlay when no keys)
jenkins-mcp policy verify --file /etc/jenkins-mcp/policy/overlay.bundle.json \
  --keys /etc/jenkins-mcp/policy/trusted_keys --json
# Optional: also enforce last-good anti-rollback (same as serve)
#   --check-downgrade

# Explain effective policy for a profile (secret-free)
jenkins-mcp policy show-effective --profile corp --json

# DEV ONLY — requires JENKINS_MCP_POLICY_SIGN_DEV=1; never commit private keys
export JENKINS_MCP_POLICY_SIGN_DEV=1
jenkins-mcp policy sign \
  --file overlay.json \
  --key /secure/path/policy-ed25519.pem \
  --key-id corp-policy-2026 \
  --bundle-seq 42 \
  --not-after 2027-08-01T00:00:00Z \
  --out overlay.bundle.json

# Multi-sig lite (Wave 35): repeatable --key / --key-id pairs (order-paired)
jenkins-mcp policy sign \
  --file overlay.json \
  --key /secure/path/a.pem --key-id corp-a \
  --key /secure/path/b.pem --key-id corp-b \
  --bundle-seq 43 \
  --out overlay.multi.bundle.json

# Or load private keys from a directory (<key_id>.pem → key_id)
jenkins-mcp policy sign \
  --file overlay.json \
  --keys-dir /secure/path/signing-keys \
  --out overlay.multi.bundle.json

# Verify dual-control (2 distinct trusted signatures)
export JENKINS_MCP_POLICY_MIN_SIGNATURES=2
jenkins-mcp policy verify \
  --file overlay.multi.bundle.json \
  --keys /etc/jenkins-mcp/policy/trusted_keys
```

One signer → MVP single-sig (`signature` field). Two or more → multi-sig lite
(`signatures[]` populated; top-level `signature` empty; top-level `key_id` =
first signer). `policy sign-multi` is an alias of the same command.

Production signing should use enterprise HSM/KMS or offline air-gapped tooling;
the built-in `policy sign` command is a **developer aid**, not a fleet CA.

## Cursor / env example (signed fleet)

```json
{
  "mcpServers": {
    "jenkins": {
      "command": "/usr/bin/jenkins-mcp",
      "args": ["serve", "--profile", "corp", "--stdio", "--read-only"],
      "env": {
        "JENKINS_MCP_READ_ONLY": "true",
        "JENKINS_MCP_POLICY_FILE": "/etc/jenkins-mcp/policy/overlay.bundle.json",
        "JENKINS_MCP_POLICY_TRUSTED_KEYS": "/etc/jenkins-mcp/policy/trusted_keys",
        "JENKINS_MCP_POLICY_REQUIRED": "1"
      }
    }
  }
}
```

## Signature state tokens

| Token | Meaning |
|-------|---------|
| `absent` | No policy file |
| `unverified_pilot` | Plain overlay, no crypto |
| `present_field` | Legacy non-empty `signature` stub field (not crypto proof) |
| `verified` | Ed25519 envelope verified |

## Residuals

| Item | Notes |
|------|-------|
| Multi-sig lite (N distinct Ed25519 keys + `MinSignatures`) | **Done\*** (Wave 34 / MGR-001 residual) |
| CLI multi-sign (`policy sign` multi-key / `--keys-dir`) | **Done\*** (Wave 35) — dev-only; not a fleet CA |
| Offline self-check canary (`policy_multisig_lite_residual`) | **Done\*** (Wave 42) — proves 2-of-2 ok / 1-of-2 fail-closed; residual flags `residual_true_threshold=false`, `residual_hsm=false` |
| Full threshold crypto (secret sharing, BLS aggregates, true *t*-of-*n* without N distinct sigs) | Residual — not implemented (self-check documents honesty; does not implement) |
| Production HSM/KMS-backed signing pipeline | Residual — operator/org-owned; CLI `policy sign` is dev-only |
| Online key discovery | Out of band only |
| Detached `.sig` files | Envelope preferred; not implemented |
| Gateway push of bundles | GWY / fleet epic |
| Automatic emergency kill-switch channel | Manual higher-seq publish |

## Security notes

- Effective access remains: Jenkins allow ∧ read-only ∧ MCP deny-only ∧ budgets.
- User profile / CLI **cannot** weaken `force_read_only` from a verified overlay.
- Do not log signature bytes, private keys, or full public key material in status.
