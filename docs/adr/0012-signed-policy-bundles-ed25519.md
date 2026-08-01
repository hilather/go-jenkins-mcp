# ADR 0012: Signed enterprise policy bundles (Ed25519 envelope)

- **Status:** Accepted  
- **Date:** 2026-08-01  
- **Owner:** engineering (security co-owner)  
- **Related:** architecture §7; MGR-001; CFG-002; ADR 0004; `docs/security/policy-bundles.md`

## Context

Enterprise fleets need a way for security to push **restricting-only** policy
(force read-only, deny tools, lower budgets) that agents cannot silently weaken
or roll back. CFG-002 landed an unsigned overlay loader with a
`SignatureVerifier` stub. Production requires real cryptography, expiry, and
rollback detection without putting credentials in policy documents.

## Decision

1. **Envelope format** (`schema_version: 1`) with nested overlay body,
   `key_id`, `alg`, `bundle_seq`, optional `not_after` / `issued_at`,
   `min_version`, and base64 Ed25519 `signature` over canonical JSON of all
   fields except `signature`.
2. **Algorithm:** Ed25519 via Go stdlib `crypto/ed25519` only for MVP.
3. **Trust store:** local public keys under
   `$XDG_CONFIG_HOME/jenkins-mcp/policy/trusted_keys/` or
   `JENKINS_MCP_POLICY_TRUSTED_KEYS` (PEM or base64 / JSON store). Private keys
   never accepted in the trust store.
4. **Fail closed** on invalid signature, unknown key, expiry, schema/min_version
   mismatch, and **bundle_seq downgrade** vs last-good cache
   (`$XDG_CACHE_HOME/jenkins-mcp/policy/last_good.json`).
5. **Pilot path preserved:** when no trusted keys are configured, plain
   unsigned overlays load with `signature_state=unverified_pilot`. Signed
   envelopes always require trusted keys.
6. **When trusted keys are present** (or production-required mode rejects
   unsigned), unsigned plain overlays are rejected.
7. **Dev-only sign CLI** gated by `JENKINS_MCP_POLICY_SIGN_DEV=1`; product trees
   must not ship private keys.

## Alternatives

| Alternative | Why not |
|-------------|---------|
| Detached `.sig` only | Harder to carry metadata (seq, expiry, key_id) atomically |
| JWT/JWS | Heavier deps; envelope + stdlib Ed25519 is enough for MVP |
| Symmetric HMAC with shared secret | Secret distribution worse than public-key; harder rotation |
| Allow seq downgrade | Enables rollback attacks after emergency deny |
| Require signatures always (no pilot) | Blocks local developer/pilot bootstrap without key setup |

## Consequences

- Operators must distribute public keys out-of-band before enforcing signed
  fleets.
- Last-good cache makes intentional rollback require cache reset (documented
  operator action) after security review.
- Key rotation = multi-key trust window + higher `bundle_seq`.
- Multi-sig lite (optional `signatures[]` + `MinSignatures` distinct Ed25519
  keys) landed as MGR-001 residual (Wave 34); full threshold crypto still residual.
- Wave 42 offline self-check `policy_multisig_lite_residual` proves MinSignatures
  dual-control path and documents residual_true_threshold / residual_hsm honesty.
- Residual: online discovery, gateway push (GWY), HSM-backed sign pipelines.

## Owner

Engineering implements; security co-approves any change that weakens fail-closed
verification, allows elevation, or logs key/signature material.
