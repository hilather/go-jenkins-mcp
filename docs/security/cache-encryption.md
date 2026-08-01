# Optional application-level cache encryption (ARC-009)

**Status:** MVP (opt-in; default **off**)  
**Related:** architecture §9.6, [threat model](threat-model.md), ADR-style keyring AUTH-002  

## Purpose

Environments that need encryption **beyond** OS ACLs and full-disk encryption can
enable AES-256-GCM sealing of **L1 independent log frames**. This does not replace
profile isolation, Secret Service for API tokens, or TLS to Jenkins.

## Operator flow

```bash
# 1) Create / select a profile (non-secret config only)
jenkins-mcp profile add corp --url https://jenkins.example.com/

# 2) Initialize a per-profile cache key in the OS keyring (Secret Service on Linux)
jenkins-mcp cache key init --profile corp

# Profile JSON now has: cacheEncryption=true, cacheKeyVersion=N (no raw key)

# 3) Serve as usual — frames written under this profile are sealed
jenkins-mcp serve --profile corp --read-only

# Optional process-wide force (still requires key + version present):
# export JENKINS_MCP_CACHE_ENCRYPTION=1
```

```bash
# Status (never prints key material) — encryption flag, write version, presence bools only
jenkins-mcp cache key status --profile corp
# → profile=corp cache_encryption=true key_version=N write_key_present=true prev_key_present=true|false …

# Rotation lite: generate N+1, store in keyring, bump profile CacheKeyVersion;
# keep N as prev; drop N-2 (last 2 versions retained only). No full rewrite.
jenkins-mcp cache key rotate --profile corp
```

## Key lifecycle

| Item | Location |
|------|----------|
| AES-256 key material (32 bytes) | OS keyring only (`method=cache_aead`, per profile + version) |
| `cacheEncryption`, `cacheKeyVersion` | Profile JSON (non-secret) |
| `enc_alg`, `enc_key_version` | SQLite `chunks` row (metadata only) |

- **Generate:** `crypto/rand` → keyring `SetCacheKey`.
- **Write:** seal zstd frame with key **N**; AAD binds generation id, seq, format, codec.
- **Read:** try key **N**, then **N-1** (rotation lite / lazy prev).
- **Rotate:** `cache key rotate` stores **N+1**, bumps `cacheKeyVersion`, keeps **N** as prev, and **deletes N-2** after the profile bump so only the **last 2 versions** remain in the active keyring set. Frames sealed with older versions become unreadable unless an operator restored those keyring entries offline.
- **No full re-encrypt:** existing frames stay sealed under their original key version. Readers use lazy **N-1** only — bulk rewrite of all old frames is **not** required and is **not** implemented.
- **Loss / revocation:** without key **N** (and **N-1** for older frames), encrypted frames fail closed (`authentication` / `corrupt_cache`). Logout that deletes only the API token does **not** delete cache keys unless operators revoke them. Policy may require purge or key deletion on logout (future).
- **Never:** keys in CLI argv, profile JSON, logs, MCP tool results, pack manifests, support bundles, status output, or tests as real production secrets (tests use Memory keyring + synthetic vectors).

## On-disk envelope (L1)

```text
magic "JME1" | key_version u32 BE | nonce[12] | AES-GCM(ciphertext||tag of zstd frame)
```

- `FrameSHA256` covers the **entire on-disk envelope**.
- `ContentSHA256` remains the SHA-256 of **uncompressed** log bytes (see tradeoff below).

## Fail closed

- Encryption required (profile flag or `JENKINS_MCP_CACHE_ENCRYPTION=1`) but key missing / version unset → serve refuses to open the store path.
- Tamper (bit flip) → AEAD authentication failure; no plaintext returned; errors omit key material.
- Encrypted frame opened without keys → clear error (not silent plaintext zstd parse).

## Residuals (MVP)

| Topic | Status |
|-------|--------|
| L1 frame AEAD | **Implemented** |
| Cache key init / status / rotate CLI | **Implemented** (Wave 21 / ARC-009) |
| Keyring `SetCacheKey` / `GetCacheKey` / `DeleteCacheKey` / `HasCacheKey` | **Implemented** |
| Active retention of last 2 versions only | **Implemented** (rotate drops **N-2** after profile bump) |
| L2 pack body re-encryption | **Not** in MVP — L2 copies **pure zstd** after decrypt (zero-recompression preserved) |
| Full re-encrypt rewrite on rotation | **Not** required (lazy **N** / **N-1** read path) |
| Explicit key revoke / purge-on-logout | Residual (operators may `DeleteCacheKey` via tooling later) |
| Dictionary / multi-alg AEAD | Out of scope |
| Windows native FUSE/keyring | Out of platform matrix |

## Deduplication / equality leakage (approved tradeoff)

SQLite still stores `content_sha256` of **uncompressed** payload. Two identical
log ranges therefore show equal content hashes even when on-disk envelopes differ
(unique nonces). This enables integrity checks and recovery without holding keys
in metadata, at the cost of **equality leakage** of plaintext identity across
frames. Operators who forbid that class of leakage should keep encryption off
and rely on FDE/ACLs, or treat content hashes as sensitive metadata under the
same profile ACL as the frames.

## Support bundle / diagnostics

Bundles list `cache_encryption_keys` under **excluded** categories. Canary tests
plant API tokens and cache keys in a Memory keyring and assert absence from zip
bytes.
