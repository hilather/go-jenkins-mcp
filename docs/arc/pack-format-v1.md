# Pack format v1 — seekable multi-frame `.tar.zst` (L2)

| Field | Value |
|-------|--------|
| **Task** | ARC-002 |
| **Status** | Accepted for native Go writer/reader (`ARC-003`) |
| **Date** | 2026-07-31 |
| **Related** | ADR 0005 (L1 frames), ADR 0007 (L2 multi-frame), architecture §9–10, ARC-000 |

## 1. Purpose

Immutable, self-describing **cold** packs of related Jenkins logs (and optional small evidence). Packs support:

- **Random access** by TAR member and byte range without decompressing the entire pack
- **Sequential** standard Zstandard decode recovering a standards-compliant TAR stream (content frames only; seek metadata is skippable)
- **Zero-recompression promotion** from L1: already-compressed independent L1 payload frames may be **copied** into the pack as payload frames

This format is the durable contract. Readers (native Go mandatory; qualified `ratarmount-rs` optional after ARC-000) must not change on-disk semantics.

## 2. Non-goals and bans

| Banned / not claimed | Reason |
|----------------------|--------|
| Ordinary **single-frame** `.tar.zst` as “random access” | One frame forces full-frame decompress for any range |
| Calling internal Zstd **blocks** random-access boundaries | Blocks may depend on prior blocks within a frame |
| Double-compressing `.zst` members inside outer `.tar.zst` as baseline | Wastes CPU; breaks L1 frame copy |
| Windows / WinFsp pack IO | Platform out of scope |

**Hard validation rule:** a pack with fewer than **two independent content frames**, or without a valid **seek-table skippable frame**, is **rejected** as a random-access L2 pack (even if `zstd -d` can decode it).

## 3. Physical layout

```text
pack-v1.tar.zst
  ┌─────────────────────────────────────────────┐
  │ Content frame 0   (independent Zstd frame)  │  → TAR stream bytes
  │ Content frame 1                             │
  │ ...                                         │
  │ Content frame N-1  (N ≥ 2)                  │
  ├─────────────────────────────────────────────┤
  │ Skippable frame   (Zstd skippable)          │  → seek table JSON (v1)
  └─────────────────────────────────────────────┘
```

- **Magic (content frames):** standard Zstandard frame magic `0xFD2FB528` (LE).
- **Skippable seek frame:** magic in range `0x184D2A50`–`0x184D2A5F` (LE), user-data = seek table document.
- **Endianness:** little-endian for all multi-byte binary fields in frame headers (Zstd). Seek table JSON uses decimal integers (no endian ambiguity).
- **Extension:** packs are stored as `*.tar.zst` (or opaque blob under `ArchiveStore`); optional sidecar manifest may duplicate catalog fields but is not required for native open when the seek table is present.

Sequential `zstd` decompression of the file yields **only** the concatenated TAR bytes (skippable frames are skipped by conforming decoders).

## 4. TAR stream

- POSIX ustar / PAX as produced by Go `archive/tar` (writer uses PAX when needed for long names).
- Members are related logs under a stable opaque namespace, e.g.:

  ```text
  manifest/pack.json          # optional in-band manifest member
  logs/root/consoleText
  logs/stage/<id>.log
  logs/downstream/<job>/<n>.log
  evidence/<name>
  ```

- Member order (affinity packs): compact metadata → root/stage → downstream/matrix → tests/evidence → derived indexes.
- Catalog **affinity group** (maintenance L1→L2 lite / Wave 31–32): prefer `profile=<id>|collection=<collectionID>` when the sealed gen is a durable collection member; append `|relation=<label>` when all members of the pack share the same non-empty catalog relation (Wave 32); else `profile=<id>|job=<fullName>` (or `job=…` / `collection=…` if profile empty); see [pack-affinity-lite.md](./pack-affinity-lite.md).
- TAR ends with two 512-byte zero blocks (standard).
- **Do not** store pre-compressed `.zst` *as TAR member payloads* for the baseline log path; L1 compressed frames are outer pack frames (see §6), not nested archives.

## 5. Independent Zstandard frames

| Parameter | v1 default | Allowed range (policy-tuned) |
|-----------|------------|------------------------------|
| Uncompressed content per **payload** frame | 8 MiB target | 1–32 MiB |
| Physical pack size target | 4–16 GiB | split volumes when exceeded |
| Dictionary | none (empty `dict_id`) | optional later; identity recorded in seek table |
| Content checksum | Zstd frame content checksum **on** | required for generated frames |

**Frame kinds** (logical, recorded in seek table):

| Kind | Role |
|------|------|
| `header` | Small generated frame: TAR header (and optional long-name PAX) for one member |
| `payload` | Log bytes; may be a **copied L1** independent `.zst` frame (bytes unchanged) |
| `padding` | Small generated frame: TAR padding to 512-byte blocks |
| `bundle` | Newly compressed frame holding one or more small members (compatibility / coalescing) |
| `terminator` | Generated frame with TAR end-of-archive zero blocks |
| `content` | Generic content frame (compatibility repack writer may use only this) |

All content frames are **independently decodable**. No cross-frame window or dictionary dependency in v1 baseline.

## 6. Preferred L1→L2 promotion (zero-recompression)

For each sealed large member:

1. Emit **header** frame (TAR header for the member).
2. **Copy** L1 payload frame files in logical order (compressed bytes identical to L1).
3. Emit **padding** frame if TAR padding is required after the member body.
4. After all members: **terminator** frame(s), then **skippable seek table**.

Manifest / seek table map each member’s uncompressed TAR `[offset, offset+size)` onto the ordered frame list (header + payload… + padding).

**Fixture requirement:** copied L1 payload-frame bytes appear **byte-identical** at their compressed offsets inside the pack.

**Compatibility repack writer:** reconstruct the full TAR stream and re-encode into independent content frames of ~target size, then append seek table. Used when a consumer cannot accept the header/payload/padding assembly. Native Go reader accepts both layouts when the seek table is valid.

## 7. Seek table (skippable frame payload)

- **Encoding:** UTF-8 JSON, object root.
- **Max size:** 16 MiB uncompressed seek payload (fail closed above).
- **Magic field:** `"JMCP-SEEK-V1"`.

### 7.1 Schema (normative)

```json
{
  "magic": "JMCP-SEEK-V1",
  "format_version": 1,
  "pack_id": "opaque-pack-id",
  "tar_size": 0,
  "frames": [
    {
      "index": 0,
      "kind": "content",
      "compressed_offset": 0,
      "compressed_size": 0,
      "raw_offset": 0,
      "raw_size": 0,
      "content_sha256": "hex of uncompressed frame bytes",
      "frame_sha256": "hex of compressed frame bytes",
      "dict_id": ""
    }
  ],
  "members": [
    {
      "name": "logs/root/consoleText",
      "entry_id": "opaque-or-name",
      "raw_offset": 0,
      "size": 0,
      "mode": 420,
      "content_sha256": "hex of member file bytes",
      "typeflag": 48
    }
  ],
  "pack_sha256": "hex SHA-256 of all content frames concatenated (no skippable)",
  "min_content_frames": 2
}
```

### 7.2 Invariants

- `frames` lists **content frames only**, in file order; compressed ranges are contiguous from offset 0 with no gaps (padding between content frames is forbidden).
- `raw_offset` / `raw_size` describe the frame’s contribution to the uncompressed TAR stream; frames are contiguous in raw space: `raw_offset[i+1] == raw_offset[i] + raw_size[i]`.
- `tar_size` equals sum of content `raw_size` (including TAR headers, padding, and terminators).
- Every `members[].raw_offset` and `size` lie within `[0, tar_size)` and refer to **file data** (not the TAR header), consistent with `archive/tar` member body offsets.
- `pack_sha256` binds content-frame bytes for Verify.
- Seek skippable frame itself is **not** included in `frames[]` or `pack_sha256`.

## 8. Random-access algorithm (readers)

1. Locate frames by scanning Zstd frame headers/blocks **or** trust a verified seek table after binding checks.
2. Load and validate seek table from the **last** skippable frame with `magic == JMCP-SEEK-V1`.
3. Reject if content frame count `< 2` or seek table missing/corrupt.
4. For member range `[start, start+length)` within the member body:
   - Map to absolute TAR raw range using `members[].raw_offset`.
   - Select content frames intersecting that raw range.
   - Decompress **only** those frames under memory/amplification limits.
   - Slice the intersection; report frames opened and decompressed bytes (amplification metrics).

A **64 KiB** logical range must not decompress the entire pack when frames are bounded.

## 9. Checksums and Verify

| Object | Checksum |
|--------|----------|
| Uncompressed frame body | `content_sha256` |
| Compressed frame bytes | `frame_sha256` |
| Member body | `content_sha256` |
| All content frames | `pack_sha256` |

`ArchiveStore.Verify` re-reads compressed frames, checks `frame_sha256` / optional content samples, and validates seek/member bounds. Fail closed on mismatch (`corrupt_cache`).

## 10. Limits and bombs

| Limit | v1 default |
|-------|------------|
| Max single content frame uncompressed | 32 MiB |
| Max pack content frames | 1_000_000 (implementation may lower) |
| Max members | 1_000_000 |
| Max OpenRange length (store policy) | 1 MiB default (caller may lower) |
| Max concurrent decompressed bytes per op | sum of intersecting frames ≤ 64 MiB |

Malformed frame headers, oversize skippable payloads, and inconsistent offsets fail with `corrupt_cache` / `invalid_argument` without unbounded allocation.

## 11. Versioning and evolution

- `format_version` starts at **1**.
- Unknown `format_version` → reject (no silent best-effort).
- Additive JSON fields may appear; readers ignore unknown fields but must enforce known invariants.
- Breaking changes require `format_version` bump and dual-read window documented in an ADR.

## 12. Compatibility with L1 (STO-003)

L1 stores one independent Zstd frame per chunk file (`frames/<gen>/<seq>.zst`) with SQLite metadata. L2 **may copy those compressed bytes** as `payload` frames. L1 `ContentSHA256` / `FrameSHA256` should match the corresponding seek-table entries after promotion.

## 13. Fixtures (implementation)

Native package tests cover at least:

- Multi-member pack, list + full entry + range read
- Multi-frame independence (64 KiB range opens subset of frames)
- Sequential decompress ≡ full TAR recovery
- Single-frame pack rejection
- Missing/corrupt seek table rejection
- Copied pre-compressed payload frame bytes unchanged in pack
- Empty member, long lines, binary-like bytes

## 14. Sidecar pack index (ARC-006)

Derived catalog files live beside packs as `<packID>.idx.json` (not required for
native `OpenPack`; the embedded seek table is authoritative for random access).

| Field | Role |
|-------|------|
| `magic` | `JMCP-IDX-V1` |
| `index_schema_version` | Sidecar schema (independent of pack `format_version`) |
| `pack_id` / `pack_format_version` | Identity + pack schema bind |
| `pack_size_bytes` | Full on-disk pack length |
| `pack_sha256` | Content-frames digest (seek table `pack_sha256`) |
| `file_sha256` | SHA-256 of entire pack file (content + seek frame) |
| `members` | Lightweight catalog rows |

**Trust rule:** wrong checksum, size, or schema ⇒ index is **never** trusted.
MCP reads use bounded native seek-table open and set `RebuildNeeded`; rebuild
only via explicit `RebuildIndex` / `RepairIndex` (off request path). Corrupt
packs may be moved under `quarantine/` (`QuarantinePack`).

## 15. Residual

- Qualified `ratarmount-rs` byte-identity: blocked on ARC-000 supply (`docs/arc/ratarmount-rs-qualification.md`).
- Encryption / versioned dictionaries: reserved fields only; not enabled in v1 baseline.
- Dual-reader (ratarmount-rs) verification: residual (ARC-000 supply). L1 release after native VerifyPack/sample is implemented (ARC-005 residual).
- Full `cache verify` / repair CLI UX: ARC-008 (**done** library + `jenkins-mcp cache verify|repair`; dual-reader re-fetch residual).
