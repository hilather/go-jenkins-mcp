package fleetcache

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// Wire protocol bounds (FLC-011) — fail closed, no silent truncate.
const (
	// ProtocolVersionV1 is the only accepted peer cache protocol id for wire manifests.
	ProtocolVersionV1 = "fleet-cache/1"
	// MaxWireManifestBytes is the max JSON body accepted for a wire manifest.
	MaxWireManifestBytes = 256 << 10 // 256 KiB
	// MaxWireFrames is the max frame descriptors in one sealed log manifest.
	MaxWireFrames = 4096
	// MaxDecodedFrameBytes mirrors store hard frame cap (16 MiB).
	MaxDecodedFrameBytes = 16 << 20
	// MaxZstdFrameBytes is a compressed-frame ceiling (same order as decoded cap).
	MaxZstdFrameBytes = 16 << 20
)

// forbiddenWireKeys are never allowed in peer-supplied JSON (local identity smuggling).
var forbiddenWireKeys = []string{
	"local_path", "path", "filepath", "file_path", "generation_id", "generation",
	"profile_id", "profile", "sqlite", "data_dir", "frames_dir",
	"credential", "token", "password", "authorization",
}

// WireFrame is one frame on the peer wire (no local generation/path fields).
type WireFrame struct {
	Seq           int    `json:"seq"`
	RawStart      int64  `json:"raw_start"`
	RawEnd        int64  `json:"raw_end"`
	LineStart     int64  `json:"line_start"`
	LineEnd       int64  `json:"line_end"`
	DecodedSize   int64  `json:"decoded_size"`
	DecodedSHA256 string `json:"decoded_sha256"`
	ZstdSize      int64  `json:"zstd_size"`
	ZstdSHA256    string `json:"zstd_sha256"`
}

// WireManifest is the peer-facing sealed-log contract (JSON).
// Optional unknown fields are ignored by the decoder; forbidden keys fail closed.
type WireManifest struct {
	ProtocolVersion string      `json:"protocol_version"`
	FleetID         string      `json:"fleet_id"`
	CachePool       string      `json:"cache_pool"`
	ControllerID    string      `json:"controller_id"`
	LocatorHash     string      `json:"locator_hash"`
	ManifestDigest  string      `json:"manifest_digest,omitempty"`
	Sealed          bool        `json:"sealed"`
	FormatVersion   int         `json:"format_version"`
	Codec           string      `json:"codec"`
	Frames          []WireFrame `json:"frames"`
	TotalRawBytes   int64       `json:"total_raw_bytes"`
	TotalLines      int64       `json:"total_lines"`
}

// ParseWireManifestJSON parses and validates a bounded peer manifest body.
// raw must not exceed MaxWireManifestBytes; larger inputs fail closed.
func ParseWireManifestJSON(raw []byte) (WireManifest, error) {
	if len(raw) == 0 {
		return WireManifest{}, apperr.New(apperr.CodeInvalidArgument, "wire manifest is empty")
	}
	if len(raw) > MaxWireManifestBytes {
		return WireManifest{}, apperr.New(apperr.CodeInvalidArgument, "wire manifest exceeds max bytes")
	}
	if err := rejectForbiddenWireKeys(raw); err != nil {
		return WireManifest{}, err
	}
	// Protocol v1: ignore unknown optional fields (forward-compat); forbidden keys already rejected.
	dec := json.NewDecoder(bytes.NewReader(raw))
	var m WireManifest
	if err := dec.Decode(&m); err != nil {
		return WireManifest{}, apperr.New(apperr.CodeInvalidArgument, "invalid wire manifest JSON")
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return WireManifest{}, apperr.New(apperr.CodeInvalidArgument, "wire manifest must be a single JSON value")
	}
	if err := ValidateWireManifest(m); err != nil {
		return WireManifest{}, err
	}
	return m, nil
}

// ValidateWireManifest enforces sealed-only protocol v1 bounds without hashing.
func ValidateWireManifest(m WireManifest) error {
	if strings.TrimSpace(m.ProtocolVersion) != ProtocolVersionV1 {
		return apperr.New(apperr.CodeInvalidArgument, "unsupported wire protocol_version")
	}
	if strings.TrimSpace(m.FleetID) == "" || strings.TrimSpace(m.CachePool) == "" || strings.TrimSpace(m.ControllerID) == "" {
		return apperr.New(apperr.CodeInvalidArgument, "wire manifest missing fleet/pool/controller identity")
	}
	if len(m.LocatorHash) != 64 || !isHex(m.LocatorHash) {
		return apperr.New(apperr.CodeInvalidArgument, "wire locator_hash must be 64 hex chars")
	}
	if m.ManifestDigest != "" && (len(m.ManifestDigest) != 64 || !isHex(m.ManifestDigest)) {
		return apperr.New(apperr.CodeInvalidArgument, "wire manifest_digest must be 64 hex chars when set")
	}
	if !m.Sealed {
		return apperr.New(apperr.CodeInvalidArgument, "wire manifest must be sealed")
	}
	if m.FormatVersion != 1 {
		return apperr.New(apperr.CodeInvalidArgument, "unsupported wire format_version")
	}
	if m.Codec != ManifestCodecZstd {
		return apperr.New(apperr.CodeInvalidArgument, "unsupported wire codec")
	}
	if len(m.Frames) == 0 {
		return apperr.New(apperr.CodeInvalidArgument, "wire manifest requires frames")
	}
	if len(m.Frames) > MaxWireFrames {
		return apperr.New(apperr.CodeInvalidArgument, "wire manifest exceeds max frames")
	}
	// Map to ManifestV1 for range/contiguity rules.
	frames := make([]FrameDescriptor, len(m.Frames))
	for i, f := range m.Frames {
		if f.DecodedSize > MaxDecodedFrameBytes || f.ZstdSize > MaxZstdFrameBytes {
			return apperr.New(apperr.CodeInvalidArgument, "wire frame exceeds size cap")
		}
		if f.ZstdSize < 1 {
			return apperr.New(apperr.CodeInvalidArgument, "wire frame zstd_size invalid")
		}
		frames[i] = FrameDescriptor{
			Seq: f.Seq, RawStart: f.RawStart, RawEnd: f.RawEnd,
			LineStart: f.LineStart, LineEnd: f.LineEnd,
			DecodedSize: f.DecodedSize, DecodedSHA256: f.DecodedSHA256,
			ZstdSize: f.ZstdSize, ZstdSHA256: f.ZstdSHA256,
		}
	}
	inner := ManifestV1{
		LocatorHash:   strings.ToLower(m.LocatorHash),
		Sealed:        true,
		FormatVersion: m.FormatVersion,
		Codec:         m.Codec,
		Frames:        frames,
		TotalRawBytes: m.TotalRawBytes,
		TotalLines:    m.TotalLines,
	}
	return inner.validate()
}

// ToManifestV1 converts a validated wire manifest into the digest identity type.
func (m WireManifest) ToManifestV1() ManifestV1 {
	frames := make([]FrameDescriptor, len(m.Frames))
	for i, f := range m.Frames {
		frames[i] = FrameDescriptor{
			Seq: f.Seq, RawStart: f.RawStart, RawEnd: f.RawEnd,
			LineStart: f.LineStart, LineEnd: f.LineEnd,
			DecodedSize: f.DecodedSize, DecodedSHA256: strings.ToLower(f.DecodedSHA256),
			ZstdSize: f.ZstdSize, ZstdSHA256: strings.ToLower(f.ZstdSHA256),
		}
	}
	return ManifestV1{
		LocatorHash:   strings.ToLower(m.LocatorHash),
		Sealed:        m.Sealed,
		FormatVersion: m.FormatVersion,
		Codec:         m.Codec,
		Frames:        frames,
		TotalRawBytes: m.TotalRawBytes,
		TotalLines:    m.TotalLines,
	}
}

func rejectForbiddenWireKeys(raw []byte) error {
	// Lightweight key scan on JSON text (case-insensitive) for smuggling local identity.
	low := strings.ToLower(string(raw))
	for _, k := range forbiddenWireKeys {
		// Match JSON object keys: "key"
		needle := `"` + k + `"`
		if strings.Contains(low, needle) {
			return apperr.New(apperr.CodeInvalidArgument, "wire manifest contains forbidden field")
		}
	}
	// Reject absolute path-looking strings in values (common smuggle).
	if strings.Contains(low, `"/tmp/`) || strings.Contains(low, `"\\`) || strings.Contains(low, `":"/var/`) {
		return apperr.New(apperr.CodeInvalidArgument, "wire manifest must not contain local paths")
	}
	return nil
}
