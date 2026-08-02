package fleetcache

import (
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// SealedPublishInput is a sealed local generation ready to become a fleet wire object.
// Frames must already carry pure-zstd size/hash (EnsureChunkWireHash / ExportPureZstd).
type SealedPublishInput struct {
	FleetID      string
	CachePool    string
	ControllerID string
	JobFullName  string
	BuildNumber  int64
	// Sealed must be true (unsealed generations cannot become fleet hits).
	Sealed bool
	// Frames in seq order with contiguous raw/line ranges and wire digests.
	Frames []FrameDescriptor
	// TotalRawBytes / TotalLines if 0 are derived from frames.
	TotalRawBytes int64
	TotalLines    int64
}

// PublishSealed builds a deterministic WireManifest for a sealed completed console log.
// Re-publishing the same input is idempotent (same locator_hash and manifest digest).
// Does not mutate local store; callers may persist the result separately.
func PublishSealed(in SealedPublishInput) (WireManifest, error) {
	if !in.Sealed {
		return WireManifest{}, apperr.New(apperr.CodeInvalidArgument, "cannot publish unsealed generation")
	}
	if len(in.Frames) == 0 {
		return WireManifest{}, apperr.New(apperr.CodeInvalidArgument, "publish requires frames")
	}
	loc, err := NewConsoleLogLocator(in.FleetID, in.CachePool, in.ControllerID, in.JobFullName, in.BuildNumber)
	if err != nil {
		return WireManifest{}, err
	}
	lh, err := loc.Hash()
	if err != nil {
		return WireManifest{}, err
	}
	// Normalize frame digests to lowercase.
	frames := make([]FrameDescriptor, len(in.Frames))
	copy(frames, in.Frames)
	var sumDecoded, lastLine int64
	for i := range frames {
		frames[i].DecodedSHA256 = strings.ToLower(strings.TrimSpace(frames[i].DecodedSHA256))
		frames[i].ZstdSHA256 = strings.ToLower(strings.TrimSpace(frames[i].ZstdSHA256))
		if frames[i].ZstdSize < 1 || frames[i].ZstdSHA256 == "" {
			return WireManifest{}, apperr.New(apperr.CodeInvalidArgument, "publish frame missing wire zstd identity")
		}
		sumDecoded += frames[i].DecodedSize
		if frames[i].LineEnd > lastLine {
			lastLine = frames[i].LineEnd
		}
	}
	totalRaw := in.TotalRawBytes
	if totalRaw == 0 {
		totalRaw = sumDecoded
	}
	totalLines := in.TotalLines
	if totalLines == 0 {
		totalLines = lastLine
	}
	inner := ManifestV1{
		LocatorHash:   lh,
		Sealed:        true,
		FormatVersion: 1,
		Codec:         ManifestCodecZstd,
		Frames:        frames,
		TotalRawBytes: totalRaw,
		TotalLines:    totalLines,
	}
	// Validate contiguity / digests before wire wrap.
	if err := inner.validate(); err != nil {
		return WireManifest{}, err
	}
	digest, err := inner.Digest()
	if err != nil {
		return WireManifest{}, err
	}
	wf := make([]WireFrame, len(frames))
	for i, f := range frames {
		wf[i] = WireFrame{
			Seq: f.Seq, RawStart: f.RawStart, RawEnd: f.RawEnd,
			LineStart: f.LineStart, LineEnd: f.LineEnd,
			DecodedSize: f.DecodedSize, DecodedSHA256: f.DecodedSHA256,
			ZstdSize: f.ZstdSize, ZstdSHA256: f.ZstdSHA256,
		}
	}
	wm := WireManifest{
		ProtocolVersion: ProtocolVersionV1,
		FleetID:         loc.FleetID,
		CachePool:       loc.CachePool,
		ControllerID:    loc.ControllerID,
		LocatorHash:     lh,
		ManifestDigest:  digest,
		Sealed:          true,
		FormatVersion:   1,
		Codec:           ManifestCodecZstd,
		Frames:          wf,
		TotalRawBytes:   totalRaw,
		TotalLines:      totalLines,
	}
	if err := ValidateWireManifest(wm); err != nil {
		return WireManifest{}, err
	}
	return wm, nil
}
