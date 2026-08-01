package archive

import (
	"context"
	"io"
	"time"
)

// FormatVersion is the pack format major version (ARC-002).
const FormatVersion = 1

// SeekMagic is the JSON "magic" field inside the skippable seek-table frame.
const SeekMagic = "JMCP-SEEK-V1"

// DefaultMaxRangeBytes bounds OpenRange / OpenEntry body reads unless overridden.
const DefaultMaxRangeBytes int64 = 1 << 20 // 1 MiB

// DefaultTargetFrameBytes is the compatibility-repack uncompressed frame target.
const DefaultTargetFrameBytes = 8 << 20

// MinContentFrames is the minimum independent content frames for a valid L2 pack.
const MinContentFrames = 2

// MaxSeekTableBytes caps skippable seek-table payload size.
const MaxSeekTableBytes = 16 << 20

// MaxFrameUncompressed is the hard cap for one content frame raw size.
const MaxFrameUncompressed = 32 << 20

// MaxDecompressPerOp bounds sum of uncompressed frames opened in one range op.
const MaxDecompressPerOp = 64 << 20

// Frame kind labels recorded in the seek table (pack-format-v1 §5).
const (
	FrameKindContent    = "content"
	FrameKindHeader     = "header"
	FrameKindPayload    = "payload"
	FrameKindPadding    = "padding"
	FrameKindBundle     = "bundle"
	FrameKindTerminator = "terminator"
)

// PackDescriptor describes a pack to publish into ArchiveStore (ARC-001).
//
// Data is the complete multi-frame .tar.zst bytes (content frames + seek table).
// Implementations must not require MCP-visible filesystem paths.
type PackDescriptor struct {
	// PackID is an opaque durable identifier (required).
	PackID string

	// SchemaVersion is the pack format version (0 → FormatVersion).
	SchemaVersion int

	// AffinityGroup groups related logs (optional catalog metadata).
	AffinityGroup string

	// Data is the immutable pack payload.
	Data []byte

	// SHA256 optional hex digest of content frames; if empty, computed on put.
	SHA256 string

	// CreatedAt optional; zero means store assigns time.Now().UTC().
	CreatedAt time.Time
}

// ArchiveRef names a pack or a pack entry (opaque IDs only).
type ArchiveRef struct {
	// PackID required.
	PackID string
	// EntryID selects a member when opening an entry (name or opaque id).
	// Empty is valid only for pack-level Verify/DeletePack.
	EntryID string
}

// EntryMetadata is safe catalog metadata for one TAR member (no host paths).
type EntryMetadata struct {
	PackID        string
	EntryID       string
	Name          string
	Size          int64
	Mode          int64
	ContentSHA256 string
	// FramesOpened / DecompressedBytes are filled on range/entry reads (metrics).
	FramesOpened      int
	DecompressedBytes int64
}

// PackInfo is pack-level catalog data returned by list/health helpers.
type PackInfo struct {
	PackID        string
	SchemaVersion int
	AffinityGroup string
	SHA256        string
	SizeBytes     int64
	MemberCount   int
	FrameCount    int
	CreatedAt     time.Time
	// IndexTrusted is true when a sidecar/catalog index bound to pack
	// checksum/size/schema was loaded (ARC-006). False ⇒ native seek-table only.
	IndexTrusted bool
	// RebuildNeeded flags that a derived index should be rebuilt off the
	// request path (missing, stale, or mismatched). MCP reads must not rebuild.
	RebuildNeeded bool
}

// Capabilities describes what a store implementation can do without leaking paths.
type Capabilities struct {
	// Name is a short backend id (e.g. "memory", "filesystem", "native").
	Name string
	// NativeReader is true when multi-frame packs are served by the Go reader.
	NativeReader bool
	// RatarmountAdapter is true only after ARC-000/004 qualification (always false until then).
	RatarmountAdapter bool
	// MaxRangeBytes is the enforced OpenRange ceiling.
	MaxRangeBytes int64
	// FUSEMountAvailable is always false for core; optional inspection is out of band.
	FUSEMountAvailable bool
}

// ArchiveStore is the L2 cold-storage interface (architecture §5.2, ARC-001).
//
// L1 and tools depend only on this surface — never on ratarmount or raw paths.
type ArchiveStore interface {
	PutPack(ctx context.Context, pack PackDescriptor) error
	OpenEntry(ctx context.Context, ref ArchiveRef) (io.ReadCloser, EntryMetadata, error)
	Verify(ctx context.Context, ref ArchiveRef) error
	DeletePack(ctx context.Context, ref ArchiveRef) error
}

// RangeStore extends ArchiveStore with bounded range reads and listing (ARC-001/003).
type RangeStore interface {
	ArchiveStore
	OpenRange(ctx context.Context, ref ArchiveRef, offset, length int64) (io.ReadCloser, EntryMetadata, error)
	ListEntries(ctx context.Context, packID string) ([]EntryMetadata, error)
	Capabilities() Capabilities
}

// ReadStats captures amplification for a single read (tests / metrics).
type ReadStats struct {
	FramesOpened      int
	DecompressedBytes int64
	LogicalBytes      int64
	ContentFrames     int
}
