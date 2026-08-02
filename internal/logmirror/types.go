package logmirror

import (
	"context"

	"github.com/hilather/go-jenkins-mcp/internal/store"
)

// LogKey is an alias of store.LogKey for mirror callers.
type LogKey = store.LogKey

// State is the durable progressive-log generation snapshot.
type State struct {
	// Generation is the monotonic generation number for this log key (starts at 1).
	Generation int64
	// GenerationID is the SQLite row id for the active generation.
	GenerationID int64
	// CommittedOffset is the next Jenkins progressive start offset.
	// With Frames configured this is the in-process accepted end (includes
	// uncommitted frame buffer). After restart it equals durable frame end.
	// SQLite jenkins_offset is only advanced to durable frame end (STO-004).
	CommittedOffset int64
	// DurableOffset is the exclusive end of committed L1 frames (0 if none / no Frames).
	DurableOffset int64
	// MoreData mirrors X-More-Data / incomplete suffix.
	MoreData bool
	// BuildComplete is true when the build is known finished (caller-supplied).
	BuildComplete bool
	// Sealed is true when the generation is closed (complete and no more data).
	Sealed bool
}

// Segment is one progressive append unit (architecture LogStore.Append).
type Segment struct {
	// Data is the raw progressive body bytes (may be empty on poll with no growth).
	Data []byte
	// ReportedNextOffset is Jenkins X-Text-Size (total log size after the fetch).
	// Use -1 when unknown. 0 is a valid empty-log total size only when Data is empty.
	// A non-empty Data with ReportedNextOffset==0 is normalized to unknown (-1).
	ReportedNextOffset int64
	// MoreData is Jenkins X-More-Data (or inferred remaining suffix).
	MoreData bool
	// BuildComplete is true when the build has finished writing.
	BuildComplete bool
}

// ProgressiveSource is a bounded progressiveText fetch (LOG-001 semantics).
// Prefer thin fakes in unit tests; *jenkins.Client satisfies via adapter.
type ProgressiveSource interface {
	// Fetch returns at most maxBytes of log starting at startOffset.
	// reportedNext is X-Text-Size when known (>= 0); use -1 if unknown.
	Fetch(ctx context.Context, job string, build int64, startOffset int64, maxBytes int) (
		data []byte, reportedNext int64, moreData bool, err error,
	)
}

// GenerationStore is the persistence surface needed by the state machine.
// *store.Meta implements this.
type GenerationStore interface {
	GetLatestGeneration(ctx context.Context, key store.LogKey) (*store.LogGeneration, error)
	InsertGeneration(ctx context.Context, g *store.LogGeneration) error
	UpdateGenerationOffset(ctx context.Context, id int64, offset int64, moreData, buildComplete, sealed bool) error
	SealGeneration(ctx context.Context, id int64) error
}

// PayloadStore receives progressive bytes into L1 independent frames (STO-003/004).
// *store.Frames implements this.
type PayloadStore interface {
	Append(ctx context.Context, generationID int64, data []byte) (store.AppendResult, error)
	Flush(ctx context.Context, generationID int64) (store.AppendResult, error)
	Forget(generationID int64)
	AcceptedEnd(ctx context.Context, generationID int64) (int64, error)
	DurableEnd(ctx context.Context, generationID int64) (int64, error)
}

// LogStore is a light mirror of architecture §5.2 LogStore for progressive L1.
// Search remains for SEARCH-001.
type LogStore interface {
	// Append commits a progressive segment for key (may open a new generation).
	Append(ctx context.Context, key LogKey, segment Segment) (State, error)
	// Seal seals the active generation when complete and no more data.
	Seal(ctx context.Context, key LogKey) (State, error)
	// State returns the latest generation snapshot (creates none).
	State(ctx context.Context, key LogKey) (State, error)
	// ReadRange returns a raw byte range from committed local frames (LOG-003).
	ReadRange(ctx context.Context, key LogKey, start, length int64) (store.ReadResult, error)
}

// DefaultFetchBytes is the default progressive poll size (bounded).
const DefaultFetchBytes = 64 * 1024
