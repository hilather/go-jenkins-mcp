package resourcecache

import "time"

// Completeness describes whether the stored object is a full canonical source.
type Completeness string

const (
	// Complete means sealed full source (safe to treat as hit for full reads).
	Complete Completeness = "complete"
	// Partial means intentionally truncated (e.g. max_length stage log, text budget).
	// Never fleet-published as complete; hit only for matching variant.
	Partial Completeness = "partial"
	// Incomplete means fetch cancelled/truncated mid-write — never treat as ready hit.
	Incomplete Completeness = "incomplete"
)

// EntryState is the metadata lifecycle state.
type EntryState string

const (
	StateReady      EntryState = "ready"
	StateFetching   EntryState = "fetching"
	StateFailed     EntryState = "failed"
	StateCorrupt    EntryState = "corrupt"
	StateQuarantine EntryState = "quarantined"
	StateStale      EntryState = "stale"
)

// Entry is immutable metadata returned to consumers (no raw paths with secrets).
type Entry struct {
	KeyDigest      string
	Kind           ResourceKind
	State          EntryState
	Completeness   Completeness
	ContentDigest  string // sha256 of object body
	ContentSize    int64
	ObjectRelPath  string // relative under objects/ (not absolute host path in metrics)
	SourceETag     string
	BuildBuilding  bool
	FetchedAt      time.Time
	ExpiresAt      time.Time // zero ⇒ no wall expiry; freshness policy applies
	Share          AuthorizationScope
	SubjectKeyHash string // empty for profile_shared; hash only
}

// LookupSource reports where a hit came from.
type LookupSource string

const (
	SourceMiss   LookupSource = "miss"
	SourceL0     LookupSource = "l0"
	SourceDisk   LookupSource = "disk"
	SourceOrigin LookupSource = "origin"
	// SourcePeer reserved for fleet v2 (default-off).
	SourcePeer LookupSource = "peer"
)

// LookupResult accompanies a successful Get/GetOrFetch.
type LookupResult struct {
	Source       LookupSource
	Entry        Entry
	FromCache    bool
	AuthorizedAt time.Time
}
