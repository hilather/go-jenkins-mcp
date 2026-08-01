package search

// Mode selects the matcher (SEARCH-001 literal, SEARCH-002 regex).
type Mode int

const (
	// ModeLiteral is case-aware substring search (default).
	ModeLiteral Mode = iota
	// ModeRegex uses Go's RE2-compatible regexp engine.
	ModeRegex
)

// Default limits (server-side; callers may lower, not raise past Max* hard caps).
const (
	// DefaultMaxMatches is the match count cap when Query.MaxMatches <= 0.
	DefaultMaxMatches = 100
	// HardMaxMatches is the absolute match count ceiling.
	HardMaxMatches = 10_000

	// DefaultMaxBytesScanned caps uncompressed bytes decompressed per search.
	DefaultMaxBytesScanned = 64 << 20 // 64 MiB
	// HardMaxBytesScanned is the absolute scan ceiling (1 GiB calibration headroom).
	HardMaxBytesScanned = 1 << 30 // 1 GiB

	// DefaultBeforeLines / DefaultAfterLines when Query fields are zero and
	// UseDefaultContext is true. Zero Query.Before/After with UseDefaultContext
	// false means no context lines (explicit).
	DefaultBeforeLines = 0
	DefaultAfterLines  = 0
	// HardMaxContextLines caps before/after context lines.
	HardMaxContextLines = 50

	// MaxPatternBytes rejects oversized patterns (regex complexity guard).
	MaxPatternBytes = 4 << 10 // 4 KiB

	// MaxSnippetBytes truncates a single line/context snippet in results.
	MaxSnippetBytes = 8 << 10 // 8 KiB

	// cancelCheckEveryNLines is how often ctx is checked during a long frame.
	cancelCheckEveryNLines = 64
)

// Query describes a local log search over one generation's L1 frames.
//
// Scope resolution:
//   - GenerationID > 0 wins (direct SQLite row id).
//   - Otherwise Profile + Job + Build is required; Generation (number) 0 means
//     the latest generation for that log key.
type Query struct {
	// GenerationID is the SQLite log_generations.id when known.
	GenerationID int64

	// Profile, Job, Build resolve the generation when GenerationID is unset.
	Profile string
	Job     string
	Build   int64
	// Generation is the monotonic generation number for Profile/Job/Build
	// (0 = latest). Ignored when GenerationID is set.
	Generation int64

	// Pattern is the literal substring or RE2 regex.
	Pattern string
	// Mode is ModeLiteral (default) or ModeRegex.
	Mode Mode
	// CaseSensitive controls literal folding and, for regex, injects (?i) when false.
	CaseSensitive bool

	// Before / After are context lines around each match (clamped to HardMaxContextLines).
	Before int
	After  int

	// MaxMatches caps returned matches (0 ⇒ DefaultMaxMatches; clamped to HardMaxMatches).
	MaxMatches int
	// MaxBytesScanned caps uncompressed frame bytes opened (0 ⇒ DefaultMaxBytesScanned).
	MaxBytesScanned int64
}

// Match is one ordered hit with evidence offsets and context snippets.
type Match struct {
	// Line is the 0-based absolute line index within the generation.
	Line int64
	// LineByteStart is the absolute raw offset of the first byte of the line.
	LineByteStart int64
	// MatchByteStart / MatchByteEnd are absolute raw offsets of the first match
	// within the line (end exclusive).
	MatchByteStart int64
	MatchByteEnd   int64

	// LineText is the matching line (newline stripped; may be truncated).
	LineText string
	// Before / After are ordered context lines (oldest first for Before).
	Before []string
	After  []string

	// FrameSeq is the L1 frame sequence containing the match line start.
	FrameSeq int
	// ContentSHA256 is the frame content checksum (evidence).
	ContentSHA256 string
}

// Result is a bounded, ordered search response.
type Result struct {
	Matches []Match

	// Truncated is true when MaxMatches stopped the search (more may exist).
	Truncated bool
	// Incomplete is true when MaxBytesScanned stopped the search before EOF.
	Incomplete bool

	FramesOpened    int
	BytesScanned    int64
	BytesScannedCap int64
	MaxMatches      int

	GenerationID int64
	Generation   int64
	Profile      string
	Job          string
	Build        int64
	Sealed       bool
}

// Scope identifies a single log generation without scanning frames.
// Used by tools to re-evaluate job policy before Search (Wave 19 SEARCH/POL).
type Scope struct {
	GenerationID int64
	Generation   int64
	Profile      string
	Job          string
	Build        int64
	Sealed       bool
}
