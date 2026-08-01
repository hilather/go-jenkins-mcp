package diagnostics

// DefaultMaxFindings is the default cap on returned findings (0 ⇒ this value).
const DefaultMaxFindings = 15

// HardMaxFindings is the absolute findings ceiling.
const HardMaxFindings = 50

// DefaultMaxEvidenceLines caps evidence lines attached per finding.
const DefaultMaxEvidenceLines = 3

// HardMaxEvidenceLines is the absolute evidence-line ceiling per finding.
const HardMaxEvidenceLines = 10

// MaxMessageBytes truncates a single finding message / evidence line.
const MaxMessageBytes = 2 << 10 // 2 KiB

// Finding is one deterministic error candidate with evidence and a signature.
//
// LineStart / LineEnd are 1-based inclusive line numbers within the scanned
// text (or absolute lines when derived from search hits). Every Finding maps
// to at least one evidence line from the source.
type Finding struct {
	// Signature is a short hex digest of Normalized (stable across volatile tokens).
	Signature string `json:"signature"`
	// Pattern is the rule id that matched (e.g. "build_failure", "error_prefix").
	Pattern string `json:"pattern"`
	// Message is the primary (first) matched line, truncated.
	Message string `json:"message"`
	// Normalized is the signature preimage after NormalizeLine.
	Normalized string `json:"normalized,omitempty"`
	// Confidence is in [0,1]; higher means a stronger literal failure marker.
	Confidence float64 `json:"confidence"`
	// LineStart / LineEnd are 1-based inclusive evidence range for the primary hit.
	LineStart int64 `json:"line_start"`
	LineEnd   int64 `json:"line_end"`
	// Count is how many times this signature appeared in the scan.
	Count int `json:"count"`
	// Evidence is a small set of representative source lines (message first).
	Evidence []EvidenceLine `json:"evidence,omitempty"`
}

// EvidenceLine is one source line tied to a finding.
type EvidenceLine struct {
	// Line is 1-based within the scanned input (or absolute when from hits).
	Line int64 `json:"line"`
	// Text is the line body (newline stripped; may be truncated).
	Text string `json:"text"`
}

// SearchHit is a line-oriented hit from local search (SEARCH-001/002) used as
// an alternate input to extraction when full log text is not available.
type SearchHit struct {
	// Line is 1-based absolute line number when known; 0 means unknown (assigned order).
	Line int64
	// Text is the matching line body.
	Text string
}

// Options controls extraction bounds. Zero values use package defaults.
type Options struct {
	// MaxFindings caps distinct signatures returned (0 ⇒ DefaultMaxFindings).
	MaxFindings int
	// MaxEvidenceLines caps evidence lines per finding (0 ⇒ DefaultMaxEvidenceLines).
	MaxEvidenceLines int
	// IncludeNormalized attaches Normalized on each Finding when true.
	IncludeNormalized bool
}

// Result is a bounded extraction response with scan metadata.
type Result struct {
	Findings []Finding `json:"findings"`
	// LinesScanned is the number of input lines examined.
	LinesScanned int `json:"lines_scanned"`
	// Truncated is true when MaxFindings stopped more signatures from being returned.
	Truncated bool `json:"truncated,omitempty"`
	// FirstErrorLine is the 1-based line of the earliest high-confidence hit (0 if none).
	FirstErrorLine int64 `json:"first_error_line,omitempty"`
	// LastErrorLine is the 1-based line of the latest high-confidence hit (0 if none).
	LastErrorLine int64 `json:"last_error_line,omitempty"`
}
