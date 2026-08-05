package cachecontrol

import "context"

// Adapter exposes management surfaces for one cache type.
// Data-path Lookup/Fill are optional; modes are enforced by callers via
// EffectiveTypeConfig and Mode helpers even when DataPath is not implemented.
type Adapter interface {
	// Descriptor returns the static capability advertisement (must match registration).
	Descriptor(ctx context.Context) Descriptor
	// Snapshot returns a secret-free operational snapshot for the type.
	Snapshot(ctx context.Context, cfg EffectiveTypeConfig) (TypeSnapshot, error)
	// ListEntries returns a page of entry summaries when SupportsList.
	// Unsupported types return a structured error with ReasonUnsupportedOp.
	ListEntries(ctx context.Context, q EntryQuery) (EntryPage, error)
	// Plan builds a lifecycle operation plan (dump/purge/verify/repair/gc).
	Plan(ctx context.Context, req OperationRequest) (OperationPlan, error)
	// Execute runs a previously planned operation under OperationContext.
	Execute(ctx context.Context, oc OperationContext, plan OperationPlan) error
}

// DataPath is an optional data-plane integration for Lookup/Fill mode gates.
// Not all adapters implement it (e.g. admin-only types may omit).
type DataPath interface {
	// Lookup attempts a cache read. Callers must already have authorized the request.
	Lookup(ctx context.Context, key ResourceKey, ac AccessContext) (LookupResult, error)
	// Fill stages or commits a cache write. Callers must re-check mode and purge epoch.
	Fill(ctx context.Context, req FillRequest) (FillResult, error)
}

// AccessContext is a non-secret identity handle for data-path calls.
// Mirrors resourcecache.AccessContext fields without importing that package.
type AccessContext struct {
	SubjectKey  string
	PrincipalID string
	ProfileID   string
	Groups      []string
}

// ResourceKey identifies a logical cache entry without embedding secrets.
type ResourceKey struct {
	TypeID      TypeID
	JobFullName string
	BuildNumber int64
	// Selector is type-specific (artifact path, stage id, etc.) — never a credential.
	Selector string
	// Variant scopes partial results (limits, redaction version, etc.).
	Variant string
}

// LookupResult is a cache lookup outcome.
type LookupResult struct {
	Hit          bool
	Complete     bool
	LogicalBytes int64
	// Body is optional small structured payload; large bodies use storage handles.
	Body []byte
}

// FillRequest describes a write into the cache.
type FillRequest struct {
	Key            ResourceKey
	Access         AccessContext
	Body           []byte
	Complete       bool
	ConfigRevision uint64
	PurgeEpoch     uint64
}

// FillResult is the outcome of a fill attempt.
type FillResult struct {
	Committed bool
	Discarded bool
	Reason    string // stable reason code when discarded
}

// TypeSnapshot is a secret-free per-type status for admin inventory.
type TypeSnapshot struct {
	TypeID         TypeID         `json:"typeId"`
	Mode           Mode           `json:"mode"`
	Availability   Availability   `json:"availability"`
	EntryCount     int64          `json:"entryCount,omitempty"`
	LogicalBytes   int64          `json:"logicalBytes,omitempty"`
	PhysicalBytes  int64          `json:"physicalBytes,omitempty"`
	SizeAccounting SizeAccounting `json:"sizeAccounting"`
	PurgeEpoch     uint64         `json:"purgeEpoch,omitempty"`
	ConfigRevision uint64         `json:"configRevision,omitempty"`
	Notes          string         `json:"notes,omitempty"`
}

// EntryQuery filters list requests.
type EntryQuery struct {
	TypeID TypeID
	Limit  int
	Cursor string
	// JobFullName / BuildNumber are optional safe internal selectors.
	JobFullName string
	BuildNumber int64
	State       string
}

// EntrySummary is a secret-free list row (identities may be hashed when required).
type EntrySummary struct {
	EntryID      string `json:"entryId"`
	TypeID       TypeID `json:"typeId"`
	State        string `json:"state,omitempty"`
	LogicalBytes int64  `json:"logicalBytes,omitempty"`
	// JobBuildLabel is optional non-secret display (may be redacted/hashed).
	JobBuildLabel string `json:"jobBuildLabel,omitempty"`
	Complete      bool   `json:"complete"`
}

// EntryPage is a cursor page of entries.
type EntryPage struct {
	Entries    []EntrySummary `json:"entries"`
	NextCursor string         `json:"nextCursor,omitempty"`
	Truncated  bool           `json:"truncated,omitempty"`
}

// OperationRequest is a plan request for a lifecycle operation.
type OperationRequest struct {
	Kind   OperationKind
	TypeID TypeID
	// DumpMode is required for dump; ignored otherwise.
	DumpMode DumpMode
	// Selector binds the plan to a query fingerprint.
	Selector map[string]string
	// Reason is operator-supplied free text (bounded; audit only).
	Reason string
}

// OperationPlan is a durable-ish plan token payload (secret-free).
type OperationPlan struct {
	PlanID         string        `json:"planId"`
	Kind           OperationKind `json:"kind"`
	TypeID         TypeID        `json:"typeId"`
	DumpMode       DumpMode      `json:"dumpMode,omitempty"`
	EstimatedBytes int64         `json:"estimatedBytes,omitempty"`
	EstimatedCount int64         `json:"estimatedCount,omitempty"`
	// ConfirmToken is the exact string required to execute (e.g. PURGE, DUMP).
	ConfirmToken  string `json:"confirmToken,omitempty"`
	ExpiresAtUnix int64  `json:"expiresAtUnix,omitempty"`
	// Fingerprint binds plan to selector/revision (opaque hex).
	Fingerprint string `json:"fingerprint,omitempty"`
	Notes       string `json:"notes,omitempty"`
}

// OperationContext carries execution authority (non-secret).
type OperationContext struct {
	ActorIDHash    string
	Source         string // admin_http | admin_mcp | cli
	Confirm        string
	ConfigRevision uint64
	PurgeEpoch     uint64
}
