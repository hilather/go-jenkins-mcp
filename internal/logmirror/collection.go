package logmirror

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/store"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"
)

// CollectionBounds limits multi-log fan-out (LOG-004).
// Zero fields use defaults from DefaultCollectionBounds.
type CollectionBounds struct {
	// MaxConcurrency is the max parallel log acquisitions (default 4).
	MaxConcurrency int
	// MaxTotalBytes caps progressive body bytes across all logs in one session.
	MaxTotalBytes int64
	// MaxPerLogBytes caps progressive body bytes for a single log (default 16 MiB).
	MaxPerLogBytes int64
	// MaxPollsPerLog caps Poll iterations per log (default 256).
	MaxPollsPerLog int
}

// DefaultCollectionBounds returns pilot-safe fan-out limits.
func DefaultCollectionBounds() CollectionBounds {
	return CollectionBounds{
		MaxConcurrency: 4,
		MaxTotalBytes:  64 << 20, // 64 MiB total remote body
		MaxPerLogBytes: 16 << 20, // 16 MiB per log
		MaxPollsPerLog: 256,
	}
}

// Normalize fills zero fields with defaults and clamps invalid values.
func (b CollectionBounds) Normalize() CollectionBounds {
	d := DefaultCollectionBounds()
	if b.MaxConcurrency <= 0 {
		b.MaxConcurrency = d.MaxConcurrency
	}
	if b.MaxTotalBytes <= 0 {
		b.MaxTotalBytes = d.MaxTotalBytes
	}
	if b.MaxPerLogBytes <= 0 {
		b.MaxPerLogBytes = d.MaxPerLogBytes
	}
	if b.MaxPollsPerLog <= 0 {
		b.MaxPollsPerLog = d.MaxPollsPerLog
	}
	return b
}

// LogRequest is one log to acquire into the local store (same profile as Coordinator).
type LogRequest struct {
	Job   string
	Build int64
	// Relation is an optional non-secret label for later pack selection
	// (e.g. "primary", "upstream", "downstream", "related").
	// Wave 30: tools layer may populate via GetBuildGraph when include_related is set.
	// Affinity / L2 pack selection from relations remains residual (ARC).
	Relation string
}

// LogAcquireResult is the per-log outcome of a multi-log acquisition.
type LogAcquireResult struct {
	Key          LogKey
	Relation     string
	State        State
	BytesFetched int64
	// Err is non-nil when this log failed or was cancelled; other logs may succeed.
	Err error
}

// CollectionResult is the outcome of Coordinator.Acquire (partial success allowed).
type CollectionResult struct {
	// CollectionID is an opaque session id for membership / later pack selection.
	CollectionID string
	Profile      string
	// Results are sorted by (job, build) for determinism.
	Results    []LogAcquireResult
	TotalBytes int64
	// Cancelled is true when the parent context was cancelled mid-fan-out.
	Cancelled bool
	// TruncatedBudget is true when MaxTotalBytes stopped further fetches.
	TruncatedBudget bool
}

// BuildStatusSource reports whether a Jenkins build has finished writing.
// Optional on Coordinator / Access; when nil, polls use buildComplete=false
// until the progressive stream reports !moreData with empty body (best effort).
type BuildStatusSource interface {
	IsComplete(ctx context.Context, job string, build int64) (bool, error)
}

// CollectionCatalog persists multi-log collection membership (LOG-004 durable).
// Membership/refs only — never log bodies. *store.Meta implements this.
// Optional on Coordinator; when nil, sessions remain in-process only.
type CollectionCatalog interface {
	CreateCollection(ctx context.Context, c *store.LogCollection) error
	GetCollection(ctx context.Context, collectionID, profile string) (*store.LogCollection, error)
	UpsertMember(ctx context.Context, mem *store.LogCollectionMember) error
	ListMembers(ctx context.Context, collectionID, profile string) ([]store.LogCollectionMember, error)
	SetCollectionSealed(ctx context.Context, collectionID, profile string, sealed bool) error
}

// Coordinator fans out multi-log acquisition into per-log generations/frames (LOG-004).
//
// Isolation: all LogKeys use Coordinator.Profile only — never mixes profiles/users.
// Streaming: each progressive response is Append'd via Machine into independent
// frames (no raw multi-log buffer). Duplicate (job,build) requests share one
// Machine acquisition (single-flight on Poll).
//
// When Catalog is set, collection membership is written to SQLite so
// collection_id survives process restart (same profile). Log bodies stay in L1 frames.
//
// Do not pack running logs into L2 archives here; seal independently first.
type Coordinator struct {
	// Profile is required and stamped on every LogKey (same-profile isolation).
	Profile string
	// Machine performs Poll/Append into store frames.
	Machine *Machine
	// Status optional build completion probe.
	Status BuildStatusSource
	// Bounds limits concurrency and remote bytes (zero ⇒ defaults).
	Bounds CollectionBounds
	// Catalog optional durable membership store (*store.Meta).
	Catalog CollectionCatalog

	mu          sync.Mutex
	collections map[string]*CollectionSession
}

// CollectionSession records membership for one acquisition session.
// In-process cache; durable copy lives in Catalog when configured.
// Relation labels may come from caller or Wave 30 related discovery; L2 pack
// affinity selection from those labels remains residual (ARC).
type CollectionSession struct {
	ID      string
	Profile string
	Members []LogKey
	// Relations maps LogKey.String() → relation label (optional).
	Relations map[string]string
}

// NewCoordinator builds a multi-log coordinator bound to one profile + machine.
// Catalog may be attached after construction (same Meta as Machine).
func NewCoordinator(profile string, m *Machine, bounds CollectionBounds) *Coordinator {
	return &Coordinator{
		Profile:     profile,
		Machine:     m,
		Bounds:      bounds.Normalize(),
		collections: make(map[string]*CollectionSession),
	}
}

// Acquire deduplicates logs, fetches concurrently under bounds, and streams
// each into its own generation/frames via Machine. Partial success is reported
// per log; cancellation stops further work and leaves recoverable committed frames.
func (c *Coordinator) Acquire(ctx context.Context, logs []LogRequest) (CollectionResult, error) {
	if c == nil || c.Machine == nil {
		return CollectionResult{}, apperr.New(apperr.CodeInternal, "log coordinator is not configured")
	}
	profile := c.Profile
	if profile == "" {
		return CollectionResult{}, apperr.New(apperr.CodeInvalidArgument, "profile is required for multi-log acquisition")
	}
	bounds := c.Bounds.Normalize()

	// Deduplicate by job|build; first relation wins.
	type member struct {
		req LogRequest
		key LogKey
	}
	seen := make(map[string]struct{})
	var members []member
	for _, req := range logs {
		key := LogKey{Profile: profile, Job: req.Job, Build: req.Build}
		if err := key.Validate(); err != nil {
			return CollectionResult{}, err
		}
		// Isolation: never accept a foreign profile via request mutation.
		if key.Profile != profile {
			return CollectionResult{}, apperr.New(apperr.CodeInvalidArgument,
				"cross-profile log acquisition is not allowed")
		}
		sk := key.String()
		if _, ok := seen[sk]; ok {
			continue
		}
		seen[sk] = struct{}{}
		members = append(members, member{req: req, key: key})
	}
	// Deterministic order for tests and pack selection.
	sort.Slice(members, func(i, j int) bool {
		if members[i].key.Job != members[j].key.Job {
			return members[i].key.Job < members[j].key.Job
		}
		return members[i].key.Build < members[j].key.Build
	})

	collID, err := newCollectionID()
	if err != nil {
		return CollectionResult{}, err
	}
	session := &CollectionSession{
		ID:        collID,
		Profile:   profile,
		Relations: make(map[string]string),
	}
	for _, m := range members {
		session.Members = append(session.Members, m.key)
		if m.req.Relation != "" {
			session.Relations[m.key.String()] = m.req.Relation
		}
	}
	// Durable catalog first so collection_id is recoverable even if process dies mid-fan-out.
	if err := c.persistNewCollection(ctx, session); err != nil {
		return CollectionResult{}, err
	}
	c.mu.Lock()
	c.collections[collID] = session
	c.mu.Unlock()

	out := CollectionResult{
		CollectionID: collID,
		Profile:      profile,
		Results:      make([]LogAcquireResult, len(members)),
	}
	if len(members) == 0 {
		return out, nil
	}

	var totalBytes atomic.Int64
	var budgetHit atomic.Bool
	sem := semaphore.NewWeighted(int64(bounds.MaxConcurrency))

	g, gctx := errgroup.WithContext(ctx)
	for i, m := range members {
		i, m := i, m
		g.Go(func() error {
			// Acquire concurrency slot (respect cancellation).
			if err := sem.Acquire(gctx, 1); err != nil {
				out.Results[i] = LogAcquireResult{
					Key:      m.key,
					Relation: m.req.Relation,
					Err:      mapCancel(err),
				}
				return nil // partial success; do not fail the group
			}
			defer sem.Release(1)

			if budgetHit.Load() {
				out.Results[i] = LogAcquireResult{
					Key:      m.key,
					Relation: m.req.Relation,
					Err:      apperr.New(apperr.CodeQuota, "collection total byte budget exhausted"),
				}
				return nil
			}

			res := c.acquireOne(gctx, m.key, m.req.Relation, bounds, &totalBytes, &budgetHit)
			out.Results[i] = res
			return nil
		})
	}
	// errgroup only returns errors from our Go funcs; we never return non-nil
	// so wait always succeeds. Context cancellation is reflected per result.
	_ = g.Wait()

	out.TotalBytes = totalBytes.Load()
	out.TruncatedBudget = budgetHit.Load()
	if err := ctx.Err(); err != nil {
		out.Cancelled = true
	}
	// Also mark cancelled if any result is cancellation without parent still active.
	for _, r := range out.Results {
		if r.Err != nil && apperr.IsCancelled(r.Err) {
			out.Cancelled = true
			break
		}
	}
	// Refresh durable member states after fan-out (best-effort; frames already durable).
	c.persistAcquireResults(ctx, collID, profile, out.Results)
	return out, nil
}

// Session returns a previously recorded collection membership.
// Prefer LoadSession when a context and durable-catalog errors matter.
// Falls back to Catalog (same profile) so membership survives restart.
func (c *Coordinator) Session(id string) (*CollectionSession, bool) {
	s, err := c.LoadSession(context.Background(), id)
	if err != nil || s == nil {
		return nil, false
	}
	return s, true
}

// LoadSession returns collection membership from the in-process cache, or loads
// durable catalog rows when Catalog is set and the id is missing in-process.
// Same-profile only. Fail closed on corrupt catalog rows.
func (c *Coordinator) LoadSession(ctx context.Context, collectionID string) (*CollectionSession, error) {
	if c == nil {
		return nil, apperr.New(apperr.CodeInternal, "log coordinator is not configured")
	}
	id := strings.TrimSpace(collectionID)
	if id == "" {
		return nil, apperr.New(apperr.CodeInvalidArgument, "collection id is required")
	}
	c.mu.Lock()
	if s, ok := c.collections[id]; ok && s != nil {
		c.mu.Unlock()
		if s.Profile != c.Profile {
			return nil, apperr.New(apperr.CodeInternal, "collection profile mismatch")
		}
		return s, nil
	}
	c.mu.Unlock()

	if c.Catalog == nil {
		return nil, apperr.New(apperr.CodeNotFound, "collection not found")
	}
	if err := ctx.Err(); err != nil {
		return nil, apperr.Wrap(apperr.CodeCancelled, "load collection cancelled", err)
	}
	coll, err := c.Catalog.GetCollection(ctx, id, c.Profile)
	if err != nil {
		return nil, err
	}
	if coll == nil {
		return nil, apperr.New(apperr.CodeNotFound, "collection not found")
	}
	if coll.Profile != c.Profile {
		return nil, apperr.New(apperr.CodeInternal, "collection profile mismatch")
	}
	members, err := c.Catalog.ListMembers(ctx, id, c.Profile)
	if err != nil {
		return nil, err
	}
	session := &CollectionSession{
		ID:        id,
		Profile:   c.Profile,
		Relations: make(map[string]string),
	}
	for _, mem := range members {
		if mem.Profile != c.Profile {
			return nil, apperr.New(apperr.CodeCorruptCache, "collection member profile mismatch")
		}
		key := LogKey{Profile: c.Profile, Job: mem.Job, Build: mem.Build}
		if err := key.Validate(); err != nil {
			return nil, apperr.Wrap(apperr.CodeCorruptCache, "corrupt collection member", err)
		}
		session.Members = append(session.Members, key)
		if mem.Relation != "" {
			session.Relations[key.String()] = mem.Relation
		}
	}
	c.mu.Lock()
	// Another goroutine may have loaded concurrently; prefer existing.
	if existing, ok := c.collections[id]; ok && existing != nil {
		c.mu.Unlock()
		return existing, nil
	}
	c.collections[id] = session
	c.mu.Unlock()
	return session, nil
}

// SealedMembers returns sealed LogKeys from a collection for later pack selection.
// Never returns keys from another profile. Loads durable catalog when needed.
func (c *Coordinator) SealedMembers(ctx context.Context, collectionID string) ([]LogKey, error) {
	s, err := c.LoadSession(ctx, collectionID)
	if err != nil {
		return nil, err
	}
	if s.Profile != c.Profile {
		return nil, apperr.New(apperr.CodeInternal, "collection profile mismatch")
	}
	var sealed []LogKey
	for _, key := range s.Members {
		if key.Profile != c.Profile {
			continue // isolation belt-and-suspenders
		}
		st, err := c.Machine.State(ctx, key)
		if err != nil {
			return nil, err
		}
		if st.Sealed {
			sealed = append(sealed, key)
		}
	}
	return sealed, nil
}

// persistNewCollection writes collection + pending members to Catalog (no-op if unset).
func (c *Coordinator) persistNewCollection(ctx context.Context, session *CollectionSession) error {
	if c == nil || c.Catalog == nil || session == nil {
		return nil
	}
	if err := c.Catalog.CreateCollection(ctx, &store.LogCollection{
		ID:      session.ID,
		Profile: session.Profile,
	}); err != nil {
		return err
	}
	for _, key := range session.Members {
		rel := ""
		if session.Relations != nil {
			rel = session.Relations[key.String()]
		}
		if err := c.Catalog.UpsertMember(ctx, &store.LogCollectionMember{
			CollectionID: session.ID,
			Profile:      session.Profile,
			Job:          key.Job,
			Build:        key.Build,
			State:        store.CollectionMemberPending,
			Relation:     rel,
		}); err != nil {
			return err
		}
	}
	return nil
}

// persistAcquireResults updates durable member states after fan-out (best-effort).
func (c *Coordinator) persistAcquireResults(ctx context.Context, collID, profile string, results []LogAcquireResult) {
	if c == nil || c.Catalog == nil {
		return
	}
	allSealed := len(results) > 0
	for _, r := range results {
		state := memberStateFromResult(r)
		if state != store.CollectionMemberSealed {
			allSealed = false
		}
		mem := &store.LogCollectionMember{
			CollectionID: collID,
			Profile:      profile,
			Job:          r.Key.Job,
			Build:        r.Key.Build,
			State:        state,
			Relation:     r.Relation,
			GenerationID: r.State.GenerationID,
		}
		// Ignore individual upsert errors: L1 frames are the source of truth for
		// seal status; residual continue re-checks Machine.State.
		_ = c.Catalog.UpsertMember(ctx, mem)
	}
	if allSealed {
		_ = c.Catalog.SetCollectionSealed(ctx, collID, profile, true)
	}
}

func memberStateFromResult(r LogAcquireResult) string {
	if r.Err != nil {
		if apperr.CodeOf(r.Err) == apperr.CodeQuota {
			return store.CollectionMemberSkipped
		}
		if r.State.Sealed {
			return store.CollectionMemberSealed
		}
		if r.State.DurableOffset > 0 {
			return store.CollectionMemberMirrored
		}
		return store.CollectionMemberError
	}
	if r.State.Sealed {
		return store.CollectionMemberSealed
	}
	return store.CollectionMemberMirrored
}

func (c *Coordinator) acquireOne(
	ctx context.Context,
	key LogKey,
	relation string,
	bounds CollectionBounds,
	totalBytes *atomic.Int64,
	budgetHit *atomic.Bool,
) LogAcquireResult {
	res := LogAcquireResult{Key: key, Relation: relation}
	before := c.Machine.BytesFetched(key)

	// Shared Ensure options for single-log path.
	opt := EnsureOptions{
		MaxBytes:     bounds.MaxPerLogBytes,
		MaxPolls:     bounds.MaxPollsPerLog,
		Status:       c.Status,
		TotalCounter: totalBytes,
		TotalLimit:   bounds.MaxTotalBytes,
		OnBudgetHit: func() {
			budgetHit.Store(true)
		},
	}
	st, err := ensureMirrored(ctx, c.Machine, key, opt)
	res.State = st
	res.BytesFetched = c.Machine.BytesFetched(key) - before
	if res.BytesFetched < 0 {
		res.BytesFetched = 0
	}
	if err != nil {
		res.Err = err
	}
	return res
}

func newCollectionID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", apperr.Wrap(apperr.CodeInternal, "failed to allocate collection id", err)
	}
	return hex.EncodeToString(b[:]), nil
}

func mapCancel(err error) error {
	if err == nil {
		return nil
	}
	if apperr.IsCancelled(err) || apperr.IsTimeout(err) {
		return err
	}
	if err == context.Canceled {
		return apperr.Wrap(apperr.CodeCancelled, "collection cancelled", err)
	}
	if err == context.DeadlineExceeded {
		return apperr.Wrap(apperr.CodeTimeout, "collection timed out", err)
	}
	return apperr.Wrap(apperr.CodeCancelled, "collection stopped", err)
}

// String for debugging (no secrets).
func (r CollectionResult) String() string {
	return fmt.Sprintf("collection=%s profile=%s logs=%d bytes=%d cancelled=%v budget=%v",
		r.CollectionID, r.Profile, len(r.Results), r.TotalBytes, r.Cancelled, r.TruncatedBudget)
}
