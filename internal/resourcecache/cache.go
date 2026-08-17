package resourcecache

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/resourcecache/blob"
	"github.com/hilather/go-jenkins-mcp/internal/resourcecache/meta"
	"github.com/hilather/go-jenkins-mcp/internal/resourcecache/structured"
	"github.com/hilather/go-jenkins-mcp/internal/store"
	"golang.org/x/sync/singleflight"
)

// ModePolicy optionally gates cache lookup/fill per kind (ADR 0018).
// When nil, both lookup and fill are allowed (pre-control-plane compatibility).
// Implementations must not authorize access — only mode decisions.
type ModePolicy interface {
	// AllowLookup reports whether existing entries may be served for kind.
	AllowLookup(kind ResourceKind) bool
	// AllowFill reports whether new entries may be written for kind.
	AllowFill(kind ResourceKind) bool
}

// EpochProvider supplies the current purge epoch for a kind (late-fill protection).
// When nil, epoch checks are skipped (compat).
type EpochProvider interface {
	PurgeEpoch(kind ResourceKind) uint64
}

// TelemetrySink records low-cardinality cache events (no job/path/subject labels).
type TelemetrySink interface {
	OnResourceEvent(kind ResourceKind, layer, outcome string, bytes int64, reason string)
}

// Config configures a Cache instance.
type Config struct {
	// CacheDir is the profile cache root (contains resources.sqlite + objects/).
	CacheDir string
	// Verifier is required for GetOrFetch authorization (fail closed if nil).
	Verifier AuthorizationVerifier
	// Freshness defaults when zero.
	Freshness FreshnessPolicy
	// DefaultShare for new entries.
	DefaultShare AuthorizationScope
	// Modes is optional cache-control mode policy (nil ⇒ read_write for all kinds).
	Modes ModePolicy
	// Epochs optional purge-epoch provider for late-fill discard.
	Epochs EpochProvider
	// Telemetry optional event sink.
	Telemetry TelemetrySink
}

// Cache is the facade used by tools and diagnostics.
type Cache struct {
	cfg   Config
	db    *meta.DB
	blobs *blob.Store
	sf    singleflight.Group
	mu    sync.RWMutex
	l0    map[string]l0entry
	l0Max int
	now   func() time.Time
	fetch SourceFetcher // optional default; overridable per request
}

type l0entry struct {
	entry Entry
	body  []byte // structured decoded raw JSON zstd still compressed, or blob bytes for small
	at    time.Time
}

// Open creates a Cache under cfg.CacheDir.
func Open(cfg Config) (*Cache, error) {
	if cfg.CacheDir == "" {
		return nil, apperr.New(apperr.CodeInvalidArgument, "resource cache dir required")
	}
	if err := store.EnsureDir(cfg.CacheDir); err != nil {
		return nil, err
	}
	db, err := meta.Open(cfg.CacheDir)
	if err != nil {
		return nil, err
	}
	bs, err := blob.New(cfg.CacheDir)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	if cfg.Freshness.BuildingTTL == 0 && cfg.Freshness.TerminalTTL == 0 {
		cfg.Freshness = DefaultFreshness()
	}
	if cfg.DefaultShare == "" {
		cfg.DefaultShare = ScopeSubjectPrivate
	}
	c := &Cache{
		cfg:   cfg,
		db:    db,
		blobs: bs,
		l0:    make(map[string]l0entry),
		l0Max: 64,
		now:   func() time.Time { return time.Now().UTC() },
	}
	// Recovery: incomplete/fetching rows must not serve as complete.
	_, _ = db.QuarantineIncomplete(context.Background())
	return c, nil
}

// Close closes metadata DB.
func (c *Cache) Close() error {
	if c == nil {
		return nil
	}
	return c.db.Close()
}

// DB exposes metadata for tests/doctor.
func (c *Cache) DB() *meta.DB { return c.db }

// Blobs exposes blob store for tests.
func (c *Cache) Blobs() *blob.Store { return c.blobs }

// FetchRequest is a GetOrFetch request.
type FetchRequest struct {
	Key    ResourceKey
	Access AccessContext
	// Source overrides the origin fetcher for this call.
	Source SourceFetcher
	// ArtifactPath for AuthorizeArtifact (may equal Key.Selector).
	ArtifactPath string
	// Verifier overrides cfg.Verifier for this call (tools pass live policy).
	Verifier AuthorizationVerifier
}

// EntryReader gives access to cached payload bytes (structured zstd or blob).
type EntryReader struct {
	Entry Entry
	// Data is the object bytes (JSON+zstd for structured; raw for blob).
	Data []byte
}

// DecodeStructured unmarshals structured JSON+zstd into dest.
func (r EntryReader) DecodeStructured(dest any) error {
	return structured.DecodeJSONZstd(r.Data, dest)
}

// GetOrFetch returns a ready entry from L0/disk or fetches from origin.
// Authorization always runs before mode gates and again on hits (ADR 0017/0018).
// Mode policy (when set) may skip lookup and/or fill; it never grants access.
func (c *Cache) GetOrFetch(ctx context.Context, req FetchRequest) (EntryReader, LookupResult, error) {
	if c == nil {
		return EntryReader{}, LookupResult{}, apperr.New(apperr.CodeInternal, "resource cache is nil")
	}
	ver := req.Verifier
	if ver == nil {
		ver = c.cfg.Verifier
	}
	if ver == nil {
		return EntryReader{}, LookupResult{}, apperr.New(apperr.CodeInternal, "authorization verifier required")
	}
	key, err := req.Key.Normalize()
	if err != nil {
		return EntryReader{}, LookupResult{}, err
	}
	key.ProfileID = firstNonEmpty(key.ProfileID, req.Access.ProfileID)
	key, err = key.Normalize()
	if err != nil {
		return EntryReader{}, LookupResult{}, err
	}
	if err := ver.AuthorizeJob(ctx, req.Access, key.JobFullName); err != nil {
		return EntryReader{}, LookupResult{}, err
	}

	// Artifact policy only for artifact kinds. Never fall Selector (stage id,
	// empty catalog selector, etc.) into AuthorizeArtifact — that evaluates
	// jenkins_get_artifact_text and deny_artifact_paths incorrectly.
	artPath := strings.TrimSpace(req.ArtifactPath)
	if artPath == "" && RequiresArtifactAuth(key.Kind) {
		artPath = key.Selector
	}
	if !RequiresArtifactAuth(key.Kind) {
		artPath = "" // ignore accidental ArtifactPath for non-artifact kinds
	}
	if artPath != "" {
		if err := ver.AuthorizeArtifact(ctx, req.Access, key.JobFullName, artPath); err != nil {
			return EntryReader{}, LookupResult{}, err
		}
	}

	allowLookup := c.allowLookup(key.Kind)
	allowFill := c.allowFill(key.Kind)

	// subject_private: isolate digests per subject so entries cannot be reused cross-subject.
	share := c.cfg.DefaultShare
	if share == "" {
		share = ScopeSubjectPrivate
	}
	digest, err := c.storageDigest(key, req.Access)
	if err != nil {
		return EntryReader{}, LookupResult{}, err
	}

	// L0 hit (only when mode allows read)
	if allowLookup {
		if er, lr, ok := c.l0Get(digest); ok && c.cfg.Freshness.IsFresh(er.Entry, c.now()) {
			if !entryVisibleTo(er.Entry, req.Access, share) {
				// Treat as miss (should not happen when digests include sk=).
			} else if err := c.reauth(ctx, req, key, artPath, ver); err != nil {
				c.emitTel(key.Kind, "l0", "auth_deny", 0, "policy")
				return EntryReader{}, LookupResult{}, err
			} else {
				lr.AuthorizedAt = c.now()
				c.emitTel(key.Kind, "l0", "hit", int64(len(er.Data)), "")
				return er, lr, nil
			}
		}

		// Disk hit
		if row, ok, err := c.db.GetRow(ctx, digest); err != nil {
			return EntryReader{}, LookupResult{}, err
		} else if ok {
			e := entryFromRow(row)
			if e.State == StateReady && e.Completeness != Incomplete && c.cfg.Freshness.IsFresh(e, c.now()) &&
				entryVisibleTo(e, req.Access, share) {
				data, err := c.readObject(e)
				if err != nil {
					e.State = StateCorrupt
					_ = c.db.PutRow(ctx, rowFromEntry(e, key))
				} else {
					if err := c.reauth(ctx, req, key, artPath, ver); err != nil {
						c.emitTel(key.Kind, "disk", "auth_deny", 0, "policy")
						return EntryReader{}, LookupResult{}, err
					}
					er := EntryReader{Entry: e, Data: data}
					c.l0Put(digest, er)
					c.emitTel(key.Kind, "disk", "hit", int64(len(data)), "")
					return er, LookupResult{Source: SourceDisk, Entry: e, FromCache: true, AuthorizedAt: c.now()}, nil
				}
			}
		}
	} else {
		c.emitTel(key.Kind, "none", "bypass", 0, "mode_disallows_read")
	}

	// Miss / stale / mode-bypass → singleflight fetch (fill gated inside)
	c.emitTel(key.Kind, "none", "miss", 0, "")
	epochAtStart := c.purgeEpoch(key.Kind)
	v, err, _ := c.sf.Do(digest, func() (any, error) {
		return c.fetchAndCommit(ctx, req, key, digest, artPath, ver, allowFill, epochAtStart)
	})
	if err != nil {
		return EntryReader{}, LookupResult{}, err
	}
	r := v.(fetchOutcome)
	return r.er, r.lr, nil
}

func (c *Cache) purgeEpoch(kind ResourceKind) uint64 {
	if c == nil || c.cfg.Epochs == nil {
		return 0
	}
	return c.cfg.Epochs.PurgeEpoch(kind)
}

func (c *Cache) emitTel(kind ResourceKind, layer, outcome string, bytes int64, reason string) {
	if c == nil || c.cfg.Telemetry == nil {
		return
	}
	c.cfg.Telemetry.OnResourceEvent(kind, layer, outcome, bytes, reason)
}

func (c *Cache) allowLookup(kind ResourceKind) bool {
	if c == nil || c.cfg.Modes == nil {
		return true
	}
	return c.cfg.Modes.AllowLookup(kind)
}

func (c *Cache) allowFill(kind ResourceKind) bool {
	if c == nil || c.cfg.Modes == nil {
		return true
	}
	return c.cfg.Modes.AllowFill(kind)
}

type fetchOutcome struct {
	er EntryReader
	lr LookupResult
}

func (c *Cache) reauth(ctx context.Context, req FetchRequest, key ResourceKey, artPath string, ver AuthorizationVerifier) error {
	if ver == nil {
		return apperr.New(apperr.CodeInternal, "authorization verifier required")
	}
	if err := ver.AuthorizeJob(ctx, req.Access, key.JobFullName); err != nil {
		return err
	}
	if artPath != "" {
		return ver.AuthorizeArtifact(ctx, req.Access, key.JobFullName, artPath)
	}
	return nil
}

func (c *Cache) fetchAndCommit(ctx context.Context, req FetchRequest, key ResourceKey, digest, artPath string, ver AuthorizationVerifier, allowFill bool, epochAtStart uint64) (fetchOutcome, error) {
	var out fetchOutcome
	src := req.Source
	if src == nil {
		src = c.fetch
	}
	if src == nil {
		return out, apperr.New(apperr.CodeInternal, "no source fetcher configured")
	}
	// Re-check auth immediately before origin
	if err := c.reauth(ctx, req, key, artPath, ver); err != nil {
		return out, err
	}

	fr, err := src.Fetch(ctx, key, nil)
	if err != nil {
		return out, err
	}
	if fr.Body != nil {
		defer fr.Body.Close()
	}

	comp := fr.Meta.Completeness
	if comp == "" {
		comp = Complete
	}
	if comp == Incomplete {
		// Never seal incomplete as ready.
		return out, apperr.New(apperr.CodeInternal, "origin reported incomplete; not caching")
	}

	class := ClassOf(key.Kind)
	var contentDigest string
	var contentSize int64
	var relPath string
	var data []byte

	// Materialize origin payload in memory first so read_only / off can return
	// without writing when fill is disallowed (mode gate; data retained on disk).
	switch class {
	case ClassImmutableBlob:
		var r io.Reader
		if fr.Body != nil {
			r = fr.Body
		} else if fr.Bytes != nil {
			r = bytes.NewReader(fr.Bytes)
		} else {
			return out, apperr.New(apperr.CodeInternal, "blob fetch missing body")
		}
		if !allowFill {
			// Stream to memory for response only; do not commit.
			b, err := io.ReadAll(io.LimitReader(r, 32<<20))
			if err != nil {
				return out, apperr.Wrap(apperr.CodeInternal, "read origin blob", err)
			}
			e := Entry{
				KeyDigest:     digest,
				Kind:          key.Kind,
				State:         StateReady,
				Completeness:  comp,
				ContentSize:   int64(len(b)),
				SourceETag:    fr.Meta.ETag,
				BuildBuilding: fr.Meta.Building,
				FetchedAt:     c.now(),
			}
			out.er = EntryReader{Entry: e, Data: b}
			out.lr = LookupResult{Source: SourceOrigin, Entry: e, FromCache: false, AuthorizedAt: c.now()}
			c.emitTel(key.Kind, "none", "bypass", int64(len(b)), "mode_disallows_write")
			return out, nil
		}
		// If context cancelled mid-stream, CommitStream fails and staging is cleaned.
		wr, err := c.blobs.CommitStream(r, "")
		if err != nil {
			return out, err
		}
		contentDigest = wr.Digest
		contentSize = wr.Size
		relPath = wr.RelPath
		// Keep small blobs in L0 for tests; large: re-read path on demand
		if contentSize <= 1<<20 {
			data, _ = c.blobs.ReadAll(contentDigest)
		}
	default:
		// structured / derived / stage log
		var payload any = fr.Structured
		if payload == nil && fr.Bytes != nil {
			payload = jsonRaw(fr.Bytes)
		}
		if payload == nil && fr.Body != nil {
			b, err := io.ReadAll(fr.Body)
			if err != nil {
				return out, apperr.Wrap(apperr.CodeInternal, "read structured body", err)
			}
			payload = jsonRaw(b)
		}
		if payload == nil {
			return out, apperr.New(apperr.CodeInternal, "structured fetch missing payload")
		}
		enc, err := structured.EncodeJSONZstd(payload)
		if err != nil {
			return out, err
		}
		if !allowFill {
			e := Entry{
				KeyDigest:     digest,
				Kind:          key.Kind,
				State:         StateReady,
				Completeness:  comp,
				ContentSize:   int64(len(enc)),
				SourceETag:    fr.Meta.ETag,
				BuildBuilding: fr.Meta.Building,
				FetchedAt:     c.now(),
			}
			out.er = EntryReader{Entry: e, Data: enc}
			out.lr = LookupResult{Source: SourceOrigin, Entry: e, FromCache: false, AuthorizedAt: c.now()}
			c.emitTel(key.Kind, "none", "bypass", int64(len(enc)), "mode_disallows_write")
			return out, nil
		}
		wr, err := c.blobs.CommitBytes(enc, "")
		if err != nil {
			return out, err
		}
		contentDigest = wr.Digest
		contentSize = wr.Size
		relPath = wr.RelPath
		data = enc
	}

	writeShare := c.cfg.DefaultShare
	if writeShare == "" {
		writeShare = ScopeSubjectPrivate
	}
	writeSubj := ""
	if writeShare == ScopeSubjectPrivate {
		writeSubj = hashOpaque(req.Access.SubjectKey)
	}
	e := Entry{
		KeyDigest:      digest,
		Kind:           key.Kind,
		State:          StateReady,
		Completeness:   comp,
		ContentDigest:  contentDigest,
		ContentSize:    contentSize,
		ObjectRelPath:  relPath,
		SourceETag:     fr.Meta.ETag,
		BuildBuilding:  fr.Meta.Building,
		FetchedAt:      c.now(),
		Share:          writeShare,
		SubjectKeyHash: writeSubj,
	}
	// Late-fill protection: discard if purge epoch advanced during origin fetch.
	if c.cfg.Epochs != nil && c.purgeEpoch(key.Kind) != epochAtStart {
		c.emitTel(key.Kind, "none", "fill_discarded", contentSize, "purged")
		// Best-effort: if we already committed blob bytes they may be GC'd later;
		// do not link a ready entry after purge.
		out.er = EntryReader{Entry: e, Data: data}
		out.lr = LookupResult{Source: SourceOrigin, Entry: e, FromCache: false, AuthorizedAt: c.now()}
		return out, nil
	}
	// Re-check mode fill before commit (runtime mode change).
	if !c.allowFill(key.Kind) {
		c.emitTel(key.Kind, "none", "fill_discarded", contentSize, "mode_disallows_write")
		out.er = EntryReader{Entry: e, Data: data}
		out.lr = LookupResult{Source: SourceOrigin, Entry: e, FromCache: false, AuthorizedAt: c.now()}
		return out, nil
	}
	if err := c.db.PutRow(ctx, rowFromEntry(e, key)); err != nil {
		return out, err
	}
	c.emitTel(key.Kind, "disk", "fill_ok", contentSize, "")
	if data == nil {
		data, err = c.blobs.ReadAll(contentDigest)
		if err != nil {
			return out, err
		}
	}
	er := EntryReader{Entry: e, Data: data}
	c.l0Put(digest, er)
	out.er = er
	out.lr = LookupResult{Source: SourceOrigin, Entry: e, FromCache: false, AuthorizedAt: c.now()}
	return out, nil
}

func (c *Cache) readObject(e Entry) ([]byte, error) {
	if e.ContentDigest == "" {
		return nil, apperr.New(apperr.CodeCorruptCache, "entry missing content digest")
	}
	if err := c.blobs.VerifyDigest(e.ContentDigest); err != nil {
		return nil, err
	}
	return c.blobs.ReadAll(e.ContentDigest)
}

func (c *Cache) l0Get(digest string) (EntryReader, LookupResult, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.l0[digest]
	if !ok {
		return EntryReader{}, LookupResult{}, false
	}
	return EntryReader{Entry: e.entry, Data: e.body}, LookupResult{Source: SourceL0, Entry: e.entry, FromCache: true}, true
}

func (c *Cache) l0Put(digest string, er EntryReader) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.l0) >= c.l0Max {
		// drop arbitrary one
		for k := range c.l0 {
			delete(c.l0, k)
			break
		}
	}
	c.l0[digest] = l0entry{entry: er.Entry, body: er.Data, at: c.now()}
}

// storageDigest computes the digest GetOrFetch stores (key, ac) under:
// profile fill + subject-private variant fold + normalize + digest.
// An empty AccessContext yields the plain key digest (shared/empty-subject
// entries) — identical to the pre-InvalidateFor behavior of Invalidate/Status.
func (c *Cache) storageDigest(key ResourceKey, ac AccessContext) (string, error) {
	key, err := key.Normalize()
	if err != nil {
		return "", err
	}
	key.ProfileID = firstNonEmpty(key.ProfileID, ac.ProfileID)
	key, err = key.Normalize()
	if err != nil {
		return "", err
	}
	share := c.cfg.DefaultShare
	if share == "" {
		share = ScopeSubjectPrivate
	}
	if share == ScopeSubjectPrivate {
		if subjHash := hashOpaque(ac.SubjectKey); subjHash != "" {
			key.Variant = key.Variant + "|sk=" + subjHash
			key, err = key.Normalize()
			if err != nil {
				return "", err
			}
		}
	}
	return key.Digest()
}

// Invalidate removes the L0+disk entry for the plain (empty-subject) key
// digest (best-effort). For entries filled with a non-empty SubjectKey
// (subject_private, the default scope), use InvalidateFor — the plain digest
// is never written by GetOrFetch for those, so plain Invalidate misses them.
func (c *Cache) Invalidate(ctx context.Context, key ResourceKey) error {
	return c.InvalidateFor(ctx, key, AccessContext{})
}

// InvalidateFor removes the L0+disk entry stored under (key, ac).
func (c *Cache) InvalidateFor(ctx context.Context, key ResourceKey, ac AccessContext) error {
	d, err := c.storageDigest(key, ac)
	if err != nil {
		return err
	}
	c.mu.Lock()
	delete(c.l0, d)
	c.mu.Unlock()
	return c.db.DeleteEntry(ctx, d)
}

// Status returns disk metadata without body for the plain (empty-subject) key
// digest. Subject-private entries require StatusFor with the filling context.
func (c *Cache) Status(ctx context.Context, key ResourceKey) (Entry, bool, error) {
	return c.StatusFor(ctx, key, AccessContext{})
}

// StatusFor returns disk metadata without body for (key, ac).
func (c *Cache) StatusFor(ctx context.Context, key ResourceKey, ac AccessContext) (Entry, bool, error) {
	d, err := c.storageDigest(key, ac)
	if err != nil {
		return Entry{}, false, err
	}
	row, ok, err := c.db.GetRow(ctx, d)
	if err != nil || !ok {
		return Entry{}, ok, err
	}
	return entryFromRow(row), true, nil
}

func entryFromRow(r meta.Row) Entry {
	e := Entry{
		KeyDigest:      r.KeyDigest,
		Kind:           ResourceKind(r.Kind),
		State:          EntryState(r.State),
		Completeness:   Completeness(r.Completeness),
		ContentDigest:  r.ContentDigest,
		ContentSize:    r.ContentSize,
		ObjectRelPath:  r.ObjectRelPath,
		SourceETag:     r.SourceETag,
		BuildBuilding:  r.BuildBuilding,
		Share:          AuthorizationScope(r.Share),
		SubjectKeyHash: r.SubjectKeyHash,
	}
	if r.FetchedAtUnix > 0 {
		e.FetchedAt = time.Unix(r.FetchedAtUnix, 0).UTC()
	}
	if r.ExpiresAtUnix > 0 {
		e.ExpiresAt = time.Unix(r.ExpiresAtUnix, 0).UTC()
	}
	return e
}

func rowFromEntry(e Entry, key ResourceKey) meta.Row {
	var fetched, exp int64
	if !e.FetchedAt.IsZero() {
		fetched = e.FetchedAt.Unix()
	}
	if !e.ExpiresAt.IsZero() {
		exp = e.ExpiresAt.Unix()
	}
	return meta.Row{
		KeyDigest: e.KeyDigest, Kind: string(e.Kind),
		ProfileID: key.ProfileID, ControllerID: key.ControllerID,
		JobFullName: key.JobFullName, BuildNumber: key.BuildNumber,
		Selector: key.Selector, Variant: key.Variant,
		State: string(e.State), Completeness: string(e.Completeness),
		ContentDigest: e.ContentDigest, ContentSize: e.ContentSize,
		ObjectRelPath: e.ObjectRelPath, SourceETag: e.SourceETag,
		BuildBuilding: e.BuildBuilding, FetchedAtUnix: fetched, ExpiresAtUnix: exp,
		Share: string(e.Share), SubjectKeyHash: e.SubjectKeyHash,
	}
}

type jsonRaw []byte

func (j jsonRaw) MarshalJSON() ([]byte, error) {
	if len(j) == 0 {
		return []byte("null"), nil
	}
	return j, nil
}

func hashOpaque(s string) string {
	if s == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:16])
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// entryVisibleTo enforces subject_private isolation on hits.
func entryVisibleTo(e Entry, ac AccessContext, defaultShare AuthorizationScope) bool {
	share := e.Share
	if share == "" {
		share = defaultShare
	}
	if share != ScopeSubjectPrivate {
		return true
	}
	want := hashOpaque(ac.SubjectKey)
	if e.SubjectKeyHash == "" {
		// Legacy/empty: only allow if caller also has empty subject key.
		return want == ""
	}
	return e.SubjectKeyHash == want
}
