package resourcecache

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"sync"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/resourcecache/blob"
	"github.com/hilather/go-jenkins-mcp/internal/resourcecache/meta"
	"github.com/hilather/go-jenkins-mcp/internal/resourcecache/structured"
	"github.com/hilather/go-jenkins-mcp/internal/store"
	"golang.org/x/sync/singleflight"
)

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
	artPath := req.ArtifactPath
	if artPath == "" {
		artPath = key.Selector
	}
	if artPath != "" {
		if err := ver.AuthorizeArtifact(ctx, req.Access, key.JobFullName, artPath); err != nil {
			return EntryReader{}, LookupResult{}, err
		}
	}
	// subject_private: isolate digests per subject so entries cannot be reused cross-subject.
	share := c.cfg.DefaultShare
	if share == "" {
		share = ScopeSubjectPrivate
	}
	subjHash := ""
	if share == ScopeSubjectPrivate {
		subjHash = hashOpaque(req.Access.SubjectKey)
		if subjHash != "" {
			key.Variant = key.Variant + "|sk=" + subjHash
			key, err = key.Normalize()
			if err != nil {
				return EntryReader{}, LookupResult{}, err
			}
		}
	}
	digest, err := key.Digest()
	if err != nil {
		return EntryReader{}, LookupResult{}, err
	}

	// L0 hit
	if er, lr, ok := c.l0Get(digest); ok && c.cfg.Freshness.IsFresh(er.Entry, c.now()) {
		if !entryVisibleTo(er.Entry, req.Access, share) {
			// Treat as miss (should not happen when digests include sk=).
		} else if err := c.reauth(ctx, req, key, artPath, ver); err != nil {
			return EntryReader{}, LookupResult{}, err
		} else {
			lr.AuthorizedAt = c.now()
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
					return EntryReader{}, LookupResult{}, err
				}
				er := EntryReader{Entry: e, Data: data}
				c.l0Put(digest, er)
				return er, LookupResult{Source: SourceDisk, Entry: e, FromCache: true, AuthorizedAt: c.now()}, nil
			}
		}
	}

	// Miss / stale / corrupt → singleflight fetch
	v, err, _ := c.sf.Do(digest, func() (any, error) {
		return c.fetchAndCommit(ctx, req, key, digest, artPath, ver)
	})
	if err != nil {
		return EntryReader{}, LookupResult{}, err
	}
	r := v.(fetchOutcome)
	return r.er, r.lr, nil
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

func (c *Cache) fetchAndCommit(ctx context.Context, req FetchRequest, key ResourceKey, digest, artPath string, ver AuthorizationVerifier) (fetchOutcome, error) {
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
	if err := c.db.PutRow(ctx, rowFromEntry(e, key)); err != nil {
		return out, err
	}
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

// Invalidate removes L0+disk entry for key (best-effort).
func (c *Cache) Invalidate(ctx context.Context, key ResourceKey) error {
	key, err := key.Normalize()
	if err != nil {
		return err
	}
	d, err := key.Digest()
	if err != nil {
		return err
	}
	c.mu.Lock()
	delete(c.l0, d)
	c.mu.Unlock()
	return c.db.DeleteEntry(ctx, d)
}

// Status returns disk metadata without body.
func (c *Cache) Status(ctx context.Context, key ResourceKey) (Entry, bool, error) {
	key, err := key.Normalize()
	if err != nil {
		return Entry{}, false, err
	}
	d, err := key.Digest()
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
