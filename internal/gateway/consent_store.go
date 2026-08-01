package gateway

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// DefaultConsentSessionTTL is the process-local consent metadata lifetime.
// Consent sessions are short-lived; this is not AgentCore vault durability.
const DefaultConsentSessionTTL = 30 * time.Minute

// DefaultConsentSessionMaxEntries bounds process-local consent metadata growth.
const DefaultConsentSessionMaxEntries = 256

// DefaultConsentSessionRelPath is the conventional metadata-only consent session
// file under XDG data (OAUTH-010 / GWY-001 residual):
//
//	$XDG_DATA_HOME/jenkins-mcp/gateway/consent_sessions.json
//
// Contents are auth URL + session id + timestamps only — never tokens.
const DefaultConsentSessionRelPath = "jenkins-mcp/gateway/consent_sessions.json"

// ConsentSessionRecord is process-local (optional file) progressive consent
// metadata only (OAUTH-010 / GWY-001 residual).
//
// Never stores access tokens, refresh tokens, client secrets, authorization
// codes, or Authorization headers.
type ConsentSessionRecord struct {
	// Info is authorization URL + session id + optional provider (never tokens).
	Info ConsentInfo
	// SubjectKey binds the consent session to a caller namespace
	// (tenant|subject|profile). Empty is allowed for unbound residual snapshots.
	SubjectKey string
	// StoredAt is when the process recorded the ConsentRequired.
	StoredAt time.Time
	// ExpiresAt is the TTL expiry; expired records are treated as missing.
	ExpiresAt time.Time
}

// SessionID returns the correlation id from Info (trimmed).
func (r ConsentSessionRecord) SessionID() string {
	return strings.TrimSpace(r.Info.SessionID)
}

// Valid reports whether the record has required consent metadata.
func (r ConsentSessionRecord) Valid() bool {
	return r.Info.Valid()
}

// expired reports whether the record is past ExpiresAt.
func (r ConsentSessionRecord) expired(now time.Time) bool {
	if r.ExpiresAt.IsZero() {
		return true
	}
	return !r.ExpiresAt.After(now)
}

// StatusMap is a non-secret summary for doctor/CLI/audit.
// Never embeds full authorization URL query (state) or any token field.
func (r ConsentSessionRecord) StatusMap() map[string]any {
	sm := r.Info.StatusMap()
	sm["session_id"] = r.SessionID()
	if sk := strings.TrimSpace(r.SubjectKey); sk != "" {
		sm["subject_key"] = sk
	}
	if !r.StoredAt.IsZero() {
		sm["stored_at"] = r.StoredAt.UTC().Format(time.RFC3339)
	}
	if !r.ExpiresAt.IsZero() {
		sm["expires_at"] = r.ExpiresAt.UTC().Format(time.RFC3339)
	}
	// Host-only progressive helper (matches ConsentInfo.String philosophy).
	if host := consentAuthorizationHost(r.Info.AuthorizationURL); host != "" {
		sm["authorization_host"] = host
	}
	return sm
}

// String never embeds secrets; host + truncated session only.
func (r ConsentSessionRecord) String() string {
	sk := strings.TrimSpace(r.SubjectKey)
	if sk != "" {
		return r.Info.String() + " subject=" + sk
	}
	return r.Info.String()
}

// ConsentSessionStore stores progressive consent metadata only (auth URL +
// session id + timestamps + optional subject binding). Implementations must
// never store or surface access/refresh tokens.
//
// Process-local (optional file-backed for crash recovery of metadata only).
// Not a multi-replica shared store (HOST-008 residual).
type ConsentSessionStore interface {
	// Put stores or replaces a consent session record (metadata only).
	// Rejects incomplete ConsentInfo. Applies TTL when ExpiresAt is zero.
	Put(rec ConsentSessionRecord) error
	// Get returns a non-expired record by session id.
	Get(sessionID string) (ConsentSessionRecord, bool)
	// GetBySubjectKey returns the latest non-expired record for subjectKey.
	GetBySubjectKey(subjectKey string) (ConsentSessionRecord, bool)
	// List returns non-expired records (newest StoredAt first).
	List() []ConsentSessionRecord
	// Delete removes a session by id (no-op if missing).
	Delete(sessionID string)
	// Clear drops all entries.
	Clear()
	// StatusMap is secret-free store summary (counts / residual flags only).
	StatusMap() map[string]any
	// String is secret-free (entry count only).
	String() string
}

// MemoryConsentSessionStore is a process-local TTL consent metadata store.
// Optional FilePath enables crash recovery of metadata only (JSON 0600 under
// XDG data). Not multi-replica HA; browser 3LO is not automated.
type MemoryConsentSessionStore struct {
	mu        sync.Mutex
	bySession map[string]ConsentSessionRecord // session id → record
	bySubject map[string]string               // subjectKey → latest session id
	// TTL applied when ExpiresAt is zero on Put (0 → DefaultConsentSessionTTL).
	TTL time.Duration
	// MaxEntries bounds growth (0 → DefaultConsentSessionMaxEntries).
	MaxEntries int
	// FilePath when non-empty persists metadata-only JSON after mutations.
	// Never holds tokens. Mode 0600; parent dir 0700.
	FilePath string
	// now is optional clock override for tests.
	now func() time.Time
}

// NewMemoryConsentSessionStore builds an empty process-local consent store.
// ttl <= 0 uses DefaultConsentSessionTTL. filePath may be empty (memory only).
func NewMemoryConsentSessionStore(ttl time.Duration, filePath string) *MemoryConsentSessionStore {
	if ttl <= 0 {
		ttl = DefaultConsentSessionTTL
	}
	return &MemoryConsentSessionStore{
		bySession:  make(map[string]ConsentSessionRecord),
		bySubject:  make(map[string]string),
		TTL:        ttl,
		MaxEntries: DefaultConsentSessionMaxEntries,
		FilePath:   strings.TrimSpace(filePath),
		now:        time.Now,
	}
}

// processConsentSessionStore is the serve-wide default used when
// AgentCoreProvider.ConsentStore is nil. Tests may inject a private store.
var processConsentSessionStore ConsentSessionStore = NewMemoryConsentSessionStore(0, "")

// ProcessConsentSessionStore returns the process-local default consent metadata
// store. Never nil after package init. Metadata only — never tokens.
func ProcessConsentSessionStore() ConsentSessionStore {
	if processConsentSessionStore == nil {
		processConsentSessionStore = NewMemoryConsentSessionStore(0, "")
	}
	return processConsentSessionStore
}

// SetProcessConsentSessionStore replaces the process default (tests / serve wire).
// nil resets to a fresh memory-only store.
func SetProcessConsentSessionStore(s ConsentSessionStore) {
	if s == nil {
		processConsentSessionStore = NewMemoryConsentSessionStore(0, "")
		return
	}
	processConsentSessionStore = s
}

func (s *MemoryConsentSessionStore) clock() time.Time {
	if s != nil && s.now != nil {
		return s.now()
	}
	return time.Now()
}

func (s *MemoryConsentSessionStore) maxEntries() int {
	if s == nil || s.MaxEntries <= 0 {
		return DefaultConsentSessionMaxEntries
	}
	return s.MaxEntries
}

// Put implements ConsentSessionStore.
func (s *MemoryConsentSessionStore) Put(rec ConsentSessionRecord) error {
	if s == nil {
		return apperr.New(apperr.CodeInternal, "consent session store is nil")
	}
	if !rec.Info.Valid() {
		return apperr.New(apperr.CodeInvalidArgument, "consent session metadata incomplete")
	}
	// Reject records that look like they smuggle token-shaped fields into Info.
	// ConsentInfo has no token fields by design; still guard obvious secret markers.
	// Do not apply JWT-prefix heuristics to AuthorizationURL (query may contain
	// base64 state/code_challenge that happens to contain "eyJ").
	sid := strings.TrimSpace(rec.Info.SessionID)
	if looksLikeSecretMaterial(sid) || authorizationURLHasTokenMarkers(rec.Info.AuthorizationURL) {
		return apperr.New(apperr.CodeInvalidArgument, "consent session metadata must not embed token material")
	}
	now := s.clock()
	if rec.StoredAt.IsZero() {
		rec.StoredAt = now
	}
	if rec.ExpiresAt.IsZero() {
		rec.ExpiresAt = now.Add(s.TTL)
	}
	rec.Info.AuthorizationURL = strings.TrimSpace(rec.Info.AuthorizationURL)
	rec.Info.SessionID = sid
	rec.Info.Provider = strings.TrimSpace(rec.Info.Provider)
	rec.SubjectKey = strings.TrimSpace(rec.SubjectKey)

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.bySession == nil {
		s.bySession = make(map[string]ConsentSessionRecord)
	}
	if s.bySubject == nil {
		s.bySubject = make(map[string]string)
	}
	s.purgeExpiredLocked(now)
	s.bySession[sid] = rec
	if rec.SubjectKey != "" {
		s.bySubject[rec.SubjectKey] = sid
	}
	s.enforceMaxLocked(now)
	return s.persistLocked()
}

// Get implements ConsentSessionStore.
func (s *MemoryConsentSessionStore) Get(sessionID string) (ConsentSessionRecord, bool) {
	if s == nil {
		return ConsentSessionRecord{}, false
	}
	sid := strings.TrimSpace(sessionID)
	if sid == "" {
		return ConsentSessionRecord{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.bySession[sid]
	if !ok || rec.expired(s.clock()) {
		if ok {
			s.deleteLocked(sid)
			_ = s.persistLocked()
		}
		return ConsentSessionRecord{}, false
	}
	return rec, true
}

// GetBySubjectKey implements ConsentSessionStore.
func (s *MemoryConsentSessionStore) GetBySubjectKey(subjectKey string) (ConsentSessionRecord, bool) {
	if s == nil {
		return ConsentSessionRecord{}, false
	}
	sk := strings.TrimSpace(subjectKey)
	if sk == "" {
		return ConsentSessionRecord{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sid, ok := s.bySubject[sk]
	if !ok {
		return ConsentSessionRecord{}, false
	}
	rec, ok := s.bySession[sid]
	if !ok || rec.expired(s.clock()) {
		delete(s.bySubject, sk)
		if ok {
			s.deleteLocked(sid)
			_ = s.persistLocked()
		}
		return ConsentSessionRecord{}, false
	}
	return rec, true
}

// List implements ConsentSessionStore.
func (s *MemoryConsentSessionStore) List() []ConsentSessionRecord {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock()
	s.purgeExpiredLocked(now)
	out := make([]ConsentSessionRecord, 0, len(s.bySession))
	for _, rec := range s.bySession {
		if !rec.expired(now) {
			out = append(out, rec)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].StoredAt.Equal(out[j].StoredAt) {
			return out[i].SessionID() > out[j].SessionID()
		}
		return out[i].StoredAt.After(out[j].StoredAt)
	})
	return out
}

// Delete implements ConsentSessionStore.
func (s *MemoryConsentSessionStore) Delete(sessionID string) {
	if s == nil {
		return
	}
	sid := strings.TrimSpace(sessionID)
	if sid == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deleteLocked(sid)
	_ = s.persistLocked()
}

// Clear implements ConsentSessionStore.
func (s *MemoryConsentSessionStore) Clear() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bySession = make(map[string]ConsentSessionRecord)
	s.bySubject = make(map[string]string)
	_ = s.persistLocked()
}

// StatusMap implements ConsentSessionStore (secret-free).
func (s *MemoryConsentSessionStore) StatusMap() map[string]any {
	n := 0
	file := ""
	if s != nil {
		s.mu.Lock()
		s.purgeExpiredLocked(s.clock())
		n = len(s.bySession)
		file = s.FilePath
		s.mu.Unlock()
	}
	m := map[string]any{
		"entries":                          n,
		"process_local":                    true,
		"multi_replica_shared":             false,
		"metadata_only":                    true,
		"stores_tokens":                    false,
		"browser_3lo_automated":            false,
		"durable_agentcore_vault_residual": true, // not AgentCore vault; residual honesty
		"file_backed":                      file != "",
	}
	if file != "" {
		m["file_backed_present"] = true
		// Never embed full path contents; basename only for residual.
		if i := strings.LastIndexAny(file, `/\`); i >= 0 && i+1 < len(file) {
			m["file_basename"] = file[i+1:]
		} else {
			m["file_basename"] = file
		}
	}
	return m
}

// String implements ConsentSessionStore (secret-free).
func (s *MemoryConsentSessionStore) String() string {
	n := 0
	if s != nil {
		s.mu.Lock()
		s.purgeExpiredLocked(s.clock())
		n = len(s.bySession)
		s.mu.Unlock()
	}
	return fmt.Sprintf("consent_session_store entries=%d metadata_only=true multi_replica=false", n)
}

// LoadFromFile reloads metadata-only entries from FilePath into memory.
// Missing file is a no-op (empty store). Corrupt file fails closed.
// Never loads token fields (file schema has none).
func (s *MemoryConsentSessionStore) LoadFromFile() error {
	if s == nil {
		return apperr.New(apperr.CodeInternal, "consent session store is nil")
	}
	if strings.TrimSpace(s.FilePath) == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadLocked()
}

func (s *MemoryConsentSessionStore) deleteLocked(sid string) {
	rec, ok := s.bySession[sid]
	if !ok {
		return
	}
	delete(s.bySession, sid)
	if sk := strings.TrimSpace(rec.SubjectKey); sk != "" {
		if s.bySubject[sk] == sid {
			delete(s.bySubject, sk)
		}
	}
}

func (s *MemoryConsentSessionStore) purgeExpiredLocked(now time.Time) {
	for sid, rec := range s.bySession {
		if rec.expired(now) {
			s.deleteLocked(sid)
		}
	}
}

// enforceMaxLocked drops oldest entries when over MaxEntries.
func (s *MemoryConsentSessionStore) enforceMaxLocked(now time.Time) {
	max := s.maxEntries()
	if len(s.bySession) <= max {
		return
	}
	type pair struct {
		sid string
		at  time.Time
	}
	list := make([]pair, 0, len(s.bySession))
	for sid, rec := range s.bySession {
		if rec.expired(now) {
			s.deleteLocked(sid)
			continue
		}
		list = append(list, pair{sid: sid, at: rec.StoredAt})
	}
	if len(list) <= max {
		return
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].at.Before(list[j].at)
	})
	drop := len(list) - max
	for i := 0; i < drop; i++ {
		s.deleteLocked(list[i].sid)
	}
}

// RememberConsentRequired records ConsentInfo metadata when Obtain returns
// ConsentRequired. Metadata only — never tokens. No-op on nil store / incomplete
// info. subjectKey may be empty.
func RememberConsentRequired(store ConsentSessionStore, subjectKey string, info ConsentInfo) {
	if store == nil || !info.Valid() {
		return
	}
	_ = store.Put(ConsentSessionRecord{
		Info:       info,
		SubjectKey: strings.TrimSpace(subjectKey),
	})
}

// consentAuthorizationHost extracts host from an authorization URL (no query).
func consentAuthorizationHost(authURL string) string {
	u := strings.TrimSpace(authURL)
	if u == "" {
		return ""
	}
	if i := strings.Index(u, "://"); i >= 0 {
		rest := u[i+3:]
		if j := strings.IndexAny(rest, "/?"); j >= 0 {
			return rest[:j]
		}
		return rest
	}
	return ""
}

// looksLikeSecretMaterial is a defensive canary for accidental token storage
// in session id / subject fields. Conservative: only flags obvious token markers.
func looksLikeSecretMaterial(s string) bool {
	low := strings.ToLower(strings.TrimSpace(s))
	if low == "" {
		return false
	}
	for _, bad := range []string{
		"access_token=",
		"refresh_token=",
		"client_secret=",
		"authorization: bearer",
	} {
		if strings.Contains(low, bad) {
			return true
		}
	}
	// JWT / opaque token prefixes as the entire session id (common accidental paste).
	if strings.HasPrefix(low, "eyj") || // JWT header {"...
		strings.HasPrefix(low, "ya29.") ||
		strings.HasPrefix(low, "sk-") {
		return true
	}
	return false
}

// authorizationURLHasTokenMarkers rejects authorize URLs that embed token-shaped
// query keys (never expected on a progressive consent URL).
func authorizationURLHasTokenMarkers(authURL string) bool {
	low := strings.ToLower(strings.TrimSpace(authURL))
	if low == "" {
		return false
	}
	for _, bad := range []string{
		"access_token=",
		"refresh_token=",
		"client_secret=",
		"id_token=",
	} {
		if strings.Contains(low, bad) {
			return true
		}
	}
	return false
}
