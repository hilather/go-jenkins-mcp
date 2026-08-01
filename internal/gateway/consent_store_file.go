package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// EnvConsentSessionStorePath overrides the process-local consent metadata file
// path (metadata only — never tokens). Empty → default under XDG data.
const EnvConsentSessionStorePath = "JENKINS_MCP_CONSENT_STORE_PATH"

// consentFileDoc is the on-disk shape for consent metadata only.
// Schema deliberately omits any token / secret field names.
type consentFileDoc struct {
	Version int                         `json:"version"`
	Entries map[string]consentFileEntry `json:"entries"`
}

// consentFileEntry is metadata only (auth URL + session id + timestamps).
// Never access_token, refresh_token, client_secret, or codes.
type consentFileEntry struct {
	AuthorizationURL string `json:"authorization_url"`
	SessionID        string `json:"session_id"`
	Provider         string `json:"provider,omitempty"`
	SubjectKey       string `json:"subject_key,omitempty"`
	StoredAt         string `json:"stored_at"`
	ExpiresAt        string `json:"expires_at"`
}

// ConsentSessionPathFromEnviron returns the consent metadata file path from env
// or the conventional XDG data default (DefaultConsentSessionRelPath).
// Path holds metadata only — never tokens.
func ConsentSessionPathFromEnviron(getenv func(string) string) string {
	if getenv == nil {
		getenv = os.Getenv
	}
	if p := strings.TrimSpace(getenv(EnvConsentSessionStorePath)); p != "" {
		return p
	}
	return filepath.Join(xdgDataHome(getenv), filepath.FromSlash(DefaultConsentSessionRelPath))
}

// NewFileBackedConsentSessionStore builds a memory store that persists metadata
// to path (crash recovery residual). path required. Parent dirs 0700; file 0600.
// Loads existing file when present. Never stores tokens.
func NewFileBackedConsentSessionStore(ttl time.Duration, path string) (*MemoryConsentSessionStore, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, apperr.New(apperr.CodeInvalidArgument, "consent session store path is required")
	}
	clean := filepath.Clean(path)
	if clean == "." || clean == string(filepath.Separator) {
		return nil, apperr.New(apperr.CodeInvalidArgument, "consent session store path is invalid")
	}
	s := NewMemoryConsentSessionStore(ttl, clean)
	if err := s.LoadFromFile(); err != nil {
		return nil, err
	}
	return s, nil
}

// OpenConsentSessionStoreForCLI opens the optional file-backed consent metadata
// store for doctor/CLI residual listing. Missing file → empty memory store (no
// error). Corrupt file fails closed. Never loads tokens (schema has none).
func OpenConsentSessionStoreForCLI(getenv func(string) string) (ConsentSessionStore, error) {
	path := ConsentSessionPathFromEnviron(getenv)
	if st, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			// Residual honesty: no durable entries yet; return empty memory view.
			return NewMemoryConsentSessionStore(0, ""), nil
		}
		return nil, apperr.Wrap(apperr.CodeInternal, "consent session store stat failed", err)
	} else if st.IsDir() {
		return nil, apperr.New(apperr.CodeInvalidArgument, "consent session store path is a directory")
	}
	return NewFileBackedConsentSessionStore(0, path)
}

// persistLocked writes metadata-only JSON when FilePath is set.
// Caller must hold s.mu. Uses flock for multi-process safety on the same path
// (HOST-008 lite; not multi-pod HA).
func (s *MemoryConsentSessionStore) persistLocked() error {
	if s == nil || strings.TrimSpace(s.FilePath) == "" {
		return nil
	}
	path := s.FilePath
	doc := consentFileDoc{
		Version: 1,
		Entries: make(map[string]consentFileEntry, len(s.bySession)),
	}
	now := s.clock()
	for sid, rec := range s.bySession {
		if rec.expired(now) {
			continue
		}
		// Defense in depth: never write fields that look like secrets.
		if looksLikeSecretMaterial(rec.Info.SessionID) || authorizationURLHasTokenMarkers(rec.Info.AuthorizationURL) {
			continue
		}
		doc.Entries[sid] = consentFileEntry{
			AuthorizationURL: strings.TrimSpace(rec.Info.AuthorizationURL),
			SessionID:        strings.TrimSpace(rec.Info.SessionID),
			Provider:         strings.TrimSpace(rec.Info.Provider),
			SubjectKey:       strings.TrimSpace(rec.SubjectKey),
			StoredAt:         rec.StoredAt.UTC().Format(time.RFC3339Nano),
			ExpiresAt:        rec.ExpiresAt.UTC().Format(time.RFC3339Nano),
		}
	}
	return withVaultFileLock(path, func() error {
		return writeConsentFile(path, doc)
	})
}

// loadLocked reads metadata-only JSON from FilePath into memory.
// Caller must hold s.mu.
func (s *MemoryConsentSessionStore) loadLocked() error {
	if s == nil || strings.TrimSpace(s.FilePath) == "" {
		return nil
	}
	path := s.FilePath
	var doc consentFileDoc
	err := withVaultFileLock(path, func() error {
		var loadErr error
		doc, loadErr = readConsentFile(path)
		return loadErr
	})
	if err != nil {
		return err
	}
	if s.bySession == nil {
		s.bySession = make(map[string]ConsentSessionRecord)
	}
	if s.bySubject == nil {
		s.bySubject = make(map[string]string)
	}
	// Replace in-memory view with file contents (crash recovery).
	s.bySession = make(map[string]ConsentSessionRecord, len(doc.Entries))
	s.bySubject = make(map[string]string)
	now := s.clock()
	for sid, e := range doc.Entries {
		rec, ok := fileEntryToRecord(sid, e)
		if !ok || rec.expired(now) {
			continue
		}
		if looksLikeSecretMaterial(rec.Info.SessionID) || authorizationURLHasTokenMarkers(rec.Info.AuthorizationURL) {
			// Skip poison entries; never load token-shaped material.
			continue
		}
		s.bySession[rec.SessionID()] = rec
		if sk := strings.TrimSpace(rec.SubjectKey); sk != "" {
			// Prefer newest by StoredAt when multiple subjects collide.
			if prevSID, exists := s.bySubject[sk]; exists {
				if prev, ok := s.bySession[prevSID]; ok && !rec.StoredAt.After(prev.StoredAt) {
					continue
				}
			}
			s.bySubject[sk] = rec.SessionID()
		}
	}
	return nil
}

func fileEntryToRecord(mapKey string, e consentFileEntry) (ConsentSessionRecord, bool) {
	sid := strings.TrimSpace(e.SessionID)
	if sid == "" {
		sid = strings.TrimSpace(mapKey)
	}
	url := strings.TrimSpace(e.AuthorizationURL)
	if url == "" || sid == "" {
		return ConsentSessionRecord{}, false
	}
	// Reject unexpected secret-looking fields (defense).
	if looksLikeSecretMaterial(sid) || authorizationURLHasTokenMarkers(url) {
		return ConsentSessionRecord{}, false
	}
	rec := ConsentSessionRecord{
		Info: ConsentInfo{
			AuthorizationURL: url,
			SessionID:        sid,
			Provider:         strings.TrimSpace(e.Provider),
		},
		SubjectKey: strings.TrimSpace(e.SubjectKey),
	}
	if t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(e.StoredAt)); err == nil {
		rec.StoredAt = t
	} else if t, err := time.Parse(time.RFC3339, strings.TrimSpace(e.StoredAt)); err == nil {
		rec.StoredAt = t
	}
	if t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(e.ExpiresAt)); err == nil {
		rec.ExpiresAt = t
	} else if t, err := time.Parse(time.RFC3339, strings.TrimSpace(e.ExpiresAt)); err == nil {
		rec.ExpiresAt = t
	}
	if !rec.Info.Valid() {
		return ConsentSessionRecord{}, false
	}
	return rec, true
}

func readConsentFile(path string) (consentFileDoc, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return consentFileDoc{Version: 1, Entries: make(map[string]consentFileEntry)}, nil
		}
		return consentFileDoc{}, apperr.Wrap(apperr.CodeInternal, "consent session store read failed", err)
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return consentFileDoc{Version: 1, Entries: make(map[string]consentFileEntry)}, nil
	}
	// Fail closed if the file contains forbidden token field names (canary).
	low := strings.ToLower(string(raw))
	for _, bad := range []string{
		`"access_token"`,
		`"refresh_token"`,
		`"client_secret"`,
		`"authorization"`,
		`"id_token"`,
	} {
		if strings.Contains(low, bad) {
			return consentFileDoc{}, apperr.New(apperr.CodeCorruptCache,
				"consent session store must not contain token fields")
		}
	}
	var doc consentFileDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return consentFileDoc{}, apperr.Wrap(apperr.CodeCorruptCache,
			"consent session store file is corrupt or unreadable", err)
	}
	if doc.Entries == nil {
		doc.Entries = make(map[string]consentFileEntry)
	}
	if doc.Version == 0 {
		doc.Version = 1
	}
	return doc, nil
}

func writeConsentFile(path string, doc consentFileDoc) error {
	if doc.Entries == nil {
		doc.Entries = make(map[string]consentFileEntry)
	}
	if doc.Version == 0 {
		doc.Version = 1
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return apperr.Wrap(apperr.CodeInternal, "consent session store directory create failed", err)
	}
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return apperr.Wrap(apperr.CodeInternal, "consent session store encode failed", err)
	}
	// Defense: refuse to write if encode somehow included forbidden keys.
	low := strings.ToLower(string(raw))
	for _, bad := range []string{`"access_token"`, `"refresh_token"`, `"client_secret"`} {
		if strings.Contains(low, bad) {
			return apperr.New(apperr.CodeInternal, "consent session store refused to write token fields")
		}
	}
	raw = append(raw, '\n')
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return apperr.Wrap(apperr.CodeInternal, "consent session store write failed", err)
	}
	_ = os.Chmod(tmp, 0o600)
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return apperr.Wrap(apperr.CodeInternal, "consent session store rename failed", err)
	}
	_ = os.Chmod(path, 0o600)
	return nil
}
