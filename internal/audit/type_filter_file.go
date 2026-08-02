package audit

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// TypeFilterFileName is stored under the profile audit directory next to JSONL.
const TypeFilterFileName = "type_filter.json"

// typeFilterDoc is the on-disk schema (secret-free).
type typeFilterDoc struct {
	SchemaVersion int `json:"schemaVersion"`
	// Enabled is the full map of known type → enabled. Missing types use defaults on load.
	Enabled map[string]bool `json:"enabled"`
	// UpdatedAt is RFC3339 UTC when last saved via admin API.
	UpdatedAt string `json:"updatedAt,omitempty"`
}

const typeFilterSchemaVersion = 1

// TypeFilterPath returns the path to type_filter.json under profileDataDir/audit.
func TypeFilterPath(profileDataDir string) string {
	profileDataDir = filepath.Clean(profileDataDir)
	if profileDataDir == "" || profileDataDir == "." {
		return ""
	}
	return filepath.Join(profileDataDir, "audit", TypeFilterFileName)
}

// LoadTypeFilter reads type_filter.json or returns DefaultTypeFilter when missing/corrupt.
// Corrupt files fail closed to defaults (never panic); operator can re-save from admin.
func LoadTypeFilter(profileDataDir string) TypeFilter {
	path := TypeFilterPath(profileDataDir)
	if path == "" {
		return DefaultTypeFilter()
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return DefaultTypeFilter()
	}
	var doc typeFilterDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return DefaultTypeFilter()
	}
	return NormalizeEnabled(doc.Enabled)
}

// SaveTypeFilter writes the filter for profileDataDir. Creates audit dir 0700, file 0600.
func SaveTypeFilter(profileDataDir string, f TypeFilter) error {
	path := TypeFilterPath(profileDataDir)
	if path == "" {
		return os.ErrInvalid
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	doc := typeFilterDoc{
		SchemaVersion: typeFilterSchemaVersion,
		Enabled:       f.EnabledMap(),
		UpdatedAt:     time.Now().UTC().Format(time.RFC3339),
	}
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ReloadingFilterSink wraps an inner sink and applies TypeFilter, reloading from
// disk when type_filter.json mtime or size changes (admin toggles without restart).
// Empty ProfileDataDir keeps DefaultTypeFilter only (no disk path — serve fallback).
type ReloadingFilterSink struct {
	Inner          Sink
	ProfileDataDir string

	mu       sync.Mutex
	filter   TypeFilter
	loadPath string
	mtime    time.Time
	size     int64
	// hasFile is true after we have successfully Stat'd the filter file.
	// When the file disappears, we reload defaults once.
	hasFile bool
}

// NewReloadingFilterSink loads the initial filter and wraps inner.
func NewReloadingFilterSink(profileDataDir string, inner Sink) *ReloadingFilterSink {
	s := &ReloadingFilterSink{
		Inner:          inner,
		ProfileDataDir: profileDataDir,
		filter:         LoadTypeFilter(profileDataDir),
		loadPath:       TypeFilterPath(profileDataDir),
	}
	if s.loadPath != "" {
		if st, err := os.Stat(s.loadPath); err == nil {
			s.mtime = st.ModTime()
			s.size = st.Size()
			s.hasFile = true
		}
	}
	return s
}

// Emit drops events whose type is disabled; otherwise forwards to Inner.
func (s *ReloadingFilterSink) Emit(ctx context.Context, e Event) error {
	if s == nil || s.Inner == nil {
		return nil
	}
	s.maybeReload()
	s.mu.Lock()
	allow := s.filter.Allows(e.Type)
	s.mu.Unlock()
	if !allow {
		return nil
	}
	return s.Inner.Emit(ctx, e)
}

// Close closes the inner sink.
func (s *ReloadingFilterSink) Close() error {
	if s == nil || s.Inner == nil {
		return nil
	}
	return s.Inner.Close()
}

// CurrentFilter returns a snapshot of the active filter (for tests/status).
func (s *ReloadingFilterSink) CurrentFilter() TypeFilter {
	if s == nil {
		return DefaultTypeFilter()
	}
	s.maybeReload()
	s.mu.Lock()
	defer s.mu.Unlock()
	// copy
	return NormalizeEnabled(s.filter.EnabledMap())
}

func (s *ReloadingFilterSink) maybeReload() {
	if s == nil || s.loadPath == "" {
		return
	}
	st, err := os.Stat(s.loadPath)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		// Missing/corrupt path after we had a file → return to defaults once.
		if s.hasFile {
			s.filter = DefaultTypeFilter()
			s.hasFile = false
			s.mtime = time.Time{}
			s.size = 0
		}
		return
	}
	// Reload when mtime advances OR size changes (coarse FS mtime resolution).
	if s.hasFile && !st.ModTime().After(s.mtime) && st.Size() == s.size {
		return
	}
	s.filter = LoadTypeFilter(s.ProfileDataDir)
	s.mtime = st.ModTime()
	s.size = st.Size()
	s.hasFile = true
}
