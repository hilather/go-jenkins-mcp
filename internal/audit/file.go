package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Default rotation and file naming.
const (
	DefaultFileName   = "audit.jsonl"
	DefaultMaxBytes   = 8 << 20 // 8 MiB per active file
	DefaultMaxRotated = 3       // keep audit.jsonl.1 .. .N
	filePerm          = 0o600
	dirPerm           = 0o700
)

// FileConfig configures a JSONL file sink under a profile data directory.
type FileConfig struct {
	// Dir is the directory for audit files (typically profile data dir).
	// Created with 0700 when missing.
	Dir string
	// FileName defaults to audit.jsonl.
	FileName string
	// MaxBytes triggers rotation when the active file would exceed this size.
	// Zero uses DefaultMaxBytes. Negative disables rotation (still 0600).
	MaxBytes int64
	// MaxRotated is how many rotated siblings to keep (audit.jsonl.1 .. N).
	// Zero uses DefaultMaxRotated.
	MaxRotated int
}

// File is a privacy-preserving JSONL audit sink with size-based rotation.
// Concurrent Emit is serialized with a mutex. Files are opened 0600.
type File struct {
	mu   sync.Mutex
	cfg  FileConfig
	path string
	f    *os.File
	size int64
}

// NewFile opens (or creates) a JSONL audit file under cfg.Dir.
func NewFile(cfg FileConfig) (*File, error) {
	if cfg.Dir == "" {
		return nil, fmt.Errorf("audit: file sink directory is required")
	}
	if cfg.FileName == "" {
		cfg.FileName = DefaultFileName
	}
	if cfg.MaxBytes == 0 {
		cfg.MaxBytes = DefaultMaxBytes
	}
	if cfg.MaxRotated <= 0 {
		cfg.MaxRotated = DefaultMaxRotated
	}
	if err := os.MkdirAll(cfg.Dir, dirPerm); err != nil {
		return nil, fmt.Errorf("audit: create dir: %w", err)
	}
	// Best-effort force owner-only dir bits.
	_ = os.Chmod(cfg.Dir, dirPerm)

	path := filepath.Join(cfg.Dir, cfg.FileName)
	f, size, err := openAuditFile(path)
	if err != nil {
		return nil, err
	}
	return &File{cfg: cfg, path: path, f: f, size: size}, nil
}

func openAuditFile(path string) (*os.File, int64, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, filePerm)
	if err != nil {
		return nil, 0, fmt.Errorf("audit: open %s: %w", path, err)
	}
	// Re-assert mode in case umask or existing file had looser bits.
	_ = f.Chmod(filePerm)
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, 0, fmt.Errorf("audit: stat: %w", err)
	}
	return f, fi.Size(), nil
}

// Path returns the active audit file path.
func (s *File) Path() string {
	if s == nil {
		return ""
	}
	return s.path
}

// Emit appends one JSON object per line. Never writes raw secrets by design of Event.
func (s *File) Emit(ctx context.Context, e Event) error {
	if s == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	e = e.Normalize()
	line, err := json.Marshal(e)
	if err != nil {
		// Marshal failure must not leak event content in the error string beyond type.
		return fmt.Errorf("audit: marshal event type=%s: %w", e.Type, err)
	}
	line = append(line, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return fmt.Errorf("audit: sink closed")
	}
	// Rotate before write when the next line would exceed MaxBytes.
	if s.cfg.MaxBytes > 0 && s.size+int64(len(line)) > s.cfg.MaxBytes && s.size > 0 {
		if err := s.rotateLocked(); err != nil {
			// Rotation failure: still attempt to write (do not silently authorize).
			// Prefer keeping the active file growing over dropping the event.
			_ = err
		}
	}
	n, err := s.f.Write(line)
	s.size += int64(n)
	if err != nil {
		return fmt.Errorf("audit: write: %w", err)
	}
	return nil
}

func (s *File) rotateLocked() error {
	if s.f != nil {
		_ = s.f.Close()
		s.f = nil
	}
	// Shift .N-1 -> .N, ..., active -> .1
	for i := s.cfg.MaxRotated; i >= 1; i-- {
		from := s.path
		if i > 1 {
			from = fmt.Sprintf("%s.%d", s.path, i-1)
		}
		to := fmt.Sprintf("%s.%d", s.path, i)
		if i == s.cfg.MaxRotated {
			_ = os.Remove(to)
		}
		if _, err := os.Stat(from); err != nil {
			continue
		}
		if err := os.Rename(from, to); err != nil {
			return fmt.Errorf("audit: rotate %s -> %s: %w", from, to, err)
		}
	}
	f, size, err := openAuditFile(s.path)
	if err != nil {
		return err
	}
	s.f = f
	s.size = size
	return nil
}

// Close flushes and closes the active file.
func (s *File) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return nil
	}
	err := s.f.Close()
	s.f = nil
	return err
}

// OpenProfileSink creates a File sink under profileDataDir (AUD-001 default layout),
// wrapped with ReloadingFilterSink so admin type enable/disable applies without restart.
// profileDataDir empty → Nop. Failures return Nop + error so callers stay fail-safe.
func OpenProfileSink(profileDataDir string) (Sink, error) {
	profileDataDir = filepath.Clean(profileDataDir)
	if profileDataDir == "" || profileDataDir == "." {
		return Nop{}, nil
	}
	// Nest under audit/ to keep profile data tidy.
	dir := filepath.Join(profileDataDir, "audit")
	f, err := NewFile(FileConfig{Dir: dir})
	if err != nil {
		return Nop{}, err
	}
	return NewReloadingFilterSink(profileDataDir, f), nil
}

// Multi fans out to several sinks (e.g. Memory + File in tests). Best-effort:
// returns the first error after attempting all.
type Multi []Sink

// Emit implements Sink.
func (m Multi) Emit(ctx context.Context, e Event) error {
	e = e.Normalize()
	var first error
	for _, s := range m {
		if s == nil {
			continue
		}
		if err := s.Emit(ctx, e); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// Close implements Sink.
func (m Multi) Close() error {
	var first error
	for _, s := range m {
		if s == nil {
			continue
		}
		if err := s.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}
