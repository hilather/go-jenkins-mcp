package blob

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/store"
)

// Store manages content-addressed immutable blobs under objects/blobs/.
type Store struct {
	root string // profile cache root
}

// New creates a blob store under cacheRoot/objects/blobs.
func New(cacheRoot string) (*Store, error) {
	dir := filepath.Join(cacheRoot, "objects", "blobs")
	if err := store.EnsureDir(dir); err != nil {
		return nil, err
	}
	staging := filepath.Join(cacheRoot, "staging")
	if err := store.EnsureDir(staging); err != nil {
		return nil, err
	}
	return &Store{root: cacheRoot}, nil
}

// RelPath returns the relative path for a digest under objects/.
func RelPath(digest string) string {
	if len(digest) < 4 {
		return filepath.Join("blobs", "sha256", digest+".blob")
	}
	return filepath.Join("blobs", "sha256", digest[:2], digest+".blob")
}

// AbsPath returns absolute path for a committed blob.
func (s *Store) AbsPath(digest string) string {
	return filepath.Join(s.root, "objects", RelPath(digest))
}

// Exists reports whether digest is committed.
func (s *Store) Exists(digest string) bool {
	_, err := os.Stat(s.AbsPath(digest))
	return err == nil
}

// WriteResult is returned after a staged write is committed.
type WriteResult struct {
	Digest  string
	Size    int64
	RelPath string
}

// CommitStream stages r to a temp file, digests, and renames into place.
// expectedDigest empty ⇒ accept computed; non-empty ⇒ fail closed on mismatch.
// On cancel/error, partial temp is removed (never sealed as complete).
func (s *Store) CommitStream(r io.Reader, expectedDigest string) (WriteResult, error) {
	if r == nil {
		return WriteResult{}, apperr.New(apperr.CodeInvalidArgument, "nil blob reader")
	}
	staging := filepath.Join(s.root, "staging")
	tmp, err := os.CreateTemp(staging, "blob-*.part")
	if err != nil {
		return WriteResult{}, apperr.Wrap(apperr.CodeInternal, "create staging blob", err)
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		_ = tmp.Close()
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()

	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), r)
	if err != nil {
		return WriteResult{}, apperr.Wrap(apperr.CodeInternal, "write staged blob", err)
	}
	if err := tmp.Sync(); err != nil {
		return WriteResult{}, apperr.Wrap(apperr.CodeInternal, "sync staged blob", err)
	}
	if err := tmp.Close(); err != nil {
		return WriteResult{}, apperr.Wrap(apperr.CodeInternal, "close staged blob", err)
	}
	digest := hex.EncodeToString(h.Sum(nil))
	if expectedDigest != "" && expectedDigest != digest {
		return WriteResult{}, apperr.New(apperr.CodeCorruptCache,
			fmt.Sprintf("blob digest mismatch: got %s want %s", digest, expectedDigest))
	}
	rel := RelPath(digest)
	final := filepath.Join(s.root, "objects", rel)
	if err := store.EnsureDir(filepath.Dir(final)); err != nil {
		return WriteResult{}, err
	}
	if _, err := os.Stat(final); err == nil {
		// Already committed (content-addressed). Drop staging.
		cleanup = true
		return WriteResult{Digest: digest, Size: n, RelPath: rel}, nil
	}
	if err := os.Rename(tmpName, final); err != nil {
		return WriteResult{}, apperr.Wrap(apperr.CodeInternal, "commit blob rename", err)
	}
	cleanup = false
	_ = os.Chmod(final, 0o600)
	return WriteResult{Digest: digest, Size: n, RelPath: rel}, nil
}

// CommitBytes writes a full buffer as a blob.
func (s *Store) CommitBytes(b []byte, expectedDigest string) (WriteResult, error) {
	return s.CommitStream(newBytesReader(b), expectedDigest)
}

// Open returns a read-only file for a committed digest.
func (s *Store) Open(digest string) (*os.File, error) {
	f, err := os.Open(s.AbsPath(digest))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, apperr.Wrap(apperr.CodeNotFound, "blob missing", err)
		}
		return nil, apperr.Wrap(apperr.CodeInternal, "open blob", err)
	}
	return f, nil
}

// ReadAll reads a committed blob fully (for small structured/test use).
func (s *Store) ReadAll(digest string) ([]byte, error) {
	f, err := s.Open(digest)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

// VerifyDigest re-hashes the committed file and fails closed on mismatch.
func (s *Store) VerifyDigest(digest string) error {
	f, err := s.Open(digest)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return apperr.Wrap(apperr.CodeInternal, "hash blob", err)
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != digest {
		return apperr.New(apperr.CodeCorruptCache,
			fmt.Sprintf("blob corrupt: path digest %s content %s", digest, got))
	}
	return nil
}

type bytesReader struct {
	b []byte
	i int
}

func newBytesReader(b []byte) *bytesReader { return &bytesReader{b: b} }

func (r *bytesReader) Read(p []byte) (int, error) {
	if r.i >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.i:])
	r.i += n
	return n, nil
}
