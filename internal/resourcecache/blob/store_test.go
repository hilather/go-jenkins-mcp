package blob_test

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/resourcecache/blob"
)

func TestCommitStream_ExactBytesAndVerify(t *testing.T) {
	dir := t.TempDir()
	s, err := blob.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("exact-artifact-bytes-0123456789")
	wr, err := s.CommitStream(bytes.NewReader(payload), "")
	if err != nil {
		t.Fatal(err)
	}
	if wr.Size != int64(len(payload)) {
		t.Fatalf("size %d", wr.Size)
	}
	if err := s.VerifyDigest(wr.Digest); err != nil {
		t.Fatal(err)
	}
	got, err := s.ReadAll(wr.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("round-trip mismatch")
	}
	// mismatch fail closed
	_, err = s.CommitStream(bytes.NewReader(payload), "00"+wr.Digest[2:])
	if err == nil || apperr.CodeOf(err) != apperr.CodeCorruptCache {
		t.Fatalf("want corrupt_cache got %v", err)
	}
}

func TestCommitStream_CancelCleansPart(t *testing.T) {
	dir := t.TempDir()
	s, err := blob.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	r, w := io.Pipe()
	errCh := make(chan error, 1)
	go func() {
		_, e := s.CommitStream(r, "")
		errCh <- e
	}()
	_, _ = w.Write([]byte("partial"))
	_ = w.CloseWithError(context.Canceled)
	if err := <-errCh; err == nil {
		t.Fatal("expected error")
	}
	// no committed blobs under objects/blobs except empty tree
	entries, _ := os.ReadDir(filepath.Join(dir, "objects", "blobs"))
	// may have sha256 dir empty or with no .blob files
	var blobs int
	_ = filepath.Walk(filepath.Join(dir, "objects"), func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && filepath.Ext(path) == ".blob" {
			blobs++
		}
		return nil
	})
	if blobs != 0 {
		t.Fatalf("partial should not commit blob files, found %d (entries=%v)", blobs, entries)
	}
}
