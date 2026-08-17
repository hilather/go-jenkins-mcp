package store_test

import (
	"context"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/store"
)

// Regression: ReadRange silently spliced non-contiguous frames. When a middle
// chunk row is missing (frame file lost + recovery deleted the row), the
// reader appended the following chunk's bytes as if they covered the gap —
// returning bytes at wrong offsets with no error. For an evidence-oriented
// log store, that is the worst failure mode. ReadRange now fails closed
// (corrupt_cache) on a raw-offset gap; ReadLineRange fails on a line gap
// (while tolerating the mid-line-cut overlap where LineStart == prev LineEnd-1).
func TestReadRange_MiddleChunkGapFailsClosed(t *testing.T) {
	meta, fr, _ := openRunningFrames(t, 0)
	ctx := context.Background()
	g := &store.LogGeneration{Profile: "corp", Job: "gap", Build: 1, Generation: 1, MoreData: true}
	if err := meta.InsertGeneration(ctx, g); err != nil {
		t.Fatal(err)
	}
	// Three committed frames: AAAA\n BBBB\n CCCC\n (raw [0,5) [5,10) [10,15)).
	for _, s := range []string{"AAAA\n", "BBBB\n", "CCCC\n"} {
		if _, err := fr.Append(ctx, g.ID, []byte(s)); err != nil {
			t.Fatal(err)
		}
		if _, err := fr.Flush(ctx, g.ID); err != nil {
			t.Fatal(err)
		}
	}

	// Delete the middle chunk row (simulates frame-file loss + recovery).
	chunks, err := meta.ListChunks(ctx, g.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) != 3 {
		t.Fatalf("chunks=%d want 3", len(chunks))
	}
	if err := meta.DeleteChunkRow(ctx, chunks[1].ID); err != nil {
		t.Fatal(err)
	}

	reader, err := fr.Reader()
	if err != nil {
		t.Fatal(err)
	}
	_, err = reader.ReadRange(ctx, g.ID, 0, 15)
	if err == nil {
		t.Fatal("ReadRange across a missing middle chunk must fail closed, not splice")
	}
	if apperr.CodeOf(err) != apperr.CodeCorruptCache {
		t.Fatalf("want corrupt_cache, got %v", err)
	}

	// A range fully inside a surviving frame still reads fine.
	res, err := reader.ReadRange(ctx, g.ID, 0, 5)
	if err != nil {
		t.Fatal(err)
	}
	if string(res.Data) != "AAAA\n" {
		t.Fatalf("prefix read = %q", res.Data)
	}
}

// Control: contiguous multi-frame reads are unaffected by the gap check.
func TestReadRange_ContiguousFramesUnaffected(t *testing.T) {
	meta, fr, _ := openRunningFrames(t, 0)
	ctx := context.Background()
	g := &store.LogGeneration{Profile: "corp", Job: "gap-ok", Build: 2, Generation: 1, MoreData: true}
	if err := meta.InsertGeneration(ctx, g); err != nil {
		t.Fatal(err)
	}
	body := strings.Repeat("abcdef\n", 3)
	for _, s := range []string{"abcdef\n", "abcdef\n", "abcdef\n"} {
		if _, err := fr.Append(ctx, g.ID, []byte(s)); err != nil {
			t.Fatal(err)
		}
		if _, err := fr.Flush(ctx, g.ID); err != nil {
			t.Fatal(err)
		}
	}
	reader, err := fr.Reader()
	if err != nil {
		t.Fatal(err)
	}
	res, err := reader.ReadRange(ctx, g.ID, 0, int64(len(body)))
	if err != nil {
		t.Fatal(err)
	}
	if string(res.Data) != body {
		t.Fatalf("got %q want %q", res.Data, body)
	}
}
