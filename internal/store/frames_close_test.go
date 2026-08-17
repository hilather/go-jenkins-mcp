package store_test

import (
	"context"
	"testing"
)

// Regression: Frames.Append/Flush after Close panicked (assignment to entry in
// nil map — Close nils f.open). Use-after-close must return an error instead:
// an in-flight request during shutdown (or embedded reuse) must not crash the
// process.
func TestFrames_AppendAfterCloseReturnsError(t *testing.T) {
	_, fr, _ := openRunningFrames(t, 0)
	ctx := context.Background()
	if err := fr.Close(); err != nil {
		t.Fatal(err)
	}
	// Double Close is fine.
	if err := fr.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := fr.Append(ctx, 1, []byte("data\n")); err == nil {
		t.Fatal("Append after Close must return an error, not panic")
	}
	if _, err := fr.Flush(ctx, 1); err == nil {
		t.Fatal("Flush after Close must return an error, not panic")
	}
}
