package search_test

import (
	"bytes"
	"context"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/search"
	"github.com/simonfxr/go-jenkins-mcp/internal/store"
)

func openSearch(t *testing.T, target int) (*store.Meta, *store.Frames, *search.Engine, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "profiles", "corp")
	meta, err := store.Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = meta.Close() })
	fr, err := store.NewFrames(meta, dir)
	if err != nil {
		t.Fatalf("NewFrames: %v", err)
	}
	if target > 0 {
		fr.TargetBytes = target
		fr.MaxBytes = target * 4
	}
	t.Cleanup(func() { _ = fr.Close() })
	if _, err := fr.Recover(context.Background()); err != nil {
		t.Fatalf("Recover: %v", err)
	}
	eng, err := search.New(meta, dir)
	if err != nil {
		t.Fatalf("search.New: %v", err)
	}
	return meta, fr, eng, dir
}

func insertGen(t *testing.T, meta *store.Meta, job string, build int64) int64 {
	t.Helper()
	g := &store.LogGeneration{
		Profile: "corp", Job: job, Build: build, Generation: 1, MoreData: true,
	}
	if err := meta.InsertGeneration(context.Background(), g); err != nil {
		t.Fatal(err)
	}
	return g.ID
}

func writeLog(t *testing.T, fr *store.Frames, genID int64, raw []byte) {
	t.Helper()
	ctx := context.Background()
	if _, err := fr.Append(ctx, genID, raw); err != nil {
		t.Fatal(err)
	}
	if _, err := fr.Flush(ctx, genID); err != nil {
		t.Fatal(err)
	}
}

func multiFrameLog(nLines, pad int) []byte {
	var b bytes.Buffer
	for i := 0; i < nLines; i++ {
		b.WriteString(strings.Repeat("x", pad))
		b.WriteString(" line=")
		num := strconv.Itoa(i)
		if len(num) < 3 {
			b.WriteString(strings.Repeat("0", 3-len(num)))
		}
		b.WriteString(num)
		switch i {
		case 10:
			b.WriteString(" ERROR boom")
		case 25:
			b.WriteString(" error again")
		case 30:
			b.WriteString(" WARN notice")
		}
		b.WriteByte('\n')
	}
	return b.Bytes()
}

func TestLiteralSearch_MultiFrame(t *testing.T) {
	meta, fr, eng, _ := openSearch(t, 64)
	ctx := context.Background()
	genID := insertGen(t, meta, "demo", 1)
	raw := multiFrameLog(40, 20)
	writeLog(t, fr, genID, raw)

	chunks, err := meta.ListChunks(ctx, genID)
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) < 2 {
		t.Fatalf("need multi-frame fixture, got %d chunks (log=%d)", len(chunks), len(raw))
	}

	res, err := eng.Search(ctx, search.Query{
		GenerationID:  genID,
		Pattern:       "ERROR",
		CaseSensitive: true,
		Before:        1,
		After:         1,
		MaxMatches:    10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Matches) != 1 {
		t.Fatalf("matches: got %d want 1 (%+v)", len(res.Matches), res.Matches)
	}
	m := res.Matches[0]
	if m.Line != 10 {
		t.Fatalf("line: %d want 10", m.Line)
	}
	if !strings.Contains(m.LineText, "ERROR boom") {
		t.Fatalf("line text: %q", m.LineText)
	}
	if len(m.Before) != 1 || len(m.After) != 1 {
		t.Fatalf("context before=%d after=%d", len(m.Before), len(m.After))
	}
	if res.FramesOpened < 1 {
		t.Fatalf("frames opened: %d", res.FramesOpened)
	}
	if res.BytesScanned <= 0 {
		t.Fatal("bytes scanned should be > 0")
	}
	if res.GenerationID != genID || res.Profile != "corp" || res.Job != "demo" || res.Build != 1 {
		t.Fatalf("scope meta: %+v", res)
	}
	if m.MatchByteStart < m.LineByteStart || m.MatchByteEnd <= m.MatchByteStart {
		t.Fatalf("bad offsets: %+v", m)
	}
	if int(m.MatchByteEnd) > len(raw) || !bytes.Equal(raw[m.MatchByteStart:m.MatchByteEnd], []byte("ERROR")) {
		t.Fatalf("evidence bytes %q", raw[m.MatchByteStart:m.MatchByteEnd])
	}
}

func TestLiteralSearch_CaseInsensitive(t *testing.T) {
	meta, fr, eng, _ := openSearch(t, 64)
	ctx := context.Background()
	genID := insertGen(t, meta, "demo", 2)
	raw := multiFrameLog(40, 20)
	writeLog(t, fr, genID, raw)

	res, err := eng.Search(ctx, search.Query{
		Profile:       "corp",
		Job:           "demo",
		Build:         2,
		Pattern:       "error",
		CaseSensitive: false,
		MaxMatches:    10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Matches) != 2 {
		t.Fatalf("case-insensitive matches: got %d want 2", len(res.Matches))
	}
	if res.Matches[0].Line >= res.Matches[1].Line {
		t.Fatalf("order: %d then %d", res.Matches[0].Line, res.Matches[1].Line)
	}
}

func TestLiteralSearch_MaxMatches(t *testing.T) {
	meta, fr, eng, _ := openSearch(t, 128)
	ctx := context.Background()
	genID := insertGen(t, meta, "demo", 3)
	var b bytes.Buffer
	for i := 0; i < 20; i++ {
		b.WriteString("hit needle here\n")
	}
	writeLog(t, fr, genID, b.Bytes())

	res, err := eng.Search(ctx, search.Query{
		GenerationID: genID,
		Pattern:      "needle",
		MaxMatches:   3,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Matches) != 3 {
		t.Fatalf("got %d matches", len(res.Matches))
	}
	if !res.Truncated {
		t.Fatal("expected Truncated")
	}
}

func TestLiteralSearch_ScanBudget(t *testing.T) {
	meta, fr, eng, _ := openSearch(t, 64)
	ctx := context.Background()
	genID := insertGen(t, meta, "demo", 4)
	raw := multiFrameLog(80, 40)
	writeLog(t, fr, genID, raw)
	chunks, _ := meta.ListChunks(ctx, genID)
	if len(chunks) < 2 {
		t.Fatalf("need multi-frame, got %d", len(chunks))
	}

	capBytes := chunks[0].UncompressedSize / 2
	if capBytes < 16 {
		capBytes = 16
	}
	res, err := eng.Search(ctx, search.Query{
		GenerationID:    genID,
		Pattern:         "ERROR",
		CaseSensitive:   true,
		MaxBytesScanned: capBytes,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Incomplete {
		t.Fatalf("expected Incomplete, frames=%d scanned=%d cap=%d",
			res.FramesOpened, res.BytesScanned, res.BytesScannedCap)
	}
	// Whole-frame decompress: the first frame may exceed the remaining cap;
	// subsequent frames must not open once the cap is reached.
	if res.FramesOpened != 1 {
		t.Fatalf("expected only first frame under tight cap, opened %d", res.FramesOpened)
	}
	if res.BytesScanned < capBytes {
		t.Fatalf("scanned %d < cap %d (should open first frame fully)", res.BytesScanned, capBytes)
	}
}

func TestLiteralSearch_Cancel(t *testing.T) {
	meta, fr, eng, _ := openSearch(t, 32)
	genID := insertGen(t, meta, "demo", 5)
	raw := multiFrameLog(200, 30)
	writeLog(t, fr, genID, raw)

	cctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := eng.Search(cctx, search.Query{
		GenerationID: genID,
		Pattern:      "line=",
	})
	if err == nil {
		t.Fatal("expected cancel error")
	}
	if !apperr.IsCancelled(err) {
		t.Fatalf("code: %v (%v)", apperr.CodeOf(err), err)
	}
}

func TestLiteralSearch_CancelDuringScan(t *testing.T) {
	meta, fr, eng, _ := openSearch(t, 32)
	genID := insertGen(t, meta, "demo", 6)
	raw := multiFrameLog(300, 40)
	writeLog(t, fr, genID, raw)

	cctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	time.Sleep(2 * time.Millisecond)
	_, err := eng.Search(cctx, search.Query{
		GenerationID: genID,
		Pattern:      "line=",
	})
	if err == nil {
		t.Skip("search finished before deadline; cancel path covered by TestLiteralSearch_Cancel")
	}
	code := apperr.CodeOf(err)
	if code != apperr.CodeCancelled && code != apperr.CodeTimeout {
		t.Fatalf("want cancelled/timeout, got %s: %v", code, err)
	}
}

func TestLiteralSearch_ResolveByJobBuild(t *testing.T) {
	meta, fr, eng, _ := openSearch(t, 0)
	genID := insertGen(t, meta, "pipe/job", 99)
	writeLog(t, fr, genID, []byte("hello unique_token world\n"))

	res, err := eng.Search(context.Background(), search.Query{
		Profile: "corp",
		Job:     "pipe/job",
		Build:   99,
		Pattern: "unique_token",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Matches) != 1 {
		t.Fatalf("matches: %d", len(res.Matches))
	}
}

func TestEngine_Resolve_GenerationID(t *testing.T) {
	meta, fr, eng, _ := openSearch(t, 0)
	genID := insertGen(t, meta, "secret-folder/job", 3)
	writeLog(t, fr, genID, []byte("secret line\n"))

	scope, err := eng.Resolve(context.Background(), search.Query{GenerationID: genID})
	if err != nil {
		t.Fatal(err)
	}
	if scope.GenerationID != genID || scope.Job != "secret-folder/job" || scope.Build != 3 || scope.Profile != "corp" {
		t.Fatalf("scope=%+v", scope)
	}

	// Missing generation → not_found (no frames opened).
	_, err = eng.Resolve(context.Background(), search.Query{GenerationID: 99999})
	if !apperr.IsCode(err, apperr.CodeNotFound) {
		t.Fatalf("want not_found, got %v", err)
	}
}

func TestLiteralSearch_NotFoundGeneration(t *testing.T) {
	_, _, eng, _ := openSearch(t, 0)
	_, err := eng.Search(context.Background(), search.Query{
		GenerationID: 99999,
		Pattern:      "x",
	})
	if !apperr.IsCode(err, apperr.CodeNotFound) {
		t.Fatalf("want not_found, got %v", err)
	}
}

func TestLiteralSearch_EmptyPattern(t *testing.T) {
	meta, fr, eng, _ := openSearch(t, 0)
	genID := insertGen(t, meta, "demo", 7)
	writeLog(t, fr, genID, []byte("a\n"))
	_, err := eng.Search(context.Background(), search.Query{
		GenerationID: genID,
		Pattern:      "",
	})
	if !apperr.IsCode(err, apperr.CodeInvalidArgument) {
		t.Fatalf("want invalid_argument, got %v", err)
	}
}

func TestRegexSearch_Simple(t *testing.T) {
	meta, fr, eng, _ := openSearch(t, 64)
	genID := insertGen(t, meta, "demo", 8)
	raw := multiFrameLog(40, 20)
	writeLog(t, fr, genID, raw)

	res, err := eng.Search(context.Background(), search.Query{
		GenerationID:  genID,
		Pattern:       `ERROR\s+\w+`,
		Mode:          search.ModeRegex,
		CaseSensitive: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Matches) != 1 {
		t.Fatalf("regex matches: %d", len(res.Matches))
	}
	if !strings.Contains(res.Matches[0].LineText, "ERROR boom") {
		t.Fatalf("text: %q", res.Matches[0].LineText)
	}
}

func TestRegexSearch_CaseInsensitive(t *testing.T) {
	meta, fr, eng, _ := openSearch(t, 64)
	genID := insertGen(t, meta, "demo", 9)
	writeLog(t, fr, genID, multiFrameLog(40, 20))

	res, err := eng.Search(context.Background(), search.Query{
		GenerationID:  genID,
		Pattern:       `error\s+\w+`,
		Mode:          search.ModeRegex,
		CaseSensitive: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Matches) < 1 {
		t.Fatal("expected at least one case-insensitive regex match")
	}
}

func TestRegexSearch_Invalid(t *testing.T) {
	meta, fr, eng, _ := openSearch(t, 0)
	genID := insertGen(t, meta, "demo", 10)
	writeLog(t, fr, genID, []byte("a\n"))
	_, err := eng.Search(context.Background(), search.Query{
		GenerationID: genID,
		Pattern:      `(unclosed`,
		Mode:         search.ModeRegex,
	})
	if !apperr.IsCode(err, apperr.CodeInvalidArgument) {
		t.Fatalf("want invalid_argument, got %v", err)
	}
}

func TestRegexSearch_Cancel(t *testing.T) {
	meta, fr, eng, _ := openSearch(t, 32)
	genID := insertGen(t, meta, "demo", 11)
	writeLog(t, fr, genID, multiFrameLog(100, 30))
	cctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := eng.Search(cctx, search.Query{
		GenerationID: genID,
		Pattern:      `line=\d+`,
		Mode:         search.ModeRegex,
	})
	if !apperr.IsCancelled(err) {
		t.Fatalf("want cancelled, got %v", err)
	}
}

func TestRegexSearch_NestedDepthRejected(t *testing.T) {
	meta, fr, eng, _ := openSearch(t, 0)
	genID := insertGen(t, meta, "demo", 12)
	writeLog(t, fr, genID, []byte("a\n"))
	pat := strings.Repeat("(", 33) + "a" + strings.Repeat(")", 33)
	_, err := eng.Search(context.Background(), search.Query{
		GenerationID: genID,
		Pattern:      pat,
		Mode:         search.ModeRegex,
	})
	if !apperr.IsCode(err, apperr.CodeInvalidArgument) {
		t.Fatalf("want invalid_argument for deep nesting, got %v", err)
	}
}

func TestGetGenerationByID(t *testing.T) {
	meta, _, _, _ := openSearch(t, 0)
	id := insertGen(t, meta, "demo", 13)
	g, err := meta.GetGenerationByID(context.Background(), id)
	if err != nil || g == nil {
		t.Fatalf("GetGenerationByID: %v %+v", err, g)
	}
	if g.Job != "demo" || g.Build != 13 {
		t.Fatalf("got %+v", g)
	}
	g2, err := meta.GetGenerationByID(context.Background(), 99999)
	if err != nil || g2 != nil {
		t.Fatalf("missing: %v %+v", err, g2)
	}
}

func TestCrossFrameLineMatch(t *testing.T) {
	// Force mid-line frame cut: tiny max so a long line is split across frames.
	meta, fr, eng, _ := openSearch(t, 16)
	fr.MaxBytes = 16
	ctx := context.Background()
	genID := insertGen(t, meta, "demo", 14)
	long := strings.Repeat("a", 12) + "FINDME" + strings.Repeat("b", 12) + "\n"
	writeLog(t, fr, genID, []byte(long))
	chunks, _ := meta.ListChunks(ctx, genID)
	if len(chunks) < 2 {
		t.Fatalf("expected split frames, got %d (len=%d)", len(chunks), len(long))
	}
	res, err := eng.Search(ctx, search.Query{
		GenerationID: genID,
		Pattern:      "FINDME",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Matches) != 1 {
		t.Fatalf("cross-frame line match: got %d (chunks=%d)", len(res.Matches), len(chunks))
	}
}
