package logmirror_test

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/logmirror"
	"github.com/simonfxr/go-jenkins-mcp/internal/store"
)

func openMachine(t *testing.T, src logmirror.ProgressiveSource) (*logmirror.Machine, logmirror.LogKey) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "profiles", "corp")
	meta, err := store.Open(dir)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = meta.Close() })
	m := logmirror.NewMachine(meta, src)
	m.FetchBytes = 8 // small chunks for multi-poll tests
	key := logmirror.LogKey{Profile: "corp", Job: "demo", Build: 7}
	return m, key
}

func TestMachine_IncrementalPollOncePerByte(t *testing.T) {
	src := &logmirror.FakeSource{Log: []byte("abcdefghij"), Running: false}
	m, key := openMachine(t, src)
	ctx := context.Background()

	var last logmirror.State
	for i := 0; i < 20; i++ {
		st, err := m.Poll(ctx, key, true)
		if err != nil {
			t.Fatalf("Poll %d: %v", i, err)
		}
		last = st
		if st.Sealed {
			break
		}
	}
	if !last.Sealed {
		t.Fatalf("expected sealed, got %s", last)
	}
	if last.CommittedOffset != 10 {
		t.Fatalf("offset: %d", last.CommittedOffset)
	}
	if m.BytesFetched(key) != 10 {
		t.Fatalf("bytes fetched: %d want 10", m.BytesFetched(key))
	}
	// Each byte once: fetch count should be enough for 10 bytes / 8 + final empty/seal polls.
	if src.FetchCount < 2 {
		t.Fatalf("expected multiple progressive fetches, got %d", src.FetchCount)
	}
}

func TestMachine_RunningThenCompleteSeals(t *testing.T) {
	src := &logmirror.FakeSource{Log: []byte("hello"), Running: true}
	m, key := openMachine(t, src)
	ctx := context.Background()

	st, err := m.Poll(ctx, key, false)
	if err != nil {
		t.Fatal(err)
	}
	if st.Sealed || !st.MoreData {
		t.Fatalf("running: %s", st)
	}

	// Build finishes; no more data.
	src.Running = false
	st, err = m.Poll(ctx, key, true)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Sealed {
		// May need one more poll if first post-complete still had more flag edge.
		st, err = m.Poll(ctx, key, true)
		if err != nil {
			t.Fatal(err)
		}
	}
	if !st.Sealed || st.MoreData {
		t.Fatalf("expected sealed complete: %s", st)
	}

	// Completed logs stop polling (no extra remote fetch).
	fetches := src.FetchCount
	st2, err := m.Poll(ctx, key, true)
	if err != nil {
		t.Fatal(err)
	}
	if src.FetchCount != fetches {
		t.Fatalf("sealed poll should not fetch: before=%d after=%d", fetches, src.FetchCount)
	}
	if !st2.Sealed {
		t.Fatalf("still sealed: %s", st2)
	}
}

func TestMachine_OffsetRegressionNewGeneration(t *testing.T) {
	src := &logmirror.FakeSource{Log: []byte("0123456789"), Running: false}
	m, key := openMachine(t, src)
	ctx := context.Background()

	// Mirror full log gen1.
	for {
		st, err := m.Poll(ctx, key, true)
		if err != nil {
			t.Fatal(err)
		}
		if st.Sealed || st.CommittedOffset >= 10 {
			break
		}
	}
	st, _ := m.State(ctx, key)
	if st.Generation != 1 || st.CommittedOffset != 10 {
		t.Fatalf("pre-rewrite: %s", st)
	}

	// Truncation/rewrite: shorter log.
	src.SetLog([]byte("ABCD"))
	// Sealed gen ignores empty activity; force rewrite path via Append with regression signal.
	// Unseal scenario: use a fresh open generation.
	// Open a new machine path: insert by appending regression against open gen.
	// Re-open store state: mark by using Append on a non-sealed gen.
	// Create new key build to have open gen, then rewrite.
	key2 := logmirror.LogKey{Profile: "corp", Job: "demo", Build: 8}
	src2 := &logmirror.FakeSource{Log: []byte("0123456789"), Running: true}
	m2, _ := openMachine(t, src2)
	for src2.FetchCount < 3 {
		if _, err := m2.Poll(ctx, key2, false); err != nil {
			t.Fatal(err)
		}
	}
	st, _ = m2.State(ctx, key2)
	if st.CommittedOffset == 0 {
		t.Fatal("expected progress before rewrite")
	}
	prevGen := st.Generation
	prevOff := st.CommittedOffset

	// Truncate while still open.
	src2.SetLog([]byte("XY"))
	st, err := m2.Poll(ctx, key2, false)
	if err != nil {
		t.Fatal(err)
	}
	if st.Generation <= prevGen {
		t.Fatalf("expected new generation after truncation; prev=%d got=%s", prevGen, st)
	}
	if st.CommittedOffset != 0 {
		t.Fatalf("new generation should start at 0, got %d (prev was %d)", st.CommittedOffset, prevOff)
	}

	// Resume downloads from 0 once.
	st, err = m2.Poll(ctx, key2, true)
	if err != nil {
		t.Fatal(err)
	}
	if st.CommittedOffset != 2 && !st.Sealed {
		// With FetchBytes=8, should get all "XY" in one poll.
		if st.CommittedOffset != 2 {
			t.Fatalf("after re-fetch: %s", st)
		}
	}
}

func TestMachine_CrashResumeFromCommittedOffset(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "profiles", "corp")
	meta, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	src := &logmirror.FakeSource{Log: []byte("abcdefghijklmnop"), Running: true}
	m := logmirror.NewMachine(meta, src)
	m.FetchBytes = 4
	key := logmirror.LogKey{Profile: "corp", Job: "demo", Build: 1}
	ctx := context.Background()

	st, err := m.Poll(ctx, key, false)
	if err != nil {
		t.Fatal(err)
	}
	if st.CommittedOffset != 4 {
		t.Fatalf("offset after first poll: %d", st.CommittedOffset)
	}
	committed := st.CommittedOffset
	fetchesBeforeCrash := src.FetchCount
	_ = meta.Close()

	// Restart: new Machine, same DB.
	meta2, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = meta2.Close() })
	src.FetchCount = 0
	m2 := logmirror.NewMachine(meta2, src)
	m2.FetchBytes = 4

	st2, err := m2.State(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if st2.CommittedOffset != committed {
		t.Fatalf("resume state offset: got %d want %d", st2.CommittedOffset, committed)
	}

	st3, err := m2.Poll(ctx, key, false)
	if err != nil {
		t.Fatal(err)
	}
	if st3.CommittedOffset != committed+4 {
		t.Fatalf("after resume poll: %s", st3)
	}
	// Must not re-download earlier bytes: one fetch of next chunk only.
	if src.FetchCount != 1 {
		t.Fatalf("expected single fetch after resume, got %d (pre-crash fetches were %d)", src.FetchCount, fetchesBeforeCrash)
	}
	if m2.BytesFetched(key) != 4 {
		// In-process counter resets on restart (residual); only this process's new bytes.
		t.Fatalf("bytes this process: %d", m2.BytesFetched(key))
	}
}

func TestMachine_SingleFlightNoDuplicateFetches(t *testing.T) {
	src := &logmirror.FakeSource{Log: []byte("0123456789abcdef"), Running: true}
	m, key := openMachine(t, src)
	m.FetchBytes = 16
	ctx := context.Background()

	// First poll establishes gen + offset (unblocked).
	if _, err := m.Poll(ctx, key, false); err != nil {
		t.Fatal(err)
	}
	base := src.FetchCount

	// Block the next Fetch so concurrent Polls overlap inside singleflight.
	fetchStarted := make(chan struct{})
	release := make(chan struct{})
	src.BeforeFetch = func() {
		select {
		case <-fetchStarted:
		default:
			close(fetchStarted)
		}
		<-release
	}

	const n = 32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, err := m.Poll(ctx, key, false); err != nil {
				t.Errorf("Poll: %v", err)
			}
		}()
	}
	close(start)
	<-fetchStarted
	// Hold the in-flight fetch until all goroutines have entered Poll.
	// singleflight coalesces them onto the one remote Fetch.
	time.Sleep(50 * time.Millisecond)
	if src.FetchCount != base+1 {
		t.Fatalf("during overlap expected exactly one new fetch, got total %d (base %d)", src.FetchCount, base)
	}
	close(release)
	wg.Wait()

	st, _ := m.State(ctx, key)
	if st.CommittedOffset > int64(len(src.Log)) {
		t.Fatalf("offset past log: %d", st.CommittedOffset)
	}
	if m.BytesFetched(key) > int64(len(src.Log)) {
		t.Fatalf("downloaded more than log size: %d", m.BytesFetched(key))
	}
	// Wave must not multiply fetches (not n additional).
	if src.FetchCount != base+1 {
		t.Fatalf("single-flight: fetch count got %d want %d (base %d + 1)", src.FetchCount, base+1, base)
	}
}

func TestMachine_AppendAndSealAPI(t *testing.T) {
	m, key := openMachine(t, nil)
	ctx := context.Background()

	st, err := m.Append(ctx, key, logmirror.Segment{
		Data:               []byte("hello"),
		ReportedNextOffset: 5,
		MoreData:           false,
		BuildComplete:      true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !st.Sealed || st.CommittedOffset != 5 {
		t.Fatalf("append seal: %s", st)
	}
	st2, err := m.Seal(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if !st2.Sealed {
		t.Fatal("seal idempotent")
	}
}

func TestMachine_SealWhileMoreDataFails(t *testing.T) {
	m, key := openMachine(t, nil)
	ctx := context.Background()
	if _, err := m.Append(ctx, key, logmirror.Segment{
		Data:               []byte("x"),
		ReportedNextOffset: 10,
		MoreData:           true,
		BuildComplete:      false,
	}); err != nil {
		t.Fatal(err)
	}
	_, err := m.Seal(ctx, key)
	if err == nil {
		t.Fatal("expected seal failure while more_data")
	}
	if !apperr.IsCode(err, apperr.CodeInvalidArgument) {
		t.Fatalf("code: %s", apperr.CodeOf(err))
	}
}

func TestMachine_CancelDuringPoll(t *testing.T) {
	src := &logmirror.FakeSource{Log: []byte("data"), Running: true}
	m, key := openMachine(t, src)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := m.Poll(ctx, key, false)
	if err == nil {
		t.Fatal("expected cancel error")
	}
	// Committed offset must remain recoverable (0 or previous).
	st, stErr := m.State(context.Background(), key)
	if stErr != nil {
		t.Fatal(stErr)
	}
	// Generation may have been created before fetch.
	if st.CommittedOffset != 0 {
		t.Fatalf("cancel must not advance offset: %s", st)
	}
}

func TestMachine_AppendUnsetReportedSizeDoesNotRewrite(t *testing.T) {
	// Regression: zero-value ReportedNextOffset with non-empty Data must not
	// be treated as total size 0 (which would spuriously open gen 2).
	m, key := openMachine(t, nil)
	ctx := context.Background()
	st, err := m.Append(ctx, key, logmirror.Segment{
		Data:     []byte("hello"),
		MoreData: true,
		// ReportedNextOffset left 0 → unknown
	})
	if err != nil {
		t.Fatal(err)
	}
	if st.Generation != 1 || st.CommittedOffset != 5 {
		t.Fatalf("unexpected state: %s", st)
	}
}

func TestMachine_AppendRegressionCreatesGeneration(t *testing.T) {
	m, key := openMachine(t, nil)
	ctx := context.Background()
	if _, err := m.Append(ctx, key, logmirror.Segment{
		Data: []byte("0123456789"), ReportedNextOffset: 10, MoreData: true,
	}); err != nil {
		t.Fatal(err)
	}
	st, err := m.Append(ctx, key, logmirror.Segment{
		Data: nil, ReportedNextOffset: 3, MoreData: true, // truncation
	})
	if err != nil {
		t.Fatal(err)
	}
	if st.Generation != 2 || st.CommittedOffset != 0 {
		t.Fatalf("rewrite: %s", st)
	}
}
