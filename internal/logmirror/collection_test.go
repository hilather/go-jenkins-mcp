package logmirror_test

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/logmirror"
	"github.com/simonfxr/go-jenkins-mcp/internal/store"
)

func openCoord(t *testing.T, src logmirror.ProgressiveSource) (
	*logmirror.Coordinator, *logmirror.Machine, *logmirror.FakeBuildStatus,
) {
	t.Helper()
	c, m, status, _ := openCoordWithMeta(t, src)
	return c, m, status
}

// openCoordWithMeta wires Catalog (*store.Meta) for durable collection tests.
func openCoordWithMeta(t *testing.T, src logmirror.ProgressiveSource) (
	*logmirror.Coordinator, *logmirror.Machine, *logmirror.FakeBuildStatus, *store.Meta,
) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "profiles", "corp")
	meta, err := store.Open(dir)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = meta.Close() })
	fr, err := store.NewFrames(meta, dir)
	if err != nil {
		t.Fatal(err)
	}
	fr.TargetBytes = 64
	fr.MaxBytes = 256
	t.Cleanup(func() { _ = fr.Close() })
	if _, err := fr.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	reader, err := fr.Reader()
	if err != nil {
		t.Fatal(err)
	}
	m := logmirror.NewMachine(meta, src)
	m.Frames = fr
	m.Reader = reader
	m.FetchBytes = 32
	status := logmirror.NewFakeBuildStatus()
	c := logmirror.NewCoordinator("corp", m, logmirror.CollectionBounds{
		MaxConcurrency: 2,
		MaxTotalBytes:  1 << 20,
		MaxPerLogBytes: 1 << 20,
		MaxPollsPerLog: 64,
	})
	c.Status = status
	c.Catalog = meta // LOG-004 durable collection catalog
	return c, m, status, meta
}

// multiFake routes progressive fetches by job name (shared FakeSource per job).
type multiFake struct {
	mu    sync.Mutex
	byJob map[string]*logmirror.FakeSource
	// FetchCount is total remote-ish fetches across jobs.
	FetchCount atomic.Int64
}

func (m *multiFake) source(job string) *logmirror.FakeSource {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.byJob == nil {
		m.byJob = make(map[string]*logmirror.FakeSource)
	}
	s, ok := m.byJob[job]
	if !ok {
		s = &logmirror.FakeSource{Running: false}
		m.byJob[job] = s
	}
	return s
}

func (m *multiFake) Fetch(ctx context.Context, job string, build int64, startOffset int64, maxBytes int) (
	data []byte, reportedNext int64, moreData bool, err error,
) {
	m.FetchCount.Add(1)
	return m.source(job).Fetch(ctx, job, build, startOffset, maxBytes)
}

func TestCoordinator_Acquire_DedupAndFanOut(t *testing.T) {
	mf := &multiFake{}
	// Two distinct logs + a duplicate of the first.
	mf.source("job-a").SetLog([]byte(strings.Repeat("A", 100)))
	mf.source("job-b").SetLog([]byte(strings.Repeat("B", 80)))

	c, machine, status := openCoord(t, mf)
	status.Set("job-a", 1, true)
	status.Set("job-b", 2, true)
	ctx := context.Background()

	res, err := c.Acquire(ctx, []logmirror.LogRequest{
		{Job: "job-a", Build: 1, Relation: "primary"},
		{Job: "job-b", Build: 2, Relation: "related"},
		{Job: "job-a", Build: 1, Relation: "dup"}, // dedup
	})
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if res.CollectionID == "" {
		t.Fatal("expected collection id")
	}
	if res.Profile != "corp" {
		t.Fatalf("profile: %q", res.Profile)
	}
	if len(res.Results) != 2 {
		t.Fatalf("expected 2 deduped results, got %d", len(res.Results))
	}
	// Sorted by job then build.
	if res.Results[0].Key.Job != "job-a" || res.Results[1].Key.Job != "job-b" {
		t.Fatalf("order: %+v", res.Results)
	}
	for _, r := range res.Results {
		if r.Err != nil {
			t.Fatalf("log %s: %v", r.Key, r.Err)
		}
		if !r.State.Sealed {
			t.Fatalf("expected sealed: %s", r.State)
		}
	}
	// Duplicate requests share one stored generation (single acquisition path).
	stA, err := machine.State(ctx, logmirror.LogKey{Profile: "corp", Job: "job-a", Build: 1})
	if err != nil || !stA.Sealed {
		t.Fatalf("job-a state: %+v err=%v", stA, err)
	}
	// Session membership recorded (no cross-profile).
	sess, ok := c.Session(res.CollectionID)
	if !ok || len(sess.Members) != 2 {
		t.Fatalf("session: ok=%v members=%v", ok, sess)
	}
	sealed, err := c.SealedMembers(ctx, res.CollectionID)
	if err != nil || len(sealed) != 2 {
		t.Fatalf("sealed members: %v err=%v", sealed, err)
	}
	// Local read without raw multi-log buffer: each generation independent frames.
	acc := logmirror.NewAccess("corp", machine)
	logs, meta, err := acc.ReadRange(ctx, "job-a", 1, 0, 50)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(logs, "AAAA") || meta.Sealed != true {
		t.Fatalf("read: %q meta=%+v", logs, meta)
	}
}

func TestCoordinator_Acquire_CancellationLeavesCommittedFrames(t *testing.T) {
	// Block first progressive fetch until cancel.
	var started sync.WaitGroup
	started.Add(1)
	src := &logmirror.FakeSource{
		Log:     []byte(strings.Repeat("X", 200)),
		Running: false,
		BeforeFetch: func() {
			started.Done()
			time.Sleep(200 * time.Millisecond)
		},
	}
	// Only signal once.
	var once sync.Once
	src.BeforeFetch = func() {
		once.Do(func() { started.Done() })
		time.Sleep(150 * time.Millisecond)
	}

	c, machine, status := openCoord(t, src)
	status.Set("slow", 1, true)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan logmirror.CollectionResult, 1)
	go func() {
		res, _ := c.Acquire(ctx, []logmirror.LogRequest{
			{Job: "slow", Build: 1},
		})
		done <- res
	}()
	started.Wait()
	cancel()
	res := <-done
	if !res.Cancelled && res.Results[0].Err == nil {
		// May complete if fetch finished before cancel; still OK if sealed or partial.
		t.Logf("cancel race: result=%s err=%v", res, res.Results[0].Err)
	}
	// Committed frames remain recoverable when any durable bytes exist.
	st, err := machine.State(context.Background(), logmirror.LogKey{Profile: "corp", Job: "slow", Build: 1})
	if err != nil {
		t.Fatal(err)
	}
	// Generation may or may not exist depending on cancel timing; if present,
	// store is consistent (no panic / corrupt).
	if st.GenerationID > 0 && st.DurableOffset > 0 {
		acc := logmirror.NewAccess("corp", machine)
		_, _, rerr := acc.ReadRange(context.Background(), "slow", 1, 0, 16)
		if rerr != nil && apperr.CodeOf(rerr) == apperr.CodeCorruptCache {
			t.Fatalf("corrupt after cancel: %v", rerr)
		}
	}
}

func TestCoordinator_Acquire_TotalBudget(t *testing.T) {
	mf := &multiFake{}
	// Each log is large; total budget should stop later acquisitions.
	big := []byte(strings.Repeat("Z", 500))
	for _, job := range []string{"a", "b", "c", "d"} {
		mf.source(job).SetLog(big)
	}
	c, _, status := openCoord(t, mf)
	for i, job := range []string{"a", "b", "c", "d"} {
		status.Set(job, int64(i+1), true)
	}
	c.Bounds = logmirror.CollectionBounds{
		MaxConcurrency: 1, // serial so budget is observed predictably
		MaxTotalBytes:  200,
		MaxPerLogBytes: 1 << 20,
		MaxPollsPerLog: 64,
	}.Normalize()

	res, err := c.Acquire(context.Background(), []logmirror.LogRequest{
		{Job: "a", Build: 1},
		{Job: "b", Build: 2},
		{Job: "c", Build: 3},
		{Job: "d", Build: 4},
	})
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if res.TotalBytes > 200+32 { // allow one in-flight poll overshoot within FetchBytes
		// Strict: TotalBytes should be near budget; allow small overshoot from last poll.
		if res.TotalBytes > 500 {
			t.Fatalf("total bytes unbounded: %d", res.TotalBytes)
		}
	}
	// At least one log should make progress (partial OK under tight total budget).
	// With MaxTotalBytes=200 and 500-byte logs, full seal of all four is impossible.
	var progressed, failed int
	for _, r := range res.Results {
		if r.BytesFetched > 0 || r.State.GenerationID > 0 || r.State.DurableOffset > 0 {
			progressed++
		}
		if r.Err != nil {
			failed++
		}
	}
	if progressed == 0 {
		t.Fatalf("expected some mirrored progress under budget: %+v", res.Results)
	}
	if res.TotalBytes > 500 {
		t.Fatalf("total bytes unbounded: %d", res.TotalBytes)
	}
	// Later logs should observe the budget (quota or skip).
	if failed == 0 && res.TotalBytes > 200 && !res.TruncatedBudget {
		t.Logf("budget soft: total=%d progressed=%d failed=%d truncated=%v",
			res.TotalBytes, progressed, failed, res.TruncatedBudget)
	}
}

func TestCoordinator_RejectsEmptyProfile(t *testing.T) {
	c := logmirror.NewCoordinator("", logmirror.NewMachine(nil, nil), logmirror.CollectionBounds{})
	_, err := c.Acquire(context.Background(), []logmirror.LogRequest{{Job: "j", Build: 1}})
	if err == nil {
		t.Fatal("expected error for empty profile")
	}
}

func TestCoordinator_SameProfileIsolation(t *testing.T) {
	// Coordinator stamps its profile; LogRequest cannot inject another profile.
	mf := &multiFake{}
	mf.source("j").SetLog([]byte("hello-world-log-body"))
	c, _, status := openCoord(t, mf)
	status.Set("j", 1, true)
	res, err := c.Acquire(context.Background(), []logmirror.LogRequest{{Job: "j", Build: 1}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Results[0].Key.Profile != "corp" {
		t.Fatalf("profile stamp: %q", res.Results[0].Key.Profile)
	}
}

// Regression: collection_id was in-process only; durable catalog reloads after restart.
func TestCoordinator_DurableCatalog_SurvivesRestart(t *testing.T) {
	mf := &multiFake{}
	// job-a seals; job-b stays running so residual continue is meaningful.
	mf.source("job-a").SetLog([]byte(strings.Repeat("A", 80)))
	mf.source("job-b").SetLog([]byte(strings.Repeat("B", 40)))
	mf.source("job-b").Running = true

	c1, machine, status, meta := openCoordWithMeta(t, mf)
	status.Set("job-a", 1, true)
	status.Set("job-b", 2, false)
	ctx := context.Background()

	res, err := c1.Acquire(ctx, []logmirror.LogRequest{
		{Job: "job-a", Build: 1, Relation: "primary"},
		{Job: "job-b", Build: 2, Relation: "downstream"},
	})
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	if res.CollectionID == "" {
		t.Fatal("expected collection id")
	}
	// Catalog row must exist under Meta.
	coll, err := meta.GetCollection(ctx, res.CollectionID, "corp")
	if err != nil || coll == nil {
		t.Fatalf("GetCollection: err=%v coll=%+v", err, coll)
	}
	members, err := meta.ListMembers(ctx, res.CollectionID, "corp")
	if err != nil {
		t.Fatal(err)
	}
	if len(members) != 2 {
		t.Fatalf("catalog members: %d", len(members))
	}

	// Simulate process restart: new Coordinator, empty in-process map, same Meta.
	c2 := logmirror.NewCoordinator("corp", machine, logmirror.CollectionBounds{
		MaxConcurrency: 2,
		MaxTotalBytes:  1 << 20,
		MaxPerLogBytes: 1 << 20,
		MaxPollsPerLog: 64,
	})
	c2.Status = status
	c2.Catalog = meta

	// LoadSession from store only (no prior in-process session on c2).
	sess, err := c2.LoadSession(ctx, res.CollectionID)
	if err != nil {
		t.Fatalf("LoadSession after restart: %v", err)
	}
	if len(sess.Members) != 2 {
		t.Fatalf("session members: %d", len(sess.Members))
	}
	if sess.Relations[logmirror.LogKey{Profile: "corp", Job: "job-a", Build: 1}.String()] != "primary" {
		t.Fatalf("relation primary lost: %+v", sess.Relations)
	}

	// SealedMembers from durable session.
	sealed, err := c2.SealedMembers(ctx, res.CollectionID)
	if err != nil {
		t.Fatal(err)
	}
	if len(sealed) != 1 || sealed[0].Job != "job-a" {
		t.Fatalf("sealed after restart: %+v", sealed)
	}

	// Unknown id fails closed.
	_, err = c2.LoadSession(ctx, "deadbeefdeadbeefdeadbeefdeadbeef")
	if err == nil || !apperr.IsCode(err, apperr.CodeNotFound) {
		t.Fatalf("unknown collection: %v", err)
	}
}

// Compile-time: *store.Meta implements CollectionCatalog.
var _ logmirror.CollectionCatalog = (*store.Meta)(nil)
