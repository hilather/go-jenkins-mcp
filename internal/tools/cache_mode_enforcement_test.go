package tools

import (
	"context"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/jenkins"
	"github.com/hilather/go-jenkins-mcp/internal/store"
)

// modeGate is a test CacheModeGate.
type modeGate struct {
	lookup, fill map[string]bool
}

func (g modeGate) AllowLookup(typeID string) bool {
	if g.lookup == nil {
		return true
	}
	v, ok := g.lookup[typeID]
	if !ok {
		return true
	}
	return v
}
func (g modeGate) AllowFill(typeID string) bool {
	if g.fill == nil {
		return true
	}
	v, ok := g.fill[typeID]
	if !ok {
		return true
	}
	return v
}

// stubLogAccess serves a fixed log body for survey extract / diagnose paths.
type stubLogAccess struct {
	body        string
	tailCalls   atomic.Int32
	readCalls   atomic.Int32
	ensureCalls atomic.Int32
}

func (s *stubLogAccess) EnsureMirrored(context.Context, string, int64) error {
	s.ensureCalls.Add(1)
	return nil
}
func (s *stubLogAccess) ReadRange(_ context.Context, _ string, _ int64, offset, length int64) (string, LogReadMeta, error) {
	s.readCalls.Add(1)
	b := s.body
	if offset > int64(len(b)) {
		offset = int64(len(b))
	}
	end := offset + length
	if end > int64(len(b)) {
		end = int64(len(b))
	}
	out := b[offset:end]
	return out, LogReadMeta{Offset: int(offset), Length: len(out), TotalSize: len(b), Sealed: true, Generation: 1}, nil
}
func (s *stubLogAccess) Tail(_ context.Context, _ string, _ int64, maxLen int64) (string, LogReadMeta, error) {
	s.tailCalls.Add(1)
	b := s.body
	if maxLen <= 0 || maxLen > int64(len(b)) {
		maxLen = int64(len(b))
	}
	start := int64(len(b)) - maxLen
	if start < 0 {
		start = 0
	}
	out := b[start:]
	return out, LogReadMeta{Offset: int(start), Length: len(out), TotalSize: len(b), Sealed: true, Generation: 1}, nil
}

// Regression: survey process L1 (surveySigCache) must honor CacheModes even when Meta is closed.
func TestLoadSurveyBuildSummary_ModeOff_ProcessL1LookupBlocked(t *testing.T) {
	c := newSurveySigCache(time.Minute, 16)
	key := surveyCacheKey("p", "demo", 7, 1024)
	c.put(key, surveyBuildSummary{
		Job: "demo", Build: 7, Result: "FAILURE",
		Findings: []surveyFindingCompact{{Signature: "deadbeef", Message: "Error: boom"}},
	})
	if c.len() != 1 {
		t.Fatal("precondition")
	}

	// mode=off: no lookup, no fill — must not hit process L1.
	st := regState{
		cacheModes: modeGate{
			lookup: map[string]bool{cacheTypeSurveySummary: false},
			fill:   map[string]bool{cacheTypeSurveySummary: false},
		},
		logs: &stubLogAccess{body: "Error: boom\nBUILD FAILURE\n"},
	}
	sum, hit, _, src := loadSurveyBuildSummary(context.Background(), nil, st, c, "p", "demo",
		jenkins.Build{Number: 7, Result: "FAILURE"}, 1024)
	if hit {
		t.Fatalf("mode off must not serve process L1 cache: hit src=%s sum=%+v", src, sum)
	}
	if src == "survey_cache" {
		t.Fatal("source must not be survey_cache under mode off")
	}
	// Process cache entry still retained (disable does not purge).
	if c.len() != 1 {
		t.Fatalf("mode off must not purge process L1: len=%d", c.len())
	}

	// Re-enable lookup → hit retained entry.
	st.cacheModes = modeGate{
		lookup: map[string]bool{cacheTypeSurveySummary: true},
		fill:   map[string]bool{cacheTypeSurveySummary: false},
	}
	_, hit, _, src = loadSurveyBuildSummary(context.Background(), nil, st, c, "p", "demo",
		jenkins.Build{Number: 7, Result: "FAILURE"}, 1024)
	if !hit || src != "survey_cache" {
		t.Fatalf("mode on should hit process L1: hit=%v src=%s", hit, src)
	}
}

// Regression: process L1 fill blocked when survey_summary mode disallows write.
func TestLoadSurveyBuildSummary_ModeReadOnly_ProcessL1NoFill(t *testing.T) {
	c := newSurveySigCache(time.Minute, 16)
	logs := &stubLogAccess{body: "Error: compilation failed\nBUILD FAILURE\nFinished: FAILURE\n"}
	st := regState{
		cacheModes: modeGate{
			lookup: map[string]bool{cacheTypeSurveySummary: true},
			fill:   map[string]bool{cacheTypeSurveySummary: false},
		},
		logs: logs,
	}
	_, hit, _, _ := loadSurveyBuildSummary(context.Background(), nil, st, c, "p", "demo",
		jenkins.Build{Number: 9, Result: "FAILURE"}, 4096)
	if hit {
		t.Fatal("first call should miss empty cache")
	}
	if c.len() != 0 {
		t.Fatalf("read_only must not fill process L1: len=%d", c.len())
	}
	// Second call still misses (no fill).
	_, hit, _, _ = loadSurveyBuildSummary(context.Background(), nil, st, c, "p", "demo",
		jenkins.Build{Number: 9, Result: "FAILURE"}, 4096)
	if hit {
		t.Fatal("second call must still miss under read_only")
	}
	if logs.tailCalls.Load()+logs.readCalls.Load() < 2 {
		t.Fatalf("expected origin extracts, calls=%d", logs.tailCalls.Load()+logs.readCalls.Load())
	}
}

// Regression: process L1 fills when mode allows write (default/read_write).
func TestLoadSurveyBuildSummary_ModeReadWrite_ProcessL1FillAndHit(t *testing.T) {
	c := newSurveySigCache(time.Minute, 16)
	logs := &stubLogAccess{body: "Error: compilation failed\nBUILD FAILURE\nFinished: FAILURE\n"}
	st := regState{
		// nil CacheModes ⇒ allow lookup+fill (compat)
		logs: logs,
	}
	_, hit, _, _ := loadSurveyBuildSummary(context.Background(), nil, st, c, "p", "demo",
		jenkins.Build{Number: 11, Result: "FAILURE"}, 4096)
	if hit {
		t.Fatal("first should miss")
	}
	if c.len() != 1 {
		t.Fatalf("read_write must fill process L1: len=%d", c.len())
	}
	before := logs.tailCalls.Load() + logs.readCalls.Load()
	_, hit, _, src := loadSurveyBuildSummary(context.Background(), nil, st, c, "p", "demo",
		jenkins.Build{Number: 11, Result: "FAILURE"}, 4096)
	if !hit || src != "survey_cache" {
		t.Fatalf("second should hit process L1: hit=%v src=%s", hit, src)
	}
	after := logs.tailCalls.Load() + logs.readCalls.Load()
	if after != before {
		t.Fatalf("hit must not re-extract: before=%d after=%d", before, after)
	}
}

// Durable Meta path: mode off skips lookup; data retained for re-enable.
func TestLoadSurveyBuildSummary_ModeOff_DurableLookupBlockedNoPurge(t *testing.T) {
	dir := t.TempDir()
	meta, err := store.Open(filepath.Join(dir, "data"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = meta.Close() })

	// Seed durable entry under allow.
	stAllow := regState{meta: meta, cacheModes: modeGate{
		lookup: map[string]bool{cacheTypeSurveySummary: true},
		fill:   map[string]bool{cacheTypeSurveySummary: true},
	}}
	putDurableSurveySummary(context.Background(), stAllow, "p", surveyBuildSummary{
		Job: "demo", Build: 3, Result: "FAILURE",
		Findings: []surveyFindingCompact{{Signature: "abc", Message: "Error: x"}},
	}, 2048)

	c := newSurveySigCache(time.Minute, 16)
	stOff := regState{meta: meta, cacheModes: modeGate{
		lookup: map[string]bool{cacheTypeSurveySummary: false},
		fill:   map[string]bool{cacheTypeSurveySummary: false},
	}, logs: &stubLogAccess{body: "Error: x\n"}}

	_, hit, _, src := loadSurveyBuildSummary(context.Background(), nil, stOff, c, "p", "demo",
		jenkins.Build{Number: 3, Result: "FAILURE"}, 2048)
	if hit || src == "survey_cache_durable" || src == "survey_cache" {
		t.Fatalf("mode off must not hit durable/process: hit=%v src=%s", hit, src)
	}
	// Re-enable → durable hit (process may also promote when fill allowed).
	stOn := regState{meta: meta, cacheModes: modeGate{
		lookup: map[string]bool{cacheTypeSurveySummary: true},
		fill:   map[string]bool{cacheTypeSurveySummary: true},
	}}
	_, hit, _, src = loadSurveyBuildSummary(context.Background(), nil, stOn, c, "p", "demo",
		jenkins.Build{Number: 3, Result: "FAILURE"}, 2048)
	if !hit || src != "survey_cache_durable" {
		t.Fatalf("durable must remain after mode off: hit=%v src=%s", hit, src)
	}
}

// getCachedBuildDetails: mode off blocks process FetchCache hit and fill.
func TestGetCachedBuildDetails_ModeOff_NoHitNoFill(t *testing.T) {
	fc := NewFetchCache(FetchCacheConfig{TTL: time.Minute, MaxEntries: 32})
	// Pre-seed process cache entry (simulates prior warm under read_write).
	seed := &jenkins.Build{Number: 5, Result: "FAILURE", DisplayName: "demo #5"}
	fc.PutBuild("demo", 5, seed, 100)

	stOff := regState{
		fetchCache: fc,
		cacheModes: modeGate{
			lookup: map[string]bool{cacheTypeDiagnosticFetch: false},
			fill:   map[string]bool{cacheTypeDiagnosticFetch: false},
		},
	}
	// Nil client + mode off → miss path returns nil (must not return seeded hit).
	got, err := getCachedBuildDetails(context.Background(), stOff, nil, "demo", 5)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("mode off must not serve FetchCache hit: %+v", got)
	}
	// Seed still present (no purge).
	if b, ok := fc.GetBuild("demo", 5); !ok || b == nil {
		t.Fatal("mode off must not purge FetchCache entries")
	}

	// Re-enable lookup → hit.
	stOn := regState{
		fetchCache: fc,
		cacheModes: modeGate{
			lookup: map[string]bool{cacheTypeDiagnosticFetch: true},
			fill:   map[string]bool{cacheTypeDiagnosticFetch: false},
		},
	}
	got, err = getCachedBuildDetails(context.Background(), stOn, nil, "demo", 5)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.Number != 5 {
		t.Fatalf("lookup on should hit: %+v", got)
	}
}

// getOrFetchCached: mode off blocks hit/fill for diagnostic process cache.
func TestGetOrFetchCached_ModeOff_NoHitNoFill(t *testing.T) {
	fc := NewFetchCache(FetchCacheConfig{TTL: time.Minute, MaxEntries: 32})
	fc.PutAny("demo", 1, FetchKindStages, "warm-stages", 50)

	stOff := regState{
		fetchCache: fc,
		cacheModes: modeGate{
			lookup: map[string]bool{cacheTypeDiagnosticFetch: false},
			fill:   map[string]bool{cacheTypeDiagnosticFetch: false},
		},
	}
	var remoteCalls atomic.Int32
	got, err := getOrFetchCached(context.Background(), stOff, "demo", 1, FetchKindStages, 50, nil,
		func(context.Context) (string, error) {
			remoteCalls.Add(1)
			return "origin-stages", nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if got != "origin-stages" {
		t.Fatalf("want origin, got %q", got)
	}
	if remoteCalls.Load() != 1 {
		t.Fatal("must fetch origin under mode off")
	}
	// Fill blocked: cache still has old warm value only (no overwrite with origin).
	if v, ok := fc.GetAny("demo", 1, FetchKindStages); !ok || v != "warm-stages" {
		t.Fatalf("mode off must not fill/overwrite: ok=%v v=%v", ok, v)
	}

	// read_only: may hit warm, must not fill new keys
	stRO := regState{
		fetchCache: fc,
		cacheModes: modeGate{
			lookup: map[string]bool{cacheTypeDiagnosticFetch: true},
			fill:   map[string]bool{cacheTypeDiagnosticFetch: false},
		},
	}
	got, err = getOrFetchCached(context.Background(), stRO, "demo", 1, FetchKindStages, 50, nil,
		func(context.Context) (string, error) {
			t.Fatal("must not call origin on hit")
			return "", nil
		})
	if err != nil || got != "warm-stages" {
		t.Fatalf("read_only hit: %v %q", err, got)
	}
	// New key under read_only: origin, no fill
	remoteCalls.Store(0)
	got, err = getOrFetchCached(context.Background(), stRO, "demo", 2, FetchKindStages, 50, nil,
		func(context.Context) (string, error) {
			remoteCalls.Add(1)
			return "new-origin", nil
		})
	if err != nil || got != "new-origin" {
		t.Fatalf("read_only miss: %v %q", err, got)
	}
	if _, ok := fc.GetAny("demo", 2, FetchKindStages); ok {
		t.Fatal("read_only must not fill new keys")
	}
}
