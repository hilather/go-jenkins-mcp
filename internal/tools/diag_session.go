package tools

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/jenkins"
	"golang.org/x/sync/singleflight"
)

// PERF-003: shared diagnostic request-plan cache and per-operation budgets.
// Diagnose/compare/graph tools share a process-scoped (per-Register) FetchCache
// so repeated tool calls do not re-download the same build meta / log tails.
// In-flight identical keys are single-flighted (Wave 27) so concurrent diagnose
// enrichment / multi-tool use does not multiply Jenkins GetBuildDetailsByJob.

// FetchKind identifies a remote diagnostic resource class.
type FetchKind string

const (
	FetchKindBuild      FetchKind = "build"
	FetchKindLogTail    FetchKind = "logtail"
	FetchKindStages     FetchKind = "stages"
	FetchKindTestReport FetchKind = "testreport"
	FetchKindArtifacts  FetchKind = "artifacts"
	// FetchKindSCMChanges caches GetBuildChanges results (job|build|base|maxcommits).
	FetchKindSCMChanges FetchKind = "scmchanges"
)

// Default cache / budget ceilings (server-enforced; RegisterOptions may only lower).
const (
	DefaultDiagCacheTTL        = 60 * time.Second
	DefaultDiagCacheMaxEntries = 256
	// DefaultBuildDetailsCacheMax is the soft guidance bound for build-meta
	// entries within the shared cache (job+build keys). Overall cache still
	// uses MaxEntries (default 256) across all fetch kinds.
	DefaultBuildDetailsCacheMax = 32

	DefaultDiagnoseMaxRemoteCalls = 12
	DefaultDiagnoseMaxRemoteBytes = 1 << 20 // 1 MiB
	DefaultDiagnoseMaxWall        = 30 * time.Second

	DefaultCompareMaxRemoteCalls = 24
	DefaultCompareMaxRemoteBytes = 2 << 20 // 2 MiB
	DefaultCompareMaxWall        = 45 * time.Second

	DefaultTraceMaxRemoteCalls = 48
	DefaultTraceMaxRemoteBytes = 2 << 20
	DefaultTraceMaxWall        = 60 * time.Second

	DefaultRegressionMaxRemoteCalls = 64
	DefaultRegressionMaxRemoteBytes = HardRegressionMaxLogBytesTotal + (256 << 10)
	DefaultRegressionMaxWall        = 90 * time.Second

	// approxBuildDetailsBytes is the budget estimate for one GetBuildDetailsByJob JSON body.
	approxBuildDetailsBytes int64 = 512
	// approxSCMChangesBytes is the budget estimate for one GetBuildChanges JSON body.
	approxSCMChangesBytes int64 = 2048
)

// DiagFetchKey builds a stable cache key: job|build|kind=…|extra…
func DiagFetchKey(job string, build int, kind FetchKind, extra ...string) string {
	var b strings.Builder
	b.Grow(64 + len(job))
	b.WriteString(job)
	b.WriteByte('|')
	b.WriteString(fmt.Sprintf("%d", build))
	b.WriteString("|kind=")
	b.WriteString(string(kind))
	for _, e := range extra {
		if e == "" {
			continue
		}
		b.WriteByte('|')
		b.WriteString(e)
	}
	return b.String()
}

// DiagBudgetConfig is an optional per-Register override for operation budgets.
// Zero fields keep tool defaults; positive values may only lower ceilings.
type DiagBudgetConfig struct {
	MaxRemoteCalls int           `json:"max_remote_calls,omitempty"`
	MaxRemoteBytes int64         `json:"max_remote_bytes,omitempty"`
	MaxWall        time.Duration `json:"max_wall,omitempty"`
}

// DiagBudget tracks remote call/byte/wall consumption for one tool invocation.
type DiagBudget struct {
	MaxRemoteCalls int
	MaxRemoteBytes int64
	MaxWall        time.Duration

	start time.Time

	mu          sync.Mutex
	remoteCalls int
	remoteBytes int64
	exhausted   bool
	reason      string
}

// NewDiagBudget constructs a budget with start clock.
func NewDiagBudget(cfg DiagBudgetConfig) *DiagBudget {
	b := &DiagBudget{
		MaxRemoteCalls: cfg.MaxRemoteCalls,
		MaxRemoteBytes: cfg.MaxRemoteBytes,
		MaxWall:        cfg.MaxWall,
		start:          time.Now(),
	}
	return b
}

// mergeDiagBudget lowers def using override when override fields are positive.
func mergeDiagBudget(def, override DiagBudgetConfig) DiagBudgetConfig {
	out := def
	if override.MaxRemoteCalls > 0 && (out.MaxRemoteCalls <= 0 || override.MaxRemoteCalls < out.MaxRemoteCalls) {
		out.MaxRemoteCalls = override.MaxRemoteCalls
	}
	if override.MaxRemoteBytes > 0 && (out.MaxRemoteBytes <= 0 || override.MaxRemoteBytes < out.MaxRemoteBytes) {
		out.MaxRemoteBytes = override.MaxRemoteBytes
	}
	if override.MaxWall > 0 && (out.MaxWall <= 0 || override.MaxWall < out.MaxWall) {
		out.MaxWall = override.MaxWall
	}
	return out
}

// AllowRemote reports whether another remote fetch of approxBytes is permitted.
// approxBytes may be 0 when size is unknown a priori.
func (b *DiagBudget) AllowRemote(approxBytes int64) bool {
	if b == nil {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.exhausted {
		return false
	}
	if b.MaxWall > 0 && time.Since(b.start) >= b.MaxWall {
		b.exhausted = true
		b.reason = "max_wall exhausted"
		return false
	}
	if b.MaxRemoteCalls > 0 && b.remoteCalls >= b.MaxRemoteCalls {
		b.exhausted = true
		b.reason = "max_remote_calls exhausted"
		return false
	}
	if b.MaxRemoteBytes > 0 && b.remoteBytes+approxBytes > b.MaxRemoteBytes && b.remoteBytes >= b.MaxRemoteBytes {
		b.exhausted = true
		b.reason = "max_remote_bytes exhausted"
		return false
	}
	if b.MaxRemoteBytes > 0 && b.remoteBytes >= b.MaxRemoteBytes {
		b.exhausted = true
		b.reason = "max_remote_bytes exhausted"
		return false
	}
	return true
}

// RecordRemote accounts for a completed remote fetch.
func (b *DiagBudget) RecordRemote(bytes int64) {
	if b == nil {
		return
	}
	if bytes < 0 {
		bytes = 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.remoteCalls++
	b.remoteBytes += bytes
	if b.MaxRemoteCalls > 0 && b.remoteCalls >= b.MaxRemoteCalls {
		b.exhausted = true
		if b.reason == "" {
			b.reason = "max_remote_calls exhausted"
		}
	}
	if b.MaxRemoteBytes > 0 && b.remoteBytes >= b.MaxRemoteBytes {
		b.exhausted = true
		if b.reason == "" {
			b.reason = "max_remote_bytes exhausted"
		}
	}
	if b.MaxWall > 0 && time.Since(b.start) >= b.MaxWall {
		b.exhausted = true
		if b.reason == "" {
			b.reason = "max_wall exhausted"
		}
	}
}

// Snapshot returns consumed counters and exhaustion state.
func (b *DiagBudget) Snapshot() (calls int, bytes int64, exhausted bool, reason string) {
	if b == nil {
		return 0, 0, false, ""
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	// Wall clock may trip without a RecordRemote.
	if !b.exhausted && b.MaxWall > 0 && time.Since(b.start) >= b.MaxWall {
		b.exhausted = true
		b.reason = "max_wall exhausted"
	}
	return b.remoteCalls, b.remoteBytes, b.exhausted, b.reason
}

// Exhausted is a convenience wrapper around Snapshot.
func (b *DiagBudget) Exhausted() (bool, string) {
	_, _, ex, reason := b.Snapshot()
	return ex, reason
}

// Context returns a child context cancelled when MaxWall elapses (if set).
func (b *DiagBudget) Context(parent context.Context) (context.Context, context.CancelFunc) {
	if b == nil || b.MaxWall <= 0 {
		return context.WithCancel(parent)
	}
	remaining := b.MaxWall - time.Since(b.start)
	if remaining <= 0 {
		ctx, cancel := context.WithCancel(parent)
		cancel()
		return ctx, cancel
	}
	return context.WithTimeout(parent, remaining)
}

// DiagPerf is optional tool-response telemetry (PERF-003).
// RemoteCalls is the diagnose/compare remote-call accounting (includes
// Jenkins build-details / log / enrichment units); reuse instead of a separate
// diagnose_jenkins_calls metric.
type DiagPerf struct {
	CacheHits   int64 `json:"cache_hits"`
	CacheMisses int64 `json:"cache_misses"`
	RemoteCalls int   `json:"remote_calls"`
	RemoteBytes int64 `json:"remote_bytes"`
	// SharedFlights counts single-flight coalesces for this invocation (waiters).
	SharedFlights   int64  `json:"shared_flights,omitempty"`
	BudgetExhausted bool   `json:"budget_exhausted,omitempty"`
	BudgetReason    string `json:"budget_reason,omitempty"`
}

// FetchCacheStats is process-cache aggregate counters (test / ops accessors).
type FetchCacheStats struct {
	Hits          int64 `json:"hits"`
	Misses        int64 `json:"misses"`
	RemoteCalls   int64 `json:"remote_calls"`
	RemoteBytes   int64 `json:"remote_bytes"`
	SharedFlights int64 `json:"shared_flights"`
	Entries       int   `json:"entries"`
}

// cachedLogTail is the log-tail payload stored in FetchCache.
type cachedLogTail struct {
	Text       string
	Meta       logMeta
	Source     string
	Incomplete bool
	// MaxLog is the maxLog used when this entry was populated.
	MaxLog int
}

// cachedBuild wraps jenkins.Build for type-safe cache storage.
type cachedBuild struct {
	Build *jenkins.Build
}

// fetchItem is one TTL-bounded cache entry.
type fetchItem struct {
	value       any
	remoteBytes int64
	storedAt    time.Time
}

// FetchCacheConfig configures TTL and capacity.
type FetchCacheConfig struct {
	TTL        time.Duration
	MaxEntries int
}

// FetchCache is a process/Register-scoped TTL cache for diagnostic fetches.
// Safe for concurrent use. Process-local only — never persisted; do not put
// secrets or cross-session credential material here (build params may be
// redacted at model surfaces; cache is still ephemeral RAM for one MCP process).
type FetchCache struct {
	ttl        time.Duration
	maxEntries int

	mu            sync.Mutex
	items         map[string]*fetchItem
	order         []string // insertion order for FIFO eviction
	hits          int64
	misses        int64
	remoteCalls   int64
	remoteBytes   int64
	sharedFlights int64

	// sf coalesces concurrent in-flight fetches for the same DiagFetchKey.
	sf singleflight.Group
}

// NewFetchCache constructs a cache with defaults for zero fields.
func NewFetchCache(cfg FetchCacheConfig) *FetchCache {
	ttl := cfg.TTL
	if ttl <= 0 {
		ttl = DefaultDiagCacheTTL
	}
	max := cfg.MaxEntries
	if max <= 0 {
		max = DefaultDiagCacheMaxEntries
	}
	return &FetchCache{
		ttl:        ttl,
		maxEntries: max,
		items:      make(map[string]*fetchItem),
	}
}

// Stats returns aggregate counters (test/ops).
func (c *FetchCache) Stats() FetchCacheStats {
	if c == nil {
		return FetchCacheStats{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return FetchCacheStats{
		Hits:          c.hits,
		Misses:        c.misses,
		RemoteCalls:   c.remoteCalls,
		RemoteBytes:   c.remoteBytes,
		SharedFlights: c.sharedFlights,
		Entries:       len(c.items),
	}
}

// Reset clears entries and counters (tests). In-flight singleflight work is not
// cancelled; completed puts may re-appear after Reset if a flight finishes late.
func (c *FetchCache) Reset() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items = make(map[string]*fetchItem)
	c.order = nil
	c.hits = 0
	c.misses = 0
	c.remoteCalls = 0
	c.remoteBytes = 0
	c.sharedFlights = 0
}

func (c *FetchCache) noteSharedFlight() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.sharedFlights++
	c.mu.Unlock()
}

func (c *FetchCache) get(key string) (any, int64, bool) {
	if c == nil {
		return nil, 0, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	it, ok := c.items[key]
	if !ok {
		c.misses++
		return nil, 0, false
	}
	if c.ttl > 0 && time.Since(it.storedAt) > c.ttl {
		delete(c.items, key)
		c.removeOrder(key)
		c.misses++
		return nil, 0, false
	}
	c.hits++
	return it.value, it.remoteBytes, true
}

func (c *FetchCache) put(key string, value any, remoteBytes int64) {
	if c == nil || key == "" {
		return
	}
	if remoteBytes < 0 {
		remoteBytes = 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.items[key]; !exists {
		c.order = append(c.order, key)
	}
	c.items[key] = &fetchItem{value: value, remoteBytes: remoteBytes, storedAt: time.Now()}
	c.remoteCalls++
	c.remoteBytes += remoteBytes
	for len(c.items) > c.maxEntries && len(c.order) > 0 {
		old := c.order[0]
		c.order = c.order[1:]
		delete(c.items, old)
	}
}

func (c *FetchCache) removeOrder(key string) {
	for i, k := range c.order {
		if k == key {
			c.order = append(c.order[:i], c.order[i+1:]...)
			return
		}
	}
}

// GetLogTail returns a cached log tail when a sufficient entry exists.
// An entry with MaxLog >= requested maxLog satisfies smaller subsequent requests
// by re-slicing the tail window.
func (c *FetchCache) GetLogTail(job string, build, maxLog int) (text string, meta logMeta, source string, incomplete bool, ok bool) {
	key := DiagFetchKey(job, build, FetchKindLogTail)
	v, _, hit := c.get(key)
	if !hit {
		return "", logMeta{}, "", false, false
	}
	entry, okCast := v.(*cachedLogTail)
	if !okCast || entry == nil {
		return "", logMeta{}, "", false, false
	}
	if entry.MaxLog < maxLog {
		// Insufficient cached window — treat as miss (undo hit accounting).
		c.mu.Lock()
		c.hits--
		c.misses++
		c.mu.Unlock()
		return "", logMeta{}, "", false, false
	}
	text, meta = sliceLogTail(entry.Text, entry.Meta, maxLog)
	return text, meta, entry.Source, entry.Incomplete || (meta.TotalSize > 0 && meta.Length < meta.TotalSize), true
}

// PutLogTail stores a log tail for subsequent hits.
// Prefer keeping the larger window when concurrent puts race (atomic under mu).
func (c *FetchCache) PutLogTail(job string, build, maxLog int, text string, meta logMeta, source string, incomplete bool) {
	if c == nil {
		return
	}
	key := DiagFetchKey(job, build, FetchKindLogTail)
	bytes := int64(meta.Length)
	if bytes == 0 && text != "" {
		bytes = int64(len(text))
	}
	val := &cachedLogTail{
		Text:       text,
		Meta:       meta,
		Source:     source,
		Incomplete: incomplete,
		MaxLog:     maxLog,
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	// Prefer larger MaxLog; skip if existing entry is strictly larger.
	if it, ok := c.items[key]; ok && it != nil {
		if c.ttl > 0 && time.Since(it.storedAt) > c.ttl {
			delete(c.items, key)
			c.removeOrder(key)
		} else if old, ok2 := it.value.(*cachedLogTail); ok2 && old != nil && old.MaxLog > maxLog {
			return
		}
	}
	if remoteBytes := bytes; true {
		if remoteBytes < 0 {
			remoteBytes = 0
		}
		if _, exists := c.items[key]; !exists {
			c.order = append(c.order, key)
		}
		c.items[key] = &fetchItem{value: val, remoteBytes: remoteBytes, storedAt: time.Now()}
		c.remoteCalls++
		c.remoteBytes += remoteBytes
		for len(c.items) > c.maxEntries && len(c.order) > 0 {
			old := c.order[0]
			c.order = c.order[1:]
			delete(c.items, old)
		}
	}
}

// peek reads without updating hit/miss counters.
func (c *FetchCache) peek(key string) (any, int64, bool) {
	if c == nil {
		return nil, 0, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	it, ok := c.items[key]
	if !ok {
		return nil, 0, false
	}
	if c.ttl > 0 && time.Since(it.storedAt) > c.ttl {
		return nil, 0, false
	}
	return it.value, it.remoteBytes, true
}

func sliceLogTail(text string, meta logMeta, maxLog int) (string, logMeta) {
	if maxLog <= 0 || len(text) <= maxLog {
		return text, meta
	}
	// Tail is the last maxLog bytes of the cached window.
	cut := len(text) - maxLog
	out := text[cut:]
	m := meta
	m.Offset = meta.Offset + cut
	m.Length = len(out)
	return out, m
}

// GetBuild returns a cached *jenkins.Build.
func (c *FetchCache) GetBuild(job string, build int) (*jenkins.Build, bool) {
	key := DiagFetchKey(job, build, FetchKindBuild)
	v, _, ok := c.get(key)
	if !ok {
		return nil, false
	}
	return copyCachedBuild(v)
}

// peekBuild reads a cached build without updating hit/miss counters (singleflight double-check).
func (c *FetchCache) peekBuild(job string, build int) (*jenkins.Build, bool) {
	if c == nil {
		return nil, false
	}
	v, _, ok := c.peek(DiagFetchKey(job, build, FetchKindBuild))
	if !ok {
		return nil, false
	}
	return copyCachedBuild(v)
}

func copyCachedBuild(v any) (*jenkins.Build, bool) {
	cb, ok2 := v.(*cachedBuild)
	if !ok2 || cb == nil || cb.Build == nil {
		return nil, false
	}
	return cloneBuild(cb.Build), true
}

// cloneBuild returns a shallow copy so callers cannot mutate cache/flight shared state.
func cloneBuild(b *jenkins.Build) *jenkins.Build {
	if b == nil {
		return nil
	}
	cp := *b
	if b.Parameters != nil {
		cp.Parameters = make(map[string]string, len(b.Parameters))
		for k, v := range b.Parameters {
			cp.Parameters[k] = v
		}
	}
	return &cp
}

// PutBuild stores build metadata (counts as one remote call of small JSON size).
func (c *FetchCache) PutBuild(job string, build int, b *jenkins.Build, remoteBytes int64) {
	if b == nil {
		return
	}
	cp := *b
	if b.Parameters != nil {
		cp.Parameters = make(map[string]string, len(b.Parameters))
		for k, v := range b.Parameters {
			cp.Parameters[k] = v
		}
	}
	if remoteBytes <= 0 {
		remoteBytes = 512 // conservative small JSON estimate
	}
	c.put(DiagFetchKey(job, build, FetchKindBuild), &cachedBuild{Build: &cp}, remoteBytes)
}

// GetAny / PutAny store opaque values (stages, tests, artifacts) under a kind key.
func (c *FetchCache) GetAny(job string, build int, kind FetchKind, extra ...string) (any, bool) {
	v, _, ok := c.get(DiagFetchKey(job, build, kind, extra...))
	return v, ok
}

// PutAny stores an opaque cached value.
func (c *FetchCache) PutAny(job string, build int, kind FetchKind, value any, remoteBytes int64, extra ...string) {
	if remoteBytes <= 0 {
		remoteBytes = 256
	}
	c.put(DiagFetchKey(job, build, kind, extra...), value, remoteBytes)
}

// DiagSession is the per-invocation request plan: shared cache + operation budget
// + request-local counters for the optional response perf object.
type DiagSession struct {
	Cache  *FetchCache
	Budget *DiagBudget

	mu            sync.Mutex
	localHits     int64
	localMisses   int64
	sharedFlights int64
}

// newDiagSession builds a session from register state and tool defaults.
func newDiagSession(st regState, toolDefault DiagBudgetConfig) *DiagSession {
	cfg := mergeDiagBudget(toolDefault, st.diagBudget)
	return &DiagSession{
		Cache:  st.fetchCache,
		Budget: NewDiagBudget(cfg),
	}
}

// BoundContext applies wall-clock budget to ctx.
func (s *DiagSession) BoundContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if s == nil || s.Budget == nil {
		return context.WithCancel(ctx)
	}
	return s.Budget.Context(ctx)
}

// NoteHit / NoteMiss update request-local counters (cache already tracks process totals).
func (s *DiagSession) NoteHit() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.localHits++
	s.mu.Unlock()
}

func (s *DiagSession) NoteMiss() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.localMisses++
	s.mu.Unlock()
}

// NoteSharedFlight records that this invocation waited on another in-flight fetch.
func (s *DiagSession) NoteSharedFlight() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.sharedFlights++
	s.mu.Unlock()
}

// AllowRemote delegates to the budget (nil-safe).
func (s *DiagSession) AllowRemote(approxBytes int64) bool {
	if s == nil {
		return true
	}
	return s.Budget.AllowRemote(approxBytes)
}

// RecordRemote records a remote fetch against the budget.
func (s *DiagSession) RecordRemote(bytes int64) {
	if s == nil {
		return
	}
	s.Budget.RecordRemote(bytes)
}

// PerfSnapshot builds the optional response perf object.
func (s *DiagSession) PerfSnapshot() DiagPerf {
	if s == nil {
		return DiagPerf{}
	}
	s.mu.Lock()
	hits, misses, shared := s.localHits, s.localMisses, s.sharedFlights
	s.mu.Unlock()
	calls, bytes, ex, reason := s.Budget.Snapshot()
	return DiagPerf{
		CacheHits:       hits,
		CacheMisses:     misses,
		RemoteCalls:     calls,
		RemoteBytes:     bytes,
		SharedFlights:   shared,
		BudgetExhausted: ex,
		BudgetReason:    reason,
	}
}

// BudgetNote returns a residual/confidence note when the budget is exhausted.
func (s *DiagSession) BudgetNote() string {
	if s == nil {
		return ""
	}
	ex, reason := s.Budget.Exhausted()
	if !ex {
		return ""
	}
	if reason == "" {
		reason = "remote budget exhausted"
	}
	return "diagnostic remote budget: " + reason
}

// session context helpers — avoid threading DiagSession through every helper.

type diagSessionCtxKey struct{}

func withDiagSession(ctx context.Context, s *DiagSession) context.Context {
	if s == nil {
		return ctx
	}
	return context.WithValue(ctx, diagSessionCtxKey{}, s)
}

func diagSessionFrom(ctx context.Context) *DiagSession {
	if ctx == nil {
		return nil
	}
	s, _ := ctx.Value(diagSessionCtxKey{}).(*DiagSession)
	return s
}

// default budgets per tool family
func diagnoseBudgetDefault() DiagBudgetConfig {
	return DiagBudgetConfig{
		MaxRemoteCalls: DefaultDiagnoseMaxRemoteCalls,
		MaxRemoteBytes: DefaultDiagnoseMaxRemoteBytes,
		MaxWall:        DefaultDiagnoseMaxWall,
	}
}

func compareBudgetDefault() DiagBudgetConfig {
	return DiagBudgetConfig{
		MaxRemoteCalls: DefaultCompareMaxRemoteCalls,
		MaxRemoteBytes: DefaultCompareMaxRemoteBytes,
		MaxWall:        DefaultCompareMaxWall,
	}
}

func traceBudgetDefault() DiagBudgetConfig {
	return DiagBudgetConfig{
		MaxRemoteCalls: DefaultTraceMaxRemoteCalls,
		MaxRemoteBytes: DefaultTraceMaxRemoteBytes,
		MaxWall:        DefaultTraceMaxWall,
	}
}

func regressionBudgetDefault() DiagBudgetConfig {
	return DiagBudgetConfig{
		MaxRemoteCalls: DefaultRegressionMaxRemoteCalls,
		MaxRemoteBytes: DefaultRegressionMaxRemoteBytes,
		MaxWall:        DefaultRegressionMaxWall,
	}
}

// flightResult is the singleflight payload for getCached* helpers.
type flightResult struct {
	value     any
	fromCache bool // true when satisfied by a double-check cache hit inside the flight
	err       error
}

// fetchCtxForFlight detaches caller cancel so one cancelled waiter cannot poison
// concurrent singleflight peers, while still honoring the caller's deadline.
func fetchCtxForFlight(ctx context.Context) (context.Context, context.CancelFunc) {
	base := context.WithoutCancel(ctx)
	if dl, ok := ctx.Deadline(); ok {
		return context.WithDeadline(base, dl)
	}
	// Bound orphaned flights when the parent had no deadline.
	return context.WithTimeout(base, DefaultDiagnoseMaxWall)
}

// getCachedBuildDetails is the PERF-003 GetBuildDetailsByJob wrapper used by
// diagnose/compare enrichment paths: process-local TTL cache + single-flight,
// keyed by job|build. Never persists across process sessions.
func getCachedBuildDetails(ctx context.Context, st regState, client *jenkins.Client, job string, build int) (*jenkins.Build, error) {
	sess := diagSessionFrom(ctx)

	// Fast path: warm cache without entering singleflight.
	if st.fetchCache != nil {
		if b, ok := st.fetchCache.GetBuild(job, build); ok {
			if sess != nil {
				sess.NoteHit()
			}
			return b, nil
		}
	}
	if client == nil {
		if sess != nil {
			sess.NoteMiss()
		}
		return nil, nil
	}
	if sess != nil && !sess.AllowRemote(approxBuildDetailsBytes) {
		return nil, errDiagBudget
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// No process cache: direct fetch (still single-invocation; no cross-tool share).
	if st.fetchCache == nil {
		if sess != nil {
			sess.NoteMiss()
		}
		b, err := client.GetBuildDetailsByJob(ctx, job, build)
		if err != nil {
			return nil, err
		}
		if sess != nil {
			sess.RecordRemote(approxBuildDetailsBytes)
		}
		return b, nil
	}

	key := DiagFetchKey(job, build, FetchKindBuild)
	v, err, shared := st.fetchCache.sf.Do(key, func() (any, error) {
		// Double-check after winning/joining the flight (no hit/miss accounting).
		if b, ok := st.fetchCache.peekBuild(job, build); ok {
			return &flightResult{value: b, fromCache: true}, nil
		}
		fetchCtx, cancel := fetchCtxForFlight(ctx)
		defer cancel()
		b, ferr := client.GetBuildDetailsByJob(fetchCtx, job, build)
		if ferr != nil {
			return &flightResult{err: ferr}, ferr
		}
		if b != nil {
			st.fetchCache.PutBuild(job, build, b, approxBuildDetailsBytes)
		}
		return &flightResult{value: b, fromCache: false}, nil
	})
	if err != nil {
		// Prefer caller's cancel when they aborted while waiting.
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	fr, _ := v.(*flightResult)
	if fr == nil {
		return nil, nil
	}
	if fr.err != nil {
		return nil, fr.err
	}
	b, _ := fr.value.(*jenkins.Build)
	// Always clone: singleflight waiters must not share a mutable *Build.
	out := cloneBuild(b)
	if shared {
		st.fetchCache.noteSharedFlight()
		if sess != nil {
			sess.NoteSharedFlight()
			sess.NoteHit()
		}
		return out, nil
	}
	if fr.fromCache {
		if sess != nil {
			sess.NoteHit()
		}
		return out, nil
	}
	if sess != nil {
		sess.NoteMiss()
		sess.RecordRemote(approxBuildDetailsBytes)
	}
	return out, nil
}

// getCachedPipelineStages prefers FetchCache then GetPipelineStages.
func getCachedPipelineStages(ctx context.Context, st regState, client *jenkins.Client, job string, build int) (*jenkins.PipelineStages, error) {
	return getOrFetchCached(ctx, st, job, build, FetchKindStages, 512, nil, func(ctx context.Context) (*jenkins.PipelineStages, error) {
		return client.GetPipelineStages(ctx, job, build)
	})
}

// getCachedTestReport prefers FetchCache then GetTestReport.
func getCachedTestReport(ctx context.Context, st regState, client *jenkins.Client, job string, build, maxFailed int) (*jenkins.TestReport, error) {
	extra := []string{fmt.Sprintf("max=%d", maxFailed)}
	return getOrFetchCached(ctx, st, job, build, FetchKindTestReport, 1024, extra, func(ctx context.Context) (*jenkins.TestReport, error) {
		return client.GetTestReport(ctx, job, build, maxFailed)
	})
}

// getCachedArtifactList prefers FetchCache then listArtifactsWithPolicyFilter
// (Wave 41). Cache extras include normalized max_artifacts and a non-secret
// deny_artifact_paths fingerprint so entries are not reused across different
// deny policies. Return path always re-applies live FilterDeniedArtifacts on a
// clone so stale/wider cache rows cannot leak denied paths after policy tighten.
func getCachedArtifactList(ctx context.Context, st regState, client *jenkins.Client, job string, build, maxArts int) (*jenkins.ArtifactList, error) {
	extra := artifactListCacheExtra(st, maxArts)
	list, err := getOrFetchCached(ctx, st, job, build, FetchKindArtifacts, 512, extra, func(ctx context.Context) (*jenkins.ArtifactList, error) {
		return listArtifactsWithPolicyFilter(ctx, client, st, job, build, maxArts)
	})
	if err != nil {
		return nil, err
	}
	return filterCachedArtifactListLive(st, list), nil
}

// getCachedBuildChanges prefers FetchCache then GetBuildChanges (SCM-001 / DIAG-003).
// Keyed by job|build|baseline|max_commits so range and single-build fetches do not collide.
// Note: multi-build baseline scans still count as one remote budget unit (bounded by MaxScanBuilds).
func getCachedBuildChanges(
	ctx context.Context,
	st regState,
	client *jenkins.Client,
	job string,
	build, baseline, maxCommits, maxScan int,
) (*jenkins.BuildChanges, error) {
	if maxCommits <= 0 {
		maxCommits = DefaultCompareMaxSCMCommits
	}
	if maxScan <= 0 {
		maxScan = MaxCompareSCMScanBuilds
	}
	extra := []string{
		fmt.Sprintf("base=%d", baseline),
		fmt.Sprintf("mc=%d", maxCommits),
		fmt.Sprintf("scan=%d", maxScan),
	}
	// Charge proportional to scan width so large ranges exhaust budget honestly.
	scanN := 1
	if baseline > 0 && build > baseline {
		scanN = build - baseline
		if scanN > maxScan {
			scanN = maxScan
		}
	}
	approx := approxSCMChangesBytes * int64(scanN)
	return getOrFetchCached(ctx, st, job, build, FetchKindSCMChanges, approx, extra, func(ctx context.Context) (*jenkins.BuildChanges, error) {
		return client.GetBuildChanges(ctx, jenkins.GetBuildChangesToolArgs{
			JobName:         job,
			BuildNumber:     build,
			BaselineBuild:   baseline,
			MaxCommits:      maxCommits,
			MaxFiles:        0, // client default
			MaxMessageBytes: 256,
			MaxScanBuilds:   maxScan,
		})
	})
}

// getOrFetchCached is the shared PERF-003 cache-aside + single-flight path for
// typed remote resources (stages, tests, artifacts).
func getOrFetchCached[T any](
	ctx context.Context,
	st regState,
	job string,
	build int,
	kind FetchKind,
	approxBytes int64,
	extra []string,
	fetch func(context.Context) (T, error),
) (T, error) {
	var zero T
	sess := diagSessionFrom(ctx)
	if st.fetchCache != nil {
		if v, ok := st.fetchCache.GetAny(job, build, kind, extra...); ok {
			if sess != nil {
				sess.NoteHit()
			}
			if typed, ok2 := v.(T); ok2 {
				return typed, nil
			}
		}
	}
	if sess != nil && !sess.AllowRemote(approxBytes) {
		return zero, errDiagBudget
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}

	// No process cache: direct fetch.
	if st.fetchCache == nil {
		if sess != nil {
			sess.NoteMiss()
		}
		val, err := fetch(ctx)
		if err != nil {
			return zero, err
		}
		if sess != nil {
			sess.RecordRemote(approxBytes)
		}
		return val, nil
	}

	key := DiagFetchKey(job, build, kind, extra...)
	v, err, shared := st.fetchCache.sf.Do(key, func() (any, error) {
		if cached, _, ok := st.fetchCache.peek(DiagFetchKey(job, build, kind, extra...)); ok {
			return &flightResult{value: cached, fromCache: true}, nil
		}
		fetchCtx, cancel := fetchCtxForFlight(ctx)
		defer cancel()
		val, ferr := fetch(fetchCtx)
		if ferr != nil {
			return &flightResult{err: ferr}, ferr
		}
		st.fetchCache.PutAny(job, build, kind, val, approxBytes, extra...)
		return &flightResult{value: val, fromCache: false}, nil
	})
	if err != nil {
		if ctx.Err() != nil {
			return zero, ctx.Err()
		}
		return zero, err
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	fr, _ := v.(*flightResult)
	if fr == nil {
		return zero, nil
	}
	if fr.err != nil {
		return zero, fr.err
	}
	typed, ok := fr.value.(T)
	if !ok {
		return zero, nil
	}
	if shared {
		st.fetchCache.noteSharedFlight()
		if sess != nil {
			sess.NoteSharedFlight()
			sess.NoteHit()
		}
		return typed, nil
	}
	if fr.fromCache {
		if sess != nil {
			sess.NoteHit()
		}
		return typed, nil
	}
	if sess != nil {
		sess.NoteMiss()
		sess.RecordRemote(approxBytes)
	}
	return typed, nil
}

// errDiagBudget is a soft sentinel for budget short-circuit (not always surfaced as tool error).
var errDiagBudget = errBudgetExhausted{}

type errBudgetExhausted struct{}

func (errBudgetExhausted) Error() string { return "diagnostic remote budget exhausted" }

func isDiagBudgetErr(err error) bool {
	_, ok := err.(errBudgetExhausted)
	return ok
}
