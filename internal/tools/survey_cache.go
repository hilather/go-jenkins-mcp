package tools

import (
	"strconv"
	"sync"
	"time"
)

// Process-scoped compact signature cache for DIAG-006 survey.
// Keyed by (profile, job, build, maxLogBytes). When RegisterOptions.Meta is set
// (profile data dir / schema v7), durable compact summaries also live in Meta
// (survey_summary_cache). Process cache remains L1; durable is L2 across restarts.

const (
	// DefaultSurveyCacheTTL is how long a build signature summary stays hot.
	DefaultSurveyCacheTTL = 5 * time.Minute
	// DefaultSurveyCacheMaxEntries caps process memory for survey summaries.
	DefaultSurveyCacheMaxEntries = 256
)

// surveyBuildSummary is a compact, redacted extraction result for one build.
type surveyBuildSummary struct {
	Job      string
	Build    int
	Result   string
	Findings []surveyFindingCompact
	Source   string
	LogBytes int
	// Incomplete when log was partial/truncated.
	Incomplete bool
}

// surveyFindingCompact is cache-friendly finding data (already sanitized).
type surveyFindingCompact struct {
	Signature  string
	Pattern    string
	Message    string
	Normalized string
	// ExactSignature is a light-hash of the raw message (pre volatile-normalize).
	ExactSignature  string
	EvidenceExcerpt string
	Confidence      float64
	Count           int
}

type surveyCacheEntry struct {
	expires time.Time
	summary surveyBuildSummary
}

// surveySigCache is a process-scoped TTL+LRU-ish map of build summaries.
type surveySigCache struct {
	mu         sync.Mutex
	ttl        time.Duration
	maxEntries int
	// insertion-order ring for eviction (oldest keys first).
	order   []string
	entries map[string]surveyCacheEntry
}

func newSurveySigCache(ttl time.Duration, maxEntries int) *surveySigCache {
	if ttl <= 0 {
		ttl = DefaultSurveyCacheTTL
	}
	if maxEntries <= 0 {
		maxEntries = DefaultSurveyCacheMaxEntries
	}
	return &surveySigCache{
		ttl:        ttl,
		maxEntries: maxEntries,
		entries:    make(map[string]surveyCacheEntry),
	}
}

// globalSurveyCache is the default process-scoped cache for survey tools.
// Tests may replace via swapSurveyCacheForTest.
var (
	globalSurveyCacheMu sync.Mutex
	globalSurveyCache   = newSurveySigCache(DefaultSurveyCacheTTL, DefaultSurveyCacheMaxEntries)
)

func surveyCache() *surveySigCache {
	globalSurveyCacheMu.Lock()
	defer globalSurveyCacheMu.Unlock()
	return globalSurveyCache
}

// swapSurveyCacheForTest replaces the process cache; restore with the returned func.
func swapSurveyCacheForTest(c *surveySigCache) (restore func()) {
	globalSurveyCacheMu.Lock()
	prev := globalSurveyCache
	if c == nil {
		c = newSurveySigCache(DefaultSurveyCacheTTL, DefaultSurveyCacheMaxEntries)
	}
	globalSurveyCache = c
	globalSurveyCacheMu.Unlock()
	return func() {
		globalSurveyCacheMu.Lock()
		globalSurveyCache = prev
		globalSurveyCacheMu.Unlock()
	}
}

// surveyCacheKey binds profile/job/build and the log-byte budget used for extract.
// Different maxLog values must not share entries (small tail must not satisfy a larger scan).
func surveyCacheKey(profile, job string, build, maxLog int) string {
	if profile == "" {
		profile = "_"
	}
	return profile + "\x00" + job + "\x00" + strconv.Itoa(build) + "\x00" + strconv.Itoa(maxLog)
}

func (c *surveySigCache) get(key string) (surveyBuildSummary, bool) {
	if c == nil {
		return surveyBuildSummary{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok {
		return surveyBuildSummary{}, false
	}
	if time.Now().After(e.expires) {
		delete(c.entries, key)
		c.removeOrderLocked(key)
		return surveyBuildSummary{}, false
	}
	return e.summary, true
}

func (c *surveySigCache) put(key string, summary surveyBuildSummary) {
	if c == nil || key == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.entries[key]; !exists {
		c.order = append(c.order, key)
	}
	c.entries[key] = surveyCacheEntry{
		expires: time.Now().Add(c.ttl),
		summary: summary,
	}
	for len(c.entries) > c.maxEntries && len(c.order) > 0 {
		old := c.order[0]
		c.order = c.order[1:]
		delete(c.entries, old)
	}
}

func (c *surveySigCache) removeOrderLocked(key string) {
	for i, k := range c.order {
		if k == key {
			c.order = append(c.order[:i], c.order[i+1:]...)
			return
		}
	}
}

func (c *surveySigCache) len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// ClearSurveyCacheForTest empties the active process cache (tests only).
func ClearSurveyCacheForTest() {
	c := surveyCache()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]surveyCacheEntry)
	c.order = nil
}
