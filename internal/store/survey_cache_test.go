package store_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/store"
)

func TestSurveySummaryCache_PutGetMiss(t *testing.T) {
	m := openTestMeta(t)
	ctx := context.Background()

	key := store.SurveyCacheKey{
		Profile: "corp", Job: "demo", Build: 10, MaxLogBytes: 65536,
	}
	// Miss.
	got, err := m.GetSurveySummary(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("expected miss, got %+v", got)
	}

	entry := &store.SurveyCacheEntry{
		Key:      key,
		Result:   "FAILURE",
		Source:   "log_tail",
		LogBytes: 1200,
		Findings: []store.SurveyCacheFinding{{
			Signature:      "aabbccddeeff0011",
			Pattern:        "build_failure",
			Message:        "compilation failed",
			Normalized:     "compilation failed",
			ExactSignature: "1122334455667788",
			Confidence:     0.95,
			Count:          1,
		}},
	}
	if err := m.PutSurveySummary(ctx, entry, store.DefaultSurveyCacheTTL, store.DefaultSurveyCacheMaxEntries); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err = m.GetSurveySummary(ctx, key)
	if err != nil || got == nil {
		t.Fatalf("Get: err=%v got=%+v", err, got)
	}
	if got.Result != "FAILURE" || got.LogBytes != 1200 || len(got.Findings) != 1 {
		t.Fatalf("entry: %+v", got)
	}
	if got.Findings[0].Signature != "aabbccddeeff0011" || got.Findings[0].Pattern != "build_failure" {
		t.Fatalf("finding: %+v", got.Findings[0])
	}

	// Different max_log_bytes is a distinct key (miss).
	other, err := m.GetSurveySummary(ctx, store.SurveyCacheKey{
		Profile: "corp", Job: "demo", Build: 10, MaxLogBytes: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	if other != nil {
		t.Fatal("expected miss for different max_log_bytes")
	}
}

func TestSurveySummaryCache_TTLExpires(t *testing.T) {
	m := openTestMeta(t)
	ctx := context.Background()
	key := store.SurveyCacheKey{
		Profile: "corp", Job: "demo", Build: 1, MaxLogBytes: 4096,
	}
	if err := m.PutSurveySummary(ctx, &store.SurveyCacheEntry{
		Key: key, Result: "FAILURE",
	}, 30*time.Millisecond, 10); err != nil {
		t.Fatal(err)
	}
	// Immediate hit.
	got, err := m.GetSurveySummary(ctx, key)
	if err != nil || got == nil {
		t.Fatalf("expected hit: err=%v got=%v", err, got)
	}
	time.Sleep(50 * time.Millisecond)
	got, err = m.GetSurveySummary(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("expected TTL miss, got %+v", got)
	}
	// Expired row should be gone.
	n, err := m.CountSurveySummaries(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("expired row still present: count=%d", n)
	}
}

func TestSurveySummaryCache_CorruptSkip(t *testing.T) {
	m := openTestMeta(t)
	ctx := context.Background()
	key := store.SurveyCacheKey{
		Profile: "corp", Job: "demo", Build: 3, MaxLogBytes: 8192,
	}
	// Seed a valid row then corrupt findings_json.
	if err := m.PutSurveySummary(ctx, &store.SurveyCacheEntry{
		Key: key, Result: "UNSTABLE",
		Findings: []store.SurveyCacheFinding{{Signature: "deadbeef"}},
	}, time.Hour, 10); err != nil {
		t.Fatal(err)
	}
	// Corrupt: invalid JSON array.
	_, err := m.DB().ExecContext(ctx, `
UPDATE survey_summary_cache SET findings_json = ? WHERE profile = ? AND job = ? AND build = ?`,
		`{not-an-array}`, key.Profile, key.Job, key.Build)
	if err != nil {
		t.Fatal(err)
	}
	got, err := m.GetSurveySummary(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("corrupt row must fail closed as miss, got %+v", got)
	}
	// Row purged.
	n, _ := m.CountSurveySummaries(ctx)
	if n != 0 {
		t.Fatalf("corrupt row not purged: count=%d", n)
	}

	// Corrupt expires_at.
	if err := m.PutSurveySummary(ctx, &store.SurveyCacheEntry{
		Key: key, Result: "FAILURE",
	}, time.Hour, 10); err != nil {
		t.Fatal(err)
	}
	_, err = m.DB().ExecContext(ctx, `
UPDATE survey_summary_cache SET expires_at = 'not-a-time' WHERE profile = ?`, key.Profile)
	if err != nil {
		t.Fatal(err)
	}
	got, err = m.GetSurveySummary(ctx, key)
	if err != nil || got != nil {
		t.Fatalf("corrupt expires must miss: err=%v got=%v", err, got)
	}
}

func TestSurveySummaryCache_MaxEntriesEviction(t *testing.T) {
	m := openTestMeta(t)
	ctx := context.Background()
	const max = 3
	for i := 1; i <= 5; i++ {
		key := store.SurveyCacheKey{
			Profile: "corp", Job: "job", Build: int64(i), MaxLogBytes: 1024,
		}
		if err := m.PutSurveySummary(ctx, &store.SurveyCacheEntry{
			Key: key, Result: "FAILURE",
		}, time.Hour, max); err != nil {
			t.Fatal(err)
		}
		// Tiny sleep so created_at ordering is stable.
		time.Sleep(2 * time.Millisecond)
	}
	n, err := m.CountSurveySummaries(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n > max {
		t.Fatalf("count=%d want <=%d", n, max)
	}
	// Oldest builds (1,2) should be gone; newest present.
	for _, b := range []int64{1, 2} {
		got, err := m.GetSurveySummary(ctx, store.SurveyCacheKey{
			Profile: "corp", Job: "job", Build: b, MaxLogBytes: 1024,
		})
		if err != nil {
			t.Fatal(err)
		}
		if got != nil {
			t.Fatalf("build %d should have been evicted", b)
		}
	}
	for _, b := range []int64{3, 4, 5} {
		got, err := m.GetSurveySummary(ctx, store.SurveyCacheKey{
			Profile: "corp", Job: "job", Build: b, MaxLogBytes: 1024,
		})
		if err != nil || got == nil {
			t.Fatalf("build %d should remain: err=%v", b, err)
		}
	}
}

func TestSurveySummaryCache_NoSecretPersistence(t *testing.T) {
	// Canary: correct usage stores hashes only — secret string never in blob.
	m := openTestMeta(t)
	ctx := context.Background()
	const secret = "supersecret-survey-durable-canary-xyz"
	key := store.SurveyCacheKey{
		Profile: "corp", Job: "demo", Build: 99, MaxLogBytes: 4096,
	}
	if err := m.PutSurveySummary(ctx, &store.SurveyCacheEntry{
		Key:    key,
		Result: "FAILURE",
		Findings: []store.SurveyCacheFinding{{
			Signature: "sighashonly",
			Pattern:   "build_failure",
			// No Message / Evidence with secret — tools path redacts before put.
		}},
	}, time.Hour, 10); err != nil {
		t.Fatal(err)
	}
	var blob string
	if err := m.DB().QueryRowContext(ctx, `
SELECT findings_json || ' ' || result || ' ' || source FROM survey_summary_cache
WHERE profile = ? AND build = ?`, key.Profile, key.Build).Scan(&blob); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(blob, secret) {
		t.Fatalf("secret leaked into cache blob: %q", blob)
	}
	// Oversized multi-line log body must be clamped (no full tail persistence).
	// Callers (tools) redact before put; store still bounds field size.
	huge := strings.Repeat("password="+secret+"\n", 500)
	if err := m.PutSurveySummary(ctx, &store.SurveyCacheEntry{
		Key: store.SurveyCacheKey{
			Profile: "corp", Job: "demo", Build: 100, MaxLogBytes: 4096,
		},
		Result: "FAILURE",
		Findings: []store.SurveyCacheFinding{{
			Signature: "h2",
			Message:   huge,
		}},
	}, time.Hour, 10); err != nil {
		t.Fatal(err)
	}
	var fj string
	if err := m.DB().QueryRowContext(ctx, `
SELECT findings_json FROM survey_summary_cache WHERE build = 100`).Scan(&fj); err != nil {
		t.Fatal(err)
	}
	if len(fj) > store.SurveyCacheMaxFindingsJSONBytes {
		t.Fatalf("findings_json unbounded: %d", len(fj))
	}
	// Full 500-line tail must not survive; at most a short clamped window.
	if strings.Count(fj, secret) >= 500 {
		t.Fatalf("full log tail persisted: secret count=%d", strings.Count(fj, secret))
	}
	// Message field itself is ≤ SurveyCacheMaxTextField (plus JSON overhead).
	got, err := m.GetSurveySummary(ctx, store.SurveyCacheKey{
		Profile: "corp", Job: "demo", Build: 100, MaxLogBytes: 4096,
	})
	if err != nil || got == nil || len(got.Findings) != 1 {
		t.Fatalf("get: err=%v got=%+v", err, got)
	}
	if len(got.Findings[0].Message) > store.SurveyCacheMaxTextField {
		t.Fatalf("message not clamped: %d", len(got.Findings[0].Message))
	}
}

func TestSurveySummaryCache_SurvivesReopen(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	m1, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	key := store.SurveyCacheKey{
		Profile: "corp", Job: "demo", Build: 7, MaxLogBytes: 2048,
	}
	if err := m1.PutSurveySummary(ctx, &store.SurveyCacheEntry{
		Key: key, Result: "FAILURE", LogBytes: 99,
		Findings: []store.SurveyCacheFinding{{Signature: "reopen-sig", Pattern: "fatal"}},
	}, time.Hour, 32); err != nil {
		t.Fatal(err)
	}
	if err := m1.Close(); err != nil {
		t.Fatal(err)
	}
	m2, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer m2.Close()
	got, err := m2.GetSurveySummary(ctx, key)
	if err != nil || got == nil {
		t.Fatalf("reopen get: err=%v got=%v", err, got)
	}
	if got.LogBytes != 99 || len(got.Findings) != 1 || got.Findings[0].Signature != "reopen-sig" {
		t.Fatalf("reopen entry: %+v", got)
	}
}

func TestSurveySummaryCache_ContextCancel(t *testing.T) {
	m := openTestMeta(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := m.GetSurveySummary(ctx, store.SurveyCacheKey{
		Profile: "p", Job: "j", Build: 1, MaxLogBytes: 1,
	})
	if err == nil {
		t.Fatal("expected context error on get")
	}
	err = m.PutSurveySummary(ctx, &store.SurveyCacheEntry{
		Key: store.SurveyCacheKey{Profile: "p", Job: "j", Build: 1, MaxLogBytes: 1},
	}, time.Hour, 10)
	if err == nil {
		t.Fatal("expected context error on put")
	}
}

func TestSurveySummaryCache_TextClampNoLogBody(t *testing.T) {
	m := openTestMeta(t)
	ctx := context.Background()
	const secret = "supersecret-survey-durable-canary-xyz"
	longMsg := "password=" + secret + " " + strings.Repeat("Z", 400)
	key := store.SurveyCacheKey{
		Profile: "corp", Job: "demo", Build: 50, MaxLogBytes: 1024,
	}
	if err := m.PutSurveySummary(ctx, &store.SurveyCacheEntry{
		Key: key, Result: "FAILURE",
		Findings: []store.SurveyCacheFinding{{
			Signature: "hashonly",
			Message:   longMsg,
		}},
	}, time.Hour, 10); err != nil {
		t.Fatal(err)
	}
	var fj string
	if err := m.DB().QueryRowContext(ctx, `
SELECT findings_json FROM survey_summary_cache WHERE build = 50`).Scan(&fj); err != nil {
		t.Fatal(err)
	}
	// Clamped field must be bounded; full longMsg must not survive intact.
	if len(fj) > store.SurveyCacheMaxFindingsJSONBytes {
		t.Fatalf("findings_json too large: %d", len(fj))
	}
	got, err := m.GetSurveySummary(ctx, key)
	if err != nil || got == nil || len(got.Findings) != 1 {
		t.Fatalf("get: err=%v got=%+v", err, got)
	}
	if len(got.Findings[0].Message) > store.SurveyCacheMaxTextField {
		t.Fatalf("message not clamped: %d", len(got.Findings[0].Message))
	}
	// Message may include secret if caller put it unredacted — tools re-redact.
	// Assert no multi-line log body markers stored.
	if strings.Contains(fj, "\nFinished: FAILURE") || strings.Count(fj, "\n") > 2 {
		t.Fatalf("looks like a log body in findings_json: %q", fj)
	}
}
