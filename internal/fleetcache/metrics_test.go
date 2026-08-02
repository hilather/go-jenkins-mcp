package fleetcache_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/fleetcache"
)

func TestMetrics_ReplicateSealedImportCommitted(t *testing.T) {
	// Not parallel: uses package Metrics registry.
	fleetcache.ResetForTest()
	wm, frames := makeSealedManifest(t, [][]byte{[]byte("m0\n"), []byte("m1\n")})
	sink := &memSink{}
	// Real API + Observe facade (ReplicateSealedObserved).
	res, err := fleetcache.ReplicateSealedObserved(context.Background(), sink, wm, frames)
	if err != nil || res.Status != fleetcache.ImportStatusCommitted {
		t.Fatalf("%+v %v", res, err)
	}
	snap := fleetcache.Metrics.Snapshot()
	if snap[fleetcache.MetricImportCommitted] != 1 {
		t.Fatalf("import_committed=%d want 1; snap=%v", snap[fleetcache.MetricImportCommitted], snap)
	}
	if snap[fleetcache.MetricReplicateFrames] != int64(res.FramesTransferred) || res.FramesTransferred != 2 {
		t.Fatalf("replicate_frames=%d frames=%d", snap[fleetcache.MetricReplicateFrames], res.FramesTransferred)
	}
	// Bare ReplicateSealed + explicit ObserveReplicateResult (same counters path).
	sink2 := &memSink{}
	resBare, err := fleetcache.ReplicateSealed(context.Background(), sink2, wm, frames)
	if err != nil || resBare.Status != fleetcache.ImportStatusCommitted {
		t.Fatalf("bare: %+v %v", resBare, err)
	}
	fleetcache.ObserveReplicateResult(resBare)
	snap = fleetcache.Metrics.Snapshot()
	if snap[fleetcache.MetricImportCommitted] != 2 {
		t.Fatalf("after bare+observe import_committed=%d", snap[fleetcache.MetricImportCommitted])
	}
	// Idempotent second observed call → import_idempotent.
	res2, err := fleetcache.ReplicateSealedObserved(context.Background(), sink, wm, frames)
	if err != nil || res2.Status != fleetcache.ImportStatusIdempotent {
		t.Fatalf("%+v %v", res2, err)
	}
	snap = fleetcache.Metrics.Snapshot()
	if snap[fleetcache.MetricImportIdempotent] != 1 {
		t.Fatalf("import_idempotent=%d", snap[fleetcache.MetricImportIdempotent])
	}
}

func TestMetrics_OriginBytesAvoided_PeerLocalHit(t *testing.T) {
	fleetcache.ResetForTest()
	// Operators calculate origin bytes avoided from process-local counters.
	fleetcache.RecordLookupOutcome("local", 100)
	fleetcache.RecordLookupOutcome("peer", 250)
	fleetcache.RecordLookupOutcome("origin", 500)
	snap := fleetcache.Metrics.Snapshot()
	if snap[fleetcache.MetricLocalHit] != 1 || snap[fleetcache.MetricPeerHit] != 1 || snap[fleetcache.MetricOriginFill] != 1 {
		t.Fatalf("hits: %+v", snap)
	}
	avoided := fleetcache.Metrics.OriginBytesAvoided()
	if avoided != 350 {
		t.Fatalf("OriginBytesAvoided=%d want 350", avoided)
	}
	if snap[fleetcache.MetricOriginBytesAvoided] != 350 {
		t.Fatalf("snapshot origin_bytes_avoided=%d", snap[fleetcache.MetricOriginBytesAvoided])
	}
	if snap[fleetcache.MetricOriginBytes] != 500 {
		t.Fatalf("origin_bytes=%d", snap[fleetcache.MetricOriginBytes])
	}
	if snap[fleetcache.MetricPeerBytesDecoded] != 250 {
		t.Fatalf("peer_bytes_decoded=%d", snap[fleetcache.MetricPeerBytesDecoded])
	}
}

func TestMetrics_RFHealth_UnderReplicated(t *testing.T) {
	fleetcache.ResetForTest()
	// required=2 healthy=1 → under-replicated signal
	under := fleetcache.Metrics.RFHealth(2, 1)
	if !under {
		t.Fatal("expected under-replicated")
	}
	snap := fleetcache.Metrics.Snapshot()
	if snap[fleetcache.MetricRFRequired] != 2 || snap[fleetcache.MetricRFHealthy] != 1 {
		t.Fatalf("rf gauges: required=%d healthy=%d", snap[fleetcache.MetricRFRequired], snap[fleetcache.MetricRFHealthy])
	}
	if snap[fleetcache.MetricRFUnderReplicated] != 1 {
		t.Fatalf("rf_under_replicated=%d", snap[fleetcache.MetricRFUnderReplicated])
	}
	// Healthy RF does not increment under-replicated again.
	if fleetcache.Metrics.RFHealth(2, 2) {
		t.Fatal("rf healthy should not be under-replicated")
	}
	if fleetcache.Metrics.Snapshot()[fleetcache.MetricRFUnderReplicated] != 1 {
		t.Fatal("under-replicated must not increment on healthy")
	}
}

func TestMetrics_AuthzDecision_ViaFreshnessGate(t *testing.T) {
	fleetcache.ResetForTest()
	allowed := true
	g := fleetcache.NewFreshnessGate(50*time.Millisecond, func(ctx context.Context, key fleetcache.AuthzKey) (bool, string, error) {
		if !allowed {
			return false, fleetcache.ReasonAuthzPolicyDeny, nil
		}
		return true, "", nil
	})
	key := fleetcache.AuthzKey{
		SubjectKeyHash: "metrics-sub",
		ControllerID:   "ctrl",
		JobFullName:    "folder/job",
		ToolName:       "jenkins_get_build_logs",
	}
	// Real API then RecordAuthzDecision (AllowObserved does both).
	d1, err := g.AllowObserved(context.Background(), key)
	if err != nil || !d1.Allowed {
		t.Fatalf("%+v %v", d1, err)
	}
	// Bare Allow + explicit RecordAuthzDecision.
	dBare, err := g.Allow(context.Background(), key)
	if err != nil || !dBare.Allowed || !dBare.FromCache {
		t.Fatalf("bare allow: %+v %v", dBare, err)
	}
	fleetcache.RecordAuthzDecision(dBare)
	snap := fleetcache.Metrics.Snapshot()
	if snap[fleetcache.MetricAuthzOK] != 2 {
		t.Fatalf("authz_ok=%d want 2", snap[fleetcache.MetricAuthzOK])
	}
	allowed = false
	g.InvalidateAll()
	d2, err := g.AllowObserved(context.Background(), key)
	if err != nil || d2.Allowed {
		t.Fatalf("deny: %+v %v", d2, err)
	}
	snap = fleetcache.Metrics.Snapshot()
	if snap[fleetcache.MetricAuthzDeny] != 1 {
		t.Fatalf("authz_deny=%d", snap[fleetcache.MetricAuthzDeny])
	}
	evs := fleetcache.Metrics.RecentSecurity(10)
	found := false
	for _, ev := range evs {
		if ev.Type == fleetcache.SecurityTypeAuthzDeny {
			found = true
			if ev.ReasonCode != fleetcache.ReasonAuthzPolicyDeny {
				t.Fatalf("reason %q", ev.ReasonCode)
			}
		}
	}
	if !found {
		t.Fatalf("expected fleet_cache_authz_deny event; got %+v", evs)
	}
}

func TestMetrics_SecurityEvent_SecretFreeCanary(t *testing.T) {
	fleetcache.ResetForTest()
	// Inject residual with token=sekrit and Bearer xyz — must scrub.
	fleetcache.Metrics.EmitSecurity(fleetcache.SecurityEvent{
		Type:              fleetcache.SecurityTypeImportConflict,
		ReasonCode:        "partition_conflict_digest",
		LocatorHashPrefix: "abcdef0123456789deadbeef",
		Residual:          "conflict token=sekrit Authorization Bearer xyz url=https://user:pass@host/path",
	})
	// ObserveReplicateResult conflict path also emits (with clean residual).
	fleetcache.ObserveReplicateResult(fleetcache.ReplicateResult{
		Status:      fleetcache.ImportStatusRejected,
		LocatorHash: "abcdef0123456789",
		Residual:    fleetcache.PartitionResidualConflictDigest,
	})

	for _, ev := range fleetcache.Metrics.RecentSecurity(20) {
		assertSecretFree(t, "type", ev.Type)
		assertSecretFree(t, "reason", ev.ReasonCode)
		assertSecretFree(t, "residual", ev.Residual)
		assertSecretFree(t, "locator", ev.LocatorHashPrefix)
		if strings.Contains(ev.Residual, "token=sekrit") || strings.Contains(ev.Residual, "Bearer xyz") {
			t.Fatalf("secret residual not scrubbed: %q", ev.Residual)
		}
		if strings.Contains(ev.Residual, "user:pass@") {
			t.Fatalf("credentialed URL not scrubbed: %q", ev.Residual)
		}
		if len(ev.LocatorHashPrefix) > 12 {
			t.Fatalf("locator prefix too long: %q", ev.LocatorHashPrefix)
		}
		// Injected residual (type import_conflict with scrubbed secret payload) must show marker.
		if ev.Type == fleetcache.SecurityTypeImportConflict &&
			ev.ReasonCode == "partition_conflict_digest" &&
			strings.Contains(ev.Residual, "url=") &&
			!strings.Contains(ev.Residual, "[redacted]") {
			t.Fatalf("expected scrub marker in residual: %q", ev.Residual)
		}
	}
	// Snapshot values are ints only — scan keys for high-cardinality leakage.
	snap := fleetcache.Metrics.Snapshot()
	for k := range snap {
		assertSecretFree(t, "metric-key", k)
		if strings.Contains(k, "/") || strings.Contains(k, "job/") {
			t.Fatalf("job-like metric label: %q", k)
		}
	}
}

func TestMetrics_ProcessLocalAggregationResidual(t *testing.T) {
	fleetcache.ResetForTest()
	if got := fleetcache.Metrics.AggregationResidual(); got != fleetcache.MetricsAggregationResidual {
		t.Fatalf("aggregation residual %q", got)
	}
	if !strings.Contains(fleetcache.MetricsAggregationResidual, "process_local_only") {
		t.Fatal("must declare process-local")
	}
	if !strings.Contains(fleetcache.MetricsAggregationResidual, "FLC-062") {
		t.Fatal("must name multi-member residual")
	}
	cfg, err := fleetcache.ResolveConfig(fleetcache.ResolveOptions{Getenv: func(string) string { return "" }})
	if err != nil {
		t.Fatal(err)
	}
	st := cfg.StatusSummary()
	agg, _ := st["aggregation"].(string)
	if agg != fleetcache.MetricsAggregationResidual {
		t.Fatalf("StatusSummary aggregation=%q", agg)
	}
	assertSecretFree(t, "status residual", fmtString(st["residual"]))
	assertSecretFree(t, "aggregation", agg)
}

func TestMetrics_ObserveReplicateResult_Conflict(t *testing.T) {
	fleetcache.ResetForTest()
	// Real ReplicateSealed success, then conflict observe facade.
	wm, frames := makeSealedManifest(t, [][]byte{[]byte("c0\n")})
	sink := &memSink{}
	res, err := fleetcache.ReplicateSealed(context.Background(), sink, wm, frames)
	if err != nil || res.Status != fleetcache.ImportStatusCommitted {
		t.Fatalf("%+v %v", res, err)
	}
	fleetcache.ObserveReplicateResult(res)
	// Explicit conflict observe (also exercises facade + security event).
	fleetcache.ObserveReplicateResult(fleetcache.ReplicateResult{
		Status:      fleetcache.ImportStatusRejected,
		LocatorHash: wm.LocatorHash,
		Residual:    fleetcache.PartitionResidualConflictDigest,
	})
	snap := fleetcache.Metrics.Snapshot()
	if snap[fleetcache.MetricImportCommitted] != 1 {
		t.Fatalf("import_committed=%d", snap[fleetcache.MetricImportCommitted])
	}
	if snap[fleetcache.MetricImportRejected] != 1 {
		t.Fatalf("import_rejected=%d", snap[fleetcache.MetricImportRejected])
	}
	found := false
	for _, ev := range fleetcache.Metrics.RecentSecurity(10) {
		if ev.Type == fleetcache.SecurityTypeImportConflict {
			found = true
			if len(ev.LocatorHashPrefix) == 0 || len(ev.LocatorHashPrefix) > 12 {
				t.Fatalf("locator prefix %q", ev.LocatorHashPrefix)
			}
		}
	}
	if !found {
		t.Fatal("expected import conflict security event")
	}
}

func TestMetrics_AddBytesKinds(t *testing.T) {
	t.Parallel()
	m := fleetcache.DefaultMetrics()
	m.AddBytes("wire", 10)
	m.AddBytes("decoded", 20)
	m.AddBytes("mcp", 30)
	m.AddBytes("origin", 40)
	snap := m.Snapshot()
	if snap[fleetcache.MetricPeerBytesWire] != 10 || snap[fleetcache.MetricPeerBytesDecoded] != 20 {
		t.Fatalf("%+v", snap)
	}
	if snap[fleetcache.MetricMCPBytesOut] != 30 || snap[fleetcache.MetricOriginBytes] != 40 {
		t.Fatalf("%+v", snap)
	}
}

func fmtString(v any) string {
	if v == nil {
		return ""
	}
	s, _ := v.(string)
	return s
}
