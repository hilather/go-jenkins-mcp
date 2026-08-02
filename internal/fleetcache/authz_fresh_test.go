package fleetcache_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/fleetcache"
)

func TestFreshnessGate_AllowDenyTTL(t *testing.T) {
	t.Parallel()
	var probes int
	allowed := true
	g := fleetcache.NewFreshnessGate(50*time.Millisecond, func(ctx context.Context, key fleetcache.AuthzKey) (bool, string, error) {
		probes++
		if !allowed {
			return false, fleetcache.ReasonAuthzPolicyDeny, nil
		}
		return true, "", nil
	})
	key := fleetcache.AuthzKey{
		SubjectKeyHash: "subhash1",
		ControllerID:   "ctrl",
		JobFullName:    "folder/job",
		ToolName:       "jenkins_get_build_logs",
		PolicyEpoch:    1,
	}
	d1, err := g.Allow(context.Background(), key)
	if err != nil || !d1.Allowed || d1.FromCache || d1.CacheHitElevation {
		t.Fatalf("%+v %v", d1, err)
	}
	d2, err := g.Allow(context.Background(), key)
	if err != nil || !d2.Allowed || !d2.FromCache {
		t.Fatalf("cache: %+v %v", d2, err)
	}
	if probes != 1 {
		t.Fatalf("probes=%d", probes)
	}
	// Deny path.
	allowed = false
	g.InvalidateAll()
	d3, err := g.Allow(context.Background(), key)
	if err != nil || d3.Allowed || d3.ReasonCode != fleetcache.ReasonAuthzPolicyDeny {
		t.Fatalf("deny: %+v %v", d3, err)
	}
	if d3.CacheHitElevation {
		t.Fatal("cache must never elevate")
	}
}

// TestFreshnessGate_TTLExpireReprobes advances the gate clock past TTL so a
// never-expiring Allow cache would fail this test (FLC-018 verification).
func TestFreshnessGate_TTLExpireReprobes(t *testing.T) {
	t.Parallel()
	var probes int
	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	g := fleetcache.NewFreshnessGate(10*time.Second, func(ctx context.Context, key fleetcache.AuthzKey) (bool, string, error) {
		probes++
		return true, "", nil
	})
	g.Now = func() time.Time { return now }

	key := fleetcache.AuthzKey{
		SubjectKeyHash: "ttl-sub",
		ControllerID:   "ctrl",
		JobFullName:    "job",
		ToolName:       "jenkins_get_build_logs",
	}
	d1, err := g.Allow(context.Background(), key)
	if err != nil || !d1.Allowed || d1.FromCache {
		t.Fatalf("first: %+v %v", d1, err)
	}
	if probes != 1 {
		t.Fatalf("probes after first=%d", probes)
	}
	// Within TTL: served from cache.
	now = now.Add(5 * time.Second)
	d2, err := g.Allow(context.Background(), key)
	if err != nil || !d2.Allowed || !d2.FromCache {
		t.Fatalf("within TTL: %+v %v", d2, err)
	}
	if probes != 1 {
		t.Fatalf("must not re-probe within TTL; probes=%d", probes)
	}
	// Past TTL: must re-probe (would fail if cache never expired).
	now = now.Add(10 * time.Second) // total +15s from first allow; TTL was 10s
	d3, err := g.Allow(context.Background(), key)
	if err != nil || !d3.Allowed {
		t.Fatalf("after TTL: %+v %v", d3, err)
	}
	if d3.FromCache {
		t.Fatal("stale allow must not be served FromCache after TTL")
	}
	if probes != 2 {
		t.Fatalf("expected re-probe after TTL expire; probes=%d", probes)
	}
}

func TestFreshnessGate_ProbeFailClosed(t *testing.T) {
	t.Parallel()
	g := fleetcache.NewFreshnessGate(time.Second, func(ctx context.Context, key fleetcache.AuthzKey) (bool, string, error) {
		return false, "", errors.New("jenkins unreachable")
	})
	d, err := g.Allow(context.Background(), fleetcache.AuthzKey{
		SubjectKeyHash: "h", ControllerID: "c", JobFullName: "j",
	})
	if err == nil || d.Allowed {
		t.Fatalf("expected fail closed: %+v %v", d, err)
	}
	if d.ReasonCode != fleetcache.ReasonAuthzProbeFail {
		t.Fatalf("%+v", d)
	}
	if apperr.CodeOf(err) != apperr.CodePolicyDenial {
		t.Fatalf("code %v", err)
	}
	if strings.Contains(err.Error(), "token") {
		t.Fatalf("secret-like: %v", err)
	}
}

func TestFreshnessGate_RejectsSecretShapedSubject(t *testing.T) {
	t.Parallel()
	g := fleetcache.NewFreshnessGate(time.Second, func(ctx context.Context, key fleetcache.AuthzKey) (bool, string, error) {
		return true, "", nil
	})
	_, err := g.Allow(context.Background(), fleetcache.AuthzKey{
		SubjectKeyHash: "Bearer abc.def.ghi",
		ControllerID:   "c",
		JobFullName:    "j",
	})
	if err == nil {
		t.Fatal("expected reject")
	}
}

func TestFreshnessGate_InvalidateSubject(t *testing.T) {
	t.Parallel()
	var probes int
	g := fleetcache.NewFreshnessGate(time.Minute, func(ctx context.Context, key fleetcache.AuthzKey) (bool, string, error) {
		probes++
		return true, "", nil
	})
	key := fleetcache.AuthzKey{SubjectKeyHash: "alice", ControllerID: "c", JobFullName: "j"}
	_, _ = g.Allow(context.Background(), key)
	_, _ = g.Allow(context.Background(), key)
	if probes != 1 {
		t.Fatalf("probes %d", probes)
	}
	g.InvalidateSubject("alice")
	_, _ = g.Allow(context.Background(), key)
	if probes != 2 {
		t.Fatalf("after invalidate probes %d", probes)
	}
}
