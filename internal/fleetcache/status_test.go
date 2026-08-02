package fleetcache_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/fleetcache"
)

func TestStatus_LocalVsReplicaHealth(t *testing.T) {
	t.Parallel()
	cfg := fleetcache.Config{Mode: fleetcache.ModeRead}
	falseLocal := false
	st := fleetcache.BuildFleetCacheStatus(cfg, nil, nil, fleetcache.StatusOptions{
		LocalHealthy: &falseLocal,
	})
	if st.LocalHealthy {
		t.Fatal("expected local unhealthy")
	}
	// No under-rep / unreachable → replica still healthy.
	if !st.ReplicaHealthy {
		t.Fatal("expected replica healthy when no peer issues")
	}
	if !hasResidualPrefix(st.Residuals, "local_cache_unhealthy") {
		t.Fatalf("expected local residual: %v", st.Residuals)
	}

	under := 2
	st2 := fleetcache.BuildFleetCacheStatus(cfg, nil, nil, fleetcache.StatusOptions{
		UnderReplicatedObjects: &under,
	})
	if !st2.LocalHealthy {
		t.Fatal("local should default healthy")
	}
	if st2.ReplicaHealthy {
		t.Fatal("under-replicated must set ReplicaHealthy=false")
	}
	if st2.UnderReplicatedObjects != 2 {
		t.Fatalf("under=%d", st2.UnderReplicatedObjects)
	}
}

func TestStatus_IncompatiblePeerResidualExplicit(t *testing.T) {
	t.Parallel()
	cfg := fleetcache.Config{Mode: fleetcache.ModeRead}
	members := []fleetcache.MemberCacheView{
		{MemberID: "m-a", ProtocolOK: true, Reachable: true},
		{MemberID: "m-b", ProtocolOK: false, Reachable: true, Residual: "protocol_mismatch fleet-cache/0"},
	}
	st := fleetcache.BuildFleetCacheStatus(cfg, nil, members, fleetcache.StatusOptions{})
	if st.EligibleMembers != 2 || st.CompatibleMembers != 1 || st.IncompatibleMembers != 1 {
		t.Fatalf("counts eligible=%d compat=%d incompat=%d", st.EligibleMembers, st.CompatibleMembers, st.IncompatibleMembers)
	}
	found := false
	for _, r := range st.Residuals {
		if strings.Contains(r, "incompatible_protocol") && strings.Contains(r, "m-b") {
			found = true
		}
	}
	if !found {
		t.Fatalf("incompatible residual missing: %v", st.Residuals)
	}
	// Protocol version on status is product v1.
	if st.Protocol != fleetcache.ProtocolVersionV1 {
		t.Fatalf("protocol=%q", st.Protocol)
	}
}

func TestStatus_UnreachableCountedAndResidual(t *testing.T) {
	t.Parallel()
	cfg := fleetcache.Config{Mode: fleetcache.ModeFull}
	members := []fleetcache.MemberCacheView{
		{MemberID: "owner-1", ProtocolOK: true, Reachable: true},
		{MemberID: "owner-2", ProtocolOK: true, Reachable: false},
		{MemberID: "owner-3", ProtocolOK: true, Reachable: false},
	}
	st := fleetcache.BuildFleetCacheStatus(cfg, nil, members, fleetcache.StatusOptions{})
	if st.UnreachableMembers != 2 {
		t.Fatalf("unreachable=%d", st.UnreachableMembers)
	}
	// Unreachable must not disappear — residuals name them.
	nUnreach := 0
	for _, r := range st.Residuals {
		if strings.Contains(r, "unreachable_peer") {
			nUnreach++
		}
	}
	if nUnreach < 2 {
		t.Fatalf("expected unreachable residuals for each peer, got %v", st.Residuals)
	}
	if st.ReplicaHealthy {
		t.Fatal("unreachable owners → ReplicaHealthy false")
	}
}

func TestStatus_UnderReplicatedReplicaHealthyFalse(t *testing.T) {
	t.Parallel()
	cfg := fleetcache.Config{Mode: fleetcache.ModeFull}
	m := fleetcache.DefaultMetrics()
	// Gauges: required 2, healthy 1 → under=1.
	m.RFHealth(2, 1)
	st := fleetcache.BuildFleetCacheStatus(cfg, m, nil, fleetcache.StatusOptions{})
	if st.UnderReplicatedObjects != 1 {
		t.Fatalf("under from metrics gauges=%d", st.UnderReplicatedObjects)
	}
	if st.ReplicaHealthy {
		t.Fatal("under-replicated → ReplicaHealthy false")
	}
	if !st.MetricsAvailable {
		t.Fatal("metrics bag supplied")
	}
}

func TestStatus_SecretCanaryResidualsAndMap(t *testing.T) {
	t.Parallel()
	cfg := fleetcache.Config{Mode: fleetcache.ModeRead}
	members := []fleetcache.MemberCacheView{
		{
			MemberID:   "peer-1",
			ProtocolOK: true,
			Reachable:  false,
			// Inject secret-shaped residual — must scrub.
			Residual: "fail token=sekrit Authorization Bearer xyz password=hunter2 https://user:pass@host/j",
		},
	}
	st := fleetcache.BuildFleetCacheStatus(cfg, nil, members, fleetcache.StatusOptions{
		AuthResidual: "mesh token=should-not-leak Bearer abc",
	})
	for i, r := range st.Residuals {
		assertSecretFree(t, fmt.Sprintf("residual[%d]", i), r)
	}
	assertSecretFree(t, "auth", st.AuthResidual)
	assertSecretFree(t, "aggregation", st.Aggregation)
	assertSecretFree(t, "mode", st.Mode)
	assertSecretFree(t, "protocol", st.Protocol)

	// JSON-ish map dump must stay secret-free.
	raw, err := json.Marshal(st.Map())
	if err != nil {
		t.Fatal(err)
	}
	assertSecretFree(t, "status-map-json", string(raw))
	// Nested StatusSummary path.
	sum := cfg.StatusSummary()
	fc, ok := sum["fleet_cache_status"].(map[string]any)
	if !ok {
		t.Fatalf("StatusSummary missing fleet_cache_status: %+v", sum)
	}
	b, err := json.Marshal(fc)
	if err != nil {
		t.Fatal(err)
	}
	assertSecretFree(t, "status-summary-nest", string(b))
}

func TestBoundResiduals_Length(t *testing.T) {
	t.Parallel()
	in := make([]string, 40)
	for i := range in {
		in[i] = fmt.Sprintf("residual_%d", i)
	}
	out := fleetcache.BoundResiduals(in, 16)
	if len(out) != 16 {
		t.Fatalf("len=%d want 16", len(out))
	}
	// max<=0 → default 16
	out2 := fleetcache.BoundResiduals(in, 0)
	if len(out2) != fleetcache.DefaultMaxStatusResiduals {
		t.Fatalf("default bound=%d", len(out2))
	}
	// Empty / secret-scrubbed empties dropped
	if got := fleetcache.BoundResiduals([]string{"  ", ""}, 8); got != nil {
		t.Fatalf("expected nil, got %v", got)
	}
	// Scrubs secrets
	got := fleetcache.BoundResiduals([]string{"ok", "token=sekrit and Bearer x"}, 8)
	if len(got) < 1 {
		t.Fatal("expected residual")
	}
	for _, s := range got {
		assertSecretFree(t, "bound", s)
	}
}

func TestDoctorFleetCache_FailsIncompatibleUnreachable(t *testing.T) {
	t.Parallel()
	cfg := fleetcache.Config{Mode: fleetcache.ModeRead}
	members := []fleetcache.MemberCacheView{
		{MemberID: "a", ProtocolOK: false, Reachable: true},
		{MemberID: "b", ProtocolOK: true, Reachable: false},
	}
	under := 1
	m := fleetcache.DefaultMetrics()
	st := fleetcache.BuildFleetCacheStatus(cfg, m, members, fleetcache.StatusOptions{
		UnderReplicatedObjects: &under,
	})
	checks := fleetcache.DoctorFleetCache(cfg, st)
	byName := map[string]fleetcache.DoctorCheck{}
	for _, c := range checks {
		byName[c.Name] = c
		assertSecretFree(t, "doctor:"+c.Name, c.Residual)
	}
	if c := byName[fleetcache.DoctorProtocolCompat]; c.OK {
		t.Fatalf("protocol_compat should fail: %+v", c)
	}
	if c := byName[fleetcache.DoctorUnreachablePeers]; c.OK {
		t.Fatalf("unreachable_peers should fail: %+v", c)
	}
	if c := byName[fleetcache.DoctorUnderReplication]; c.OK {
		t.Fatalf("under_replication should fail: %+v", c)
	}
	if c := byName[fleetcache.DoctorAggregationProcessLocal]; !c.OK || !strings.Contains(c.Residual, "process_local") {
		t.Fatalf("aggregation residual honesty: %+v", c)
	}
	if c := byName[fleetcache.DoctorMetricsAvailable]; !c.OK {
		t.Fatalf("metrics available: %+v", c)
	}
	if c := byName[fleetcache.DoctorModeDefaultOff]; !c.OK {
		t.Fatalf("mode check always ok honesty: %+v", c)
	}
}

func TestDoctorFleetCache_ModeOffHonestyAndHealthy(t *testing.T) {
	t.Parallel()
	cfg, err := fleetcache.ResolveConfig(fleetcache.ResolveOptions{Getenv: func(string) string { return "" }})
	if err != nil {
		t.Fatal(err)
	}
	m := fleetcache.DefaultMetrics()
	st := fleetcache.BuildFleetCacheStatus(cfg, m, nil, fleetcache.StatusOptions{})
	if st.Mode != "off" || st.Active {
		t.Fatalf("mode off: %+v", st)
	}
	if !st.LocalHealthy || !st.ReplicaHealthy {
		t.Fatalf("mode-off no peers should be healthy: local=%v replica=%v", st.LocalHealthy, st.ReplicaHealthy)
	}
	checks := fleetcache.DoctorFleetCache(cfg, st)
	for _, c := range checks {
		assertSecretFree(t, c.Name, c.Residual)
		switch c.Name {
		case fleetcache.DoctorModeDefaultOff:
			if !c.OK || !strings.Contains(c.Residual, "mode_default_off") {
				t.Fatalf("mode honesty: %+v", c)
			}
		case fleetcache.DoctorProtocolCompat, fleetcache.DoctorUnreachablePeers, fleetcache.DoctorUnderReplication:
			if !c.OK {
				t.Fatalf("%s should pass when no peers: %+v", c.Name, c)
			}
		}
	}
}

func TestStatus_ModeOffResidualsAndProtocol(t *testing.T) {
	t.Parallel()
	cfg := fleetcache.Config{Mode: fleetcache.ModeOff}
	st := fleetcache.BuildFleetCacheStatus(cfg, nil, nil, fleetcache.StatusOptions{
		PlacementEpoch: 7,
		ImportBacklog:  3,
		RepairBacklog:  1,
		DrainActive:    true,
	})
	if st.Protocol != "fleet-cache/1" {
		t.Fatalf("protocol %q", st.Protocol)
	}
	if st.Aggregation != fleetcache.MetricsAggregationResidual {
		t.Fatalf("aggregation %q", st.Aggregation)
	}
	if st.PlacementEpoch != 7 || st.ImportBacklog != 3 || st.RepairBacklog != 1 || !st.DrainActive {
		t.Fatalf("%+v", st)
	}
	if st.MetricsAvailable {
		t.Fatal("nil metrics → MetricsAvailable false")
	}
	// Doctor metrics_available fails when bag not supplied.
	checks := fleetcache.DoctorFleetCache(cfg, st)
	for _, c := range checks {
		if c.Name == fleetcache.DoctorMetricsAvailable && c.OK {
			t.Fatalf("metrics should fail: %+v", c)
		}
	}
}

func hasResidualPrefix(residuals []string, needle string) bool {
	for _, r := range residuals {
		if strings.Contains(r, needle) {
			return true
		}
	}
	return false
}
