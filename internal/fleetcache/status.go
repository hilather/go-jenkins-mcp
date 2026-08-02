package fleetcache

import (
	"fmt"
	"strings"
)

// Fleet-cache operator status / doctor (FLC-062).
//
// Distinguishes local cache health from fleet replica health. Unreachable and
// protocol-incompatible peers appear as residuals (they never silently drop).
// All residual strings are secret-free; no tokens, credentialed URLs, raw logs,
// or free-form object/job names.

// DefaultMaxStatusResiduals bounds Residuals on FleetCacheStatus.
const DefaultMaxStatusResiduals = 16

// Auth residual honesty when peer mesh trust is not fully production-pinned.
const AuthResidualDefault = "peer_auth_mesh_or_mtls residual; scoped assertions only"

// Doctor check names (stable, low-cardinality).
const (
	DoctorModeDefaultOff          = "mode_default_off"
	DoctorProtocolCompat          = "protocol_compat"
	DoctorUnreachablePeers        = "unreachable_peers"
	DoctorUnderReplication        = "under_replication"
	DoctorAggregationProcessLocal = "aggregation_process_local"
	DoctorMetricsAvailable        = "metrics_available"
)

// FleetCacheStatus is a bounded, secret-free operator view of fleet-cache health (FLC-062).
// LocalHealthy is process/local plane; ReplicaHealthy is fleet RF / peer reachability.
type FleetCacheStatus struct {
	Mode                   string   `json:"mode"`
	Active                 bool     `json:"active"`
	PeerReadHandlersLive   bool     `json:"peer_read_handlers_live"`
	Aggregation            string   `json:"aggregation"` // process-local MetricsAggregationResidual
	Protocol               string   `json:"protocol"`    // fleet-cache/1
	PlacementEpoch         int64    `json:"placement_epoch,omitempty"`
	EligibleMembers        int      `json:"eligible_members"`
	CompatibleMembers      int      `json:"compatible_members"`
	IncompatibleMembers    int      `json:"incompatible_members"`
	UnreachableMembers     int      `json:"unreachable_members"`
	UnderReplicatedObjects int      `json:"under_replicated_objects"`
	ImportBacklog          int      `json:"import_backlog"`
	RepairBacklog          int      `json:"repair_backlog"`
	DrainActive            bool     `json:"drain_active"`
	AuthResidual           string   `json:"auth_residual,omitempty"`
	LocalHealthy           bool     `json:"local_healthy"`
	ReplicaHealthy         bool     `json:"replica_healthy"`
	Residuals              []string `json:"residuals,omitempty"`
	// MetricsAvailable is true when a non-nil metrics bag was supplied.
	MetricsAvailable bool `json:"metrics_available"`
}

// MemberCacheView is one roster member's cache-plane observation (FLC-062).
// MemberID is an operator id (not a secret). Residual must stay secret-free.
type MemberCacheView struct {
	MemberID   string
	ProtocolOK bool
	Reachable  bool
	Residual   string
}

// StatusOptions supplies optional operator/runtime inputs for BuildFleetCacheStatus.
// Zero values mean defaults; negative backlogs/object counts clamp to 0.
type StatusOptions struct {
	// PlacementEpoch is optional placement generation (0 omitted in status).
	PlacementEpoch int64
	// ImportBacklog / RepairBacklog are operator-observed queue depths (not secret).
	ImportBacklog int
	RepairBacklog int
	// DrainActive when this member is draining (refuse new primary).
	DrainActive bool
	// AuthResidual overrides default peer-auth residual (scrubbed).
	AuthResidual string
	// LocalHealthy overrides local plane health; nil → true.
	LocalHealthy *bool
	// UnderReplicatedObjects overrides metrics-derived under-replication count; nil → metrics/0.
	UnderReplicatedObjects *int
	// MaxResiduals bounds Residuals (0 → DefaultMaxStatusResiduals).
	MaxResiduals int
}

// DoctorCheck is one secret-free fleet-cache doctor result (FLC-062).
// Pure fleetcache type — not diagnostics.Check (admin/CLI wire is FLC-063).
type DoctorCheck struct {
	Name     string `json:"name"`
	OK       bool   `json:"ok"`
	Residual string `json:"residual,omitempty"`
}

// BuildFleetCacheStatus builds a bounded operator status from config, optional
// process-local metrics, and member views. Unreachable / incompatible members
// remain visible as counts + residuals (never disappear).
func BuildFleetCacheStatus(cfg Config, metrics *FleetCacheMetrics, members []MemberCacheView, opts StatusOptions) FleetCacheStatus {
	mode := cfg.Mode
	if mode == "" {
		mode = ModeOff
	}

	localHealthy := true
	if opts.LocalHealthy != nil {
		localHealthy = *opts.LocalHealthy
	}

	maxRes := opts.MaxResiduals
	if maxRes <= 0 {
		maxRes = DefaultMaxStatusResiduals
	}

	eligible := len(members)
	compatible := 0
	incompatible := 0
	unreachable := 0
	var rawResiduals []string

	// Mode honesty residual first.
	if mode == ModeOff {
		rawResiduals = append(rawResiduals, "mode_default_off; peer plane inactive")
	}

	// Aggregation residual always noted (process-local honesty).
	rawResiduals = append(rawResiduals, MetricsAggregationResidual)

	for _, m := range members {
		if m.ProtocolOK {
			compatible++
		} else {
			incompatible++
			id := scrubMemberID(m.MemberID)
			rawResiduals = append(rawResiduals, fmt.Sprintf("incompatible_protocol member=%s", id))
		}
		if !m.Reachable {
			unreachable++
			id := scrubMemberID(m.MemberID)
			rawResiduals = append(rawResiduals, fmt.Sprintf("unreachable_peer member=%s", id))
		}
		if r := strings.TrimSpace(m.Residual); r != "" {
			rawResiduals = append(rawResiduals, scrubSecretFree(r))
		}
	}

	under := 0
	if opts.UnderReplicatedObjects != nil {
		under = *opts.UnderReplicatedObjects
	} else if metrics != nil {
		snap := metrics.Snapshot()
		req := snap[MetricRFRequired]
		healthy := snap[MetricRFHealthy]
		if req > healthy {
			under = int(req - healthy)
		}
	}
	if under < 0 {
		under = 0
	}
	if under > 0 {
		rawResiduals = append(rawResiduals, fmt.Sprintf("under_replicated objects=%d", under))
	}

	importBacklog := opts.ImportBacklog
	if importBacklog < 0 {
		importBacklog = 0
	}
	repairBacklog := opts.RepairBacklog
	if repairBacklog < 0 {
		repairBacklog = 0
	}
	if importBacklog > 0 {
		rawResiduals = append(rawResiduals, fmt.Sprintf("import_backlog=%d", importBacklog))
	}
	if repairBacklog > 0 {
		rawResiduals = append(rawResiduals, fmt.Sprintf("repair_backlog=%d", repairBacklog))
	}
	if opts.DrainActive {
		rawResiduals = append(rawResiduals, "drain_active")
	}

	authResidual := strings.TrimSpace(opts.AuthResidual)
	if authResidual == "" {
		authResidual = AuthResidualDefault
	}
	authResidual = scrubSecretFree(authResidual)
	if authResidual != "" {
		rawResiduals = append(rawResiduals, "auth: "+authResidual)
	}

	if !localHealthy {
		rawResiduals = append(rawResiduals, "local_cache_unhealthy")
	}

	// ReplicaHealthy: false if under-replicated or unreachable owners (acceptance).
	// Mode-off with no peers remains replica-healthy (no fleet RF expectation).
	replicaHealthy := under == 0 && unreachable == 0

	st := FleetCacheStatus{
		Mode:                   string(mode),
		Active:                 cfg.Active(),
		PeerReadHandlersLive:   cfg.PeerReadHandlersLive(),
		Aggregation:            MetricsAggregationResidual,
		Protocol:               ProtocolVersionV1,
		PlacementEpoch:         opts.PlacementEpoch,
		EligibleMembers:        eligible,
		CompatibleMembers:      compatible,
		IncompatibleMembers:    incompatible,
		UnreachableMembers:     unreachable,
		UnderReplicatedObjects: under,
		ImportBacklog:          importBacklog,
		RepairBacklog:          repairBacklog,
		DrainActive:            opts.DrainActive,
		AuthResidual:           authResidual,
		LocalHealthy:           localHealthy,
		ReplicaHealthy:         replicaHealthy,
		Residuals:              BoundResiduals(rawResiduals, maxRes),
		MetricsAvailable:       metrics != nil,
	}
	return st
}

// BoundResiduals returns at most max secret-free residual strings.
// Empty/whitespace entries are dropped; max<=0 uses DefaultMaxStatusResiduals.
func BoundResiduals(in []string, max int) []string {
	if max <= 0 {
		max = DefaultMaxStatusResiduals
	}
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, min(len(in), max))
	for _, s := range in {
		s = scrubSecretFree(strings.TrimSpace(s))
		if s == "" {
			continue
		}
		// Cap individual residual length (no raw log bodies).
		const maxOne = 256
		if len(s) > maxOne {
			s = s[:maxOne]
		}
		out = append(out, s)
		if len(out) >= max {
			break
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// DoctorFleetCache returns stable secret-free doctor checks for fleet-cache (FLC-062).
// Failures: protocol_compat, unreachable_peers, under_replication (when counts > 0).
// Honesty residuals: mode_default_off, aggregation_process_local, metrics_available.
func DoctorFleetCache(cfg Config, st FleetCacheStatus) []DoctorCheck {
	mode := cfg.Mode
	if mode == "" {
		mode = ModeOff
	}
	// Prefer status mode when non-empty (already resolved).
	if st.Mode != "" {
		mode = Mode(st.Mode)
	}

	checks := make([]DoctorCheck, 0, 6)

	// mode_default_off: honesty — ok always; residual names default-off when off.
	modeRes := "mode=" + string(mode)
	if mode == ModeOff {
		modeRes = "mode_default_off; fleet-cache peer plane inactive"
	}
	checks = append(checks, DoctorCheck{
		Name:     DoctorModeDefaultOff,
		OK:       true,
		Residual: scrubSecretFree(modeRes),
	})

	// protocol_compat: fail when any incompatible peers.
	protoOK := st.IncompatibleMembers == 0
	protoRes := "compatible_members=" + itoa(st.CompatibleMembers)
	if !protoOK {
		protoRes = fmt.Sprintf("incompatible_members=%d residual=mixed_version_or_protocol", st.IncompatibleMembers)
	}
	checks = append(checks, DoctorCheck{
		Name:     DoctorProtocolCompat,
		OK:       protoOK,
		Residual: scrubSecretFree(protoRes),
	})

	// unreachable_peers: fail when any unreachable (visible residual, not drop).
	unreachOK := st.UnreachableMembers == 0
	unreachRes := "unreachable_members=0"
	if !unreachOK {
		unreachRes = fmt.Sprintf("unreachable_members=%d residual=peers_not_disappeared", st.UnreachableMembers)
	}
	checks = append(checks, DoctorCheck{
		Name:     DoctorUnreachablePeers,
		OK:       unreachOK,
		Residual: scrubSecretFree(unreachRes),
	})

	// under_replication
	underOK := st.UnderReplicatedObjects == 0
	underRes := "under_replicated_objects=0"
	if !underOK {
		underRes = fmt.Sprintf("under_replicated_objects=%d", st.UnderReplicatedObjects)
	}
	checks = append(checks, DoctorCheck{
		Name:     DoctorUnderReplication,
		OK:       underOK,
		Residual: scrubSecretFree(underRes),
	})

	// aggregation_process_local: always noted residual; check ok (honesty, not failure).
	checks = append(checks, DoctorCheck{
		Name:     DoctorAggregationProcessLocal,
		OK:       true,
		Residual: scrubSecretFree(MetricsAggregationResidual),
	})

	// metrics_available
	metricsOK := st.MetricsAvailable
	metricsRes := "metrics_available"
	if !metricsOK {
		metricsRes = "metrics_unavailable residual=process_local_registry_not_supplied"
	}
	checks = append(checks, DoctorCheck{
		Name:     DoctorMetricsAvailable,
		OK:       metricsOK,
		Residual: scrubSecretFree(metricsRes),
	})

	return checks
}

// Map returns a secret-free operator map suitable for StatusSummary nesting / JSON.
func (st FleetCacheStatus) Map() map[string]any {
	m := map[string]any{
		"mode":                     st.Mode,
		"active":                   st.Active,
		"peer_read_handlers_live":  st.PeerReadHandlersLive,
		"aggregation":              st.Aggregation,
		"protocol":                 st.Protocol,
		"eligible_members":         st.EligibleMembers,
		"compatible_members":       st.CompatibleMembers,
		"incompatible_members":     st.IncompatibleMembers,
		"unreachable_members":      st.UnreachableMembers,
		"under_replicated_objects": st.UnderReplicatedObjects,
		"import_backlog":           st.ImportBacklog,
		"repair_backlog":           st.RepairBacklog,
		"drain_active":             st.DrainActive,
		"local_healthy":            st.LocalHealthy,
		"replica_healthy":          st.ReplicaHealthy,
		"metrics_available":        st.MetricsAvailable,
	}
	if st.PlacementEpoch != 0 {
		m["placement_epoch"] = st.PlacementEpoch
	}
	if st.AuthResidual != "" {
		m["auth_residual"] = st.AuthResidual
	}
	if len(st.Residuals) > 0 {
		// Defensive copy.
		res := make([]string, len(st.Residuals))
		copy(res, st.Residuals)
		m["residuals"] = res
	}
	return m
}

func scrubMemberID(id string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		return "unknown"
	}
	// Member IDs are operator labels; still scrub secret-shaped values.
	return scrubSecretFree(id)
}

func itoa(n int) string {
	return fmt.Sprintf("%d", n)
}
