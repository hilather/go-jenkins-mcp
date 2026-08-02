package fleetmcp

import (
	"time"
)

// Collection identifies a fleet read collection.
type Collection string

const (
	CollectionMembers  Collection = "members"
	CollectionHealth   Collection = "health"
	CollectionVersion  Collection = "version"
	CollectionMetrics  Collection = "metrics"
	CollectionResidual Collection = "residual-status"
	CollectionDoctor   Collection = "doctor"
	CollectionCache    Collection = "cache-status"
)

// MemberResult is one member's contribution to a fleet aggregate.
type MemberResult struct {
	ID        string `json:"id"`
	Source    string `json:"source"` // local | peer
	OK        bool   `json:"ok"`
	LatencyMS int64  `json:"latency_ms,omitempty"`
	ErrorCode string `json:"error_code,omitempty"`
	Residual  string `json:"residual,omitempty"`
	// Payload is secret-free collection-specific data.
	Payload any `json:"payload,omitempty"`
}

// AggregateEnvelope is the common fleet_* tool result shape.
type AggregateEnvelope struct {
	Schema           string         `json:"schema"`
	Collection       string         `json:"collection"`
	FleetID          string         `json:"fleet_id"`
	CoordinatorID    string         `json:"coordinator_id"`
	RosterBundleSeq  int            `json:"roster_bundle_seq,omitempty"`
	QueriedAt        string         `json:"queried_at"`
	Members          []MemberResult `json:"members"`
	Summary          AggregateSummary `json:"summary"`
	Aggregate        map[string]any `json:"aggregate,omitempty"`
	Incomplete       bool           `json:"incomplete"`
	ResidualNotes    []string       `json:"residual_notes,omitempty"`
	NotMultiPodHA    bool           `json:"not_multi_pod_ha"`
}

// AggregateSummary is count honesty.
type AggregateSummary struct {
	MembersTotal  int `json:"members_total"`
	MembersOK     int `json:"members_ok"`
	MembersFailed int `json:"members_failed"`
}

// BuildEnvelope assembles the secret-free aggregate from member rows.
func BuildEnvelope(cfg Config, collection Collection, members []MemberResult, aggregate map[string]any) AggregateEnvelope {
	fleetID := ""
	seq := 0
	if cfg.Roster != nil {
		fleetID = cfg.Roster.FleetID
		seq = cfg.Roster.BundleSeq
	}
	ok, fail := 0, 0
	for _, m := range members {
		if m.OK {
			ok++
		} else {
			fail++
		}
	}
	incomplete := fail > 0
	notes := []string{
		"request-time fan-out across independent multi-fleet members; not multi-pod HA",
	}
	if incomplete {
		notes = append(notes, "partial fleet view; do not treat missing members as healthy")
	}
	return AggregateEnvelope{
		Schema:          "jenkins-mcp.fleet-aggregate.v1",
		Collection:      string(collection),
		FleetID:         fleetID,
		CoordinatorID:   cfg.MemberID,
		RosterBundleSeq: seq,
		QueriedAt:       time.Now().UTC().Format(time.RFC3339Nano),
		Members:         members,
		Summary: AggregateSummary{
			MembersTotal:  len(members),
			MembersOK:     ok,
			MembersFailed: fail,
		},
		Aggregate:     aggregate,
		Incomplete:    incomplete,
		ResidualNotes: notes,
		NotMultiPodHA: true,
	}
}

// AllowlistedMetricsCounters may be summed in aggregate (optional lite).
var AllowlistedMetricsCounters = []string{
	"tool_calls",
	"mcp_tool_ok",
	"mcp_tool_error",
	"mcp_tool_deny",
	"jenkins_http_requests_total",
	"jenkins_http_errors_total",
}

// SumAllowlistedCounters sums matching counter keys from successful metrics payloads.
func SumAllowlistedCounters(members []MemberResult) map[string]int64 {
	sums := make(map[string]int64)
	for _, m := range members {
		if !m.OK || m.Payload == nil {
			continue
		}
		pl, ok := m.Payload.(map[string]any)
		if !ok {
			continue
		}
		counters, _ := pl["counters"].(map[string]int64)
		if counters == nil {
			// JSON round-trip may yield map[string]any
			if raw, ok := pl["counters"].(map[string]any); ok {
				counters = make(map[string]int64, len(raw))
				for k, v := range raw {
					switch n := v.(type) {
					case int64:
						counters[k] = n
					case float64:
						counters[k] = int64(n)
					case int:
						counters[k] = int64(n)
					}
				}
			}
		}
		if counters == nil {
			continue
		}
		for _, name := range AllowlistedMetricsCounters {
			if v, ok := counters[name]; ok {
				sums[name] += v
			}
		}
	}
	if len(sums) == 0 {
		return nil
	}
	return sums
}
