package fleetmcp

import (
	"encoding/json"
	"net/url"
	"os"
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// RosterSchemaVersion is the supported roster.json schema_version.
// Cache eligibility fields are optional on v1 members (FLC-012); absent cache
// blocks keep operator fleet_* fan-out working with peer cache disabled.
const RosterSchemaVersion = 1

// MaxRosterMembers is the absolute fail-closed cap on fleet size.
const MaxRosterMembers = 64

// DefaultCacheCapacityWeight when cache.enabled and capacity_weight omitted/0.
const DefaultCacheCapacityWeight = 100

// MaxCacheCapacityWeight is the fail-closed upper bound for capacity_weight.
const MaxCacheCapacityWeight = 10000

// Roster is the gitops membership SoT (secret-free).
type Roster struct {
	SchemaVersion int            `json:"schema_version"`
	FleetID       string         `json:"fleet_id"`
	BundleSeq     int            `json:"bundle_seq,omitempty"`
	Members       []RosterMember `json:"members"`
}

// RosterMember is one independent multi-fleet process.
type RosterMember struct {
	ID          string            `json:"id"`
	DisplayName string            `json:"display_name,omitempty"`
	PeerURL     string            `json:"peer_url"`
	ProfileID   string            `json:"profile_id,omitempty"`
	Region      string            `json:"region,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	// Cache is optional FLC eligibility (ADR 0016). Nil/disabled → not a cache owner.
	Cache *MemberCache `json:"cache,omitempty"`
}

// MemberCache describes whether a member may store/serve fleet shared-cache objects.
// Secret-free; no credentials or data-dir paths.
type MemberCache struct {
	Enabled        bool     `json:"enabled"`
	ControllerID   string   `json:"controller_id,omitempty"`
	Pool           string   `json:"pool,omitempty"`
	CapacityWeight int      `json:"capacity_weight,omitempty"`
	FailureDomain  string   `json:"failure_domain,omitempty"`
	Draining       bool     `json:"draining,omitempty"`
	Protocols      []string `json:"protocols,omitempty"`
}

// LoadRosterFile reads and validates roster JSON from path.
func LoadRosterFile(path string) (*Roster, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, apperr.New(apperr.CodeInvalidArgument, "fleet roster path is empty")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeNotFound, "read fleet roster", err)
	}
	return ParseRoster(raw)
}

// ParseRoster validates roster JSON bytes (no secrets expected).
func ParseRoster(raw []byte) (*Roster, error) {
	if len(raw) == 0 {
		return nil, apperr.New(apperr.CodeInvalidArgument, "fleet roster is empty")
	}
	var r Roster
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, apperr.New(apperr.CodeInvalidArgument, "invalid fleet roster JSON")
	}
	if err := ValidateRoster(&r); err != nil {
		return nil, err
	}
	return &r, nil
}

// ValidateRoster enforces fail-closed membership rules.
func ValidateRoster(r *Roster) error {
	if r == nil {
		return apperr.New(apperr.CodeInvalidArgument, "fleet roster is nil")
	}
	if r.SchemaVersion != RosterSchemaVersion {
		return apperr.New(apperr.CodeInvalidArgument, "unsupported fleet roster schema_version")
	}
	if strings.TrimSpace(r.FleetID) == "" {
		return apperr.New(apperr.CodeInvalidArgument, "fleet_id is required")
	}
	if len(r.Members) == 0 {
		return apperr.New(apperr.CodeInvalidArgument, "fleet roster has no members")
	}
	if len(r.Members) > MaxRosterMembers {
		return apperr.New(apperr.CodeInvalidArgument, "fleet roster exceeds max members")
	}
	seen := make(map[string]struct{}, len(r.Members))
	for i := range r.Members {
		m := &r.Members[i]
		id := strings.TrimSpace(m.ID)
		if id == "" {
			return apperr.New(apperr.CodeInvalidArgument, "roster member id is required")
		}
		m.ID = id
		if _, ok := seen[id]; ok {
			return apperr.New(apperr.CodeInvalidArgument, "duplicate roster member id")
		}
		seen[id] = struct{}{}
		if err := validatePeerURL(m.PeerURL); err != nil {
			return err
		}
		m.PeerURL = strings.TrimSpace(m.PeerURL)
		// Labels: drop empty keys; never treat values as secrets here (caller canary).
		if len(m.Labels) > 0 {
			clean := make(map[string]string, len(m.Labels))
			for k, v := range m.Labels {
				k = strings.TrimSpace(k)
				if k == "" {
					continue
				}
				clean[k] = strings.TrimSpace(v)
			}
			m.Labels = clean
		}
		if err := validateMemberCache(m.Cache); err != nil {
			return err
		}
	}
	return nil
}

func validateMemberCache(c *MemberCache) error {
	if c == nil || !c.Enabled {
		// Disabled or absent: strip accidental empty enabled blocks to a clean nil-like state.
		if c != nil && !c.Enabled {
			// Allow disabled block without controller/pool (explicit opt-out).
			c.ControllerID = strings.TrimSpace(c.ControllerID)
			c.Pool = strings.TrimSpace(c.Pool)
			c.FailureDomain = strings.TrimSpace(c.FailureDomain)
		}
		return nil
	}
	c.ControllerID = strings.TrimSpace(c.ControllerID)
	c.Pool = strings.TrimSpace(c.Pool)
	c.FailureDomain = strings.TrimSpace(c.FailureDomain)
	if c.ControllerID == "" {
		return apperr.New(apperr.CodeInvalidArgument, "cache-enabled member requires controller_id")
	}
	if c.Pool == "" {
		return apperr.New(apperr.CodeInvalidArgument, "cache-enabled member requires pool")
	}
	if c.CapacityWeight < 0 {
		return apperr.New(apperr.CodeInvalidArgument, "cache capacity_weight must not be negative")
	}
	if c.CapacityWeight == 0 {
		c.CapacityWeight = DefaultCacheCapacityWeight
	}
	if c.CapacityWeight > MaxCacheCapacityWeight {
		return apperr.New(apperr.CodeInvalidArgument, "cache capacity_weight exceeds maximum")
	}
	if len(c.Protocols) == 0 {
		return apperr.New(apperr.CodeInvalidArgument, "cache-enabled member requires protocols (e.g. fleet-cache/1)")
	}
	cleanProto := make([]string, 0, len(c.Protocols))
	seen := make(map[string]struct{}, len(c.Protocols))
	for _, p := range c.Protocols {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		cleanProto = append(cleanProto, p)
	}
	if len(cleanProto) == 0 {
		return apperr.New(apperr.CodeInvalidArgument, "cache-enabled member requires non-empty protocols")
	}
	c.Protocols = cleanProto
	return nil
}

// CacheEligibleOptions controls CacheEligibleMembers filtering.
type CacheEligibleOptions struct {
	// Protocol required advertisement (e.g. fleet-cache/1). Empty → any protocol list non-empty.
	Protocol string
	// IncludeDraining keeps draining members (readable grace); default false excludes them from new ownership.
	IncludeDraining bool
}

// CacheEligibleMembers returns members that may own/serve objects for controller/pool.
// Members without cache.enabled are omitted (ops-only roster rows remain valid for fleet_*).
// Cross-controller or cross-pool members are never returned together for a single query.
func (r *Roster) CacheEligibleMembers(controllerID, pool string, opts CacheEligibleOptions) []RosterMember {
	if r == nil {
		return nil
	}
	controllerID = strings.TrimSpace(controllerID)
	pool = strings.TrimSpace(pool)
	if controllerID == "" || pool == "" {
		return nil
	}
	proto := strings.TrimSpace(opts.Protocol)
	out := make([]RosterMember, 0, len(r.Members))
	for _, m := range r.Members {
		c := m.Cache
		if c == nil || !c.Enabled {
			continue
		}
		if c.ControllerID != controllerID || c.Pool != pool {
			continue
		}
		if c.Draining && !opts.IncludeDraining {
			continue
		}
		if proto != "" && !memberHasProtocol(c, proto) {
			continue
		}
		if proto == "" && len(c.Protocols) == 0 {
			continue
		}
		out = append(out, m)
	}
	return out
}

func memberHasProtocol(c *MemberCache, want string) bool {
	if c == nil {
		return false
	}
	for _, p := range c.Protocols {
		if p == want {
			return true
		}
	}
	return false
}

func validatePeerURL(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return apperr.New(apperr.CodeInvalidArgument, "roster member peer_url is required")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return apperr.New(apperr.CodeInvalidArgument, "roster member peer_url is invalid")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return apperr.New(apperr.CodeInvalidArgument, "roster member peer_url must be http or https")
	}
	// Reject userinfo (credentials) in peer URLs — secret-free roster.
	if u.User != nil {
		return apperr.New(apperr.CodeInvalidArgument, "roster member peer_url must not contain credentials")
	}
	return nil
}

// MemberByID returns the member with id or nil.
func (r *Roster) MemberByID(id string) *RosterMember {
	if r == nil {
		return nil
	}
	id = strings.TrimSpace(id)
	for i := range r.Members {
		if r.Members[i].ID == id {
			return &r.Members[i]
		}
	}
	return nil
}

// PeerMembers returns members excluding selfID (for fan-out).
func (r *Roster) PeerMembers(selfID string) []RosterMember {
	if r == nil {
		return nil
	}
	selfID = strings.TrimSpace(selfID)
	out := make([]RosterMember, 0, len(r.Members))
	for _, m := range r.Members {
		if m.ID == selfID {
			continue
		}
		out = append(out, m)
	}
	return out
}
