package fleetmcp

import (
	"encoding/json"
	"net/url"
	"os"
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// RosterSchemaVersion is the supported roster.json schema_version.
const RosterSchemaVersion = 1

// MaxRosterMembers is the absolute fail-closed cap on fleet size.
const MaxRosterMembers = 64

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
	}
	return nil
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
