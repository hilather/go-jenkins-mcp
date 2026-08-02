package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/audit"
)

// AuditSettingsResponse is GET /admin/v1/profiles/{id}/audit/settings (secret-free).
type AuditSettingsResponse struct {
	ProfileID string          `json:"profileId"`
	Types     []string        `json:"types"`   // catalog: KnownEventTypes
	Enabled   map[string]bool `json:"enabled"` // type → emit enabled
	PathNote  string          `json:"pathNote,omitempty"`
	Residual  string          `json:"residual,omitempty"`
}

// AuditSettingsPutRequest is PUT/POST body for audit type enable/disable.
type AuditSettingsPutRequest struct {
	// Enabled partial or full map of known types. Unknown keys ignored.
	Enabled map[string]bool `json:"enabled"`
}

// handleAuditSettingsGET returns the event-type catalog and enabled map.
func (s *server) handleAuditSettingsGET(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "invalid_argument", "method not allowed")
		return
	}
	id := r.PathValue("id")
	if err := ValidateProfileID(id); err != nil {
		writeAppErr(w, err)
		return
	}
	dataDir, err := s.profileDataDirForAudit(id)
	if err != nil {
		writeAppErr(w, err)
		return
	}
	f := audit.LoadTypeFilter(dataDir)
	writeJSON(w, http.StatusOK, AuditSettingsResponse{
		ProfileID: id,
		Types:     audit.KnownEventTypes(),
		Enabled:   f.EnabledMap(),
		PathNote:  "profile_data/audit/type_filter.json",
		Residual:  "type filter applies to File sink; serve reloads on mtime; multi-pod residual",
	})
}

// handleAuditSettingsPUT updates enabled types (requires gateway_ops: operator or policy_admin).
func (s *server) handleAuditSettingsPUT(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut && r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "invalid_argument", "method not allowed")
		return
	}
	if !CheckPermission(w, r, PermGatewayOps) {
		return
	}
	id := r.PathValue("id")
	if err := ValidateProfileID(id); err != nil {
		writeAppErr(w, err)
		return
	}
	var body AuditSettingsPutRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_argument", "invalid JSON body")
		return
	}
	if body.Enabled == nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_argument", "enabled map required")
		return
	}
	dataDir, err := s.profileDataDirForAudit(id)
	if err != nil {
		writeAppErr(w, err)
		return
	}
	cur := audit.LoadTypeFilter(dataDir).EnabledMap()
	for k, v := range body.Enabled {
		if !audit.IsKnownEventType(k) {
			continue
		}
		cur[k] = v
	}
	next := audit.NormalizeEnabled(cur)
	if err := audit.SaveTypeFilter(dataDir, next); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal", "failed to save audit settings")
		return
	}
	// Best-effort AUD-001: record that type filter changed. Bare File sink so
	// operators cannot hide this event by disabling audit_settings in the filter.
	// TargetHash is an opaque digest of the enabled map (no free-form type list).
	// Residual: no confirm token to disable security-critical types (operator trust).
	s.emitAuditSettingsChange(id, dataDir, next.EnabledMap())
	writeJSON(w, http.StatusOK, AuditSettingsResponse{
		ProfileID: id,
		Types:     audit.KnownEventTypes(),
		Enabled:   next.EnabledMap(),
		PathNote:  "profile_data/audit/type_filter.json",
		Residual:  "File sink reloads filter on mtime+size; multi-pod residual; no confirm to disable critical types",
	})
}

// emitAuditSettingsChange appends a secret-free audit_settings event (AUD-001).
func (s *server) emitAuditSettingsChange(profileID, profileDataDir string, enabled map[string]bool) {
	if strings.TrimSpace(profileDataDir) == "" {
		return
	}
	auditDir := filepath.Join(filepath.Clean(profileDataDir), "audit")
	if _, err := os.Stat(filepath.Clean(profileDataDir)); err != nil {
		return
	}
	sink, err := audit.NewFile(audit.FileConfig{Dir: auditDir})
	if err != nil {
		return
	}
	defer func() { _ = sink.Close() }()
	// Stable secret-free digest of enabled flags for forensics (not human type names).
	digestSrc := strings.Builder{}
	for _, k := range audit.SortedEnabledKeys(enabled) {
		digestSrc.WriteString(k)
		digestSrc.WriteByte('=')
		if enabled[k] {
			digestSrc.WriteByte('1')
		} else {
			digestSrc.WriteByte('0')
		}
		digestSrc.WriteByte(';')
	}
	_ = audit.Emit(context.Background(), sink, audit.Event{
		Time:       time.Now().UTC(),
		Type:       audit.TypeAuditSettings,
		ProfileID:  profileID,
		Action:     "audit_type_filter",
		Decision:   audit.DecisionSuccess,
		ReasonCode: "type_filter_updated",
		TargetHash: audit.HashOpaque(digestSrc.String()),
	})
}

func (s *server) profileDataDirForAudit(profileID string) (string, error) {
	var dataOverride string
	if p, err := s.loadProfile(profileID); err == nil && p != nil {
		dataOverride = strings.TrimSpace(p.DataDir)
	}
	paths, err := s.resolvePaths()
	if err != nil {
		return "", err
	}
	auditJSONL, err := ProfileAuditPath(paths, profileID, dataOverride)
	if err != nil {
		return "", err
	}
	// .../dataDir/audit/audit.jsonl → dataDir
	return filepath.Dir(filepath.Dir(auditJSONL)), nil
}
