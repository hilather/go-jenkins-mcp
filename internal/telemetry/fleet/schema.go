package fleet

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"runtime"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/telemetry"
)

// SchemaVersion is the fleet health event schema version.
const SchemaVersion = 1

// EventTypeHealthSnapshot is the only MVP event type (aggregate counters).
const EventTypeHealthSnapshot = "health_snapshot"

// Auth method enums allowed in export (low cardinality; no secrets).
const (
	AuthMethodAPIToken           = "api_token"
	AuthMethodOIDCBearer         = "oidc_bearer"
	AuthMethodAgentCoreDelegated = "agentcore_delegated"
	AuthMethodLegacy             = "legacy"
	AuthMethodUnknown            = "unknown"
)

// ErrorCodeMetricPrefix prefixes per-code error counters in Metrics
// (e.g. "error:timeout"). Only stable apperr codes are exported.
const ErrorCodeMetricPrefix = "error:"

// Max lengths for string fields on the wire (reject/clamp at sanitize+validate).
// Keeps export low-cardinality and blocks free-text / secret dumps.
const (
	MaxVersionLen        = 64
	MaxInstallationIDLen = 64
	MaxOSLen             = 32
	MaxArchLen           = 32
	MaxAuthMethodLen     = 32
	MaxEventTypeLen      = 64
	MaxProfileHashLen    = 64 // SHA-256 hex
	MaxTimestampLen      = 40 // RFC3339
	MaxCounterNameLen    = 64
	MaxErrorCodeKeyLen   = 64
)

// AllowedCounterNames is the closed set of counter names that may leave the host.
// Unknown counter keys are dropped at snapshot time (fail closed on free-form labels).
// Keep in sync with docs/observability.md and docs/security/fleet-telemetry.md.
var AllowedCounterNames = map[string]struct{}{
	telemetry.MetricToolCalls:                     {},
	telemetry.MetricMCPToolOK:                     {},
	telemetry.MetricMCPToolError:                  {},
	telemetry.MetricMCPToolDeny:                   {}, // also MetricPolicyDenials
	telemetry.MetricMCPSubjectRateQuota:           {}, // HOST-006 / OBS residual lite
	telemetry.MetricMCPSubjectSlotQuota:           {}, // HOST-006 / OBS residual lite
	telemetry.MetricJenkinsHTTPRequestsTotal:      {},
	telemetry.MetricJenkinsHTTPErrorsTotal:        {},
	telemetry.MetricJenkinsHTTPWireBytesTotal:     {},
	telemetry.MetricJenkinsHTTPDecodedBytesTotal:  {},
	telemetry.MetricJenkinsCircuitOpenEventsTotal: {},
	telemetry.MetricCacheHits:                     {},
	telemetry.MetricMCPBytesOut:                   {},
	telemetry.MetricDuplicateBytes:                {},
	telemetry.MetricCacheMaintTicks:               {},
	telemetry.MetricCacheEvictItems:               {},
	telemetry.MetricCacheEvictBytes:               {},
	telemetry.MetricCachePacksCreated:             {},
	telemetry.MetricCacheL1Released:               {},
	telemetry.MetricCacheL1ReleaseBytes:           {},
}

// AllowedJSONFields is the closed set of top-level JSON object keys for Event v1.
// Documented in docs/security/fleet-telemetry.md — keep in sync.
var AllowedJSONFields = []string{
	"schema_version",
	"event_type",
	"installation_id",
	"profile_id_hash",
	"version",
	"os",
	"arch",
	"auth_method",
	"read_only",
	"counters",
	"error_codes",
	"ts",
}

// ExportedCategories lists human-readable categories included in fleet export.
// Used by `jenkins-mcp telemetry status` for operator inspection (MGR-002).
var ExportedCategories = []string{
	"installation_id",
	"profile_id_hash",
	"version",
	"os",
	"arch",
	"auth_method",
	"read_only",
	"tool_call_counters",
	"policy_denials",
	"cache_hit_counters",
	"error_codes",
	"event_type",
	"schema_version",
	"timestamp",
}

// ForbiddenCategories are never exported (privacy canary surface).
var ForbiddenCategories = []string{
	"logs",
	"prompts",
	"tokens",
	"api_tokens",
	"oauth_refresh_tokens",
	"authorization_headers",
	"artifact_content",
	"raw_job_parameters",
	"job_log_text",
	"jenkins_urls_with_credentials",
	"free_text",
	"stack_traces_with_bodies",
}

// Event is a versioned, privacy-preserving fleet health payload.
// JSON field names are stable; do not rename without a schema bump.
//
// Allowed fields only (see AllowedJSONFields): version, os/arch (goos/goarch),
// auth_method enum, read_only bool, allowlisted counters, stable error_code class.
type Event struct {
	// SchemaVersion is always SchemaVersion for this binary.
	SchemaVersion int `json:"schema_version"`
	// EventType is "health_snapshot" for MVP aggregates.
	EventType string `json:"event_type"`
	// InstallationID is a random UUID stored once under XDG data (pseudonymous).
	InstallationID string `json:"installation_id"`
	// ProfileIDHash is optional SHA-256 hex of the profile id (not the raw id).
	ProfileIDHash string `json:"profile_id_hash,omitempty"`
	// Version is the binary version string (non-secret).
	Version string `json:"version"`
	// OS is runtime.GOOS.
	OS string `json:"os"`
	// Arch is runtime.GOARCH.
	Arch string `json:"arch"`
	// AuthMethod is a closed enum (api_token, oidc_bearer, …).
	AuthMethod string `json:"auth_method"`
	// ReadOnly is the effective global read-only gate (bool; low cardinality).
	ReadOnly bool `json:"read_only"`
	// Counters are allowlisted aggregate counters only.
	Counters map[string]int64 `json:"counters"`
	// ErrorCodes maps stable apperr.Code → count (empty keys / unknown codes dropped).
	ErrorCodes map[string]int64 `json:"error_codes,omitempty"`
	// Timestamp is RFC3339 UTC when the snapshot was taken.
	Timestamp string `json:"ts"`
}

// NormalizeAuthMethod maps a profile/auth method string to an export enum.
func NormalizeAuthMethod(m string) string {
	switch strings.TrimSpace(strings.ToLower(m)) {
	case AuthMethodAPIToken, "api-token", "apitoken":
		return AuthMethodAPIToken
	case AuthMethodOIDCBearer, "oidc", "oidc-bearer":
		return AuthMethodOIDCBearer
	case AuthMethodAgentCoreDelegated, "agentcore", "agentcore-delegated":
		return AuthMethodAgentCoreDelegated
	case AuthMethodLegacy:
		return AuthMethodLegacy
	case "":
		return AuthMethodUnknown
	default:
		// Unknown free-form values collapse to "unknown" (no high-cardinality labels).
		return AuthMethodUnknown
	}
}

// HashProfileID returns a hex SHA-256 of profileID, or empty when profileID is empty.
func HashProfileID(profileID string) string {
	id := strings.TrimSpace(profileID)
	if id == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:])
}

// BuildEvent constructs a health snapshot from metrics and process metadata.
// Only allowlisted counters and valid apperr error-code counters are included.
// The result is sanitized (field length caps, enum normalization).
func BuildEvent(opts BuildOptions) Event {
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	osName := opts.OS
	if osName == "" {
		osName = runtime.GOOS
	}
	arch := opts.Arch
	if arch == "" {
		arch = runtime.GOARCH
	}
	counters := filterCounters(opts.Counters)
	errorCodes := filterErrorCodes(opts.ErrorCodes)
	// Also pull error:* counters from the metrics bag when present.
	if opts.Counters != nil {
		for k, v := range opts.Counters {
			if !strings.HasPrefix(k, ErrorCodeMetricPrefix) || v <= 0 {
				continue
			}
			code := apperr.Code(strings.TrimPrefix(k, ErrorCodeMetricPrefix))
			if !code.Valid() {
				continue
			}
			if errorCodes == nil {
				errorCodes = make(map[string]int64)
			}
			errorCodes[string(code)] += v
		}
	}
	ev := Event{
		SchemaVersion:  SchemaVersion,
		EventType:      EventTypeHealthSnapshot,
		InstallationID: strings.TrimSpace(opts.InstallationID),
		ProfileIDHash:  HashProfileID(opts.ProfileID),
		Version:        strings.TrimSpace(opts.Version),
		OS:             osName,
		Arch:           arch,
		AuthMethod:     NormalizeAuthMethod(opts.AuthMethod),
		ReadOnly:       opts.ReadOnly,
		Counters:       counters,
		ErrorCodes:     errorCodes,
		Timestamp:      now.UTC().Format(time.RFC3339),
	}
	return SanitizeEvent(ev)
}

// BuildOptions supplies non-secret inputs for BuildEvent.
type BuildOptions struct {
	InstallationID string
	ProfileID      string // raw; hashed into Event.ProfileIDHash
	Version        string
	OS             string
	Arch           string
	AuthMethod     string
	ReadOnly       bool
	Counters       map[string]int64
	ErrorCodes     map[string]int64
	Now            time.Time
}

// SnapshotFromMetrics copies allowlisted counters from a telemetry.Metrics bag.
func SnapshotFromMetrics(m *telemetry.Metrics) map[string]int64 {
	if m == nil {
		return map[string]int64{}
	}
	snap := m.Snapshot()
	return filterCounters(snap.Counters)
}

// SanitizeEvent clamps string fields, re-filters maps, and normalizes enums.
// Call before enqueue/export so free-form or oversize values never leave the host.
func SanitizeEvent(e Event) Event {
	e.SchemaVersion = SchemaVersion
	e.EventType = clampString(EventTypeHealthSnapshot, MaxEventTypeLen)
	e.InstallationID = clampString(strings.TrimSpace(e.InstallationID), MaxInstallationIDLen)
	e.ProfileIDHash = clampString(strings.TrimSpace(e.ProfileIDHash), MaxProfileHashLen)
	// Profile hash must be hex SHA-256 or empty (drop smuggled free text).
	if e.ProfileIDHash != "" && !isHexSHA256(e.ProfileIDHash) {
		e.ProfileIDHash = ""
	}
	e.Version = clampString(strings.TrimSpace(e.Version), MaxVersionLen)
	e.OS = clampString(strings.TrimSpace(e.OS), MaxOSLen)
	e.Arch = clampString(strings.TrimSpace(e.Arch), MaxArchLen)
	e.AuthMethod = clampString(NormalizeAuthMethod(e.AuthMethod), MaxAuthMethodLen)
	e.Counters = filterCounters(e.Counters)
	e.ErrorCodes = filterErrorCodes(e.ErrorCodes)
	e.Timestamp = clampString(strings.TrimSpace(e.Timestamp), MaxTimestampLen)
	return e
}

func filterCounters(in map[string]int64) map[string]int64 {
	out := make(map[string]int64)
	if in == nil {
		return out
	}
	for k, v := range in {
		if len(k) > MaxCounterNameLen {
			continue
		}
		if _, ok := AllowedCounterNames[k]; !ok {
			continue
		}
		if v < 0 {
			continue
		}
		out[k] = v
	}
	return out
}

func filterErrorCodes(in map[string]int64) map[string]int64 {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]int64)
	for k, v := range in {
		k = strings.TrimSpace(k)
		if len(k) > MaxErrorCodeKeyLen {
			continue
		}
		code := apperr.Code(k)
		if !code.Valid() || v <= 0 {
			continue
		}
		out[string(code)] = v
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// MarshalEvent returns canonical JSON for a sanitized event.
func MarshalEvent(e Event) ([]byte, error) {
	e = SanitizeEvent(e)
	if err := validateEventFields(e); err != nil {
		return nil, err
	}
	return json.Marshal(e)
}

// ValidateExportJSON scans marshaled event JSON for schema + size violations.
// Returns an error when a canary-like leak surface or oversize field is detected
// (used in tests + belt-and-suspenders before enqueue/export).
func ValidateExportJSON(raw []byte) error {
	// Structural: must unmarshal as Event.
	var e Event
	if err := json.Unmarshal(raw, &e); err != nil {
		return err
	}
	// Reject unknown top-level keys (fail closed on schema expansion smuggling).
	var generic map[string]json.RawMessage
	if err := json.Unmarshal(raw, &generic); err != nil {
		return err
	}
	allowed := make(map[string]struct{}, len(AllowedJSONFields))
	for _, k := range AllowedJSONFields {
		allowed[k] = struct{}{}
	}
	for k := range generic {
		if _, ok := allowed[k]; !ok {
			return errString("export field not allowlisted: " + k)
		}
	}
	if err := validateEventFields(e); err != nil {
		return err
	}
	// Counters must only contain allowlisted names.
	for k := range e.Counters {
		if _, ok := AllowedCounterNames[k]; !ok {
			return errString("export counter not allowlisted: " + k)
		}
	}
	for k := range e.ErrorCodes {
		if !apperr.Code(k).Valid() {
			return errString("export error_code not stable apperr: " + k)
		}
	}
	return nil
}

func validateEventFields(e Event) error {
	if e.SchemaVersion != SchemaVersion {
		return errString("export schema_version mismatch")
	}
	if e.EventType != EventTypeHealthSnapshot {
		return errString("export event_type not approved")
	}
	if oversize(e.InstallationID, MaxInstallationIDLen) ||
		oversize(e.ProfileIDHash, MaxProfileHashLen) ||
		oversize(e.Version, MaxVersionLen) ||
		oversize(e.OS, MaxOSLen) ||
		oversize(e.Arch, MaxArchLen) ||
		oversize(e.AuthMethod, MaxAuthMethodLen) ||
		oversize(e.EventType, MaxEventTypeLen) ||
		oversize(e.Timestamp, MaxTimestampLen) {
		return errString("export string field exceeds max length")
	}
	if e.ProfileIDHash != "" && !isHexSHA256(e.ProfileIDHash) {
		return errString("export profile_id_hash invalid")
	}
	switch e.AuthMethod {
	case AuthMethodAPIToken, AuthMethodOIDCBearer, AuthMethodAgentCoreDelegated,
		AuthMethodLegacy, AuthMethodUnknown:
		// ok
	default:
		return errString("export auth_method not in enum")
	}
	for k := range e.Counters {
		if oversize(k, MaxCounterNameLen) {
			return errString("export counter name exceeds max length")
		}
	}
	for k := range e.ErrorCodes {
		if oversize(k, MaxErrorCodeKeyLen) {
			return errString("export error_code key exceeds max length")
		}
	}
	return nil
}

func oversize(s string, max int) bool {
	return utf8.RuneCountInString(s) > max
}

func clampString(s string, max int) string {
	if max <= 0 || s == "" {
		return s
	}
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	// Rune-safe truncate.
	n := 0
	for i := range s {
		if n == max {
			return s[:i]
		}
		n++
	}
	return s
}

func isHexSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// SortedCategories returns a copy of ExportedCategories sorted for stable CLI output.
func SortedCategories() []string {
	out := append([]string(nil), ExportedCategories...)
	sort.Strings(out)
	return out
}

// SortedAllowedJSONFields returns AllowedJSONFields sorted for docs/CLI.
func SortedAllowedJSONFields() []string {
	out := append([]string(nil), AllowedJSONFields...)
	sort.Strings(out)
	return out
}

type errString string

func (e errString) Error() string { return string(e) }
