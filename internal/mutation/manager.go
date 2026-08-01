package mutation

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/audit"
	"github.com/simonfxr/go-jenkins-mcp/internal/policy"
)

// Action identifies a mutation class (stable, low cardinality).
type Action string

const (
	ActionStartJob    Action = "start_job"
	ActionStopBuild   Action = "stop_build"
	ActionCancelQueue Action = "cancel_queue"
)

// DefaultTokenTTL is the confirmation window (MUT-001: expire quickly).
// Operator resolve path: empty/0/"0s" → default; cannot disable via 0
// (see ResolveTokenTTL / MinTokenTTL / AbsoluteMaxTokenTTL).
const DefaultTokenTTL = 2 * time.Minute

// DefaultMaxPreviewsPerMinute is the process-local Preview sliding-window limit
// when Config.MaxPreviewsPerMinute is 0 (MUT-001 rate limit).
const DefaultMaxPreviewsPerMinute = 30

// DefaultConfirmCooldown is the minimum wait after a successful Confirm before
// another Confirm for the same (profile, action, targetHash) is allowed when
// Config.ConfirmCooldown is 0 and no process live ConfirmCooldown() is set
// (MUT-001 cooldown). Operator resolve path: empty/0/"0s" → default; cannot
// disable via 0 (see ResolveConfirmCooldown / MinConfirmCooldown /
// AbsoluteMaxConfirmCooldown).
const DefaultConfirmCooldown = 5 * time.Second

// Audit event types (AUD-001 privacy-preserving).
const (
	TypePreview = "mutation_preview"
	TypeConfirm = "mutation_confirm"
	TypeDeny    = "mutation_deny"
)

// Reason codes (stable, non-secret).
const (
	ReasonPreviewOK          = "preview_ok"
	ReasonConfirmOK          = "confirm_ok"
	ReasonReadOnly           = "read_only"
	ReasonTokenMissing       = "token_missing"
	ReasonTokenUnknown       = "token_unknown"
	ReasonTokenExpired       = "token_expired"
	ReasonTokenReused        = "token_reused"
	ReasonTargetMismatch     = "target_mismatch"
	ReasonBindingMismatch    = "binding_mismatch"
	ReasonInvalidIntent      = "invalid_intent"
	ReasonPreviewRateLimited = "preview_rate_limited"
	ReasonConfirmCooldown    = "confirm_cooldown"
)

// Intent is the normalized mutation to preview or execute.
// Parameters may hold values for execution; never put them in audit events.
type Intent struct {
	Action        Action
	ToolName      string
	JobName       string
	BuildNumber   int
	QueueID       int            // cancel_queue only
	Parameters    map[string]any // nil for stop/cancel
	EndpointClass string
	// CurrentState is optional state shown in preview (e.g. "building", "queued").
	CurrentState string
}

// PreviewResult is the model-facing dry-run payload (no Jenkins write).
type PreviewResult struct {
	Status            string         `json:"status"` // always "preview"
	Action            string         `json:"action"`
	Tool              string         `json:"tool"`
	JobName           string         `json:"jobName,omitempty"`
	BuildNumber       int            `json:"buildNumber,omitempty"`
	QueueID           int            `json:"queueId,omitempty"`
	Parameters        map[string]any `json:"parameters,omitempty"` // redacted
	EndpointClass     string         `json:"endpointClass"`
	ConfirmationToken string         `json:"confirmationToken"`
	ExpiresAt         time.Time      `json:"expiresAt"`
	ExpiresInSeconds  int            `json:"expiresInSeconds"`
	TargetHash        string         `json:"targetHash"`
	CurrentState      string         `json:"currentState,omitempty"`
	Message           string         `json:"message"`
}

// BoundIntent is returned after a successful Confirm for a single execute.
type BoundIntent struct {
	Intent
	TokenID    string
	TargetHash string
	RequestID  string
}

// Config configures a Manager.
type Config struct {
	// Gate is the POL-001 read-only kill switch. Nil ⇒ fail-closed read-only.
	Gate *policy.ReadOnlyGate
	// Audit is optional (AUD-001).
	Audit audit.Sink
	// ProfileID / PrincipalID bind tokens (non-secret).
	ProfileID   string
	PrincipalID string
	// TTL for confirmation tokens. 0 or negative ⇒ process live TokenTTL()
	// when positive (serve SetTokenTTL after Resolve), else DefaultTokenTTL.
	// Operator ResolveTokenTTL never yields 0/disable (0 → default).
	TTL time.Duration
	// MaxPreviewsPerMinute is a process-local sliding 1-minute window on Preview
	// for this Manager. 0 ⇒ process live (SetMaxPreviewsPerMinute) if positive,
	// else DefaultMaxPreviewsPerMinute; negative ⇒ unlimited (library/tests only;
	// operator ResolveMaxPreviewsPerMinute never yields unlimited).
	MaxPreviewsPerMinute int
	// ConfirmCooldown is the minimum time after a successful Confirm before
	// another Confirm for the same (profile, action, targetHash) may succeed.
	// 0 ⇒ process live ConfirmCooldown() when positive (serve SetConfirmCooldown
	// after Resolve), else DefaultConfirmCooldown; negative ⇒ off (library/test
	// escape hatch — operator ResolveConfirmCooldown cannot set 0/disable).
	ConfirmCooldown time.Duration
	// Now is optional clock for tests.
	Now func() time.Time
}

// Manager is the process-local preview/confirm gate (MUT-001).
// Safe for concurrent use.
type Manager struct {
	gate              *policy.ReadOnlyGate
	audit             audit.Sink
	profileID         string
	principalID       string
	ttl               time.Duration
	maxPreviewsPerMin int           // negative ⇒ unlimited
	confirmCooldown   time.Duration // ≤0 ⇒ off
	now               func() time.Time

	mu           sync.Mutex
	tokens       map[string]*tokenRecord
	previewTimes []time.Time          // sliding window timestamps
	cooldowns    map[string]time.Time // key → not-before (until) for next confirm
}

type tokenRecord struct {
	id         string
	profileID  string
	principal  string
	action     Action
	toolName   string
	jobName    string
	buildNum   int
	queueID    int
	params     map[string]any
	endpoint   string
	targetHash string
	expiresAt  time.Time
	used       bool
}

// NewManager builds a Manager. Zero rate/cooldown fields take production defaults
// (see DefaultMaxPreviewsPerMinute / DefaultConfirmCooldown); negative disables
// the corresponding limit. Zero/negative TTL prefers process live TokenTTL()
// when positive, else DefaultTokenTTL (no unlimited/disabled TTL path).
//
// When Config.MaxPreviewsPerMinute == 0, the process live value from
// SetMaxPreviewsPerMinute is used when positive; otherwise DefaultMaxPreviewsPerMinute.
// When Config.ConfirmCooldown is 0, NewManager prefers the process-level live
// ConfirmCooldown() if set positive (serve calls SetConfirmCooldown after
// ResolveConfirmCooldown), else DefaultConfirmCooldown. When Config.TTL ≤ 0,
// NewManager prefers process live TokenTTL() if set positive (serve calls
// SetTokenTTL after ResolveTokenTTL), else DefaultTokenTTL. Operator resolve
// never yields unlimited rate, disabled cooldown, or disabled/infinite TTL
// (0 → default on those paths).
func NewManager(cfg Config) *Manager {
	ttl := cfg.TTL
	if ttl <= 0 {
		// Wave 53 Track A: honor serve process live after Resolve+Set; else default.
		if live := TokenTTL(); live > 0 {
			ttl = live
		} else {
			ttl = DefaultTokenTTL
		}
	}
	maxPrev := cfg.MaxPreviewsPerMinute
	if maxPrev == 0 {
		// Wave 52 Track C: honor serve process live after Resolve+Set; else default.
		if live := int(processMaxPreviewsPerMinute.Load()); live > 0 {
			maxPrev = live
		} else {
			maxPrev = DefaultMaxPreviewsPerMinute
		}
	}
	// maxPrev < 0 ⇒ unlimited (stored as-is; library/tests only).

	cooldown := cfg.ConfirmCooldown
	if cooldown == 0 {
		// Wave 52 Track A: honor serve process live after Resolve+Set; else default.
		if live := ConfirmCooldown(); live > 0 {
			cooldown = live
		} else {
			cooldown = DefaultConfirmCooldown
		}
	}
	if cooldown < 0 {
		cooldown = 0 // off (library/test escape hatch)
	}
	now := cfg.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	gate := cfg.Gate
	if gate == nil {
		gate = policy.NewDefaultReadOnlyGate()
	}
	return &Manager{
		gate:              gate,
		audit:             cfg.Audit,
		profileID:         strings.TrimSpace(cfg.ProfileID),
		principalID:       strings.TrimSpace(cfg.PrincipalID),
		ttl:               ttl,
		maxPreviewsPerMin: maxPrev,
		confirmCooldown:   cooldown,
		now:               now,
		tokens:            make(map[string]*tokenRecord),
		cooldowns:         make(map[string]time.Time),
	}
}

// Preview validates the intent, creates a short-lived confirmation token, and
// returns a dry-run description without executing the Jenkins write.
// Fails closed when read-only is effective.
func (m *Manager) Preview(ctx context.Context, intent Intent) (*PreviewResult, error) {
	if m == nil {
		return nil, apperr.New(apperr.CodePolicyDenial, "mutation manager not configured")
	}
	start := m.now()
	tool := strings.TrimSpace(intent.ToolName)
	if tool == "" {
		tool = toolForAction(intent.Action)
	}
	if err := m.gate.DenyMutation(tool); err != nil {
		m.emitDeny(ctx, tool, string(intent.Action), ReasonReadOnly, "", start)
		return nil, err
	}
	norm, err := normalizeIntent(intent)
	if err != nil {
		m.emitDeny(ctx, tool, string(intent.Action), ReasonInvalidIntent, "", start)
		return nil, err
	}
	paramFP := ParamFingerprint(norm.Parameters)
	th := TargetHash(norm.Action, norm.JobName, norm.BuildNumber, norm.QueueID, paramFP)
	if err := m.reservePreview(start); err != nil {
		m.emitDeny(ctx, tool, string(norm.Action), ReasonPreviewRateLimited, th, start)
		return nil, err
	}
	tok, exp, err := m.issueToken(norm, th, start)
	if err != nil {
		m.emitDeny(ctx, tool, string(norm.Action), ReasonInvalidIntent, th, start)
		return nil, err
	}
	m.emit(ctx, audit.Event{
		Time:        start,
		Type:        TypePreview,
		ProfileID:   m.profileID,
		PrincipalID: m.principalID,
		Tool:        tool,
		Action:      string(norm.Action),
		Decision:    audit.DecisionAllow,
		ReasonCode:  ReasonPreviewOK,
		TargetHash:  th,
		Duration:    m.now().Sub(start),
	})
	secs := int(m.ttl.Seconds())
	if secs < 1 {
		secs = 1
	}
	return &PreviewResult{
		Status:            "preview",
		Action:            string(norm.Action),
		Tool:              tool,
		JobName:           norm.JobName,
		BuildNumber:       norm.BuildNumber,
		QueueID:           norm.QueueID,
		Parameters:        RedactParams(norm.Parameters),
		EndpointClass:     norm.EndpointClass,
		ConfirmationToken: tok,
		ExpiresAt:         exp,
		ExpiresInSeconds:  secs,
		TargetHash:        th,
		CurrentState:      norm.CurrentState,
		Message:           "Confirmation required: re-invoke with confirmation_token to execute. Token is single-use and short-lived.",
	}, nil
}

// Confirm validates a single-use token bound to profile+subject+action+target.
// expected must match the token's target hash (wrong job/params/action denied).
// On success the token is consumed and BoundIntent is returned for one execute.
// Fails closed when read-only is effective — even with a previously issued token.
func (m *Manager) Confirm(ctx context.Context, token string, expected Intent) (*BoundIntent, error) {
	if m == nil {
		return nil, apperr.New(apperr.CodePolicyDenial, "mutation manager not configured")
	}
	start := m.now()
	tool := strings.TrimSpace(expected.ToolName)
	if tool == "" {
		tool = toolForAction(expected.Action)
	}
	// POL-001: RO blocks even with a valid token.
	if err := m.gate.DenyMutation(tool); err != nil {
		m.emitDeny(ctx, tool, string(expected.Action), ReasonReadOnly, "", start)
		return nil, err
	}
	token = strings.TrimSpace(token)
	if token == "" {
		m.emitDeny(ctx, tool, string(expected.Action), ReasonTokenMissing, "", start)
		return nil, apperr.New(apperr.CodeInvalidArgument, "confirmation_token is required to execute a mutation")
	}
	norm, err := normalizeIntent(expected)
	if err != nil {
		m.emitDeny(ctx, tool, string(expected.Action), ReasonInvalidIntent, "", start)
		return nil, err
	}
	paramFP := ParamFingerprint(norm.Parameters)
	wantHash := TargetHash(norm.Action, norm.JobName, norm.BuildNumber, norm.QueueID, paramFP)

	m.mu.Lock()
	rec, ok := m.tokens[token]
	if !ok {
		m.mu.Unlock()
		m.emitDeny(ctx, tool, string(norm.Action), ReasonTokenUnknown, wantHash, start)
		return nil, apperr.New(apperr.CodePolicyDenial, "confirmation token is unknown or already discarded")
	}
	// Copy fields under lock, then decide.
	if rec.used {
		m.mu.Unlock()
		m.emitDeny(ctx, tool, string(norm.Action), ReasonTokenReused, rec.targetHash, start)
		return nil, apperr.New(apperr.CodePolicyDenial, "confirmation token has already been used")
	}
	if !start.Before(rec.expiresAt) {
		// Drop expired token.
		delete(m.tokens, token)
		m.mu.Unlock()
		m.emitDeny(ctx, tool, string(norm.Action), ReasonTokenExpired, rec.targetHash, start)
		return nil, apperr.New(apperr.CodePolicyDenial, "confirmation token has expired; request a new preview")
	}
	if rec.profileID != m.profileID || rec.principal != m.principalID {
		m.mu.Unlock()
		m.emitDeny(ctx, tool, string(norm.Action), ReasonBindingMismatch, rec.targetHash, start)
		return nil, apperr.New(apperr.CodePolicyDenial, "confirmation token is not bound to this profile/subject")
	}
	if rec.action != norm.Action || rec.targetHash != wantHash {
		m.mu.Unlock()
		m.emitDeny(ctx, tool, string(norm.Action), ReasonTargetMismatch, rec.targetHash, start)
		return nil, apperr.New(apperr.CodePolicyDenial, "confirmation token does not match the requested target/parameters")
	}
	// MUT-001: cooldown after successful confirm for same (profile, action, targetHash).
	// Checked before single-use consume so a denied confirm leaves the token usable.
	cdKey := m.cooldownKey(norm.Action, wantHash)
	if m.confirmCooldown > 0 {
		if until, ok := m.cooldowns[cdKey]; ok && start.Before(until) {
			m.mu.Unlock()
			m.emitDeny(ctx, tool, string(norm.Action), ReasonConfirmCooldown, wantHash, start)
			return nil, apperr.New(apperr.CodePolicyDenial, "mutation confirm cooldown active for this target; retry later")
		}
	}
	// Single-use: mark consumed before unlock (race-safe).
	rec.used = true
	// Prefer stored params (authoritative for execute).
	params := cloneParams(rec.params)
	bound := &BoundIntent{
		Intent: Intent{
			Action:        rec.action,
			ToolName:      rec.toolName,
			JobName:       rec.jobName,
			BuildNumber:   rec.buildNum,
			QueueID:       rec.queueID,
			Parameters:    params,
			EndpointClass: rec.endpoint,
		},
		TokenID:    rec.id,
		TargetHash: rec.targetHash,
		RequestID:  rec.id,
	}
	// Remove after use to prevent map growth; used flag already set.
	delete(m.tokens, token)
	if m.confirmCooldown > 0 {
		m.cooldowns[cdKey] = start.Add(m.confirmCooldown)
		m.purgeCooldownsLocked(start)
	}
	m.mu.Unlock()

	m.emit(ctx, audit.Event{
		Time:        start,
		Type:        TypeConfirm,
		ProfileID:   m.profileID,
		PrincipalID: m.principalID,
		Tool:        tool,
		Action:      string(bound.Action),
		Decision:    audit.DecisionAllow,
		ReasonCode:  ReasonConfirmOK,
		TargetHash:  bound.TargetHash,
		RequestID:   bound.RequestID,
		Duration:    m.now().Sub(start),
	})
	return bound, nil
}

// EmitExecuteFail records a post-confirm Jenkins failure (no secrets).
func (m *Manager) EmitExecuteFail(ctx context.Context, tool, action, reason, targetHash string) {
	if m == nil {
		return
	}
	m.emit(ctx, audit.Event{
		Time:        m.now(),
		Type:        TypeDeny,
		ProfileID:   m.profileID,
		PrincipalID: m.principalID,
		Tool:        tool,
		Action:      action,
		Decision:    audit.DecisionFail,
		ReasonCode:  reason,
		TargetHash:  targetHash,
	})
}

// EmitExecuteOK records a successful mutation execute summary (no secrets).
func (m *Manager) EmitExecuteOK(ctx context.Context, tool, action, targetHash, requestID string) {
	if m == nil {
		return
	}
	m.emit(ctx, audit.Event{
		Time:        m.now(),
		Type:        audit.TypeToolSuccess,
		ProfileID:   m.profileID,
		PrincipalID: m.principalID,
		Tool:        tool,
		Action:      action,
		Decision:    audit.DecisionSuccess,
		ReasonCode:  "execute_ok",
		TargetHash:  targetHash,
		RequestID:   requestID,
	})
}

// reservePreview records a Preview attempt under the sliding 1-minute window.
// Returns CodeThrottled when the limit is exceeded.
func (m *Manager) reservePreview(now time.Time) error {
	if m == nil || m.maxPreviewsPerMin < 0 {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cutoff := now.Add(-time.Minute)
	// Compact in place: keep timestamps strictly after cutoff.
	kept := m.previewTimes[:0]
	for _, t := range m.previewTimes {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	m.previewTimes = kept
	if len(m.previewTimes) >= m.maxPreviewsPerMin {
		return apperr.New(apperr.CodeThrottled, "mutation preview rate limited; retry later")
	}
	m.previewTimes = append(m.previewTimes, now)
	return nil
}

func (m *Manager) cooldownKey(action Action, targetHash string) string {
	// Include profile so a shared process store cannot cross profile boundaries.
	return m.profileID + "\x00" + string(action) + "\x00" + targetHash
}

func (m *Manager) issueToken(norm Intent, targetHash string, now time.Time) (token string, exp time.Time, err error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", time.Time{}, apperr.Wrap(apperr.CodeInternal, "failed to mint confirmation token", err)
	}
	token = hex.EncodeToString(raw)
	exp = now.Add(m.ttl)
	id := token[:16]
	rec := &tokenRecord{
		id:         id,
		profileID:  m.profileID,
		principal:  m.principalID,
		action:     norm.Action,
		toolName:   norm.ToolName,
		jobName:    norm.JobName,
		buildNum:   norm.BuildNumber,
		queueID:    norm.QueueID,
		params:     cloneParams(norm.Parameters),
		endpoint:   norm.EndpointClass,
		targetHash: targetHash,
		expiresAt:  exp,
	}
	m.mu.Lock()
	// Opportunistic purge of a few expired tokens.
	m.purgeExpiredLocked(now)
	m.tokens[token] = rec
	m.mu.Unlock()
	return token, exp, nil
}

func (m *Manager) purgeExpiredLocked(now time.Time) {
	n := 0
	for k, rec := range m.tokens {
		if n >= 32 {
			break
		}
		if !now.Before(rec.expiresAt) || rec.used {
			delete(m.tokens, k)
			n++
		}
	}
}

func (m *Manager) purgeCooldownsLocked(now time.Time) {
	n := 0
	for k, until := range m.cooldowns {
		if n >= 32 {
			break
		}
		if !now.Before(until) {
			delete(m.cooldowns, k)
			n++
		}
	}
}

func (m *Manager) emitDeny(ctx context.Context, tool, action, reason, targetHash string, start time.Time) {
	m.emit(ctx, audit.Event{
		Time:        start,
		Type:        TypeDeny,
		ProfileID:   m.profileID,
		PrincipalID: m.principalID,
		Tool:        tool,
		Action:      action,
		Decision:    audit.DecisionDeny,
		ReasonCode:  reason,
		TargetHash:  targetHash,
		Duration:    m.now().Sub(start),
	})
}

func (m *Manager) emit(ctx context.Context, e audit.Event) {
	if m == nil || m.audit == nil {
		return
	}
	_ = audit.Emit(ctx, m.audit, e)
}

func normalizeIntent(in Intent) (Intent, error) {
	action := in.Action
	if action == "" {
		return Intent{}, apperr.New(apperr.CodeInvalidArgument, "mutation action is required")
	}
	job := strings.TrimSpace(in.JobName)
	if job != "" && strings.Contains(job, "://") {
		return Intent{}, apperr.New(apperr.CodeInvalidArgument, "job_name must be a full name path, not a URL")
	}
	params, err := NormalizeParams(in.Parameters)
	if err != nil {
		return Intent{}, err
	}
	endpoint := strings.TrimSpace(in.EndpointClass)
	queueID := in.QueueID
	buildNum := in.BuildNumber
	switch action {
	case ActionStartJob:
		if job == "" {
			return Intent{}, apperr.New(apperr.CodeInvalidArgument, "job_name is required")
		}
		if endpoint == "" {
			endpoint = EndpointBuildWithParameters
		}
		if buildNum != 0 {
			return Intent{}, apperr.New(apperr.CodeInvalidArgument, "build_number is not valid for start_job")
		}
		if queueID != 0 {
			return Intent{}, apperr.New(apperr.CodeInvalidArgument, "queue_id is not valid for start_job")
		}
	case ActionStopBuild:
		if job == "" {
			return Intent{}, apperr.New(apperr.CodeInvalidArgument, "job_name is required")
		}
		if buildNum <= 0 {
			return Intent{}, apperr.New(apperr.CodeInvalidArgument, "build_number must be positive for stop_build")
		}
		if endpoint == "" {
			endpoint = EndpointStop
		}
		if len(params) > 0 {
			return Intent{}, apperr.New(apperr.CodeInvalidArgument, "parameters are not valid for stop_build")
		}
		if queueID != 0 {
			return Intent{}, apperr.New(apperr.CodeInvalidArgument, "queue_id is not valid for stop_build")
		}
	case ActionCancelQueue:
		if queueID <= 0 {
			return Intent{}, apperr.New(apperr.CodeInvalidArgument, "queue_id must be positive for cancel_queue")
		}
		if buildNum != 0 {
			return Intent{}, apperr.New(apperr.CodeInvalidArgument, "build_number is not valid for cancel_queue")
		}
		if endpoint == "" {
			endpoint = EndpointCancelItem
		}
		if len(params) > 0 {
			return Intent{}, apperr.New(apperr.CodeInvalidArgument, "parameters are not valid for cancel_queue")
		}
		// JobName is optional display context from GetQueueItem; not required for binding.
	default:
		return Intent{}, apperr.New(apperr.CodeInvalidArgument, fmt.Sprintf("unknown mutation action %q", action))
	}
	tool := strings.TrimSpace(in.ToolName)
	if tool == "" {
		tool = toolForAction(action)
	}
	return Intent{
		Action:        action,
		ToolName:      tool,
		JobName:       job,
		BuildNumber:   buildNum,
		QueueID:       queueID,
		Parameters:    params,
		EndpointClass: endpoint,
		CurrentState:  strings.TrimSpace(in.CurrentState),
	}, nil
}

func toolForAction(a Action) string {
	switch a {
	case ActionStartJob:
		return policy.ToolStartJob
	case ActionStopBuild:
		return policy.ToolStopBuild
	case ActionCancelQueue:
		return policy.ToolCancelQueueItem
	default:
		return string(a)
	}
}

func cloneParams(in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// TokenCount returns live tokens (tests).
func (m *Manager) TokenCount() int {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.tokens)
}
