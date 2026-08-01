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
	ActionStartJob               Action = "start_job"
	ActionStopBuild              Action = "stop_build"
	ActionCancelQueue            Action = "cancel_queue"
	ActionInterruptBuild         Action = "interrupt_build"
	ActionRebuildBuild           Action = "rebuild_build"
	ActionReplayPipeline         Action = "replay_pipeline"
	ActionSetJobBuildable        Action = "set_job_buildable"
	ActionSetBuildKeepForever    Action = "set_build_keep_forever"
	ActionSetBuildDescription    Action = "set_build_description"
	ActionCancelQueueItemsForJob Action = "cancel_queue_items_for_job"
)

// DefaultTokenTTL is the confirmation window (MUT-001: expire quickly).
// Operator resolve path: empty/0/"0s" → default; cannot disable via 0
// (see ResolveTokenTTL / MinTokenTTL / AbsoluteMaxTokenTTL).
const DefaultTokenTTL = 2 * time.Minute

// DefaultMaxPreviewsPerMinute is the process-local Preview sliding-window limit
// when Config.MaxPreviewsPerMinute is 0 (MUT-001 rate limit).
const DefaultMaxPreviewsPerMinute = 30

// DefaultConfirmCooldown is the minimum wait after a successful Confirm before
// another Confirm for the same (binding, action, targetHash) is allowed when
// Config.ConfirmCooldown is 0 and no process live ConfirmCooldown() is set
// (MUT-001 cooldown). Binding includes profile+principal+external+tenant so
// multi-user cooldowns do not cross subjects. Operator resolve path:
// empty/0/"0s" → default; cannot disable via 0 (see ResolveConfirmCooldown /
// MinConfirmCooldown / AbsoluteMaxConfirmCooldown).
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
	QueueID       int            // cancel_queue single-item
	Parameters    map[string]any // nil for stop/cancel; rebuild may carry redacted params
	EndpointClass string
	// Mode is action-specific (interrupt: stop|term|kill; set_job_buildable: enable|disable).
	Mode string
	// Extra is non-secret bind material (description text, keep true/false, bulk queue id list).
	Extra string
	// QueueIDs is for bulk cancel (sorted unique positive ids); bound via Extra + Mode.
	QueueIDs []int
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
	QueueIDs          []int          `json:"queueIds,omitempty"`
	Mode              string         `json:"mode,omitempty"`
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

// Binding is the non-secret identity fingerprint bound into confirmation tokens
// (MUT-001 / HOST-006 multi-user). Tokens must not replay across distinct
// bindings. Fields are labels only — never tokens or secrets.
//
// Stdio / single-user: ProfileID + PrincipalID (Jenkins user). Gateway multi-user:
// also ExternalSubject (IdP sub) and Tenant so two principals sharing a process
// Manager cannot confirm each other's preview tokens.
type Binding struct {
	ProfileID       string
	PrincipalID     string // Jenkins principal label (non-secret)
	ExternalSubject string // validated IdP sub when multi-user; empty for API-token
	Tenant          string // IdP tenant when multi-user; empty for API-token / stdio
}

// Equal reports whether two bindings are identical for confirm-token matching.
func (b Binding) Equal(o Binding) bool {
	return b.ProfileID == o.ProfileID &&
		b.PrincipalID == o.PrincipalID &&
		b.ExternalSubject == o.ExternalSubject &&
		b.Tenant == o.Tenant
}

// normalizeBinding trims binding label fields.
func normalizeBinding(b Binding) Binding {
	return Binding{
		ProfileID:       strings.TrimSpace(b.ProfileID),
		PrincipalID:     strings.TrimSpace(b.PrincipalID),
		ExternalSubject: strings.TrimSpace(b.ExternalSubject),
		Tenant:          strings.TrimSpace(b.Tenant),
	}
}

// bindingKey is a stable map/cooldown key for a binding (includes external+tenant).
func (b Binding) bindingKey() string {
	return b.ProfileID + "\x00" + b.PrincipalID + "\x00" + b.ExternalSubject + "\x00" + b.Tenant
}

// subjectKey returns tenant|external|profile for multi-user audit correlation
// when ExternalSubject is set; empty for stdio / API-token residual.
// Same shape as gateway.SubjectKeyParts (never PrincipalID, tokens, or vault bytes).
func (b Binding) subjectKey() string {
	ext := strings.TrimSpace(b.ExternalSubject)
	if ext == "" {
		return ""
	}
	return strings.Join([]string{
		strings.TrimSpace(b.Tenant),
		ext,
		strings.TrimSpace(b.ProfileID),
	}, "|")
}

// auditSubjectFields returns ExternalSubject + SubjectKeyHash for audit events
// from Binding. SubjectKeyHash is audit.HashOpaque(tenant|external|profile)
// when ExternalSubject is set; both empty for single-user residual.
// Never returns raw subject keys, tokens, or vault material.
func (b Binding) auditSubjectFields() (externalSubject, subjectKeyHash string) {
	externalSubject = strings.TrimSpace(b.ExternalSubject)
	if sk := b.subjectKey(); sk != "" {
		subjectKeyHash = audit.HashOpaque(sk)
	}
	return externalSubject, subjectKeyHash
}

// Config configures a Manager.
type Config struct {
	// Gate is the POL-001 read-only kill switch. Nil ⇒ fail-closed read-only.
	Gate *policy.ReadOnlyGate
	// Audit is optional (AUD-001).
	Audit audit.Sink
	// ProfileID / PrincipalID bind tokens (non-secret). Process-default binding
	// when BindingFromContext is unset or returns ok=false.
	ProfileID   string
	PrincipalID string
	// ExternalSubject / Tenant extend the confirm-token fingerprint for multi-user
	// gateway (IdP sub + tenant). Empty for stdio / API-token single-user.
	ExternalSubject string
	Tenant          string
	// BindingFromContext optionally supplies a per-request binding (multi-user
	// gateway: CallerFromContext → Binding). When set and ok=true, Preview/
	// Confirm/audit use that binding instead of Config process defaults.
	// Never derived from tool arguments. Nil ⇒ always Config defaults.
	BindingFromContext func(ctx context.Context) (Binding, bool)
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
	// another Confirm for the same (binding, action, targetHash) may succeed.
	// 0 ⇒ process live ConfirmCooldown() when positive (serve SetConfirmCooldown
	// after Resolve), else DefaultConfirmCooldown; negative ⇒ off (library/test
	// escape hatch — operator ResolveConfirmCooldown cannot set 0/disable).
	ConfirmCooldown time.Duration
	// Now is optional clock for tests.
	Now func() time.Time
}

// Manager is the process-local preview/confirm gate (MUT-001).
// Safe for concurrent use. Multi-user: one shared Manager + BindingFromContext
// so Alice preview tokens cannot be confirmed by Bob.
type Manager struct {
	gate               *policy.ReadOnlyGate
	audit              audit.Sink
	defaultBinding     Binding
	bindingFromContext func(ctx context.Context) (Binding, bool)
	ttl                time.Duration
	maxPreviewsPerMin  int           // negative ⇒ unlimited
	confirmCooldown    time.Duration // ≤0 ⇒ off
	now                func() time.Time

	mu           sync.Mutex
	tokens       map[string]*tokenRecord
	previewTimes []time.Time          // sliding window timestamps
	cooldowns    map[string]time.Time // key → not-before (until) for next confirm
}

type tokenRecord struct {
	id         string
	binding    Binding
	action     Action
	toolName   string
	jobName    string
	buildNum   int
	queueID    int
	queueIDs   []int
	params     map[string]any
	endpoint   string
	mode       string
	extra      string
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
		gate:  gate,
		audit: cfg.Audit,
		defaultBinding: normalizeBinding(Binding{
			ProfileID:       cfg.ProfileID,
			PrincipalID:     cfg.PrincipalID,
			ExternalSubject: cfg.ExternalSubject,
			Tenant:          cfg.Tenant,
		}),
		bindingFromContext: cfg.BindingFromContext,
		ttl:                ttl,
		maxPreviewsPerMin:  maxPrev,
		confirmCooldown:    cooldown,
		now:                now,
		tokens:             make(map[string]*tokenRecord),
		cooldowns:          make(map[string]time.Time),
	}
}

// effectiveBinding returns the per-request binding when BindingFromContext is
// set and ok, else the Manager process-default binding (HOST-006 multi-user).
func (m *Manager) effectiveBinding(ctx context.Context) Binding {
	if m == nil {
		return Binding{}
	}
	if m.bindingFromContext != nil && ctx != nil {
		if b, ok := m.bindingFromContext(ctx); ok {
			return normalizeBinding(b)
		}
	}
	return m.defaultBinding
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
	th := TargetHash(norm.Action, norm.JobName, norm.BuildNumber, norm.QueueID, paramFP, norm.Mode, norm.Extra)
	if err := m.reservePreview(start); err != nil {
		m.emitDeny(ctx, tool, string(norm.Action), ReasonPreviewRateLimited, th, start)
		return nil, err
	}
	bind := m.effectiveBinding(ctx)
	tok, exp, err := m.issueToken(norm, th, start, bind)
	if err != nil {
		m.emitDeny(ctx, tool, string(norm.Action), ReasonInvalidIntent, th, start)
		return nil, err
	}
	extSub, skHash := bind.auditSubjectFields()
	m.emit(ctx, audit.Event{
		Time:            start,
		Type:            TypePreview,
		ProfileID:       bind.ProfileID,
		PrincipalID:     bind.PrincipalID,
		ExternalSubject: extSub,
		SubjectKeyHash:  skHash,
		Tool:            tool,
		Action:          string(norm.Action),
		Decision:        audit.DecisionAllow,
		ReasonCode:      ReasonPreviewOK,
		TargetHash:      th,
		Duration:        m.now().Sub(start),
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
		QueueIDs:          append([]int(nil), norm.QueueIDs...),
		Mode:              norm.Mode,
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
	wantHash := TargetHash(norm.Action, norm.JobName, norm.BuildNumber, norm.QueueID, paramFP, norm.Mode, norm.Extra)
	bind := m.effectiveBinding(ctx)

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
	// HOST-006: compare stored token binding to effective request subject
	// (BindingFromContext when multi-user; else process defaults). Prevents
	// Alice preview tokens from being confirmed by Bob on a shared Manager.
	if !rec.binding.Equal(bind) {
		m.mu.Unlock()
		m.emitDeny(ctx, tool, string(norm.Action), ReasonBindingMismatch, rec.targetHash, start)
		return nil, apperr.New(apperr.CodePolicyDenial, "confirmation token is not bound to this profile/subject")
	}
	if rec.action != norm.Action || rec.targetHash != wantHash {
		m.mu.Unlock()
		m.emitDeny(ctx, tool, string(norm.Action), ReasonTargetMismatch, rec.targetHash, start)
		return nil, apperr.New(apperr.CodePolicyDenial, "confirmation token does not match the requested target/parameters")
	}
	// MUT-001: cooldown after successful confirm for same (binding, action, targetHash).
	// Checked before single-use consume so a denied confirm leaves the token usable.
	cdKey := cooldownKey(bind, norm.Action, wantHash)
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
			QueueIDs:      append([]int(nil), rec.queueIDs...),
			Parameters:    params,
			EndpointClass: rec.endpoint,
			Mode:          rec.mode,
			Extra:         rec.extra,
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

	extSub, skHash := bind.auditSubjectFields()
	m.emit(ctx, audit.Event{
		Time:            start,
		Type:            TypeConfirm,
		ProfileID:       bind.ProfileID,
		PrincipalID:     bind.PrincipalID,
		ExternalSubject: extSub,
		SubjectKeyHash:  skHash,
		Tool:            tool,
		Action:          string(bound.Action),
		Decision:        audit.DecisionAllow,
		ReasonCode:      ReasonConfirmOK,
		TargetHash:      bound.TargetHash,
		RequestID:       bound.RequestID,
		Duration:        m.now().Sub(start),
	})
	return bound, nil
}

// EmitExecuteFail records a post-confirm Jenkins failure (no secrets).
func (m *Manager) EmitExecuteFail(ctx context.Context, tool, action, reason, targetHash string) {
	if m == nil {
		return
	}
	bind := m.effectiveBinding(ctx)
	extSub, skHash := bind.auditSubjectFields()
	m.emit(ctx, audit.Event{
		Time:            m.now(),
		Type:            TypeDeny,
		ProfileID:       bind.ProfileID,
		PrincipalID:     bind.PrincipalID,
		ExternalSubject: extSub,
		SubjectKeyHash:  skHash,
		Tool:            tool,
		Action:          action,
		Decision:        audit.DecisionFail,
		ReasonCode:      reason,
		TargetHash:      targetHash,
	})
}

// EmitExecuteOK records a successful mutation execute summary (no secrets).
func (m *Manager) EmitExecuteOK(ctx context.Context, tool, action, targetHash, requestID string) {
	if m == nil {
		return
	}
	bind := m.effectiveBinding(ctx)
	extSub, skHash := bind.auditSubjectFields()
	m.emit(ctx, audit.Event{
		Time:            m.now(),
		Type:            audit.TypeToolSuccess,
		ProfileID:       bind.ProfileID,
		PrincipalID:     bind.PrincipalID,
		ExternalSubject: extSub,
		SubjectKeyHash:  skHash,
		Tool:            tool,
		Action:          action,
		Decision:        audit.DecisionSuccess,
		ReasonCode:      "execute_ok",
		TargetHash:      targetHash,
		RequestID:       requestID,
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

func cooldownKey(bind Binding, action Action, targetHash string) string {
	// Full binding (profile+principal+external+tenant) so multi-user cooldown
	// and token isolation cannot cross subjects on a shared Manager.
	return bind.bindingKey() + "\x00" + string(action) + "\x00" + targetHash
}

func (m *Manager) issueToken(norm Intent, targetHash string, now time.Time, bind Binding) (token string, exp time.Time, err error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", time.Time{}, apperr.Wrap(apperr.CodeInternal, "failed to mint confirmation token", err)
	}
	token = hex.EncodeToString(raw)
	exp = now.Add(m.ttl)
	id := token[:16]
	rec := &tokenRecord{
		id:         id,
		binding:    bind,
		action:     norm.Action,
		toolName:   norm.ToolName,
		jobName:    norm.JobName,
		buildNum:   norm.BuildNumber,
		queueID:    norm.QueueID,
		queueIDs:   append([]int(nil), norm.QueueIDs...),
		params:     cloneParams(norm.Parameters),
		endpoint:   norm.EndpointClass,
		mode:       norm.Mode,
		extra:      norm.Extra,
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
	bind := m.effectiveBinding(ctx)
	extSub, skHash := bind.auditSubjectFields()
	m.emit(ctx, audit.Event{
		Time:            start,
		Type:            TypeDeny,
		ProfileID:       bind.ProfileID,
		PrincipalID:     bind.PrincipalID,
		ExternalSubject: extSub,
		SubjectKeyHash:  skHash,
		Tool:            tool,
		Action:          action,
		Decision:        audit.DecisionDeny,
		ReasonCode:      reason,
		TargetHash:      targetHash,
		Duration:        m.now().Sub(start),
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
	mode := strings.ToLower(strings.TrimSpace(in.Mode))
	extra := strings.TrimSpace(in.Extra)
	queueIDs := normalizeQueueIDs(in.QueueIDs)
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
		mode, extra = "", ""
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
		mode, extra = "", ""
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
		mode, extra = "", ""
	case ActionInterruptBuild:
		if job == "" {
			return Intent{}, apperr.New(apperr.CodeInvalidArgument, "job_name is required")
		}
		if buildNum <= 0 {
			return Intent{}, apperr.New(apperr.CodeInvalidArgument, "build_number must be positive for interrupt_build")
		}
		switch mode {
		case "stop", "term", "kill":
		default:
			return Intent{}, apperr.New(apperr.CodeInvalidArgument, "mode must be stop, term, or kill for interrupt_build")
		}
		if endpoint == "" {
			switch mode {
			case "term":
				endpoint = EndpointTerm
			case "kill":
				endpoint = EndpointKill
			default:
				endpoint = EndpointStop
			}
		}
		if len(params) > 0 || queueID != 0 {
			return Intent{}, apperr.New(apperr.CodeInvalidArgument, "parameters/queue_id are not valid for interrupt_build")
		}
		extra = ""
	case ActionRebuildBuild:
		if job == "" {
			return Intent{}, apperr.New(apperr.CodeInvalidArgument, "job_name is required")
		}
		if buildNum <= 0 {
			return Intent{}, apperr.New(apperr.CodeInvalidArgument, "build_number (source build) must be positive for rebuild_build")
		}
		if endpoint == "" {
			endpoint = EndpointRebuild
		}
		if queueID != 0 {
			return Intent{}, apperr.New(apperr.CodeInvalidArgument, "queue_id is not valid for rebuild_build")
		}
		mode = ""
		// Extra may hold source-build note; parameters are the rebuilt params.
	case ActionReplayPipeline:
		if job == "" {
			return Intent{}, apperr.New(apperr.CodeInvalidArgument, "job_name is required")
		}
		if buildNum <= 0 {
			return Intent{}, apperr.New(apperr.CodeInvalidArgument, "build_number must be positive for replay_pipeline")
		}
		// mode must be empty or "same" — script edit is never default and not accepted.
		if mode != "" && mode != "same" {
			return Intent{}, apperr.New(apperr.CodeInvalidArgument, "pipeline replay script-edit is not enabled; mode must be empty or same")
		}
		mode = "same"
		if endpoint == "" {
			endpoint = EndpointReplay
		}
		if len(params) > 0 || queueID != 0 {
			return Intent{}, apperr.New(apperr.CodeInvalidArgument, "parameters/queue_id are not valid for replay_pipeline")
		}
		extra = ""
	case ActionSetJobBuildable:
		if job == "" {
			return Intent{}, apperr.New(apperr.CodeInvalidArgument, "job_name is required")
		}
		switch mode {
		case "enable", "disable":
		default:
			return Intent{}, apperr.New(apperr.CodeInvalidArgument, "mode must be enable or disable for set_job_buildable")
		}
		if endpoint == "" {
			if mode == "enable" {
				endpoint = EndpointEnable
			} else {
				endpoint = EndpointDisable
			}
		}
		if buildNum != 0 || queueID != 0 || len(params) > 0 {
			return Intent{}, apperr.New(apperr.CodeInvalidArgument, "build_number/queue_id/parameters are not valid for set_job_buildable")
		}
		extra = ""
	case ActionSetBuildKeepForever:
		if job == "" {
			return Intent{}, apperr.New(apperr.CodeInvalidArgument, "job_name is required")
		}
		if buildNum <= 0 {
			return Intent{}, apperr.New(apperr.CodeInvalidArgument, "build_number must be positive for set_build_keep_forever")
		}
		switch mode {
		case "true", "false":
		default:
			return Intent{}, apperr.New(apperr.CodeInvalidArgument, "mode must be true or false for set_build_keep_forever")
		}
		if endpoint == "" {
			endpoint = EndpointToggleKeepForever
		}
		if queueID != 0 || len(params) > 0 {
			return Intent{}, apperr.New(apperr.CodeInvalidArgument, "queue_id/parameters are not valid for set_build_keep_forever")
		}
		extra = mode
	case ActionSetBuildDescription:
		if job == "" {
			return Intent{}, apperr.New(apperr.CodeInvalidArgument, "job_name is required")
		}
		if buildNum <= 0 {
			return Intent{}, apperr.New(apperr.CodeInvalidArgument, "build_number must be positive for set_build_description")
		}
		if extra == "" && strings.TrimSpace(in.Extra) == "" {
			// Allow empty description (clear); bind empty string.
			extra = ""
		}
		if len(extra) > MaxBuildDescriptionLen {
			return Intent{}, apperr.New(apperr.CodeInvalidArgument, fmt.Sprintf("description exceeds max length %d", MaxBuildDescriptionLen))
		}
		if endpoint == "" {
			endpoint = EndpointSubmitDescription
		}
		if queueID != 0 || len(params) > 0 {
			return Intent{}, apperr.New(apperr.CodeInvalidArgument, "queue_id/parameters are not valid for set_build_description")
		}
		mode = ""
	case ActionCancelQueueItemsForJob:
		if job == "" {
			return Intent{}, apperr.New(apperr.CodeInvalidArgument, "job_name is required")
		}
		if len(queueIDs) == 0 {
			return Intent{}, apperr.New(apperr.CodeInvalidArgument, "queue_ids must be non-empty for cancel_queue_items_for_job")
		}
		if len(queueIDs) > MaxBulkQueueCancel {
			return Intent{}, apperr.New(apperr.CodeInvalidArgument, fmt.Sprintf("queue_ids exceeds cap %d", MaxBulkQueueCancel))
		}
		// Stickiness filter is optional mode: "" | "stuck".
		if mode != "" && mode != "stuck" {
			return Intent{}, apperr.New(apperr.CodeInvalidArgument, "mode must be empty or stuck for cancel_queue_items_for_job")
		}
		if endpoint == "" {
			endpoint = EndpointCancelItemBulk
		}
		if buildNum != 0 || queueID != 0 || len(params) > 0 {
			return Intent{}, apperr.New(apperr.CodeInvalidArgument, "build_number/queue_id/parameters are not valid for cancel_queue_items_for_job")
		}
		extra = formatQueueIDsExtra(queueIDs)
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
		QueueIDs:      queueIDs,
		Parameters:    params,
		EndpointClass: endpoint,
		Mode:          mode,
		Extra:         extra,
		CurrentState:  strings.TrimSpace(in.CurrentState),
	}, nil
}

// MaxBuildDescriptionLen is the hard cap for set_build_description (MUT-014).
const MaxBuildDescriptionLen = 4096

// MaxBulkQueueCancel is the hard cap for bulk queue cancel (MUT-016).
const MaxBulkQueueCancel = 20

func normalizeQueueIDs(in []int) []int {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[int]struct{}, len(in))
	out := make([]int, 0, len(in))
	for _, id := range in {
		if id <= 0 {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	// Sort for stable Extra / fingerprint.
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

func formatQueueIDsExtra(ids []int) string {
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = fmt.Sprintf("%d", id)
	}
	return strings.Join(parts, ",")
}

func toolForAction(a Action) string {
	switch a {
	case ActionStartJob:
		return policy.ToolStartJob
	case ActionStopBuild:
		return policy.ToolStopBuild
	case ActionCancelQueue:
		return policy.ToolCancelQueueItem
	case ActionInterruptBuild:
		return policy.ToolInterruptBuild
	case ActionRebuildBuild:
		return policy.ToolRebuildBuild
	case ActionReplayPipeline:
		return policy.ToolReplayPipeline
	case ActionSetJobBuildable:
		return policy.ToolSetJobBuildable
	case ActionSetBuildKeepForever:
		return policy.ToolSetBuildKeepForever
	case ActionSetBuildDescription:
		return policy.ToolSetBuildDescription
	case ActionCancelQueueItemsForJob:
		return policy.ToolCancelQueueItemsForJob
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
