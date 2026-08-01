package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/contracts"
	"github.com/simonfxr/go-jenkins-mcp/internal/policy"
)

// MaxInboundGroups is the default hard cap on groups accepted from inbound claims
// (GWY-002 / OAUTH-006 group-overage behavior: truncate is not elevation; excess
// fails closed when FailOnGroupOverage is set, otherwise groups are truncated
// with a residual note). Aligns with auth.MaxStoredGroups.
const MaxInboundGroups = 64

// MaxInboundGroupNameBytes is the hard cap on a single group/role claim name
// (OAUTH-006 parity with auth.MaxGroupNameBytes). Oversize names fail closed.
const MaxInboundGroupNameBytes = 256

// DefaultBindingTTL is the short revalidation window for gateway subject binding.
const DefaultBindingTTL = 2 * time.Minute

// Non-secret gateway identity env keys (GWY-002 foundation binding).
const (
	EnvGatewaySubject          = "JENKINS_MCP_GATEWAY_SUBJECT"
	EnvGatewayTenant           = "JENKINS_MCP_GATEWAY_TENANT"
	EnvGatewayWorkload         = "JENKINS_MCP_GATEWAY_WORKLOAD"
	EnvGatewayJenkinsPrincipal = "JENKINS_MCP_GATEWAY_JENKINS_PRINCIPAL"
)

// GroupMeta is non-secret metadata about group bounding (OAUTH-006 overage).
type GroupMeta struct {
	// Count is the number of groups retained on the subject.
	Count int
	// Truncated is true when input exceeded the MaxGroups cap and was cut.
	Truncated bool
	// ResidualNote is set when Truncated (operator/audit residual).
	ResidualNote string
}

// InboundClaims are trusted gateway / Entra claims after gateway authentication.
// They must never be taken from MCP tool arguments (GWY-002).
type InboundClaims struct {
	// Subject is the Entra/OIDC sub (required).
	Subject string
	// Tenant is the IdP tenant (required for multi-tenant gateways).
	Tenant string
	// Groups is a bounded list of group/role ids (optional).
	Groups []string
	// WorkloadID is the AgentCore workload identity (required in gateway mode).
	WorkloadID string
	// JenkinsPrincipal is the exchanged Jenkins user id when present.
	JenkinsPrincipal string
	// ProfileID is the MCP profile namespace for this connection.
	ProfileID contracts.ProfileID
	// Verified is true only when the gateway trust path verified the caller.
	Verified bool
}

// BindOptions controls claim → policy.Subject mapping.
type BindOptions struct {
	// RequireTenant fails closed when Tenant is empty.
	RequireTenant bool
	// RequireWorkload fails closed when WorkloadID is empty.
	RequireWorkload bool
	// RequireJenkinsPrincipal fails closed when JenkinsPrincipal is empty.
	// Local hybrid tests may leave this false until OBO is live.
	RequireJenkinsPrincipal bool
	// RequireVerified fails closed when Verified is false.
	RequireVerified bool
	// FailOnGroupOverage fails closed when unique group count > MaxGroups.
	// When false, groups are truncated to MaxGroups with residual note.
	FailOnGroupOverage bool
	// MaxGroups caps stored groups after dedupe (0 → MaxInboundGroups).
	MaxGroups int
	// ExpectedJenkinsPrincipal, when non-empty, must equal claims.JenkinsPrincipal
	// (after trim). Used to deny env label vs verified whoAmI mismatches (GWY-002).
	ExpectedJenkinsPrincipal string
}

// DefaultBindOptions returns production-leaning gateway bind options.
func DefaultBindOptions() BindOptions {
	return BindOptions{
		RequireTenant:           true,
		RequireWorkload:         true,
		RequireJenkinsPrincipal: false, // until live OBO pins Jenkins principal
		RequireVerified:         true,
		FailOnGroupOverage:      true,
		MaxGroups:               MaxInboundGroups,
	}
}

// BindSubject maps trusted inbound claims to a policy.Subject (GWY-002).
// Tool arguments must never be passed as claims — only InboundClaims fields
// participate; there is no args parameter by design.
func BindSubject(claims InboundClaims, opts BindOptions) (policy.Subject, error) {
	s, _, err := BindSubjectWithMeta(claims, opts)
	return s, err
}

// BindSubjectWithMeta is BindSubject plus group overage residual metadata (OAUTH-006).
func BindSubjectWithMeta(claims InboundClaims, opts BindOptions) (policy.Subject, GroupMeta, error) {
	sub := strings.TrimSpace(claims.Subject)
	if sub == "" {
		return policy.Subject{}, GroupMeta{}, apperr.New(apperr.CodeAuthentication,
			"gateway inbound subject is required")
	}
	profileID := contracts.ProfileID(strings.TrimSpace(string(claims.ProfileID)))
	if profileID == "" {
		return policy.Subject{}, GroupMeta{}, apperr.New(apperr.CodeAuthentication,
			"gateway profile id is required for subject binding")
	}
	if opts.RequireVerified && !claims.Verified {
		return policy.Subject{}, GroupMeta{}, apperr.New(apperr.CodeAuthentication,
			"gateway claims are not verified")
	}
	tenant := strings.TrimSpace(claims.Tenant)
	if opts.RequireTenant && tenant == "" {
		return policy.Subject{}, GroupMeta{}, apperr.New(apperr.CodeAuthentication,
			"gateway tenant is required")
	}
	workload := strings.TrimSpace(claims.WorkloadID)
	if opts.RequireWorkload && workload == "" {
		return policy.Subject{}, GroupMeta{}, apperr.New(apperr.CodeAuthentication,
			"gateway workload id is required")
	}
	jenkins := strings.TrimSpace(claims.JenkinsPrincipal)
	if opts.RequireJenkinsPrincipal && jenkins == "" {
		return policy.Subject{}, GroupMeta{}, apperr.New(apperr.CodeAuthentication,
			"exchanged jenkins principal is required")
	}
	// When Jenkins principal is absent, policy still needs a JenkinsUserID for
	// Valid() — use external subject only if Jenkins principal is present;
	// otherwise leave JenkinsUserID empty and mark verified=false for Jenkins
	// binding, keeping ExternalSubject for audit.
	if jenkins != "" && strings.EqualFold(jenkins, policy.AnonymousJenkinsUser) {
		return policy.Subject{}, GroupMeta{}, apperr.New(apperr.CodeAuthentication,
			"anonymous jenkins principal is not a valid gateway subject")
	}
	// Mismatch: expected (e.g. verified whoAmI) vs claim/env Jenkins principal.
	// When expected is set and jenkins is empty, do not invent membership —
	// RequireJenkinsPrincipal already fails empty; otherwise leave unbound.
	expected := strings.TrimSpace(opts.ExpectedJenkinsPrincipal)
	if expected != "" && jenkins != "" && jenkins != expected {
		return policy.Subject{}, GroupMeta{}, apperr.New(apperr.CodeAuthentication,
			"gateway jenkins principal does not match verified whoAmI identity")
	}

	groups, meta, err := boundGroups(claims.Groups, opts.MaxGroups, opts.FailOnGroupOverage)
	if err != nil {
		return policy.Subject{}, GroupMeta{}, err
	}

	// Prefer exchanged Jenkins principal for MCP RBAC JenkinsUserID.
	// Without it, subject is not yet Jenkins-bound (Valid() is false).
	// Valid() is true only when ProfileID + non-anonymous JenkinsUserID are set —
	// i.e. binding succeeded for RBAC only with a Jenkins principal present.
	verified := claims.Verified && jenkins != ""
	s := policy.Subject{
		ProfileID:       profileID,
		JenkinsUserID:   jenkins,
		ExternalSubject: sub,
		Verified:        verified,
		Tenant:          tenant,
		WorkloadID:      workload,
		Groups:          groups,
	}
	return s, meta, nil
}

// BindSubjectFromEnviron builds InboundClaims from non-secret gateway env labels
// and binds them (GWY-002). Used by cmd so unit tests avoid os.Getenv scatter.
//
// getenv nil defaults to os.Getenv. verifiedJenkinsUser is the whoAmI / AUTH-004
// principal; when env JENKINS_MCP_GATEWAY_JENKINS_PRINCIPAL is set and disagrees
// with verifiedJenkinsUser, binding fails closed.
//
// Tool arguments never enter this path.
func BindSubjectFromEnviron(profileID contracts.ProfileID, verifiedJenkinsUser string, getenv func(string) string) (policy.Subject, error) {
	s, _, err := BindSubjectFromEnvironWithMeta(profileID, verifiedJenkinsUser, getenv, DefaultBindOptions())
	return s, err
}

// BindSubjectFromEnvironWithMeta is BindSubjectFromEnviron with explicit opts and group meta.
func BindSubjectFromEnvironWithMeta(
	profileID contracts.ProfileID,
	verifiedJenkinsUser string,
	getenv func(string) string,
	opts BindOptions,
) (policy.Subject, GroupMeta, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	envPrincipal := strings.TrimSpace(getenv(EnvGatewayJenkinsPrincipal))
	verified := strings.TrimSpace(verifiedJenkinsUser)
	// Resolve Jenkins principal: env label optional; defaults to verified whoAmI.
	jenkins := envPrincipal
	if jenkins == "" {
		jenkins = verified
	}
	// Mismatch deny when both present and disagree (before RequireJenkinsPrincipal).
	if envPrincipal != "" && verified != "" && envPrincipal != verified {
		return policy.Subject{}, GroupMeta{}, apperr.New(apperr.CodeAuthentication,
			"gateway jenkins principal does not match verified whoAmI identity")
	}
	claims := InboundClaims{
		Subject:          strings.TrimSpace(getenv(EnvGatewaySubject)),
		Tenant:           strings.TrimSpace(getenv(EnvGatewayTenant)),
		WorkloadID:       strings.TrimSpace(getenv(EnvGatewayWorkload)),
		JenkinsPrincipal: jenkins,
		ProfileID:        profileID,
		Verified:         true, // process env path is operator-provisioned foundation trust
		// Groups are not loaded from env (no group list in foundation env contract).
	}
	// When a Jenkins principal is resolved (env or whoAmI), require it for Valid().
	if claims.JenkinsPrincipal != "" {
		opts.RequireJenkinsPrincipal = true
	}
	// Pin expected for defense in depth when whoAmI is known.
	if verified != "" {
		opts.ExpectedJenkinsPrincipal = verified
	}
	return BindSubjectWithMeta(claims, opts)
}

func boundGroups(in []string, max int, failOnOverage bool) ([]string, GroupMeta, error) {
	if max <= 0 {
		max = MaxInboundGroups
	}
	if len(in) == 0 {
		return nil, GroupMeta{}, nil
	}
	// Dedupe + name-length fail-closed, then enforce hard cap (OAUTH-006:
	// overage cannot broaden; oversize names never truncated into collisions).
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, g := range in {
		g = strings.TrimSpace(g)
		if g == "" {
			continue
		}
		if len(g) > MaxInboundGroupNameBytes {
			return nil, GroupMeta{}, apperr.New(apperr.CodeAuthentication,
				fmt.Sprintf("gateway group name exceeds length bound of %d bytes", MaxInboundGroupNameBytes))
		}
		if _, ok := seen[g]; ok {
			continue
		}
		seen[g] = struct{}{}
		out = append(out, g)
	}
	meta := GroupMeta{Count: len(out)}
	if len(out) <= max {
		return out, meta, nil
	}
	if failOnOverage {
		return nil, GroupMeta{}, apperr.New(apperr.CodeAuthentication,
			fmt.Sprintf("gateway group list exceeds bound of %d", max))
	}
	out = out[:max]
	meta = GroupMeta{
		Count:     len(out),
		Truncated: true,
		ResidualNote: fmt.Sprintf(
			"group_overage_truncated: stored_groups capped at %d; excess ignored (cannot broaden access)",
			max),
	}
	return out, meta, nil
}

// ClaimsFingerprint is a non-secret stable hash of binding-critical claim fields
// used to detect mid-session identity changes.
func ClaimsFingerprint(claims InboundClaims) string {
	groups := append([]string(nil), claims.Groups...)
	for i := range groups {
		groups[i] = strings.TrimSpace(groups[i])
	}
	sort.Strings(groups)
	raw := strings.Join([]string{
		strings.TrimSpace(claims.Subject),
		strings.TrimSpace(claims.Tenant),
		strings.TrimSpace(claims.WorkloadID),
		strings.TrimSpace(claims.JenkinsPrincipal),
		strings.TrimSpace(string(claims.ProfileID)),
		strings.Join(groups, ","),
	}, "|")
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:16])
}

// Binding holds a revalidated gateway subject for a short TTL (GWY-002).
type Binding struct {
	mu          sync.Mutex
	subject     policy.Subject
	fingerprint string
	boundAt     time.Time
	ttl         time.Duration
	now         func() time.Time
}

// NewBinding creates a binding from claims. Fails closed on bind errors.
func NewBinding(claims InboundClaims, opts BindOptions, ttl time.Duration) (*Binding, error) {
	s, err := BindSubject(claims, opts)
	if err != nil {
		return nil, err
	}
	if ttl <= 0 {
		ttl = DefaultBindingTTL
	}
	return &Binding{
		subject:     s,
		fingerprint: ClaimsFingerprint(claims),
		boundAt:     time.Now(),
		ttl:         ttl,
		now:         time.Now,
	}, nil
}

// Subject returns the bound policy subject (copy of scalar fields; groups copied).
func (b *Binding) Subject() policy.Subject {
	if b == nil {
		return policy.Subject{}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return copySubject(b.subject)
}

// Fresh reports whether the binding is still within TTL.
func (b *Binding) Fresh() bool {
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now
	if now == nil {
		now = time.Now
	}
	return now().Sub(b.boundAt) <= b.ttl
}

// Revalidate checks claims against the bound fingerprint and refreshes TTL.
// Identity mismatch or expired binding fails closed.
func (b *Binding) Revalidate(claims InboundClaims, opts BindOptions) (policy.Subject, error) {
	if b == nil {
		return policy.Subject{}, apperr.New(apperr.CodeAuthentication, "gateway subject binding is missing")
	}
	fp := ClaimsFingerprint(claims)
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now
	if now == nil {
		now = time.Now
	}
	if b.fingerprint != "" && fp != b.fingerprint {
		return policy.Subject{}, apperr.New(apperr.CodeAuthentication,
			"gateway identity mismatch: inbound claims do not match bound subject")
	}
	if now().Sub(b.boundAt) > b.ttl {
		// Expired: re-bind from claims (still fail closed on bind errors).
		s, err := BindSubject(claims, opts)
		if err != nil {
			return policy.Subject{}, err
		}
		b.subject = s
		b.fingerprint = fp
		b.boundAt = now()
		return copySubject(s), nil
	}
	// Within TTL: ensure claims still bind to the same subject shape.
	s, err := BindSubject(claims, opts)
	if err != nil {
		return policy.Subject{}, err
	}
	if !subjectsEqual(b.subject, s) {
		return policy.Subject{}, apperr.New(apperr.CodeAuthentication,
			"gateway identity mismatch: bound subject changed")
	}
	b.boundAt = now() // sliding window within TTL check above
	return copySubject(b.subject), nil
}

func copySubject(s policy.Subject) policy.Subject {
	out := s
	if len(s.Groups) > 0 {
		out.Groups = append([]string(nil), s.Groups...)
	}
	return out
}

func subjectsEqual(a, b policy.Subject) bool {
	if a.ProfileID != b.ProfileID ||
		a.JenkinsUserID != b.JenkinsUserID ||
		a.ExternalSubject != b.ExternalSubject ||
		a.Verified != b.Verified ||
		a.Tenant != b.Tenant ||
		a.WorkloadID != b.WorkloadID {
		return false
	}
	if len(a.Groups) != len(b.Groups) {
		return false
	}
	for i := range a.Groups {
		if a.Groups[i] != b.Groups[i] {
			return false
		}
	}
	return true
}

// ForbiddenIdentityArgKeys are tool argument keys that must not be used to
// override process identity (GWY-002). Callers reject these when present.
var ForbiddenIdentityArgKeys = []string{
	"subject",
	"external_subject",
	"jenkins_user",
	"jenkins_user_id",
	"jenkinsUser",
	"jenkinsUserId",
	"tenant",
	"tenant_id",
	"workload_id",
	"workloadId",
	"as_user",
	"impersonate",
	"on_behalf_of",
	"gateway_subject",
	"policy_subject",
}

// RejectIdentityToolArgs fails closed when tool arguments attempt to supply
// or override identity. Trusted identity comes only from Binding / auth session.
func RejectIdentityToolArgs(args map[string]any) error {
	if len(args) == 0 {
		return nil
	}
	// Case-insensitive match on known forbidden keys.
	forbidden := make(map[string]struct{}, len(ForbiddenIdentityArgKeys))
	for _, k := range ForbiddenIdentityArgKeys {
		forbidden[strings.ToLower(k)] = struct{}{}
	}
	for k := range args {
		if _, ok := forbidden[strings.ToLower(strings.TrimSpace(k))]; ok {
			return apperr.New(apperr.CodePolicyDenial,
				"tool arguments cannot change gateway identity")
		}
	}
	return nil
}
