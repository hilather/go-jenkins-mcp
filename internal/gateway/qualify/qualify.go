package qualify

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/auth"
	"github.com/simonfxr/go-jenkins-mcp/internal/contracts"
	"github.com/simonfxr/go-jenkins-mcp/internal/gateway"
)

// CanaryToken is a synthetic secret used only inside the offline harness to
// prove errors/strings never leak token material. Never a real credential.
const CanaryToken = "CANARY_GWY003_TOKEN_must_never_appear_xyz789"

// ConcurrentObtainN is the concurrency level for the offline Obtain stub budget.
const ConcurrentObtainN = 32

// ConcurrentObtainBudget is the wall-clock budget for N concurrent fail-closed
// or stub Obtain calls (offline mock only — not a live AgentCore SLO).
const ConcurrentObtainBudget = 500 * time.Millisecond

// FailClosedLatencyBudget bounds a single fail-closed Obtain (config reject /
// not configured). Offline mock only.
const FailClosedLatencyBudget = 50 * time.Millisecond

// CaseResult is one security or performance case outcome (no secrets).
type CaseResult struct {
	Name       string `json:"name"`
	Category   string `json:"category"` // security | performance
	Passed     bool   `json:"passed"`
	Detail     string `json:"detail,omitempty"`
	DurationMs int64  `json:"duration_ms"`
}

// Summary is the offline qualification report (safe for JSON stdout).
type Summary struct {
	Suite     string       `json:"suite"` // offline
	Passed    int          `json:"passed"`
	Failed    int          `json:"failed"`
	Cases     []CaseResult `json:"cases"`
	Residuals []string     `json:"residuals"`
	OK        bool         `json:"ok"`
}

// RunOffline executes the in-process security + performance suite without
// network I/O. Suitable for `jenkins-mcp gateway qualify --offline`.
//
// Includes HOST-011 modes A/B/C offline Obtain matrix and no-silent-fallthrough.
// Does not claim live Entra / AgentCore / jwt-auth-filter production pin.
func RunOffline(ctx context.Context) Summary {
	if ctx == nil {
		ctx = context.Background()
	}
	sum := Summary{
		Suite: "offline",
		Residuals: []string{
			"Live AgentCore / Entra network acquisition not exercised (GWY-003 full pin residual)",
			// Offline vault hit/miss + mock IdP outage + JWKS kid-lite + mode A/B/C matrix are exercised below (Done*).
			// Live Entra JWKS rotation under load / real IdP outage remain residual.
			"Live Entra JWKS rotation under load and live IdP outage chaos remain residual (offline vault hit/miss + mock IdP outage + JWKS kid-lite + mode A/B/C matrix Done*)",
			"Mode B live jwt-auth-filter / IdP pin residual (OAUTH-009); offline JWT vault Bearer + claim fail-closed matrix Done*",
			"OAUTH-009 offline: wrong aud/exp/iss rejected; ID token never API credential; Mode B Obtain never Basic fallthrough — live RS pin still open",
			"Mode C live Entra 3LO/OBO + AgentCore Identity vault residual (OAUTH-010 / GWY-003); offline Live=false / mock Fetcher / auth_code consent / token_exchange / wrong audience Done* (oauth010_mode_c_offline_matrix + mode_c_agentcore_live_matrix)",
			"OAUTH-010: HTTPTokenFetcher https mock AS covered in package tests (TestOAUTH010_* / TestHTTPTokenFetcher_*); do not claim live Entra Done",
			"Opt-in residual lab: testdata/oauth-lab + make live-oauth-* (HOST-012…015); go test -tags=live_oauth Mode C Obtain vs mock-token via TLS test shim (HTTPTokenFetcher https-only; lab is HTTP loopback — TLS residual; not production Entra / jwt-auth-filter / AgentCore vault)",
			"Cross-link: docs/auth/oauth-capability-matrix.md §4 + docs/auth/jwt-auth-filter-qualification.md + docs/gateway/qualification.md (GWY-003 / OAUTH-010)",
			"P95/P99 live token acquisition SLOs require production pin evidence",
			"Generic-token passthrough remains disabled; exact-audience exception is residual approval",
		},
	}

	run := func(name, category string, fn func(context.Context) error) {
		start := time.Now()
		err := fn(ctx)
		cr := CaseResult{
			Name:       name,
			Category:   category,
			DurationMs: time.Since(start).Milliseconds(),
		}
		if err != nil {
			cr.Passed = false
			cr.Detail = safeDetail(err)
			sum.Failed++
		} else {
			cr.Passed = true
			sum.Passed++
		}
		sum.Cases = append(sum.Cases, cr)
	}

	// --- Security cases ---
	run("jenkins_as_as_rejected", "security", caseJenkinsAsAS)
	run("wrong_audience_rejected", "security", caseWrongAudience)
	run("wrong_subject_binding_rejected", "security", caseWrongSubjectBinding)
	run("subject_binding_contracts", "security", caseSubjectBindingContracts)
	run("token_never_in_errors", "security", caseTokenNeverInErrors)
	run("consent_url_has_no_token", "security", caseConsentURLNoToken)
	run("cross_user_cache_isolation", "security", caseCrossUserCacheIsolation)
	run("vault_hit_miss", "security", caseVaultHitMiss)
	run("idp_outage_chaos", "security", caseIdPOutageChaos)
	run("jwks_key_rotation_lite", "security", caseJWKSKeyRotationLite)

	// --- HOST-011 modes A/B/C offline Obtain matrix (GWY-003 qualify rows) ---
	run("mode_a_vault_obtain_basic", "security", caseModeAVaultObtainBasic)
	run("mode_b_jwt_vault_bearer", "security", caseModeBJWTVaultBearer)
	run("mode_c_agentcore_live_matrix", "security", caseModeCAgentCoreLiveMatrix)
	run("host011_no_silent_fallthrough", "security", caseHOST011NoSilentFallthrough)
	// OAUTH-009 offline foundations (claim fail-closed + classifier + Mode B no Basic).
	run("oauth009_offline_bearer_matrix", "security", caseOAUTH009OfflineBearerMatrix)
	// OAUTH-010 Mode C prototype matrix (auth_code consent + OBO exchange + Live gates).
	// Complements mode_c_agentcore_live_matrix (HOST-011 row) with flow-mode honesty.
	run("oauth010_mode_c_offline_matrix", "security", caseOAUTH010ModeCOfflineMatrix)

	// --- Performance cases (mock) ---
	run("concurrent_obtain_stub_under_budget", "performance", caseConcurrentObtain)
	run("fail_closed_obtain_latency", "performance", caseFailClosedLatency)

	sum.OK = sum.Failed == 0
	return sum
}

func safeDetail(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	if strings.Contains(msg, CanaryToken) {
		return "error detail redacted (contained canary)"
	}
	// Bound length for JSON summary.
	if len(msg) > 240 {
		return msg[:240] + "…"
	}
	return msg
}

func validASCfg() gateway.AgentCoreConfig {
	return gateway.AgentCoreConfig{
		AuthorizationServerBaseURL: "https://login.microsoftonline.com/tenant/v2.0",
		Audience:                   "api://jenkins-api",
		ClientID:                   "public-client",
		Mode:                       gateway.ModeAuthorizationCode,
		JenkinsBaseURL:             "https://jenkins.example.com",
	}
}

func caseJenkinsAsAS(ctx context.Context) error {
	_ = ctx
	err := gateway.ValidateProviderConfig(gateway.AgentCoreConfig{
		AuthorizationServerBaseURL: "https://jenkins.example.com",
		Audience:                   "api://jenkins-api",
		JenkinsBaseURL:             "https://jenkins.example.com",
	})
	if err == nil {
		return fmt.Errorf("expected Jenkins-as-AS rejection")
	}
	if apperr.CodeOf(err) != apperr.CodeInvalidArgument {
		return fmt.Errorf("code %v", apperr.CodeOf(err))
	}
	if !strings.Contains(strings.ToLower(err.Error()), "jenkins") {
		return fmt.Errorf("expected jenkins wording: %v", err)
	}
	return nil
}

func caseWrongAudience(ctx context.Context) error {
	_ = ctx
	// Use the shared OAUTH-006 claim validator (exact Jenkins API audience).
	expected := "api://jenkins-api"
	wrong := map[string]any{"aud": "api://graph.microsoft.com", "sub": "u1"}
	if err := auth.ValidateAudienceClaim(wrong, expected); err == nil {
		return fmt.Errorf("wrong audience must be rejected")
	}
	okClaims := map[string]any{"aud": expected, "sub": "u1"}
	if err := auth.ValidateAudienceClaim(okClaims, expected); err != nil {
		return err
	}
	// Multi-valued aud must still require exact resource membership.
	multi := map[string]any{"aud": []any{"api://other", expected}}
	if err := auth.ValidateAudienceClaim(multi, expected); err != nil {
		return err
	}
	return nil
}

func caseWrongSubjectBinding(ctx context.Context) error {
	_ = ctx
	claims := gateway.InboundClaims{
		Subject: "user-a", Tenant: "t", WorkloadID: "w", ProfileID: "corp",
		JenkinsPrincipal: "alice", Verified: true,
	}
	b, err := gateway.NewBinding(claims, gateway.DefaultBindOptions(), time.Minute)
	if err != nil {
		return err
	}
	changed := claims
	changed.Subject = "user-b"
	if _, err := b.Revalidate(changed, gateway.DefaultBindOptions()); err == nil {
		return fmt.Errorf("wrong subject binding must fail closed")
	}
	// Tool-arg identity override rejected.
	if err := gateway.RejectIdentityToolArgs(map[string]any{"as_user": "bob"}); err == nil {
		return fmt.Errorf("tool args must not change identity")
	}
	return nil
}

// caseSubjectBindingContracts exercises GWY-002 offline binding rules:
// missing tenant/workload/subject, principal mismatch, Valid() only with
// Jenkins principal, group overage fail-closed default.
func caseSubjectBindingContracts(ctx context.Context) error {
	_ = ctx
	opts := gateway.DefaultBindOptions()
	ok := gateway.InboundClaims{
		Subject: "user-a", Tenant: "t", WorkloadID: "w", ProfileID: "corp",
		JenkinsPrincipal: "alice", Verified: true,
	}
	s, err := gateway.BindSubject(ok, opts)
	if err != nil {
		return err
	}
	if !s.Valid() {
		return fmt.Errorf("bound subject with jenkins principal must be Valid()")
	}

	// Missing each required field fails closed.
	for _, tc := range []struct {
		name string
		c    gateway.InboundClaims
	}{
		{"tenant", gateway.InboundClaims{Subject: "s", WorkloadID: "w", ProfileID: "corp", Verified: true}},
		{"workload", gateway.InboundClaims{Subject: "s", Tenant: "t", ProfileID: "corp", Verified: true}},
		{"subject", gateway.InboundClaims{Tenant: "t", WorkloadID: "w", ProfileID: "corp", Verified: true}},
		{"profile", gateway.InboundClaims{Subject: "s", Tenant: "t", WorkloadID: "w", Verified: true}},
	} {
		if _, err := gateway.BindSubject(tc.c, opts); err == nil {
			return fmt.Errorf("missing %s must fail closed", tc.name)
		}
	}

	// Env principal vs whoAmI mismatch.
	env := map[string]string{
		gateway.EnvGatewaySubject:          "entra-sub",
		gateway.EnvGatewayTenant:           "tid",
		gateway.EnvGatewayWorkload:         "wl",
		gateway.EnvGatewayJenkinsPrincipal: "bob",
	}
	_, err = gateway.BindSubjectFromEnviron("corp", "alice", func(k string) string { return env[k] })
	if err == nil || !strings.Contains(err.Error(), "whoAmI") {
		return fmt.Errorf("principal mismatch must fail closed: %v", err)
	}

	// Without Jenkins principal, Valid() is false (not RBAC-ready).
	unbound, err := gateway.BindSubject(gateway.InboundClaims{
		Subject: "s", Tenant: "t", WorkloadID: "w", ProfileID: "corp", Verified: true,
	}, opts)
	if err != nil {
		return err
	}
	if unbound.Valid() {
		return fmt.Errorf("subject without jenkins principal must not be Valid()")
	}

	// Default FailOnGroupOverage.
	groups := make([]string, gateway.MaxInboundGroups+1)
	for i := range groups {
		groups[i] = fmt.Sprintf("g-%d", i)
	}
	if _, err := gateway.BindSubject(gateway.InboundClaims{
		Subject: "s", Tenant: "t", WorkloadID: "w", ProfileID: "corp",
		Groups: groups, Verified: true,
	}, opts); err == nil {
		return fmt.Errorf("group overage must fail closed by default")
	}
	return nil
}

func caseTokenNeverInErrors(ctx context.Context) error {
	// Plant canary in Credential / CachedToken / ConsentRequired error paths.
	cred := gateway.Credential{
		AccessToken:      CanaryToken,
		JenkinsPrincipal: "alice",
		Mode:             gateway.ModeTokenExchange,
	}
	if strings.Contains(cred.String(), CanaryToken) {
		return fmt.Errorf("Credential.String leaked canary")
	}
	tok := gateway.CachedToken{
		AccessToken:      CanaryToken,
		JenkinsPrincipal: "alice",
		Mode:             gateway.ModeOBO,
	}
	if strings.Contains(tok.String(), CanaryToken) {
		return fmt.Errorf("CachedToken.String leaked canary")
	}
	p := gateway.UnconfiguredProvider{Reason: "not_configured qualify"}
	_, err := p.Obtain(ctx, gateway.Caller{Subject: "s", ProfileID: "p"})
	if err == nil {
		return fmt.Errorf("expected fail closed obtain")
	}
	if strings.Contains(err.Error(), CanaryToken) {
		return fmt.Errorf("Obtain error leaked canary")
	}
	// Consent error path.
	cerr := gateway.NewConsentRequired(gateway.ConsentInfo{
		AuthorizationURL: "https://login.microsoftonline.com/t/oauth2/v2.0/authorize?state=abc",
		SessionID:        "sess-qualify-1",
		Provider:         "agentcore",
	})
	if cerr == nil || strings.Contains(cerr.Error(), CanaryToken) {
		return fmt.Errorf("consent error leaked or nil: %v", cerr)
	}
	return nil
}

func caseConsentURLNoToken(ctx context.Context) error {
	_ = ctx
	// Consent metadata must not embed access/refresh tokens.
	info := gateway.ConsentInfo{
		AuthorizationURL: "https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize?client_id=public&response_type=code&state=xyz",
		SessionID:        "opaque-session-id",
		Provider:         "agentcore",
	}
	if !info.Valid() {
		return fmt.Errorf("consent info invalid")
	}
	blob := info.AuthorizationURL + " " + info.SessionID + " " + info.String() + " " + fmt.Sprint(info.StatusMap())
	for _, bad := range []string{
		CanaryToken,
		"access_token=",
		"refresh_token=",
		"client_secret=",
	} {
		if strings.Contains(strings.ToLower(blob), strings.ToLower(bad)) {
			return fmt.Errorf("consent surface contained %q", bad)
		}
	}
	// Explicitly reject consent that tries to smuggle a token as session id
	// only at the application layer; harness documents the rule.
	if strings.Contains(info.AuthorizationURL, CanaryToken) {
		return fmt.Errorf("authorization URL must not embed canary token")
	}
	return nil
}

func caseCrossUserCacheIsolation(ctx context.Context) error {
	_ = ctx
	c := gateway.NewMemoryTokenCache(time.Hour)
	userA := gateway.CacheKey{User: "user-a", Workload: "wl", Profile: "corp"}
	userB := gateway.CacheKey{User: "user-b", Workload: "wl", Profile: "corp"}
	c.Set(userA, gateway.CachedToken{
		AccessToken:      CanaryToken + "-a",
		JenkinsPrincipal: "alice",
		Mode:             gateway.ModeAuthorizationCode,
		ExpiresAt:        time.Now().Add(time.Hour),
	})
	c.Set(userB, gateway.CachedToken{
		AccessToken:      CanaryToken + "-b",
		JenkinsPrincipal: "bob",
		Mode:             gateway.ModeAuthorizationCode,
		ExpiresAt:        time.Now().Add(time.Hour),
	})
	gotA, okA := c.Get(userA)
	gotB, okB := c.Get(userB)
	if !okA || !okB {
		return fmt.Errorf("cache miss")
	}
	if gotA.AccessToken == gotB.AccessToken {
		return fmt.Errorf("cross-user token collision")
	}
	if gotA.JenkinsPrincipal != "alice" || gotB.JenkinsPrincipal != "bob" {
		return fmt.Errorf("principal mix-up")
	}
	// Different workload must not share.
	if _, ok := c.Get(gateway.CacheKey{User: "user-a", Workload: "other", Profile: "corp"}); ok {
		return fmt.Errorf("cross-workload leak")
	}
	// Different profile must not share.
	if _, ok := c.Get(gateway.CacheKey{User: "user-a", Workload: "wl", Profile: "other"}); ok {
		return fmt.Errorf("cross-profile leak")
	}
	return nil
}

// caseVaultHitMiss proves process memory vault (MemoryTokenCache) hit/miss via
// AgentCoreProvider Live + counting mock Fetcher: second Obtain is a cache hit
// (fetch count 1); Invalidate/Clear force miss and refetch; cross-user isolation.
func caseVaultHitMiss(ctx context.Context) error {
	var calls atomic.Int32
	cache := gateway.NewMemoryTokenCache(time.Hour)
	p, err := gateway.NewAgentCoreProvider(validASCfg(), cache)
	if err != nil {
		return err
	}
	p.Live = true
	p.Fetcher = gateway.FuncTokenFetcher(func(ctx context.Context, caller gateway.Caller, cfg gateway.AgentCoreConfig) (gateway.Credential, error) {
		n := calls.Add(1)
		return gateway.Credential{
			AccessToken:      CanaryToken + fmt.Sprintf("-vault-%d-%s", n, caller.Subject),
			ExpiresAt:        time.Now().Add(time.Hour),
			JenkinsPrincipal: "jp-" + caller.Subject,
			Mode:             gateway.ModeTokenExchange,
		}, nil
	})

	callerA := gateway.Caller{
		Subject: "user-vault-a", Tenant: "t", WorkloadID: "wl",
		ProfileID: contracts.ProfileID("corp"),
	}
	callerB := gateway.Caller{
		Subject: "user-vault-b", Tenant: "t", WorkloadID: "wl",
		ProfileID: contracts.ProfileID("corp"),
	}

	c1, err := p.Obtain(ctx, callerA)
	if err != nil {
		return fmt.Errorf("first obtain: %w", err)
	}
	if c1.AccessToken == "" {
		return fmt.Errorf("empty token on first obtain")
	}

	c2, err := p.Obtain(ctx, callerB)
	if err != nil {
		return fmt.Errorf("user-b obtain: %w", err)
	}
	// Hit for same caller: Fetcher must not run again for A.
	c1b, err := p.Obtain(ctx, callerA)
	if err != nil {
		return fmt.Errorf("cache hit obtain: %w", err)
	}
	if c1b.AccessToken != c1.AccessToken {
		return fmt.Errorf("cache hit returned different token material")
	}
	// Two users + one hit → Fetcher called twice only (A miss, B miss; A hit).
	if got := calls.Load(); got != 2 {
		return fmt.Errorf("fetcher calls after hit path = %d; want 2 (A miss + B miss, A hit)", got)
	}
	if c1.AccessToken == c2.AccessToken {
		return fmt.Errorf("cross-user token collision on vault path")
	}
	if c1.JenkinsPrincipal == c2.JenkinsPrincipal {
		return fmt.Errorf("cross-user principal mix-up")
	}

	// Invalidate A → miss → fetch again.
	if err := p.Invalidate(ctx, callerA); err != nil {
		return err
	}
	c1c, err := p.Obtain(ctx, callerA)
	if err != nil {
		return fmt.Errorf("post-invalidate obtain: %w", err)
	}
	if got := calls.Load(); got != 3 {
		return fmt.Errorf("fetcher calls after invalidate = %d; want 3", got)
	}
	if c1c.AccessToken == c1.AccessToken {
		return fmt.Errorf("post-invalidate token should be new material")
	}
	// B still cached (isolation: Invalidate A must not drop B).
	beforeB := calls.Load()
	c2b, err := p.Obtain(ctx, callerB)
	if err != nil {
		return err
	}
	if calls.Load() != beforeB {
		return fmt.Errorf("invalidate A must not force B refetch")
	}
	if c2b.AccessToken != c2.AccessToken {
		return fmt.Errorf("B cache broken after A invalidate")
	}

	// Clear → full miss for remaining entries.
	cache.Clear()
	if _, err := p.Obtain(ctx, callerA); err != nil {
		return fmt.Errorf("post-clear A: %w", err)
	}
	if _, err := p.Obtain(ctx, callerB); err != nil {
		return fmt.Errorf("post-clear B: %w", err)
	}
	if got := calls.Load(); got != 5 {
		return fmt.Errorf("fetcher calls after clear = %d; want 5", got)
	}

	// Canary never in Credential.String / errors / Status.
	if strings.Contains(c1.String(), CanaryToken) {
		return fmt.Errorf("Credential.String leaked canary")
	}
	st := p.Status(ctx)
	if strings.Contains(fmt.Sprintf("%+v", st), CanaryToken) {
		return fmt.Errorf("Status leaked canary")
	}
	return nil
}

// caseIdPOutageChaos proves mock IdP/fetcher failures fail closed (no token,
// canary absent from errors), timeouts map cleanly, and recovery succeeds.
func caseIdPOutageChaos(ctx context.Context) error {
	cache := gateway.NewMemoryTokenCache(time.Hour)
	p, err := gateway.NewAgentCoreProvider(validASCfg(), cache)
	if err != nil {
		return err
	}
	p.Live = true
	caller := gateway.Caller{
		Subject: "user-outage", Tenant: "t", WorkloadID: "wl",
		ProfileID: contracts.ProfileID("corp"),
	}

	// Phase 1: generic IdP error that embeds canary in upstream text.
	p.Fetcher = gateway.FuncTokenFetcher(func(ctx context.Context, caller gateway.Caller, cfg gateway.AgentCoreConfig) (gateway.Credential, error) {
		return gateway.Credential{}, errors.New("idp unavailable upstream token=" + CanaryToken)
	})
	cred, err := p.Obtain(ctx, caller)
	if err == nil {
		return fmt.Errorf("expected IdP error fail closed")
	}
	if cred.AccessToken != "" {
		return fmt.Errorf("token present on IdP error path")
	}
	if apperr.CodeOf(err) != apperr.CodeAuthentication {
		return fmt.Errorf("idp error code %v want authentication", apperr.CodeOf(err))
	}
	if strings.Contains(err.Error(), CanaryToken) {
		return fmt.Errorf("canary in mapped IdP error: %v", err)
	}

	// Phase 2: deadline exceeded (timeout chaos).
	p.Fetcher = gateway.FuncTokenFetcher(func(ctx context.Context, caller gateway.Caller, cfg gateway.AgentCoreConfig) (gateway.Credential, error) {
		return gateway.Credential{}, context.DeadlineExceeded
	})
	cred, err = p.Obtain(ctx, caller)
	if err == nil {
		return fmt.Errorf("expected timeout fail closed")
	}
	if cred.AccessToken != "" {
		return fmt.Errorf("token present on timeout path")
	}
	if apperr.CodeOf(err) != apperr.CodeTimeout {
		return fmt.Errorf("timeout code %v want timeout", apperr.CodeOf(err))
	}
	if strings.Contains(err.Error(), CanaryToken) {
		return fmt.Errorf("canary in timeout error")
	}

	// Phase 3: cancelled (still fail closed, no token).
	p.Fetcher = gateway.FuncTokenFetcher(func(ctx context.Context, caller gateway.Caller, cfg gateway.AgentCoreConfig) (gateway.Credential, error) {
		return gateway.Credential{}, context.Canceled
	})
	cred, err = p.Obtain(ctx, caller)
	if err == nil || cred.AccessToken != "" {
		return fmt.Errorf("cancel path must fail closed without token: cred=%v err=%v", cred, err)
	}
	if apperr.CodeOf(err) != apperr.CodeCancelled {
		return fmt.Errorf("cancel code %v", apperr.CodeOf(err))
	}

	// Nothing must have been cached during outage phases.
	if _, ok := cache.Get(caller.CacheKey()); ok {
		return fmt.Errorf("cache must stay empty after outage failures")
	}

	// Phase 4: recovery — IdP healthy again → Obtain succeeds once.
	var calls atomic.Int32
	p.Fetcher = gateway.FuncTokenFetcher(func(ctx context.Context, caller gateway.Caller, cfg gateway.AgentCoreConfig) (gateway.Credential, error) {
		calls.Add(1)
		return gateway.Credential{
			AccessToken:      CanaryToken + "-recovered",
			ExpiresAt:        time.Now().Add(time.Hour),
			JenkinsPrincipal: "jp-recovered",
			Mode:             gateway.ModeTokenExchange,
		}, nil
	})
	got, err := p.Obtain(ctx, caller)
	if err != nil {
		return fmt.Errorf("recovery obtain: %w", err)
	}
	if got.AccessToken == "" || got.JenkinsPrincipal != "jp-recovered" {
		return fmt.Errorf("recovery credential incomplete")
	}
	// Hit after recovery must not re-fetch.
	if _, err := p.Obtain(ctx, caller); err != nil {
		return err
	}
	if calls.Load() != 1 {
		return fmt.Errorf("recovery fetch count %d want 1", calls.Load())
	}
	if strings.Contains(got.String(), CanaryToken) {
		return fmt.Errorf("recovery Credential.String leaked canary")
	}
	return nil
}

// caseJWKSKeyRotationLite exercises offline JWKS kid selection + outage fail-closed
// contracts, plus a key_id-version-aware mock fetcher (stale key rejected).
// Partial by design: no live Entra JWKS fetch/rotation under load (residual).
func caseJWKSKeyRotationLite(ctx context.Context) error {
	// Pure outage contracts (MCP-side): unavailable JWKS never allows verify.
	for _, avail := range []auth.JWKSAvailability{
		auth.JWKSUnreachable, auth.JWKSEmpty, auth.JWKSNil,
	} {
		r := auth.EvaluateJWKSOutageForVerification(avail)
		if r.MayVerify || !r.FailClosed {
			return fmt.Errorf("JWKS %s must fail closed (got %+v)", avail, r)
		}
	}
	if ok := auth.EvaluateJWKSOutageForVerification(auth.JWKSAvailable); !ok.MayVerify {
		return fmt.Errorf("available JWKS must allow verify")
	}
	if d := auth.EvaluateJWKSOutageBehavior(auth.RequiredJWKSOutageBehavior); !d.Acceptable {
		return fmt.Errorf("RequiredJWKSOutageBehavior must be acceptable")
	}
	if d := auth.EvaluateJWKSOutageBehavior(auth.JWKSOutageFailOpen); d.Acceptable {
		return fmt.Errorf("fail_open must be unacceptable")
	}

	// Kid rotation lite: multi-key set accepts current/overlap kids; removed kid fails.
	kCurrent, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return fmt.Errorf("rsa current: %w", err)
	}
	kStale, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return fmt.Errorf("rsa stale: %w", err)
	}
	jwk := func(kid string, pub *rsa.PublicKey) auth.JWK {
		return auth.JWK{
			Kty: "RSA", Kid: kid, Use: "sig", Alg: "RS256",
			N: base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}
	}
	// Rotation overlap: both kids present.
	overlap := &auth.JWKS{Keys: []auth.JWK{
		jwk("kid-current", &kCurrent.PublicKey),
		jwk("kid-stale", &kStale.PublicKey),
	}}
	if _, err := overlap.KeyByID("kid-current"); err != nil {
		return fmt.Errorf("overlap current kid: %w", err)
	}
	if _, err := overlap.KeyByID("kid-stale"); err != nil {
		return fmt.Errorf("overlap stale kid still present: %w", err)
	}
	if _, err := overlap.KeyByID("kid-unknown"); err == nil {
		return fmt.Errorf("unknown kid must fail closed")
	}
	// After rotation: only current remains → stale kid rejected.
	post := &auth.JWKS{Keys: []auth.JWK{jwk("kid-current", &kCurrent.PublicKey)}}
	if _, err := post.KeyByID("kid-stale"); err == nil {
		return fmt.Errorf("stale kid after rotation must fail closed")
	}
	if _, err := post.KeyByID("kid-current"); err != nil {
		return fmt.Errorf("current kid after rotation: %w", err)
	}
	// Multi-key without kid is ambiguous → fail closed.
	if _, err := overlap.KeyByID(""); err == nil {
		return fmt.Errorf("multi-key empty kid must fail closed")
	}

	// Fetcher key_id version field: stale presented key rejected; current accepted.
	const acceptedKeyID = "kid-current"
	var presented atomic.Value // string
	presented.Store("kid-stale")
	cache := gateway.NewMemoryTokenCache(time.Hour)
	p, err := gateway.NewAgentCoreProvider(validASCfg(), cache)
	if err != nil {
		return err
	}
	p.Live = true
	p.Fetcher = gateway.FuncTokenFetcher(func(ctx context.Context, caller gateway.Caller, cfg gateway.AgentCoreConfig) (gateway.Credential, error) {
		kid, _ := presented.Load().(string)
		if strings.TrimSpace(kid) != acceptedKeyID {
			// Fail closed; never return token or embed canary.
			return gateway.Credential{}, apperr.New(apperr.CodeAuthentication,
				"token signing key_id is not accepted (stale or unknown after rotation)")
		}
		return gateway.Credential{
			AccessToken:      CanaryToken + "-kid-ok",
			ExpiresAt:        time.Now().Add(time.Hour),
			JenkinsPrincipal: "jp-kid",
			Mode:             gateway.ModeTokenExchange,
		}, nil
	})
	caller := gateway.Caller{
		Subject: "user-kid", Tenant: "t", WorkloadID: "wl",
		ProfileID: contracts.ProfileID("corp"),
	}
	cred, err := p.Obtain(ctx, caller)
	if err == nil || cred.AccessToken != "" {
		return fmt.Errorf("stale key_id must fail closed without token: err=%v", err)
	}
	if apperr.CodeOf(err) != apperr.CodeAuthentication {
		return fmt.Errorf("stale key_id code %v", apperr.CodeOf(err))
	}
	if strings.Contains(err.Error(), CanaryToken) {
		return fmt.Errorf("canary in stale key_id error")
	}
	// Recovery to current key_id.
	presented.Store(acceptedKeyID)
	okCred, err := p.Obtain(ctx, caller)
	if err != nil {
		return fmt.Errorf("current key_id obtain: %w", err)
	}
	if okCred.AccessToken == "" {
		return fmt.Errorf("current key_id empty token")
	}
	if strings.Contains(okCred.String(), CanaryToken) {
		return fmt.Errorf("canary in Credential.String after key_id ok")
	}
	return nil
}

// caseModeAVaultObtainBasic — HOST-011 Mode A offline row:
// vault Obtain → Basic for subject; cross-subject miss; secret canary.
func caseModeAVaultObtainBasic(ctx context.Context) error {
	v := gateway.NewMemoryAPITokenVault()
	callerA := gateway.Caller{
		Subject: "user-mode-a", Tenant: "t", WorkloadID: "wl",
		ProfileID: contracts.ProfileID("corp"),
	}
	callerB := gateway.Caller{
		Subject: "user-mode-a-other", Tenant: "t", WorkloadID: "wl",
		ProfileID: contracts.ProfileID("corp"),
	}
	if err := v.Put(ctx, gateway.SubjectKey(callerA), "alice", CanaryToken+"-modeA"); err != nil {
		return fmt.Errorf("vault put: %w", err)
	}
	p, err := gateway.RequireAPITokenVaultSetup(v)
	if err != nil {
		return err
	}
	if p.Mode() != gateway.ModeAPITokenVault {
		return fmt.Errorf("mode want api_token_vault got %s", p.Mode())
	}

	// Obtain + HTTP auth shape = Basic for subject.
	auth, err := gateway.ObtainHTTPAuth(ctx, p, callerA)
	if err != nil {
		return fmt.Errorf("mode A obtain: %w", err)
	}
	if auth.Scheme != gateway.HTTPAuthSchemeBasic || auth.Username != "alice" {
		return fmt.Errorf("mode A must be Basic alice: %+v", auth)
	}
	if auth.Token != CanaryToken+"-modeA" {
		return fmt.Errorf("mode A token material mismatch")
	}
	if strings.Contains(auth.String(), CanaryToken) {
		return fmt.Errorf("mode A HTTPAuth.String leaked canary")
	}

	// Cross-subject miss: other subject has no vault entry.
	cred, err := p.Obtain(ctx, callerB)
	if err == nil || apperr.CodeOf(err) != apperr.CodeNotFound {
		return fmt.Errorf("cross-subject miss want not_found: err=%v", err)
	}
	if cred.AccessToken != "" {
		return fmt.Errorf("cross-subject must not return token")
	}
	if strings.Contains(err.Error(), CanaryToken) {
		return fmt.Errorf("mode A canary in cross-subject error")
	}

	// Credential.String / Status never leak canary.
	okCred, err := p.Obtain(ctx, callerA)
	if err != nil {
		return err
	}
	if strings.Contains(okCred.String(), CanaryToken) {
		return fmt.Errorf("mode A Credential.String leaked canary")
	}
	st := p.Status(ctx)
	if strings.Contains(fmt.Sprintf("%+v", st), CanaryToken) {
		return fmt.Errorf("mode A Status leaked canary")
	}
	return nil
}

// caseModeBJWTVaultBearer — HOST-011 Mode B offline row:
// JWT vault Obtain → Bearer; ID token reject; wrong subject miss.
func caseModeBJWTVaultBearer(ctx context.Context) error {
	v := gateway.NewMemoryJWTVault()
	callerA := gateway.Caller{
		Subject: "user-mode-b", Tenant: "t", WorkloadID: "wl",
		ProfileID: contracts.ProfileID("corp"),
	}
	callerB := gateway.Caller{
		Subject: "user-mode-b-other", Tenant: "t", WorkloadID: "wl",
		ProfileID: contracts.ProfileID("corp"),
	}
	// Access-token shaped JWT (token_use=access_token) accepted.
	at := compactJWTClaims(map[string]string{
		"sub": "user-mode-b", "token_use": "access_token", "aud": "api://jenkins-api",
	})
	if err := v.Put(ctx, gateway.SubjectKey(callerA), at); err != nil {
		return fmt.Errorf("jwt vault put access: %w", err)
	}
	// Opaque lab token for second subject isolation path is separate.

	p, err := gateway.RequireJWTRSBearerSetup(v)
	if err != nil {
		return err
	}
	if p.Mode() != gateway.ModeJWTRSBearer {
		return fmt.Errorf("mode want jwt_rs_bearer got %s", p.Mode())
	}

	auth, err := gateway.ObtainHTTPAuth(ctx, p, callerA)
	if err != nil {
		return fmt.Errorf("mode B obtain: %w", err)
	}
	if auth.Scheme != gateway.HTTPAuthSchemeBearer || auth.Username != "" {
		return fmt.Errorf("mode B must be Bearer without username: %+v", auth)
	}
	if auth.Token != at {
		return fmt.Errorf("mode B token material mismatch")
	}
	if strings.Contains(auth.String(), at) || strings.Contains(auth.String(), CanaryToken) {
		return fmt.Errorf("mode B HTTPAuth.String leaked token")
	}

	// Wrong subject miss.
	cred, err := p.Obtain(ctx, callerB)
	if err == nil || apperr.CodeOf(err) != apperr.CodeNotFound {
		return fmt.Errorf("wrong subject miss want not_found: err=%v", err)
	}
	if cred.AccessToken != "" {
		return fmt.Errorf("wrong subject must not return token")
	}
	if strings.Contains(err.Error(), at) || strings.Contains(err.Error(), CanaryToken) {
		return fmt.Errorf("mode B canary/token in wrong-subject error")
	}

	// ID token reject (HOST-010): vault Put and Obtain must fail closed.
	idTok := compactJWTClaims(map[string]string{
		"sub": "user-mode-b", "token_use": "id_token",
	})
	putErr := v.Put(ctx, gateway.SubjectKey(callerB), idTok)
	if putErr == nil {
		return fmt.Errorf("id_token must be rejected at vault Put")
	}
	if apperr.CodeOf(putErr) != apperr.CodeInvalidArgument {
		return fmt.Errorf("id_token Put code %v", apperr.CodeOf(putErr))
	}
	if strings.Contains(putErr.Error(), idTok) {
		return fmt.Errorf("id_token material in Put error")
	}
	// Defense-in-depth: even if put bypassed via corrupt path, Obtain rejects.
	// Memory vault cannot store id_token; assert residual wording path via Put only.
	// Canary check on Status.
	st := p.Status(ctx)
	if strings.Contains(fmt.Sprintf("%+v", st), CanaryToken) || strings.Contains(fmt.Sprintf("%+v", st), at) {
		return fmt.Errorf("mode B Status leaked token material")
	}
	return nil
}

// caseModeCAgentCoreLiveMatrix — HOST-011 Mode C offline row:
// Live=false → not_configured; Live+mock Fetcher → Bearer; wrong audience fail;
// ConsentRequired metadata only (no tokens).
func caseModeCAgentCoreLiveMatrix(ctx context.Context) error {
	cfg := validASCfg()
	cfg.Mode = gateway.ModeTokenExchange
	cache := gateway.NewMemoryTokenCache(time.Hour)
	p, err := gateway.NewAgentCoreProvider(cfg, cache)
	if err != nil {
		return err
	}
	caller := gateway.Caller{
		Subject: "user-mode-c", Tenant: "t", WorkloadID: "wl",
		ProfileID: contracts.ProfileID("corp"),
	}

	// Live=false (default) → not_configured; no token elevation from empty cache.
	if p.Live {
		return fmt.Errorf("default AgentCore Live must be false")
	}
	cred, err := p.Obtain(ctx, caller)
	if err == nil || apperr.CodeOf(err) != apperr.CodeCapabilityMissing {
		return fmt.Errorf("Live=false want not_configured/capability_missing: err=%v", err)
	}
	if cred.AccessToken != "" {
		return fmt.Errorf("Live=false must not return token")
	}
	if strings.Contains(err.Error(), CanaryToken) {
		return fmt.Errorf("Live=false error leaked canary")
	}
	st := p.Status(ctx)
	if st.Ready {
		return fmt.Errorf("Live=false Status must not be Ready: %+v", st)
	}

	// Live + mock Fetcher → Bearer credential.
	p.Live = true
	p.Fetcher = gateway.FuncTokenFetcher(func(ctx context.Context, c gateway.Caller, cfg gateway.AgentCoreConfig) (gateway.Credential, error) {
		return gateway.Credential{
			AccessToken:      CanaryToken + "-modeC-" + c.Subject,
			ExpiresAt:        time.Now().Add(time.Hour),
			JenkinsPrincipal: "jp-" + c.Subject,
			Mode:             gateway.ModeTokenExchange,
		}, nil
	})
	auth, err := gateway.ObtainHTTPAuth(ctx, p, caller)
	if err != nil {
		return fmt.Errorf("mode C live mock obtain: %w", err)
	}
	if auth.Scheme != gateway.HTTPAuthSchemeBearer || auth.Username != "" {
		return fmt.Errorf("mode C must be Bearer: %+v", auth)
	}
	if auth.Token != CanaryToken+"-modeC-"+caller.Subject {
		return fmt.Errorf("mode C token mismatch")
	}
	if strings.Contains(auth.String(), CanaryToken) {
		return fmt.Errorf("mode C HTTPAuth.String leaked canary")
	}

	// Wrong audience fail closed (no token; canary absent).
	// Clear cache so fetcher runs again.
	cache.Clear()
	p.Fetcher = gateway.FuncTokenFetcher(func(ctx context.Context, c gateway.Caller, cfg gateway.AgentCoreConfig) (gateway.Credential, error) {
		// Same residual shape as HTTPTokenFetcher wrong-audience path.
		return gateway.Credential{}, apperr.New(apperr.CodeAuthentication,
			"token audience does not match configured Jenkins API resource")
	})
	cred, err = p.Obtain(ctx, caller)
	if err == nil || cred.AccessToken != "" {
		return fmt.Errorf("wrong audience must fail closed without token: err=%v", err)
	}
	if apperr.CodeOf(err) != apperr.CodeAuthentication {
		return fmt.Errorf("wrong audience code %v", apperr.CodeOf(err))
	}
	if !strings.Contains(strings.ToLower(err.Error()), "audience") {
		return fmt.Errorf("wrong audience wording: %v", err)
	}
	if strings.Contains(err.Error(), CanaryToken) {
		return fmt.Errorf("wrong audience error leaked canary")
	}

	// ConsentRequired metadata only (URL + session; no access/refresh tokens).
	p.Fetcher = gateway.FuncTokenFetcher(func(ctx context.Context, c gateway.Caller, cfg gateway.AgentCoreConfig) (gateway.Credential, error) {
		return gateway.Credential{}, gateway.NewConsentRequired(gateway.ConsentInfo{
			AuthorizationURL: "https://login.microsoftonline.com/t/oauth2/v2.0/authorize?client_id=public&state=xyz",
			SessionID:        "sess-mode-c-qualify",
			Provider:         "agentcore",
		})
	})
	cred, err = p.Obtain(ctx, caller)
	if err == nil || cred.AccessToken != "" {
		return fmt.Errorf("consent path must fail closed without token")
	}
	cr, ok := gateway.AsConsentRequired(err)
	if !ok || cr == nil {
		return fmt.Errorf("want ConsentRequired got %T %v", err, err)
	}
	if !cr.Info.Valid() {
		return fmt.Errorf("consent info invalid: %+v", cr.Info)
	}
	blob := err.Error() + " " + cr.Info.String() + " " + fmt.Sprint(cr.Info.StatusMap()) + " " + cr.Info.AuthorizationURL
	for _, bad := range []string{CanaryToken, "access_token=", "refresh_token=", "client_secret="} {
		if strings.Contains(strings.ToLower(blob), strings.ToLower(bad)) {
			return fmt.Errorf("consent surface contained %q", bad)
		}
	}
	return nil
}

// caseHOST011NoSilentFallthrough proves disabled/failed mode does not use
// another mode's or another subject's credential (HOST-011 cross-link).
// Invoked from the GWY-003 qualify suite so qualify coverage cannot drift
// away from the mode matrix contract.
func caseHOST011NoSilentFallthrough(ctx context.Context) error {
	caller := gateway.Caller{
		Subject: "user-fallthrough", Tenant: "t", WorkloadID: "wl",
		ProfileID: contracts.ProfileID("corp"),
	}
	canaryA := CanaryToken + "-fallthrough-A"
	canaryB := CanaryToken + "-fallthrough-B"

	// Provision Mode A vault for the same subject.
	apiVault := gateway.NewMemoryAPITokenVault()
	if err := apiVault.Put(ctx, gateway.SubjectKey(caller), "alice", canaryA); err != nil {
		return err
	}

	// Mode B primary with empty JWT vault — must not fall through to Mode A.
	jwtVault := gateway.NewMemoryJWTVault()
	pB, err := gateway.RequireJWTRSBearerSetup(jwtVault)
	if err != nil {
		return err
	}
	cred, err := pB.Obtain(ctx, caller)
	if err == nil || cred.AccessToken != "" {
		return fmt.Errorf("empty Mode B vault must fail closed without token")
	}
	if apperr.CodeOf(err) != apperr.CodeNotFound {
		return fmt.Errorf("empty Mode B code %v want not_found", apperr.CodeOf(err))
	}
	if strings.Contains(err.Error(), canaryA) {
		return fmt.Errorf("Mode A canary in Mode B error (silent fallthrough)")
	}

	// Residual Mode B also no fallthrough / no ambient SA.
	res := gateway.NewResidualJWTRSProvider()
	cred, err = res.Obtain(ctx, caller)
	if err == nil || cred.AccessToken != "" {
		return fmt.Errorf("residual Mode B must not return credentials")
	}
	if apperr.CodeOf(err) != apperr.CodeCapabilityMissing {
		return fmt.Errorf("residual Mode B code %v", apperr.CodeOf(err))
	}

	// Mode A primary never returns Bearer JWT scheme.
	pA, err := gateway.RequireAPITokenVaultSetup(apiVault)
	if err != nil {
		return err
	}
	authA, err := gateway.ObtainHTTPAuth(ctx, pA, caller)
	if err != nil {
		return err
	}
	if authA.Scheme != gateway.HTTPAuthSchemeBasic {
		return fmt.Errorf("Mode A must stay Basic: %+v", authA)
	}

	// Mode B with its own vault never returns Basic / Mode A material.
	if err := jwtVault.Put(ctx, gateway.SubjectKey(caller), canaryB); err != nil {
		return err
	}
	authB, err := gateway.ObtainHTTPAuth(ctx, pB, caller)
	if err != nil {
		return err
	}
	if authB.Scheme != gateway.HTTPAuthSchemeBearer || authB.Token != canaryB {
		return fmt.Errorf("Mode B must be Bearer with own token: %+v", authB)
	}
	if authB.Token == canaryA || authB.Username != "" {
		return fmt.Errorf("Mode B must not use Mode A material: %+v", authB)
	}
	if strings.Contains(authA.String(), canaryA) || strings.Contains(authB.String(), canaryB) {
		return fmt.Errorf("HTTPAuth.String leaked canary on fallthrough matrix")
	}

	// CredentialProviderFromEnviron: invalid mode fails start (no silent AgentCore).
	env := map[string]string{
		gateway.EnvGatewayCredentialMode: "not_a_real_mode",
	}
	getenv := func(k string) string { return env[k] }
	_, err = gateway.CredentialProviderFromEnviron("https://jenkins.example.com", getenv)
	if err == nil {
		return fmt.Errorf("invalid mode must fail start")
	}
	if apperr.CodeOf(err) != apperr.CodeInvalidArgument {
		return fmt.Errorf("invalid mode code %v", apperr.CodeOf(err))
	}

	// HOST-011: primary not in ENABLED_MODES fails closed (no silent fallthrough).
	env = map[string]string{
		gateway.EnvGatewayCredentialMode: string(gateway.CredentialModeAgentCore),
		gateway.EnvGatewayEnabledModes:   "api_token_vault,jwt_rs_bearer",
	}
	_, err = gateway.ModeMatrixFromEnviron(getenv)
	if err == nil {
		return fmt.Errorf("primary agentcore not in enabled A+B must fail closed")
	}
	if apperr.CodeOf(err) != apperr.CodeInvalidArgument {
		return fmt.Errorf("primary-not-enabled code %v", apperr.CodeOf(err))
	}
	return nil
}

// caseOAUTH010ModeCOfflineMatrix — OAUTH-010 Mode C prototype matrix (GWY-003 qualify):
// authorization_code → ConsentRequired (URL+session only); token_exchange → Bearer
// Jenkins audience; wrong audience fail; Live=false not_configured; Live=true nil
// Fetcher fail closed; ModeMatrix residual honesty.
// Complements mode_c_agentcore_live_matrix (HOST-011 row) with flow-mode separation.
// Does not claim live Entra 3LO/OBO + AgentCore production pin.
// HTTPTokenFetcher mock-AS TLS paths: package TestOAUTH010_* / TestHTTPTokenFetcher_*.
// Opt-in lab residual: make live-oauth-* HOST-015 mock-token.
func caseOAUTH010ModeCOfflineMatrix(ctx context.Context) error {
	caller := gateway.Caller{
		Subject: "oauth010-qualify", Tenant: "t", WorkloadID: "wl",
		ProfileID: contracts.ProfileID("corp"),
	}

	// --- Live=false → not_configured (cache ignored even if Fetcher would succeed) ---
	cfg := validASCfg()
	cfg.Mode = gateway.ModeTokenExchange
	p, err := gateway.NewAgentCoreProvider(cfg, gateway.NewMemoryTokenCache(time.Hour))
	if err != nil {
		return err
	}
	p.Fetcher = gateway.FuncTokenFetcher(func(ctx context.Context, c gateway.Caller, cfg gateway.AgentCoreConfig) (gateway.Credential, error) {
		return gateway.Credential{AccessToken: CanaryToken + "-must-not-run"}, nil
	})
	if p.Live {
		return fmt.Errorf("default AgentCore Live must be false")
	}
	cred, err := p.Obtain(ctx, caller)
	if err == nil || cred.AccessToken != "" {
		return fmt.Errorf("Live=false must not_configured without token: err=%v", err)
	}
	if apperr.CodeOf(err) != apperr.CodeCapabilityMissing {
		return fmt.Errorf("Live=false code %v", apperr.CodeOf(err))
	}
	if strings.Contains(err.Error(), CanaryToken) {
		return fmt.Errorf("Live=false error leaked canary")
	}
	if p.Status(ctx).Ready {
		return fmt.Errorf("Live=false Status must not be Ready")
	}

	// --- Live=true + nil Fetcher → fail closed ---
	p.Live = true
	p.Fetcher = nil
	cred, err = p.Obtain(ctx, caller)
	if err == nil || cred.AccessToken != "" {
		return fmt.Errorf("Live=true nil Fetcher must fail closed: err=%v", err)
	}
	if apperr.CodeOf(err) != apperr.CodeCapabilityMissing {
		return fmt.Errorf("nil Fetcher code %v", apperr.CodeOf(err))
	}
	low := strings.ToLower(err.Error())
	if !strings.Contains(low, "tokenfetcher") && !strings.Contains(low, "fetcher") {
		return fmt.Errorf("nil Fetcher wording: %v", err)
	}
	if p.Status(ctx).Ready {
		return fmt.Errorf("nil Fetcher Status must not be Ready")
	}

	// --- authorization_code mock: ConsentRequired with auth URL + session only ---
	cfgAuth := validASCfg()
	cfgAuth.Mode = gateway.ModeAuthorizationCode
	pAuth, err := gateway.NewAgentCoreProvider(cfgAuth, nil)
	if err != nil {
		return err
	}
	pAuth.Live = true
	authURL := "https://login.microsoftonline.com/t/oauth2/v2.0/authorize?client_id=public&state=oauth010-qualify"
	sessionID := "sess-oauth010-qualify"
	pAuth.Fetcher = gateway.FuncTokenFetcher(func(ctx context.Context, c gateway.Caller, cfg gateway.AgentCoreConfig) (gateway.Credential, error) {
		if gateway.NormalizeMode(cfg.Mode) != gateway.ModeAuthorizationCode {
			return gateway.Credential{}, fmt.Errorf("want authorization_code got %s", cfg.Mode)
		}
		return gateway.Credential{}, gateway.NewConsentRequired(gateway.ConsentInfo{
			AuthorizationURL: authURL,
			SessionID:        sessionID,
			Provider:         "agentcore",
		})
	})
	cred, err = pAuth.Obtain(ctx, caller)
	if err == nil || cred.AccessToken != "" {
		return fmt.Errorf("authorization_code consent must fail closed without token")
	}
	cr, ok := gateway.AsConsentRequired(err)
	if !ok || cr == nil || !cr.Info.Valid() {
		return fmt.Errorf("want ConsentRequired got %T %v", err, err)
	}
	if cr.Info.AuthorizationURL != authURL || cr.Info.SessionID != sessionID {
		return fmt.Errorf("consent metadata mismatch: %+v", cr.Info)
	}
	blob := err.Error() + " " + cr.Info.String() + " " + fmt.Sprint(cr.Info.StatusMap()) + " " + cr.Info.AuthorizationURL
	for _, bad := range []string{CanaryToken, "access_token=", "refresh_token=", "client_secret="} {
		if strings.Contains(strings.ToLower(blob), strings.ToLower(bad)) {
			return fmt.Errorf("consent surface contained %q", bad)
		}
	}

	// --- token_exchange / OBO mock: success Bearer Jenkins audience ---
	cfgEx := validASCfg()
	cfgEx.Mode = gateway.ModeTokenExchange
	cache := gateway.NewMemoryTokenCache(time.Hour)
	pEx, err := gateway.NewAgentCoreProvider(cfgEx, cache)
	if err != nil {
		return err
	}
	pEx.Live = true
	wantTok := CanaryToken + "-oauth010-obo"
	pEx.Fetcher = gateway.FuncTokenFetcher(func(ctx context.Context, c gateway.Caller, cfg gateway.AgentCoreConfig) (gateway.Credential, error) {
		if gateway.NormalizeMode(cfg.Mode) != gateway.ModeTokenExchange {
			return gateway.Credential{}, fmt.Errorf("want token_exchange got %s", cfg.Mode)
		}
		return gateway.Credential{
			AccessToken:      wantTok,
			ExpiresAt:        time.Now().Add(time.Hour),
			JenkinsPrincipal: "jp-" + c.Subject,
			Mode:             gateway.ModeTokenExchange,
		}, nil
	})
	ha, err := gateway.ObtainHTTPAuth(ctx, pEx, caller)
	if err != nil {
		return fmt.Errorf("token_exchange obtain: %w", err)
	}
	if ha.Scheme != gateway.HTTPAuthSchemeBearer || ha.Username != "" {
		return fmt.Errorf("token_exchange must be Bearer: %+v", ha)
	}
	if ha.Token != wantTok {
		return fmt.Errorf("token_exchange token material mismatch")
	}
	if strings.Contains(ha.String(), CanaryToken) {
		return fmt.Errorf("token_exchange HTTPAuth.String leaked canary")
	}

	// --- wrong audience fail closed (no token; canary absent) ---
	cache.Clear()
	pEx.Fetcher = gateway.FuncTokenFetcher(func(ctx context.Context, c gateway.Caller, cfg gateway.AgentCoreConfig) (gateway.Credential, error) {
		return gateway.Credential{}, apperr.New(apperr.CodeAuthentication,
			"token audience does not match configured Jenkins API resource")
	})
	cred, err = pEx.Obtain(ctx, caller)
	if err == nil || cred.AccessToken != "" {
		return fmt.Errorf("wrong audience must fail closed without token: err=%v", err)
	}
	if apperr.CodeOf(err) != apperr.CodeAuthentication {
		return fmt.Errorf("wrong audience code %v", apperr.CodeOf(err))
	}
	if !strings.Contains(strings.ToLower(err.Error()), "audience") {
		return fmt.Errorf("wrong audience wording: %v", err)
	}
	if strings.Contains(err.Error(), CanaryToken) {
		return fmt.Errorf("wrong audience error leaked canary")
	}

	// --- ModeMatrix residual honesty when Mode C primary ---
	env := map[string]string{
		gateway.EnvGatewayCredentialMode: string(gateway.CredentialModeAgentCore),
	}
	mx, err := gateway.ModeMatrixFromEnviron(func(k string) string { return env[k] })
	if err != nil {
		return err
	}
	if mx.Primary != gateway.CredentialModeAgentCore {
		return fmt.Errorf("primary %s", mx.Primary)
	}
	if mx.Residual == "" || !strings.Contains(mx.Residual, "OAUTH-010") {
		return fmt.Errorf("Mode C residual must note OAUTH-010: %q", mx.Residual)
	}
	lowRes := strings.ToLower(mx.Residual)
	if !strings.Contains(lowRes, "live") && !strings.Contains(lowRes, "entra") && !strings.Contains(lowRes, "agentcore") {
		return fmt.Errorf("Mode C residual must be honest about live pin: %q", mx.Residual)
	}

	// AS endpoints never stock Jenkins (OAUTH-010 / ADR 0003).
	if err := gateway.ValidateProviderConfig(gateway.AgentCoreConfig{
		AuthorizationServerBaseURL: "https://jenkins.example.com",
		Audience:                   "api://jenkins-api",
		JenkinsBaseURL:             "https://jenkins.example.com",
	}); err == nil {
		return fmt.Errorf("Jenkins-as-AS must be rejected under OAUTH-010 matrix")
	}
	return nil
}

// caseOAUTH009OfflineBearerMatrix — OAUTH-009 offline foundations (GWY-003 qualify):
// wrong aud / exp / iss rejected via ValidateAccessToken; ID token rejected;
// OfflineFallthroughFixtures self-consistent; Mode B Obtain never Basic fallthrough.
// Does not claim live jwt-auth-filter / Entra production pin.
func caseOAUTH009OfflineBearerMatrix(ctx context.Context) error {
	_ = ctx
	// --- Claim fail-closed (MCP validator) ---
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	n := base64.RawURLEncoding.EncodeToString(priv.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(priv.E)).Bytes())
	jwks := &auth.JWKS{Keys: []auth.JWK{{
		Kty: "RSA", Kid: "gwy-oauth009", Use: "sig", Alg: "RS256", N: n, E: e,
	}}}
	now := time.Unix(1_700_200_000, 0)
	const (
		issuer = "https://idp.example.com/gwy-oauth009"
		aud    = "api://jenkins-api"
	)
	params := auth.AccessTokenParams{
		Issuer: issuer, Audience: aud,
		Now: func() time.Time { return now },
	}
	sign := func(claims map[string]any) (string, error) {
		return signRS256Compact(priv, "gwy-oauth009", claims)
	}
	good, err := sign(map[string]any{
		"iss": issuer, "sub": "u1", "aud": aud,
		"exp": now.Add(time.Hour).Unix(), "token_use": "access_token",
	})
	if err != nil {
		return err
	}
	if _, err := auth.ValidateAccessToken(good, jwks, params); err != nil {
		return fmt.Errorf("good token: %w", err)
	}
	for _, row := range []struct {
		name   string
		claims map[string]any
	}{
		{"wrong_aud", map[string]any{
			"iss": issuer, "sub": "u1", "aud": "https://graph.microsoft.com",
			"exp": now.Add(time.Hour).Unix(), "token_use": "access_token",
		}},
		{"wrong_iss", map[string]any{
			"iss": "https://evil.example", "sub": "u1", "aud": aud,
			"exp": now.Add(time.Hour).Unix(), "token_use": "access_token",
		}},
		{"expired", map[string]any{
			"iss": issuer, "sub": "u1", "aud": aud,
			"exp": now.Add(-time.Hour).Unix(), "token_use": "access_token",
		}},
		{"id_token", map[string]any{
			"iss": issuer, "sub": "u1", "aud": aud,
			"exp": now.Add(time.Hour).Unix(), "token_use": "id_token",
		}},
	} {
		tok, serr := sign(row.claims)
		if serr != nil {
			return serr
		}
		_, verr := auth.ValidateAccessToken(tok, jwks, params)
		if verr == nil {
			return fmt.Errorf("%s must fail closed", row.name)
		}
		if strings.Contains(verr.Error(), good) || (len(tok) > 24 && strings.Contains(verr.Error(), tok[:24])) {
			return fmt.Errorf("%s error leaked token material", row.name)
		}
	}

	// --- Classifier fixtures ---
	fixtures := auth.OfflineFallthroughFixtures()
	if len(fixtures) < 12 {
		return fmt.Errorf("OfflineFallthroughFixtures floor: %d", len(fixtures))
	}
	for _, f := range fixtures {
		got := auth.ClassifyFallthroughProbe(f.Input)
		if got.Denied != f.WantDenied || got.FallthroughDetected != f.WantFallthrough {
			return fmt.Errorf("fixture %s mismatch denied=%v fall=%v", f.ID, got.Denied, got.FallthroughDetected)
		}
	}
	// Invalid bearer authenticated success → FallthroughDetected.
	ft := auth.ClassifyFallthroughProbe(auth.FallthroughProbeInput{
		StatusCode: 200, BodyClass: auth.BodyClassWhoAmIAuthenticated, WhoAmIAuthenticated: true,
	})
	if !ft.FallthroughDetected {
		return fmt.Errorf("authenticated success must be FallthroughDetected")
	}

	// --- Mode B Obtain: never Basic fallthrough to Mode A vault ---
	caller := gateway.Caller{
		Subject: "oauth009-qualify", Tenant: "t", ProfileID: contracts.ProfileID("corp"),
	}
	apiVault := gateway.NewMemoryAPITokenVault()
	if err := apiVault.Put(context.Background(), gateway.SubjectKey(caller), "alice", CanaryToken+"-A"); err != nil {
		return err
	}
	jwtVault := gateway.NewMemoryJWTVault()
	pB, err := gateway.RequireJWTRSBearerSetup(jwtVault)
	if err != nil {
		return err
	}
	cred, err := pB.Obtain(context.Background(), caller)
	if err == nil || cred.AccessToken != "" {
		return fmt.Errorf("empty Mode B vault must fail closed (no Mode A fallthrough)")
	}
	if strings.Contains(err.Error(), CanaryToken) {
		return fmt.Errorf("Mode A canary in Mode B Obtain error")
	}
	// Mode matrix residual honesty when Mode B primary.
	env := map[string]string{
		gateway.EnvGatewayCredentialMode: string(gateway.CredentialModeJWTRSBearer),
	}
	mx, err := gateway.ModeMatrixFromEnviron(func(k string) string { return env[k] })
	if err != nil {
		return err
	}
	if mx.Residual == "" || !strings.Contains(mx.Residual, "OAUTH-009") {
		return fmt.Errorf("Mode B residual must note OAUTH-009: %q", mx.Residual)
	}
	// ID token never API credential.
	idTok := compactJWTClaims(map[string]string{"sub": "u", "token_use": "id_token"})
	if putErr := jwtVault.Put(context.Background(), gateway.SubjectKey(caller), idTok); putErr == nil {
		return fmt.Errorf("id_token must be rejected at JWT vault Put")
	}
	return nil
}

// signRS256Compact signs claims as compact JWT for offline OAUTH-009 qualify.
func signRS256Compact(priv *rsa.PrivateKey, kid string, claims map[string]any) (string, error) {
	hdr, err := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": kid})
	if err != nil {
		return "", err
	}
	pl, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	h := base64.RawURLEncoding.EncodeToString(hdr)
	p := base64.RawURLEncoding.EncodeToString(pl)
	input := h + "." + p
	sum := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// compactJWTClaims builds an unsigned compact JWT for offline id_token /
// access_token shape checks (HOST-010). Never a production credential.
func compactJWTClaims(claims map[string]string) string {
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	parts := make([]string, 0, len(claims))
	for k, v := range claims {
		parts = append(parts, fmt.Sprintf("%q:%q", k, v))
	}
	pl := base64.RawURLEncoding.EncodeToString([]byte("{" + strings.Join(parts, ",") + "}"))
	return hdr + "." + pl + ".sig"
}

// stubObtainProvider is an offline CredentialProvider that returns per-caller
// tokens without network (GWY-003 lite performance harness).
type stubObtainProvider struct {
	cache gateway.TokenCache
	delay time.Duration
}

func (p *stubObtainProvider) Mode() gateway.Mode { return gateway.ModeTokenExchange }

func (p *stubObtainProvider) Obtain(ctx context.Context, caller gateway.Caller) (gateway.Credential, error) {
	if err := ctx.Err(); err != nil {
		return gateway.Credential{}, apperr.Wrap(apperr.CodeCancelled, "obtain cancelled", err)
	}
	if !caller.Valid() {
		return gateway.Credential{}, apperr.New(apperr.CodeAuthentication,
			"gateway caller subject and profile are required")
	}
	if p.delay > 0 {
		select {
		case <-ctx.Done():
			return gateway.Credential{}, apperr.Wrap(apperr.CodeCancelled, "obtain cancelled", ctx.Err())
		case <-time.After(p.delay):
		}
	}
	key := caller.CacheKey()
	if p.cache != nil {
		if tok, ok := p.cache.Get(key); ok {
			return gateway.Credential{
				AccessToken:      tok.AccessToken,
				ExpiresAt:        tok.ExpiresAt,
				JenkinsPrincipal: tok.JenkinsPrincipal,
				Mode:             tok.Mode,
			}, nil
		}
	}
	// Per-caller token material (synthetic).
	token := "stub-token-" + strings.TrimSpace(caller.Subject) + "-" + strings.TrimSpace(string(caller.ProfileID))
	cred := gateway.Credential{
		AccessToken:      token,
		ExpiresAt:        time.Now().Add(5 * time.Minute),
		JenkinsPrincipal: "jp-" + strings.TrimSpace(caller.Subject),
		Mode:             gateway.ModeTokenExchange,
	}
	if p.cache != nil {
		p.cache.Set(key, gateway.CachedToken{
			AccessToken:      cred.AccessToken,
			ExpiresAt:        cred.ExpiresAt,
			JenkinsPrincipal: cred.JenkinsPrincipal,
			Mode:             cred.Mode,
		})
	}
	return cred, nil
}

func (p *stubObtainProvider) Invalidate(ctx context.Context, caller gateway.Caller) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if p.cache != nil {
		p.cache.Delete(caller.CacheKey())
	}
	return nil
}

func (p *stubObtainProvider) Status(ctx context.Context) gateway.ProviderStatus {
	_ = ctx
	return gateway.ProviderStatus{Configured: true, Ready: true, Mode: gateway.ModeTokenExchange}
}

func caseConcurrentObtain(ctx context.Context) error {
	cache := gateway.NewMemoryTokenCache(time.Hour)
	p := &stubObtainProvider{cache: cache, delay: time.Millisecond}
	start := time.Now()
	var wg sync.WaitGroup
	var failCount atomic.Int32
	var tokens sync.Map

	for i := 0; i < ConcurrentObtainN; i++ {
		wg.Add(1)
		i := i
		go func() {
			defer wg.Done()
			caller := gateway.Caller{
				Subject:    fmt.Sprintf("user-%d", i),
				Tenant:     "t",
				WorkloadID: "wl",
				ProfileID:  contracts.ProfileID("corp"),
			}
			cred, err := p.Obtain(ctx, caller)
			if err != nil || cred.AccessToken == "" {
				failCount.Add(1)
				return
			}
			if strings.Contains(cred.String(), CanaryToken) {
				failCount.Add(1)
				return
			}
			// Isolation: token must be unique per subject.
			if _, loaded := tokens.LoadOrStore(cred.AccessToken, caller.Subject); loaded {
				failCount.Add(1)
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)
	if failCount.Load() > 0 {
		return fmt.Errorf("concurrent obtain failures: %d", failCount.Load())
	}
	if elapsed > ConcurrentObtainBudget {
		return fmt.Errorf("concurrent obtain took %s > budget %s", elapsed, ConcurrentObtainBudget)
	}
	// Cross-user: user-0 token must not be returned for user-1 cache key.
	if tok, ok := cache.Get(gateway.CacheKey{User: "user-0", Workload: "wl", Profile: "corp"}); ok {
		if tok2, ok2 := cache.Get(gateway.CacheKey{User: "user-1", Workload: "wl", Profile: "corp"}); ok2 {
			if tok.AccessToken == tok2.AccessToken {
				return fmt.Errorf("cache isolation failure under concurrency")
			}
		}
	}
	return nil
}

func caseFailClosedLatency(ctx context.Context) error {
	p := gateway.UnconfiguredProvider{Reason: "not_configured qualify latency"}
	start := time.Now()
	_, err := p.Obtain(ctx, gateway.Caller{Subject: "s", ProfileID: "p"})
	elapsed := time.Since(start)
	if err == nil {
		return fmt.Errorf("expected fail closed")
	}
	if apperr.CodeOf(err) != apperr.CodeCapabilityMissing {
		return fmt.Errorf("code %v", apperr.CodeOf(err))
	}
	if elapsed > FailClosedLatencyBudget {
		return fmt.Errorf("fail-closed obtain took %s > budget %s", elapsed, FailClosedLatencyBudget)
	}
	// Also: Jenkins-as-AS config validate under budget.
	start = time.Now()
	_ = gateway.ValidateProviderConfig(gateway.AgentCoreConfig{
		AuthorizationServerBaseURL: "https://jenkins.example.com",
		Audience:                   "api://jenkins-api",
		JenkinsBaseURL:             "https://jenkins.example.com",
	})
	if time.Since(start) > FailClosedLatencyBudget {
		return fmt.Errorf("jenkins-as-as validate too slow")
	}
	_ = validASCfg()
	return nil
}
