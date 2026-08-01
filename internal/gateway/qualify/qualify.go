package qualify

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
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
func RunOffline(ctx context.Context) Summary {
	if ctx == nil {
		ctx = context.Background()
	}
	sum := Summary{
		Suite: "offline",
		Residuals: []string{
			"Live AgentCore / Entra network acquisition not exercised (GWY-003 full pin residual)",
			// Offline vault hit/miss + mock IdP outage + JWKS kid-lite are exercised below (Done*).
			// Live Entra JWKS rotation under load / real IdP outage remain residual.
			"Live Entra JWKS rotation under load and live IdP outage chaos remain residual (offline vault hit/miss + mock IdP outage + JWKS kid-lite Done*)",
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
