package gateway_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/contracts"
	"github.com/simonfxr/go-jenkins-mcp/internal/gateway"
)

func testCaller() gateway.Caller {
	return gateway.Caller{
		Subject:    "entra-sub-1",
		Tenant:     "tenant-1",
		WorkloadID: "wl-1",
		ProfileID:  contracts.ProfileID("corp"),
	}
}

// Regression: Live=false always not_configured even when Fetcher would succeed.
func TestAgentCoreProvider_LiveFalseNotConfigured(t *testing.T) {
	t.Parallel()
	p, err := gateway.NewAgentCoreProvider(validCfg(), nil)
	if err != nil {
		t.Fatal(err)
	}
	p.Fetcher = gateway.FuncTokenFetcher(func(ctx context.Context, caller gateway.Caller, cfg gateway.AgentCoreConfig) (gateway.Credential, error) {
		return gateway.Credential{AccessToken: canaryAccessToken}, nil
	})
	// Live remains false from NewAgentCoreProvider.
	_, err = p.Obtain(context.Background(), testCaller())
	if err == nil {
		t.Fatal("expected fail closed")
	}
	if apperr.CodeOf(err) != apperr.CodeCapabilityMissing {
		t.Fatalf("code %v", apperr.CodeOf(err))
	}
	if !strings.Contains(err.Error(), "not configured") && !strings.Contains(err.Error(), "not_configured") {
		t.Fatalf("want not_configured wording: %v", err)
	}
	if strings.Contains(err.Error(), canaryAccessToken) {
		t.Fatal("canary in error")
	}
	st := p.Status(context.Background())
	if st.Ready {
		t.Fatalf("Ready must be false when Live=false: %+v", st)
	}
}

// Live=true + nil Fetcher → capability_missing (not silent success).
func TestAgentCoreProvider_LiveTrueNilFetcher(t *testing.T) {
	t.Parallel()
	p, err := gateway.NewAgentCoreProvider(validCfg(), nil)
	if err != nil {
		t.Fatal(err)
	}
	p.Live = true
	p.Fetcher = nil
	cred, err := p.Obtain(context.Background(), testCaller())
	if err == nil {
		t.Fatal("expected capability_missing")
	}
	if apperr.CodeOf(err) != apperr.CodeCapabilityMissing {
		t.Fatalf("code %v err %v", apperr.CodeOf(err), err)
	}
	if !strings.Contains(strings.ToLower(err.Error()), "tokenfetcher") &&
		!strings.Contains(strings.ToLower(err.Error()), "fetcher") {
		t.Fatalf("want Fetcher wording: %v", err)
	}
	if cred.AccessToken != "" {
		t.Fatal("must not return token")
	}
	st := p.Status(context.Background())
	if st.Ready {
		t.Fatalf("Ready must be false without Fetcher: %+v", st)
	}
	if st.ErrorCode != string(apperr.CodeCapabilityMissing) {
		t.Fatalf("status code %s", st.ErrorCode)
	}
}

// Live=true + Fetcher success → cache hit on second Obtain (Fetcher called once).
func TestAgentCoreProvider_LiveFetcherCacheHit(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	p, err := gateway.NewAgentCoreProvider(validCfg(), gateway.NewMemoryTokenCache(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	p.Live = true
	p.Fetcher = gateway.FuncTokenFetcher(func(ctx context.Context, caller gateway.Caller, cfg gateway.AgentCoreConfig) (gateway.Credential, error) {
		calls.Add(1)
		return gateway.Credential{
			AccessToken:      canaryAccessToken,
			ExpiresAt:        time.Now().Add(time.Hour),
			JenkinsPrincipal: "alice",
			Mode:             gateway.ModeTokenExchange,
		}, nil
	})

	c1, err := p.Obtain(context.Background(), testCaller())
	if err != nil {
		t.Fatal(err)
	}
	if c1.AccessToken != canaryAccessToken {
		t.Fatal("token mismatch")
	}
	if c1.JenkinsPrincipal != "alice" {
		t.Fatalf("principal %q", c1.JenkinsPrincipal)
	}

	c2, err := p.Obtain(context.Background(), testCaller())
	if err != nil {
		t.Fatal(err)
	}
	if c2.AccessToken != canaryAccessToken {
		t.Fatal("cache miss token")
	}
	if calls.Load() != 1 {
		t.Fatalf("Fetcher called %d times; want 1 (cache hit)", calls.Load())
	}

	// Canary never in String/Status.
	if strings.Contains(c1.String(), canaryAccessToken) {
		t.Fatal("Credential.String leaked")
	}
	st := p.Status(context.Background())
	blob := fmt.Sprintf("%+v", st)
	if strings.Contains(blob, canaryAccessToken) {
		t.Fatal("Status leaked canary")
	}
	if !st.Ready {
		t.Fatalf("want Ready: %+v", st)
	}
}

// Invalidate drops cache so Fetcher runs again.
func TestAgentCoreProvider_InvalidateForcesRefetch(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	p, err := gateway.NewAgentCoreProvider(validCfg(), gateway.NewMemoryTokenCache(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	p.Live = true
	p.Fetcher = gateway.FuncTokenFetcher(func(ctx context.Context, caller gateway.Caller, cfg gateway.AgentCoreConfig) (gateway.Credential, error) {
		n := calls.Add(1)
		return gateway.Credential{
			AccessToken: canaryAccessToken + fmt.Sprintf("-%d", n),
			ExpiresAt:   time.Now().Add(time.Hour),
		}, nil
	})
	caller := testCaller()
	if _, err := p.Obtain(context.Background(), caller); err != nil {
		t.Fatal(err)
	}
	if err := p.Invalidate(context.Background(), caller); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Obtain(context.Background(), caller); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatalf("calls=%d want 2", calls.Load())
	}
}

// Fetcher returns wrong-audience residual → authentication fail closed.
func TestAgentCoreProvider_WrongAudience(t *testing.T) {
	t.Parallel()
	p, err := gateway.NewAgentCoreProvider(validCfg(), nil)
	if err != nil {
		t.Fatal(err)
	}
	p.Live = true
	p.Fetcher = gateway.FuncTokenFetcher(func(ctx context.Context, caller gateway.Caller, cfg gateway.AgentCoreConfig) (gateway.Credential, error) {
		// Simulate HTTPTokenFetcher audience check residual.
		return gateway.Credential{}, apperr.New(apperr.CodeAuthentication,
			"token audience does not match configured Jenkins API resource")
	})
	_, err = p.Obtain(context.Background(), testCaller())
	if err == nil {
		t.Fatal("expected fail closed")
	}
	if apperr.CodeOf(err) != apperr.CodeAuthentication {
		t.Fatalf("code %v", apperr.CodeOf(err))
	}
	if !strings.Contains(strings.ToLower(err.Error()), "audience") {
		t.Fatalf("want audience: %v", err)
	}
	if strings.Contains(err.Error(), canaryAccessToken) {
		t.Fatal("canary")
	}
}

// ConsentRequired from Fetcher is surfaced without secrets.
func TestAgentCoreProvider_ConsentRequired(t *testing.T) {
	t.Parallel()
	p, err := gateway.NewAgentCoreProvider(validCfg(), nil)
	if err != nil {
		t.Fatal(err)
	}
	p.Live = true
	p.Fetcher = gateway.FuncTokenFetcher(func(ctx context.Context, caller gateway.Caller, cfg gateway.AgentCoreConfig) (gateway.Credential, error) {
		return gateway.Credential{}, gateway.NewConsentRequired(gateway.ConsentInfo{
			AuthorizationURL: "https://login.microsoftonline.com/t/oauth2/v2.0/authorize?state=abc",
			SessionID:        "sess-consent-1",
			Provider:         "agentcore",
		})
	})
	_, err = p.Obtain(context.Background(), testCaller())
	if err == nil {
		t.Fatal("expected consent")
	}
	cr, ok := gateway.AsConsentRequired(err)
	if !ok || cr == nil {
		t.Fatalf("want ConsentRequired got %T %v", err, err)
	}
	if !cr.Info.Valid() {
		t.Fatalf("invalid consent: %+v", cr.Info)
	}
	if strings.Contains(err.Error(), canaryAccessToken) {
		t.Fatal("canary in consent error")
	}
	sm := cr.Info.StatusMap()
	blob := fmt.Sprintf("%v %v", err.Error(), sm)
	if strings.Contains(blob, canaryAccessToken) {
		t.Fatal("canary in status map path")
	}
}

// Token never appears in errors / Status / String / audit-like maps.
func TestAgentCoreProvider_TokenNeverInSurfaces(t *testing.T) {
	t.Parallel()
	p, err := gateway.NewAgentCoreProvider(validCfg(), gateway.NewMemoryTokenCache(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	p.Live = true
	p.Fetcher = gateway.FuncTokenFetcher(func(ctx context.Context, caller gateway.Caller, cfg gateway.AgentCoreConfig) (gateway.Credential, error) {
		return gateway.Credential{
			AccessToken:      canaryAccessToken,
			ExpiresAt:        time.Now().Add(time.Hour),
			JenkinsPrincipal: "alice",
		}, nil
	})
	cred, err := p.Obtain(context.Background(), testCaller())
	if err != nil {
		t.Fatal(err)
	}
	// Plant canary into a synthetic fetch error path as well.
	p.Cache.Clear()
	p.Fetcher = gateway.FuncTokenFetcher(func(ctx context.Context, caller gateway.Caller, cfg gateway.AgentCoreConfig) (gateway.Credential, error) {
		return gateway.Credential{}, errors.New("upstream said token=" + canaryAccessToken)
	})
	_, err2 := p.Obtain(context.Background(), testCaller())
	if err2 == nil {
		t.Fatal("expected mapped error")
	}

	surfaces := []string{
		cred.String(),
		fmt.Sprintf("%+v", p.Status(context.Background())),
		err2.Error(),
		fmt.Sprintf("%v", testCaller().StatusMap()),
	}
	for i, s := range surfaces {
		if strings.Contains(s, canaryAccessToken) {
			t.Fatalf("surface %d leaked canary: %s", i, s)
		}
	}
}

// Cancelled context fails closed before/during obtain.
func TestAgentCoreProvider_LiveCancel(t *testing.T) {
	t.Parallel()
	p, err := gateway.NewAgentCoreProvider(validCfg(), nil)
	if err != nil {
		t.Fatal(err)
	}
	p.Live = true
	p.Fetcher = gateway.FuncTokenFetcher(func(ctx context.Context, caller gateway.Caller, cfg gateway.AgentCoreConfig) (gateway.Credential, error) {
		return gateway.Credential{AccessToken: canaryAccessToken}, nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = p.Obtain(ctx, testCaller())
	if err == nil || apperr.CodeOf(err) != apperr.CodeCancelled {
		t.Fatalf("got %v", err)
	}
	if strings.Contains(err.Error(), canaryAccessToken) {
		t.Fatal("canary")
	}
}

// Fetcher cancel during fetch is mapped.
func TestAgentCoreProvider_FetcherContextCancel(t *testing.T) {
	t.Parallel()
	p, err := gateway.NewAgentCoreProvider(validCfg(), nil)
	if err != nil {
		t.Fatal(err)
	}
	p.Live = true
	p.Fetcher = gateway.FuncTokenFetcher(func(ctx context.Context, caller gateway.Caller, cfg gateway.AgentCoreConfig) (gateway.Credential, error) {
		return gateway.Credential{}, ctx.Err()
	})
	ctx, cancel := context.WithCancel(context.Background())
	// Context still live at Obtain entry; fetcher sees cancel if we cancel after
	// entry — here we cancel before call so Obtain returns cancelled first.
	// Separate path: live ctx, fetcher returns context.Canceled.
	cancel()
	// Re-open with valid ctx that fetcher treats as canceled via return value.
	p2, err := gateway.NewAgentCoreProvider(validCfg(), nil)
	if err != nil {
		t.Fatal(err)
	}
	p2.Live = true
	p2.Fetcher = gateway.FuncTokenFetcher(func(ctx context.Context, caller gateway.Caller, cfg gateway.AgentCoreConfig) (gateway.Credential, error) {
		return gateway.Credential{}, context.Canceled
	})
	_, err = p2.Obtain(context.Background(), testCaller())
	if err == nil {
		t.Fatal("expected error")
	}
	if apperr.CodeOf(err) != apperr.CodeCancelled {
		t.Fatalf("code %v err %v", apperr.CodeOf(err), err)
	}
	_ = ctx
}

// Empty token from Fetcher fails closed (no cache poison).
func TestAgentCoreProvider_EmptyTokenFromFetcher(t *testing.T) {
	t.Parallel()
	p, err := gateway.NewAgentCoreProvider(validCfg(), gateway.NewMemoryTokenCache(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	p.Live = true
	p.Fetcher = gateway.FuncTokenFetcher(func(ctx context.Context, caller gateway.Caller, cfg gateway.AgentCoreConfig) (gateway.Credential, error) {
		return gateway.Credential{AccessToken: "  ", ExpiresAt: time.Now().Add(time.Hour)}, nil
	})
	_, err = p.Obtain(context.Background(), testCaller())
	if err == nil || apperr.CodeOf(err) != apperr.CodeAuthentication {
		t.Fatalf("got %v", err)
	}
	// Second call should still hit Fetcher (nothing cached).
	var calls atomic.Int32
	p.Fetcher = gateway.FuncTokenFetcher(func(ctx context.Context, caller gateway.Caller, cfg gateway.AgentCoreConfig) (gateway.Credential, error) {
		calls.Add(1)
		return gateway.Credential{
			AccessToken: canaryAccessToken,
			ExpiresAt:   time.Now().Add(time.Hour),
		}, nil
	})
	if _, err := p.Obtain(context.Background(), testCaller()); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("calls=%d", calls.Load())
	}
}
