package gateway_test

import (
	"context"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/gateway"
)

// Regression: expires_in → ExpiresAt overflowed time.Duration for
// expires_in ≥ ~9.2e9 seconds (int64 nanoseconds), potentially wrapping to a
// far-future ExpiresAt so the Obtain token cache could serve a token long past
// its real IdP expiry. The conversion now clamps before the multiply.
func TestHTTPTokenFetcher_ExpiresInOverflowClamped(t *testing.T) {
	t.Parallel()
	m := startMockAS(t)
	m.expiresIn = 1 << 40 // ~1.1e12 seconds — far beyond int64 nanosecond range
	cfg := cfgWithTokenEndpoint(m.server.URL + "/oauth2/v2.0/token")
	fetcher := gateway.NewHTTPTokenFetcher(m.tlsClient())

	p, err := gateway.NewAgentCoreProvider(cfg, gateway.NewMemoryTokenCache(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	p.Live = true
	p.Fetcher = fetcher

	cred, err := p.Obtain(context.Background(), testCaller())
	if err != nil {
		t.Fatal(err)
	}
	// Clamped to a sane bound, never wrapped negative or absurdly far.
	maxExp := time.Now().Add(366 * 24 * time.Hour)
	if cred.ExpiresAt.After(maxExp) {
		t.Fatalf("ExpiresAt overflowed into the far future: %v", cred.ExpiresAt)
	}
	if cred.ExpiresAt.Before(time.Now()) {
		t.Fatalf("ExpiresAt in the past: %v", cred.ExpiresAt)
	}
}
