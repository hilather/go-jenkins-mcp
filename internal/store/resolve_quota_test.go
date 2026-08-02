package store_test

import (
	"context"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/store"
)

func TestResolveQuotaConfig_Default(t *testing.T) {
	t.Parallel()
	cfg, err := store.ResolveQuotaConfig("", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TotalQuotaBytes != store.DefaultTotalQuotaBytes {
		t.Fatalf("total: got %d want default %d", cfg.TotalQuotaBytes, store.DefaultTotalQuotaBytes)
	}
	if cfg.LowDiskBytes != store.DefaultLowDiskBytes {
		t.Fatalf("low: got %d want default %d", cfg.LowDiskBytes, store.DefaultLowDiskBytes)
	}
	// Whitespace-only is unset.
	cfg, err = store.ResolveQuotaConfig("  ", "\t", " ", "\n")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TotalQuotaBytes != store.DefaultTotalQuotaBytes || cfg.LowDiskBytes != store.DefaultLowDiskBytes {
		t.Fatalf("whitespace: %+v", cfg)
	}
	// Explicit 0 ⇒ default (fail-closed product budget, not zero-byte).
	cfg, err = store.ResolveQuotaConfig("0", "", "0", "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TotalQuotaBytes != store.DefaultTotalQuotaBytes || cfg.LowDiskBytes != store.DefaultLowDiskBytes {
		t.Fatalf("explicit 0: %+v", cfg)
	}
	// Drift guards.
	if store.DefaultTotalQuotaBytes != 10<<30 {
		t.Fatalf("DefaultTotalQuotaBytes drift: %d", store.DefaultTotalQuotaBytes)
	}
	if store.DefaultLowDiskBytes != 1<<30 {
		t.Fatalf("DefaultLowDiskBytes drift: %d", store.DefaultLowDiskBytes)
	}
	if store.MinTotalQuotaBytes != 64<<20 {
		t.Fatalf("MinTotalQuotaBytes drift: %d", store.MinTotalQuotaBytes)
	}
	if store.AbsoluteMaxTotalQuotaBytes != 1<<40 {
		t.Fatalf("AbsoluteMaxTotalQuotaBytes drift: %d", store.AbsoluteMaxTotalQuotaBytes)
	}
}

func TestResolveQuotaConfig_Precedence(t *testing.T) {
	t.Parallel()
	wantEnv := store.MinTotalQuotaBytes + 1
	wantFlag := store.MinTotalQuotaBytes + 2
	// Env only.
	cfg, err := store.ResolveQuotaConfig("", strconv.FormatInt(wantEnv, 10), "", "")
	if err != nil || cfg.TotalQuotaBytes != wantEnv {
		t.Fatalf("env: got %d %v", cfg.TotalQuotaBytes, err)
	}
	// Flag wins over env.
	cfg, err = store.ResolveQuotaConfig(strconv.FormatInt(wantFlag, 10), strconv.FormatInt(wantEnv, 10), "", "")
	if err != nil || cfg.TotalQuotaBytes != wantFlag {
		t.Fatalf("flag wins: got %d %v", cfg.TotalQuotaBytes, err)
	}
	// Low-disk independent of total.
	lowEnv := store.MinLowDiskBytes + 3
	lowFlag := store.MinLowDiskBytes + 4
	cfg, err = store.ResolveQuotaConfig(
		"", strconv.FormatInt(wantEnv, 10),
		strconv.FormatInt(lowFlag, 10), strconv.FormatInt(lowEnv, 10),
	)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TotalQuotaBytes != wantEnv || cfg.LowDiskBytes != lowFlag {
		t.Fatalf("independent fields: %+v", cfg)
	}
}

func TestResolveQuotaConfig_MinMaxBounds(t *testing.T) {
	t.Parallel()
	// At min / at absolute max accepted.
	cfg, err := store.ResolveQuotaConfig(strconv.FormatInt(store.MinTotalQuotaBytes, 10), "", "", "")
	if err != nil || cfg.TotalQuotaBytes != store.MinTotalQuotaBytes {
		t.Fatalf("at min total: %v %v", cfg.TotalQuotaBytes, err)
	}
	cfg, err = store.ResolveQuotaConfig(strconv.FormatInt(store.AbsoluteMaxTotalQuotaBytes, 10), "", "", "")
	if err != nil || cfg.TotalQuotaBytes != store.AbsoluteMaxTotalQuotaBytes {
		t.Fatalf("at max total: %v %v", cfg.TotalQuotaBytes, err)
	}
	cfg, err = store.ResolveQuotaConfig("", "", strconv.FormatInt(store.MinLowDiskBytes, 10), "")
	if err != nil || cfg.LowDiskBytes != store.MinLowDiskBytes {
		t.Fatalf("at min low: %v %v", cfg.LowDiskBytes, err)
	}
	cfg, err = store.ResolveQuotaConfig("", "", strconv.FormatInt(store.AbsoluteMaxLowDiskBytes, 10), "")
	if err != nil || cfg.LowDiskBytes != store.AbsoluteMaxLowDiskBytes {
		t.Fatalf("at max low: %v %v", cfg.LowDiskBytes, err)
	}
	// Defaults sit inside the window.
	if store.DefaultTotalQuotaBytes < store.MinTotalQuotaBytes ||
		store.DefaultTotalQuotaBytes > store.AbsoluteMaxTotalQuotaBytes {
		t.Fatalf("default total outside window")
	}
	if store.DefaultLowDiskBytes < store.MinLowDiskBytes ||
		store.DefaultLowDiskBytes > store.AbsoluteMaxLowDiskBytes {
		t.Fatalf("default low outside window")
	}
}

func TestResolveQuotaConfig_RejectInvalid(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name                 string
		flagTotal, envTotal  string
		flagLow, envLow      string
		wantCode             apperr.Code
		wantSubstr           string
	}{
		{"garbage total", "not-a-number", "", "", "", apperr.CodeInvalidArgument, "invalid cache-total-quota-bytes"},
		{"negative total", "-1", "", "", "", apperr.CodeInvalidArgument, "non-negative"},
		{"below min total", strconv.FormatInt(store.MinTotalQuotaBytes-1, 10), "", "", "", apperr.CodeInvalidArgument, "below minimum"},
		{"over max total", strconv.FormatInt(store.AbsoluteMaxTotalQuotaBytes+1, 10), "", "", "", apperr.CodeInvalidArgument, "exceeds absolute maximum"},
		{"garbage low", "", "", "xyz", "", apperr.CodeInvalidArgument, "invalid cache-low-disk-bytes"},
		{"negative low", "", "", "-5", "", apperr.CodeInvalidArgument, "non-negative"},
		{"below min low", "", "", strconv.FormatInt(store.MinLowDiskBytes-1, 10), "", apperr.CodeInvalidArgument, "below minimum"},
		{"over max low", "", "", strconv.FormatInt(store.AbsoluteMaxLowDiskBytes+1, 10), "", apperr.CodeInvalidArgument, "exceeds absolute maximum"},
		{"env over max", "", strconv.FormatInt(store.AbsoluteMaxTotalQuotaBytes+1, 10), "", "", apperr.CodeInvalidArgument, "exceeds absolute maximum"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := store.ResolveQuotaConfig(tc.flagTotal, tc.envTotal, tc.flagLow, tc.envLow)
			if err == nil {
				t.Fatal("expected error")
			}
			if apperr.CodeOf(err) != tc.wantCode {
				t.Fatalf("code: got %v want %v err=%v", apperr.CodeOf(err), tc.wantCode, err)
			}
			if !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Fatalf("msg %q missing %q", err.Error(), tc.wantSubstr)
			}
			// Secret-free canary.
			for _, bad := range []string{"token=", "password", "Authorization", "/home/"} {
				if strings.Contains(err.Error(), bad) {
					t.Fatalf("secret-shaped error: %q", err.Error())
				}
			}
		})
	}
}

// TestResolveQuotaConfig_EffectiveMatchesManager asserts resolved values drive
// QuotaManager Usage/NeedsEviction (real store APIs, not reimplemented math).
func TestResolveQuotaConfig_EffectiveMatchesManager(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "profiles", "corp")
	meta, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = meta.Close() })

	wantTotal := int64(128 << 20) // 128 MiB ≥ min
	wantLow := int64(32 << 20)    // 32 MiB ≥ min low
	cfg, err := store.ResolveQuotaConfig(
		strconv.FormatInt(wantTotal, 10), "",
		strconv.FormatInt(wantLow, 10), "",
	)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TotalQuotaBytes != wantTotal || cfg.LowDiskBytes != wantLow {
		t.Fatalf("resolve: %+v", cfg)
	}
	// Simulated free space under low-disk threshold.
	cfg.DiskFree = func(string) (int64, error) { return wantLow - 1, nil }

	qm, err := store.NewQuotaManager(meta, dir, cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	u, err := qm.Usage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if u.QuotaBytes != wantTotal {
		t.Fatalf("Usage.QuotaBytes=%d want %d (manager must use resolved TotalQuotaBytes)", u.QuotaBytes, wantTotal)
	}
	if !u.LowDisk {
		t.Fatal("expected LowDisk true when free < resolved LowDiskBytes")
	}
	need, _, err := qm.NeedsEviction(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !need {
		t.Fatal("NeedsEviction should be true under low-disk with resolved threshold")
	}
}

func TestResolveQuotaConfigFromEnviron(t *testing.T) {
	t.Parallel()
	want := store.MinTotalQuotaBytes + 9
	cfg, err := store.ResolveQuotaConfigFromEnviron(strconv.FormatInt(want, 10), "")
	if err != nil || cfg.TotalQuotaBytes != want {
		t.Fatalf("got %+v %v", cfg, err)
	}
}
