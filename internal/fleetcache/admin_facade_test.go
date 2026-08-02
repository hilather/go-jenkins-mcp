package fleetcache_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/fleetcache"
)

func TestAdminFacade_StatusAndDoctor_SecretFreeModeOff(t *testing.T) {
	t.Parallel()
	cfg, err := fleetcache.ResolveConfig(fleetcache.ResolveOptions{
		Getenv: func(string) string { return "" },
	})
	if err != nil {
		t.Fatal(err)
	}
	st := fleetcache.StatusSnapshot(cfg, nil, nil, fleetcache.StatusOptions{})
	raw, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	for _, bad := range []string{"token=", "bearer ", "password", "Authorization", "ghp_"} {
		if strings.Contains(strings.ToLower(body), strings.ToLower(bad)) {
			t.Fatalf("secret-shaped %q in status: %s", bad, body)
		}
	}
	if st["mode"] != "off" {
		t.Fatalf("mode=%v want off", st["mode"])
	}
	if st["spa_residual"] != fleetcache.AdminSPAResidual {
		t.Fatalf("spa_residual=%v", st["spa_residual"])
	}
	if st["mode_default_off"] != true {
		t.Fatalf("mode_default_off missing: %+v", st)
	}

	doc := fleetcache.DoctorSnapshot(cfg, nil, nil, fleetcache.StatusOptions{})
	checks, ok := doc["checks"].([]map[string]any)
	if !ok {
		// JSON-style decode may present []any — accept both.
		if anyChecks, ok2 := doc["checks"].([]any); ok2 {
			if len(anyChecks) < 6 {
				t.Fatalf("checks=%d body=%+v", len(anyChecks), doc)
			}
		} else {
			t.Fatalf("checks type %T", doc["checks"])
		}
	} else if len(checks) < 6 {
		t.Fatalf("checks=%d body=%+v", len(checks), doc)
	}
	// admin_spa residual present.
	foundSPA := false
	switch typed := doc["checks"].(type) {
	case []map[string]any:
		for _, c := range typed {
			if c["name"] == "admin_spa" {
				foundSPA = true
			}
		}
	case []any:
		for _, row := range typed {
			m, _ := row.(map[string]any)
			if m != nil && m["name"] == "admin_spa" {
				foundSPA = true
			}
		}
	}
	if !foundSPA {
		// DoctorChecksMaps returns []map[string]any directly — always map slices.
		for _, c := range fleetcache.DoctorChecksMaps(cfg, fleetcache.BuildFleetCacheStatus(cfg, nil, nil, fleetcache.StatusOptions{})) {
			if c["name"] == "admin_spa" {
				foundSPA = true
			}
		}
	}
	if !foundSPA {
		t.Fatal("expected admin_spa residual check")
	}
}

func TestAdminPurge_RoleConfirmAndBounded(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	lh := strings.Repeat("ab", 32) // 64 hex-ish

	// Viewer denied.
	_, err := fleetcache.AdminPurge(ctx, fleetcache.AdminPurgeOptions{
		Role:        "viewer",
		Confirm:     fleetcache.PurgeConfirmToken,
		LocatorHash: lh,
	})
	if err == nil || apperr.CodeOf(err) != apperr.CodeAuthorization {
		t.Fatalf("viewer: %v", err)
	}

	// Wrong confirm.
	_, err = fleetcache.AdminPurge(ctx, fleetcache.AdminPurgeOptions{
		Role:        fleetcache.PurgeRoleOperator,
		Confirm:     "yes",
		LocatorHash: lh,
	})
	if err == nil || apperr.CodeOf(err) != apperr.CodeInvalidArgument {
		t.Fatalf("confirm: %v", err)
	}

	// Empty locator denied.
	_, err = fleetcache.AdminPurge(ctx, fleetcache.AdminPurgeOptions{
		Role:    fleetcache.PurgeRoleOperator,
		Confirm: fleetcache.PurgeConfirmToken,
	})
	if err == nil {
		t.Fatal("empty locator expected error")
	}

	// Operator + PURGE succeeds (nop sink + memory tombstone).
	ts := fleetcache.NewMemoryTombstoneStore()
	now := time.Now().UTC()
	out, err := fleetcache.AdminPurge(ctx, fleetcache.AdminPurgeOptions{
		Role:        fleetcache.PurgeRoleOperator,
		Confirm:     fleetcache.PurgeConfirmToken,
		LocatorHash: lh,
		Tombstones:  ts,
		Reason:      "token=should-scrub",
		Now:         now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if out["status"] != fleetcache.PurgeStatusPurged && out["status"] != fleetcache.PurgeStatusPartial {
		t.Fatalf("status=%v out=%+v", out["status"], out)
	}
	if out["http_peer_prop"] != false {
		t.Fatal("http peer prop must be false")
	}
	if out["confirm_token"] != fleetcache.PurgeConfirmToken {
		t.Fatalf("confirm_token field=%v", out["confirm_token"])
	}
	if out["purge_residual"] != fleetcache.AdminPurgeHTTPResidual {
		t.Fatalf("purge_residual=%v", out["purge_residual"])
	}
	raw, _ := json.Marshal(out)
	if strings.Contains(string(raw), "token=should-scrub") {
		t.Fatalf("reason secret leaked: %s", raw)
	}
	// Tombstone blocks resurrection.
	blocked, residual := fleetcache.TombstoneBlocks(ts, lh, "", now.Add(time.Minute))
	if !blocked {
		t.Fatalf("expected tombstone block residual=%q", residual)
	}
}
