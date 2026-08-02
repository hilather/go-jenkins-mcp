package adminops_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/adminops"
	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/audit"
	"github.com/hilather/go-jenkins-mcp/internal/fleetcache"
)

func TestService_FleetCacheStatusDoctor_ViewerOK(t *testing.T) {
	t.Parallel()
	svc := adminops.New(adminops.Config{
		Role:   adminops.RoleViewer,
		Getenv: func(string) string { return "" },
	})
	st, err := svc.FleetCacheStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st["mode"] != "off" {
		t.Fatalf("mode=%v", st["mode"])
	}
	raw, _ := json.Marshal(st)
	assertFleetCacheSecretFree(t, string(raw))

	doc, err := svc.FleetCacheDoctor(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if doc["status"] == nil || doc["checks"] == nil {
		t.Fatalf("%+v", doc)
	}
	raw, _ = json.Marshal(doc)
	assertFleetCacheSecretFree(t, string(raw))
}

func TestService_FleetCachePurge_RoleAndConfirm(t *testing.T) {
	t.Parallel()
	lh := strings.Repeat("cd", 32)
	viewer := adminops.New(adminops.Config{Role: adminops.RoleViewer})
	_, err := viewer.FleetCachePurge(context.Background(), adminops.FleetCachePurgeArgs{
		Confirm:     adminops.ConfirmPURGE,
		LocatorHash: lh,
	})
	if err == nil || apperr.CodeOf(err) != apperr.CodeAuthorization {
		t.Fatalf("viewer purge: %v", err)
	}

	mem := &audit.Memory{}
	op := adminops.New(adminops.Config{
		Role:  adminops.RoleOperator,
		Audit: mem,
	})
	_, err = op.FleetCachePurge(context.Background(), adminops.FleetCachePurgeArgs{
		Confirm:     "nope",
		LocatorHash: lh,
	})
	if err == nil || apperr.CodeOf(err) != apperr.CodeInvalidArgument {
		t.Fatalf("confirm: %v", err)
	}

	out, err := op.FleetCachePurge(context.Background(), adminops.FleetCachePurgeArgs{
		Confirm:     adminops.ConfirmPURGE,
		LocatorHash: lh,
		Reason:      "cleanup",
	})
	if err != nil {
		t.Fatal(err)
	}
	if out["status"] != fleetcache.PurgeStatusPurged && out["status"] != fleetcache.PurgeStatusPartial {
		t.Fatalf("status=%v out=%+v", out["status"], out)
	}
	if out["confirm_token"] != fleetcache.PurgeConfirmToken {
		t.Fatalf("confirm_token=%v", out["confirm_token"])
	}
	raw, _ := json.Marshal(out)
	assertFleetCacheSecretFree(t, string(raw))

	var found bool
	for _, e := range mem.Events() {
		if e.Type == audit.TypeAdminFleetCachePurge {
			found = true
			if e.Decision != audit.DecisionSuccess {
				t.Fatalf("audit decision=%s", e.Decision)
			}
			// No raw locator in event fields other than TargetHash.
			if strings.Contains(e.ReasonCode, lh) {
				t.Fatal("locator in reasonCode")
			}
		}
	}
	if !found {
		t.Fatal("expected admin_fleet_cache_purge audit event")
	}
}

func TestToolCatalog_IncludesFleetCache(t *testing.T) {
	t.Parallel()
	cat := adminops.ToolCatalog()
	need := []string{
		"admin_fleet_cache_status",
		"admin_fleet_cache_doctor",
		"admin_fleet_cache_purge",
	}
	set := map[string]struct{}{}
	for _, n := range cat {
		set[n] = struct{}{}
	}
	for _, n := range need {
		if _, ok := set[n]; !ok {
			t.Fatalf("missing %s in catalog", n)
		}
	}
}

func assertFleetCacheSecretFree(t *testing.T, body string) {
	t.Helper()
	lower := strings.ToLower(body)
	for _, bad := range []string{
		"bearer ", "password", "authorization:", `"api_token"`, "ghp_", "sk-live",
	} {
		if strings.Contains(lower, bad) {
			t.Fatalf("secret-shaped %q in body: %s", bad, body)
		}
	}
	// Bounded: no multi-KB log dumps.
	if len(body) > 64*1024 {
		t.Fatalf("response too large for secret-free status (%d)", len(body))
	}
}
