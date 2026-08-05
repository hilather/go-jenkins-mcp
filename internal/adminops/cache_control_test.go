package adminops_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/adminops"
	"github.com/hilather/go-jenkins-mcp/internal/cachecontrol"
)

func TestCacheInventory_ViewerOK_DefaultCompat(t *testing.T) {
	svc := adminops.New(adminops.Config{Role: adminops.RoleViewer})
	out, err := svc.CacheInventory(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	types, ok := out["types"].([]map[string]any)
	if !ok {
		// JSON-ish: may be []any
		raw, ok := out["types"].([]any)
		if !ok || len(raw) != 12 {
			t.Fatalf("types: %#v", out["types"])
		}
	} else if len(types) != 12 {
		t.Fatalf("len %d", len(types))
	}
	if out["allowRawDump"] != false {
		t.Fatal("raw dump default")
	}
	_ = types
}

func TestCacheInventory_ViewerSeesModesReadWrite(t *testing.T) {
	svc := adminops.New(adminops.Config{Role: adminops.RoleViewer})
	out, err := svc.CacheInventory(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	raw := out["types"].([]map[string]any)
	foundOff := false
	for _, row := range raw {
		id, _ := row["typeId"].(string)
		mode, _ := row["mode"].(string)
		if id == "ratarmount_index" {
			if mode != "off" {
				t.Fatalf("ratarmount mode %s", mode)
			}
			foundOff = true
			continue
		}
		if mode != "read_write" {
			t.Fatalf("%s mode %s", id, mode)
		}
	}
	if !foundOff {
		t.Fatal("missing ratarmount")
	}
}

func TestCachePatchMode_OperatorWithStore(t *testing.T) {
	dir := t.TempDir()
	st, err := cachecontrol.OpenOverrideStore(filepath.Join(dir, "cc"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	cc, err := cachecontrol.NewService(cachecontrol.ServiceConfig{
		OverrideStore: st,
		ProfileID:     "lab",
	})
	if err != nil {
		t.Fatal(err)
	}
	op := adminops.New(adminops.Config{
		Role:              adminops.RoleOperator,
		CacheControl:      cc,
		CacheControlStore: st,
		DefaultProfileID:  "lab",
	})
	// Viewer denied
	viewer := adminops.New(adminops.Config{
		Role: adminops.RoleViewer, CacheControl: cc, CacheControlStore: st,
	})
	_, err = viewer.CachePatchMode(context.Background(), adminops.CachePatchModeArgs{
		TypeID: "artifact_blob", Mode: "off", ExpectedRevision: 0,
	})
	if err == nil {
		t.Fatal("viewer must not patch")
	}

	out, err := op.CachePatchMode(context.Background(), adminops.CachePatchModeArgs{
		TypeID: "artifact_blob", Mode: "off", ExpectedRevision: 0, Reason: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if out["mode"] != "off" {
		t.Fatalf("%+v", out)
	}
	eff, err := op.CacheEffectiveConfig(context.Background(), "artifact_blob")
	if err != nil {
		t.Fatal(err)
	}
	typ := eff["type"].(map[string]any)
	if typ["mode"] != "off" {
		t.Fatalf("%+v", typ)
	}
}

func TestCachePlanOp_NoInlinePayload_RawBlocked(t *testing.T) {
	svc := adminops.New(adminops.Config{Role: adminops.RoleOperator})
	out, err := svc.CachePlanOp(context.Background(), adminops.CachePlanOpArgs{
		TypeID: "console_log", Kind: "purge",
	})
	if err != nil {
		t.Fatal(err)
	}
	if out["inlinePayload"] != false {
		t.Fatal("must never inline large dump")
	}
	if out["confirmToken"] != "PURGE" {
		t.Fatalf("%v", out["confirmToken"])
	}
	_, err = svc.CachePlanOp(context.Background(), adminops.CachePlanOpArgs{
		TypeID: "artifact_blob", Kind: "dump", DumpMode: "raw",
	})
	if err == nil {
		t.Fatal("raw dump must be rejected by default")
	}
}

func TestCacheTelemetry_SecretFreeNote(t *testing.T) {
	svc := adminops.New(adminops.Config{Role: adminops.RoleViewer})
	out, err := svc.CacheTelemetry(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if out["note"] == nil || out["note"] == "" {
		t.Fatal("note required")
	}
}

func TestToolCatalog_IncludesCacheControl(t *testing.T) {
	cat := adminops.ToolCatalog()
	need := []string{
		"admin_cache_inventory", "admin_cache_effective", "admin_cache_patch_mode",
		"admin_cache_plan", "admin_cache_telemetry", "admin_cache_status",
	}
	set := map[string]bool{}
	for _, n := range cat {
		set[n] = true
	}
	for _, n := range need {
		if !set[n] {
			t.Fatalf("missing %s", n)
		}
	}
}
