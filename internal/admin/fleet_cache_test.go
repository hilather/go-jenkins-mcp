package admin_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/admin"
	"github.com/hilather/go-jenkins-mcp/internal/fleetcache"
)

const fleetCacheSecretCanary = "planted-FLEET-TOKEN-never-echo-FLC063-9x7z"

func TestFleetCache_StatusDoctor_ViewerOK_SecretFree(t *testing.T) {
	paths := opsTestPaths(t)
	h := newOpsHandler(t, paths, admin.RoleViewer, "tok", nil)

	for _, path := range []string{
		"/admin/v1/fleet-cache/status",
		"/admin/v1/fleet-cache/doctor",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer tok")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("%s status=%d body=%s", path, rr.Code, rr.Body.String())
		}
		assertNoSecretCanary(t, rr.Body.String())
		if strings.Contains(rr.Body.String(), fleetCacheSecretCanary) {
			t.Fatal("canary in body")
		}
		var m map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		switch path {
		case "/admin/v1/fleet-cache/status":
			if m["mode"] != "off" {
				t.Fatalf("mode=%v", m["mode"])
			}
			if m["spa_residual"] == nil || m["spa_residual"] == "" {
				t.Fatal("spa_residual required")
			}
		case "/admin/v1/fleet-cache/doctor":
			if m["checks"] == nil {
				t.Fatalf("checks missing: %v", m)
			}
		}
	}
}

func TestFleetCache_Purge_Viewer403_OperatorMissingConfirm400(t *testing.T) {
	paths := opsTestPaths(t)
	lh := strings.Repeat("ef", 32)

	hViewer := newOpsHandler(t, paths, admin.RoleViewer, "tok", nil)
	body, _ := json.Marshal(map[string]any{
		"confirm":      "PURGE",
		"locator_hash": lh,
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/fleet-cache/purge", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer tok")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	hViewer.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("viewer purge: status=%d body=%s want 403", rr.Code, rr.Body.String())
	}
	assertNoSecretCanary(t, rr.Body.String())

	hOp := newOpsHandler(t, paths, admin.RoleOperator, "tok", nil)
	body2, _ := json.Marshal(map[string]any{
		"confirm":      "yes",
		"locator_hash": lh,
	})
	req2 := httptest.NewRequest(http.MethodPost, "/admin/v1/fleet-cache/purge", bytes.NewReader(body2))
	req2.Header.Set("Authorization", "Bearer tok")
	req2.Header.Set("Content-Type", "application/json")
	rr2 := httptest.NewRecorder()
	hOp.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusBadRequest {
		t.Fatalf("operator wrong confirm: status=%d body=%s want 400", rr2.Code, rr2.Body.String())
	}
	assertNoSecretCanary(t, rr2.Body.String())
}

func TestFleetCache_Purge_OperatorSuccess_SecretFree(t *testing.T) {
	paths := opsTestPaths(t)
	// Ensure profile data dir exists so optional audit emit can write.
	_ = ensureProfileData(t, paths, "admin")
	lh := strings.Repeat("11", 32)
	hOp := newOpsHandler(t, paths, admin.RoleOperator, fleetCacheSecretCanary, nil)

	body, _ := json.Marshal(map[string]any{
		"confirm":      admin.PurgeConfirmToken,
		"locator_hash": lh,
		"reason":       "operator cleanup",
		"profile_id":   "admin",
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/fleet-cache/purge", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+fleetCacheSecretCanary)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	hOp.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("operator purge: status=%d body=%s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), fleetCacheSecretCanary) {
		t.Fatalf("secret canary leaked: %s", rr.Body.String())
	}
	assertNoSecretCanary(t, rr.Body.String())

	var out map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out["status"] != fleetcache.PurgeStatusPurged && out["status"] != fleetcache.PurgeStatusPartial {
		t.Fatalf("status=%v", out["status"])
	}
	if out["http_peer_prop"] != false {
		t.Fatal("http_peer_prop must be false")
	}
	if out["confirm_token"] != fleetcache.PurgeConfirmToken {
		t.Fatalf("confirm_token=%v", out["confirm_token"])
	}
}

func TestFleetCache_Purge_MissingLocator400(t *testing.T) {
	paths := opsTestPaths(t)
	hOp := newOpsHandler(t, paths, admin.RoleOperator, "tok", nil)
	body, _ := json.Marshal(map[string]any{"confirm": "PURGE"})
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/fleet-cache/purge", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer tok")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	hOp.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s want 400", rr.Code, rr.Body.String())
	}
}

func TestFleetCache_ParityBFFCoreFields(t *testing.T) {
	// HTTP status and doctor share core fields with fleetcache facade maps.
	paths := opsTestPaths(t)
	h := newOpsHandler(t, paths, admin.RoleViewer, "tok", nil)
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/fleet-cache/status", nil)
	req.Header.Set("Authorization", "Bearer tok")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	var httpMap map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &httpMap); err != nil {
		t.Fatal(err)
	}
	cfg, err := fleetcache.ResolveConfig(fleetcache.ResolveOptions{Getenv: func(string) string { return "" }})
	if err != nil {
		t.Fatal(err)
	}
	lib := fleetcache.StatusSnapshot(cfg, nil, nil, fleetcache.StatusOptions{})
	for _, k := range []string{"mode", "active", "local_healthy", "replica_healthy", "spa_residual", "protocol"} {
		if httpMap[k] != lib[k] {
			t.Fatalf("field %s: http=%v lib=%v", k, httpMap[k], lib[k])
		}
	}
}
