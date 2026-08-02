package mcpserver_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/mcpserver"
)

// HOST-001 mid-session rebind residual offline expand:
// PathPrefix strip does not weaken session fingerprint; lab group claim change
// on the same Mcp-Session-Id fails closed; same groups different order remains
// stable; health (root + prefixed) stays exempt; 401 bodies stay secret-free.
// Live Entra / jwt-auth-filter remain residual (not Done).

// assertHOST001Rebind401Canary checks 401 and no transport secret / subjects /
// fingerprints / Bearer material in the body.
func assertHOST001Rebind401Canary(t *testing.T, rr *httptest.ResponseRecorder, leaks ...string) {
	t.Helper()
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if strings.Contains(body, canaryHTTPToken) {
		t.Fatalf("Regression: canary transport secret leaked in 401: %s", body)
	}
	if strings.Contains(body, "Bearer ") {
		t.Fatalf("Regression: Bearer material in 401: %s", body)
	}
	for _, leak := range leaks {
		if leak != "" && strings.Contains(body, leak) {
			t.Fatalf("Regression: %q leaked in 401 body: %s", leak, body)
		}
	}
	// Generic identity fail body — never session fingerprint hex or clear subjects.
	if strings.Contains(body, "fingerprint") || strings.Contains(body, "IdentityFingerprint") {
		t.Fatalf("Regression: fingerprint material wording in 401: %s", body)
	}
}

// postPathLoopback POSTs under an arbitrary path (PathPrefix cases).
func postPathLoopback(t *testing.T, h http.Handler, path string, setHeaders func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	if path == "" {
		path = "/mcp"
	}
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1"+path, strings.NewReader(`{}`))
	req.Host = "127.0.0.1:8765"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if setHeaders != nil {
		setHeaders(req)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

// HOST-001 + HOST-002: PathPrefix strip still binds Mcp-Session-Id fingerprint;
// Alice→Bob mid-session swap under /mcp → 401 secret-free.
func TestHOST001_PathPrefix_MidSessionSubjectSwap401(t *testing.T) {
	t.Parallel()
	srv := mcpserver.NewServer("test", "0.0.1")
	cfg := mcpserver.DefaultHTTPConfig()
	cfg.RequireSubject = true
	cfg.LabIdentity = true
	cfg.BearerToken = canaryHTTPToken
	cfg.PathPrefix = "/mcp"
	h, err := mcpserver.NewHTTPHandler(srv, cfg)
	if err != nil {
		t.Fatal(err)
	}
	const sessionID = "sess-host001-prefix-swap"

	// Alice establishes under PathPrefix. Protect must not 401; SDK may still
	// return non-2xx (e.g. session not found) after identity bind.
	rr1 := postPathLoopback(t, h, "/mcp", func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+canaryHTTPToken)
		r.Header.Set(mcpserver.HeaderMCPSessionID, sessionID)
		r.Header.Set(mcpserver.HeaderLabSubject, "alice")
		r.Header.Set(mcpserver.HeaderLabTenant, "tid-a")
	})
	if rr1.Code == http.StatusUnauthorized {
		t.Fatalf("alice under PathPrefix should not 401: %s", rr1.Body.String())
	}
	// Path-level NotFound from Go's http.NotFound is "404 page not found".
	// MCP "session not found" is a different residual after protect passed.
	if rr1.Code == http.StatusNotFound && strings.Contains(rr1.Body.String(), "page not found") {
		t.Fatalf("PathPrefix MCP route must not path-404: %s", rr1.Body.String())
	}

	// Same subject rebind under nested residual path also OK (no identity 401).
	rrSame := postPathLoopback(t, h, "/mcp/v1", func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+canaryHTTPToken)
		r.Header.Set(mcpserver.HeaderMCPSessionID, sessionID)
		r.Header.Set(mcpserver.HeaderLabSubject, "alice")
		r.Header.Set(mcpserver.HeaderLabTenant, "tid-a")
	})
	if rrSame.Code == http.StatusUnauthorized {
		t.Fatalf("same subject under nested prefix residual should not 401: %s", rrSame.Body.String())
	}

	// Bob mid-session swap → 401.
	rrSwap := postPathLoopback(t, h, "/mcp", func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+canaryHTTPToken)
		r.Header.Set(mcpserver.HeaderMCPSessionID, sessionID)
		r.Header.Set(mcpserver.HeaderLabSubject, "bob")
		r.Header.Set(mcpserver.HeaderLabTenant, "tid-a")
	})
	assertHOST001Rebind401Canary(t, rrSwap, "alice", "bob", "tid-a", sessionID)

	// Outside prefix still path-404 (strip does not open root MCP).
	rrRoot := postPathLoopback(t, h, "/", func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+canaryHTTPToken)
		r.Header.Set(mcpserver.HeaderMCPSessionID, sessionID)
		r.Header.Set(mcpserver.HeaderLabSubject, "alice")
	})
	if rrRoot.Code != http.StatusNotFound {
		t.Fatalf("root MCP with PathPrefix want 404, got %d", rrRoot.Code)
	}
}

// HOST-001: IdentityFingerprint includes Groups — mid-session group claim change
// (same subject) fails closed. Lab header path offline (not live Entra Done).
func TestHOST001_MidSessionGroupClaimChange401(t *testing.T) {
	t.Parallel()
	srv := mcpserver.NewServer("test", "0.0.1")
	cfg := mcpserver.DefaultHTTPConfig()
	cfg.RequireSubject = true
	cfg.LabIdentity = true
	cfg.BearerToken = canaryHTTPToken
	h, err := mcpserver.NewHTTPHandler(srv, cfg)
	if err != nil {
		t.Fatal(err)
	}
	const sessionID = "sess-host001-group-change"

	// Establish with groups ops,dev.
	rr1 := postLoopback(t, h, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+canaryHTTPToken)
		r.Header.Set(mcpserver.HeaderMCPSessionID, sessionID)
		r.Header.Set(mcpserver.HeaderLabSubject, "alice")
		r.Header.Set(mcpserver.HeaderLabGroups, "ops,dev")
	})
	if rr1.Code == http.StatusUnauthorized {
		t.Fatalf("establish with groups should not 401: %s", rr1.Body.String())
	}

	// Same groups (order-stable) rebind OK.
	rrSame := postLoopback(t, h, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+canaryHTTPToken)
		r.Header.Set(mcpserver.HeaderMCPSessionID, sessionID)
		r.Header.Set(mcpserver.HeaderLabSubject, "alice")
		r.Header.Set(mcpserver.HeaderLabGroups, "ops,dev")
	})
	if rrSame.Code == http.StatusUnauthorized {
		t.Fatalf("same groups rebind should not 401: %s", rrSame.Body.String())
	}

	// Group membership change (add admins) → fail closed.
	rrChange := postLoopback(t, h, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+canaryHTTPToken)
		r.Header.Set(mcpserver.HeaderMCPSessionID, sessionID)
		r.Header.Set(mcpserver.HeaderLabSubject, "alice")
		r.Header.Set(mcpserver.HeaderLabGroups, "ops,dev,admins")
	})
	assertHOST001Rebind401Canary(t, rrChange, "alice", "ops", "dev", "admins")

	// Drop all groups (empty) while subject same → also fail closed.
	// Re-establish on a fresh session for empty-groups case.
	const sessionEmpty = "sess-host001-group-drop"
	rrEst := postLoopback(t, h, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+canaryHTTPToken)
		r.Header.Set(mcpserver.HeaderMCPSessionID, sessionEmpty)
		r.Header.Set(mcpserver.HeaderLabSubject, "alice")
		r.Header.Set(mcpserver.HeaderLabGroups, "ops")
	})
	if rrEst.Code == http.StatusUnauthorized {
		t.Fatalf("establish: %s", rrEst.Body.String())
	}
	rrDrop := postLoopback(t, h, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+canaryHTTPToken)
		r.Header.Set(mcpserver.HeaderMCPSessionID, sessionEmpty)
		r.Header.Set(mcpserver.HeaderLabSubject, "alice")
		// no groups header
	})
	assertHOST001Rebind401Canary(t, rrDrop, "alice", "ops")
}

// HOST-001: sorted Groups → same subject + different group order still OK
// (stable fingerprint). Handler path, not only unit IdentityFingerprint.
func TestHOST001_MidSessionSameGroupsDifferentOrderOK(t *testing.T) {
	t.Parallel()
	srv := mcpserver.NewServer("test", "0.0.1")
	cfg := mcpserver.DefaultHTTPConfig()
	cfg.RequireSubject = true
	cfg.LabIdentity = true
	cfg.BearerToken = canaryHTTPToken
	h, err := mcpserver.NewHTTPHandler(srv, cfg)
	if err != nil {
		t.Fatal(err)
	}
	const sessionID = "sess-host001-group-order"

	rr1 := postLoopback(t, h, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+canaryHTTPToken)
		r.Header.Set(mcpserver.HeaderMCPSessionID, sessionID)
		r.Header.Set(mcpserver.HeaderLabSubject, "alice")
		r.Header.Set(mcpserver.HeaderLabGroups, "ops,dev,readers")
	})
	if rr1.Code == http.StatusUnauthorized {
		t.Fatalf("establish: %s", rr1.Body.String())
	}

	// Permute order + whitespace.
	rrOrder := postLoopback(t, h, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+canaryHTTPToken)
		r.Header.Set(mcpserver.HeaderMCPSessionID, sessionID)
		r.Header.Set(mcpserver.HeaderLabSubject, "alice")
		r.Header.Set(mcpserver.HeaderLabGroups, " readers , ops ,dev ")
	})
	if rrOrder.Code == http.StatusUnauthorized {
		t.Fatalf("Regression: different group order must not 401 (stable fingerprint): %s",
			rrOrder.Body.String())
	}

	// Unit parity: fingerprint itself is order-independent.
	a := mcpserver.IdentityFingerprint(mcpserver.RequestIdentity{
		ExternalSubject: "alice",
		Groups:          []string{"ops", "dev", "readers"},
	})
	b := mcpserver.IdentityFingerprint(mcpserver.RequestIdentity{
		ExternalSubject: "alice",
		Groups:          []string{"readers", "ops", "dev"},
	})
	if a == "" || a != b {
		t.Fatalf("stable fingerprint want equal opaque hashes, a=%q b=%q", a, b)
	}
	if strings.Contains(a, "alice") || strings.Contains(a, "ops") {
		t.Fatalf("fingerprint must be opaque: %q", a)
	}
}

// HOST-001: PathPrefix + group claim mid-session change still 401; health exempt
// at root and {prefix}/healthz even after a bound session.
func TestHOST001_PathPrefix_GroupChangeAndHealthExempt(t *testing.T) {
	t.Parallel()
	srv := mcpserver.NewServer("test", "0.0.1")
	cfg := mcpserver.DefaultHTTPConfig()
	cfg.RequireSubject = true
	cfg.LabIdentity = true
	cfg.BearerToken = canaryHTTPToken
	cfg.PathPrefix = "/mcp"
	h, err := mcpserver.NewHTTPHandler(srv, cfg)
	if err != nil {
		t.Fatal(err)
	}
	const sessionID = "sess-host001-prefix-groups"

	rr1 := postPathLoopback(t, h, "/mcp", func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+canaryHTTPToken)
		r.Header.Set(mcpserver.HeaderMCPSessionID, sessionID)
		r.Header.Set(mcpserver.HeaderLabSubject, "alice")
		r.Header.Set(mcpserver.HeaderLabGroups, "g1,g2")
	})
	if rr1.Code == http.StatusUnauthorized {
		t.Fatalf("establish under prefix: %s", rr1.Body.String())
	}

	rrSwapGroups := postPathLoopback(t, h, "/mcp", func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+canaryHTTPToken)
		r.Header.Set(mcpserver.HeaderMCPSessionID, sessionID)
		r.Header.Set(mcpserver.HeaderLabSubject, "alice")
		r.Header.Set(mcpserver.HeaderLabGroups, "g1,g2,g3")
	})
	assertHOST001Rebind401Canary(t, rrSwapGroups, "alice", "g1", "g2", "g3")

	// Health remains exempt (no subject, spoofed session+subject) at root + prefix.
	for _, path := range []string{
		mcpserver.HealthzPath,
		mcpserver.ReadyzPath,
		"/mcp" + mcpserver.HealthzPath,
		"/mcp" + mcpserver.ReadyzPath,
	} {
		req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1"+path, nil)
		req.Host = "127.0.0.1:8765"
		req.Header.Set(mcpserver.HeaderMCPSessionID, sessionID)
		req.Header.Set(mcpserver.HeaderLabSubject, "bob")
		req.Header.Set(mcpserver.HeaderLabGroups, "admins")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("%s must stay 200 (session bind exempt), got %d body=%s",
				path, rr.Code, rr.Body.String())
		}
		body := rr.Body.String()
		if strings.Contains(body, canaryHTTPToken) || strings.Contains(body, "alice") || strings.Contains(body, "bob") {
			t.Fatalf("%s must stay secret/subject-free: %s", path, body)
		}
	}
}

// Table-driven HOST-001 mid-session residual expand: several fingerprint-changing
// fields fail closed; health still exempt; secret-free 401.
func TestHOST001_MidSessionRebindExpand_Table(t *testing.T) {
	t.Parallel()

	type step struct {
		name       string
		subject    string
		tenant     string
		groups     string // raw lab groups header; empty = omit
		wantStatus int    // 0 → not 401 (protect pass); 401 → fail closed
		leaks      []string
	}

	cases := []struct {
		name  string
		steps []step
	}{
		{
			name: "subject_swap",
			steps: []step{
				{name: "alice", subject: "alice", tenant: "t1", wantStatus: 0},
				{name: "bob_swap", subject: "bob", tenant: "t1", wantStatus: http.StatusUnauthorized, leaks: []string{"alice", "bob"}},
			},
		},
		{
			name: "tenant_change",
			steps: []step{
				{name: "tid_a", subject: "alice", tenant: "tid-a", wantStatus: 0},
				{name: "tid_b", subject: "alice", tenant: "tid-b", wantStatus: http.StatusUnauthorized, leaks: []string{"alice", "tid-a", "tid-b"}},
			},
		},
		{
			name: "group_claim_change",
			steps: []step{
				{name: "g_ops", subject: "alice", groups: "ops", wantStatus: 0},
				{name: "g_dev", subject: "alice", groups: "dev", wantStatus: http.StatusUnauthorized, leaks: []string{"alice", "ops", "dev"}},
			},
		},
		{
			name: "group_order_stable",
			steps: []step{
				{name: "order1", subject: "alice", groups: "a,b,c", wantStatus: 0},
				{name: "order2", subject: "alice", groups: "c,a,b", wantStatus: 0},
			},
		},
		{
			name: "same_subject_ok",
			steps: []step{
				{name: "first", subject: "alice", tenant: "t", groups: "x,y", wantStatus: 0},
				{name: "second", subject: "alice", tenant: "t", groups: "x,y", wantStatus: 0},
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv := mcpserver.NewServer("test", "0.0.1")
			cfg := mcpserver.DefaultHTTPConfig()
			cfg.RequireSubject = true
			cfg.LabIdentity = true
			cfg.BearerToken = canaryHTTPToken
			h, err := mcpserver.NewHTTPHandler(srv, cfg)
			if err != nil {
				t.Fatal(err)
			}
			sessionID := "sess-table-" + tc.name
			for _, st := range tc.steps {
				st := st
				rr := postLoopback(t, h, func(r *http.Request) {
					r.Header.Set("Authorization", "Bearer "+canaryHTTPToken)
					r.Header.Set(mcpserver.HeaderMCPSessionID, sessionID)
					r.Header.Set(mcpserver.HeaderLabSubject, st.subject)
					if st.tenant != "" {
						r.Header.Set(mcpserver.HeaderLabTenant, st.tenant)
					}
					if st.groups != "" {
						r.Header.Set(mcpserver.HeaderLabGroups, st.groups)
					}
				})
				if st.wantStatus == http.StatusUnauthorized {
					assertHOST001Rebind401Canary(t, rr, append(st.leaks, sessionID)...)
				} else if rr.Code == http.StatusUnauthorized {
					t.Fatalf("%s/%s: unexpected 401 body=%s", tc.name, st.name, rr.Body.String())
				}
			}
		})
	}
}

// HOST-001: IdentityResolver-simulated JWT subjects — mid-session Alice→Bob
// swap 401 (package-level offline expand; full lab JWT mint is in cmd).
func TestHOST001_ResolverSimulatedJWT_MidSessionAliceBobSwap(t *testing.T) {
	t.Parallel()
	srv := mcpserver.NewServer("test", "0.0.1")
	cfg := mcpserver.DefaultHTTPConfig()
	cfg.RequireSubject = true
	cfg.BearerToken = canaryHTTPToken
	// Simulate validated JWT: Authorization Bearer value is a non-secret subject label
	// in lab tests only (not a real token). Production uses JWKS validation.
	const aliceLabel = "jwt-sub-alice"
	const bobLabel = "jwt-sub-bob"
	cfg.IdentityResolver = func(r *http.Request) (mcpserver.RequestIdentity, error) {
		authz := r.Header.Get("Authorization")
		if !strings.HasPrefix(authz, "Bearer ") {
			return mcpserver.RequestIdentity{}, nil
		}
		raw := strings.TrimSpace(strings.TrimPrefix(authz, "Bearer "))
		// Transport secret alone is never identity.
		if raw == "" || raw == canaryHTTPToken {
			return mcpserver.RequestIdentity{}, nil
		}
		// Lab JWT stand-in: "jwt:<sub>:<groups csv>"
		if !strings.HasPrefix(raw, "jwt:") {
			return mcpserver.RequestIdentity{}, nil
		}
		parts := strings.SplitN(raw, ":", 3)
		if len(parts) < 2 || parts[1] == "" {
			return mcpserver.RequestIdentity{}, nil
		}
		var groups []string
		if len(parts) == 3 && parts[2] != "" {
			for _, g := range strings.Split(parts[2], ",") {
				g = strings.TrimSpace(g)
				if g != "" {
					groups = append(groups, g)
				}
			}
		}
		return mcpserver.RequestIdentity{
			ExternalSubject: parts[1],
			Tenant:          strings.TrimSpace(r.Header.Get(mcpserver.HeaderLabTenant)),
			Groups:          groups,
			Source:          mcpserver.IdentitySourceJWT,
			Verified:        true,
		}, nil
	}
	h, err := mcpserver.NewHTTPHandler(srv, cfg)
	if err != nil {
		t.Fatal(err)
	}
	const sessionID = "sess-host001-jwt-sim"

	// Transport secret on separate header; JWT-sim on Authorization.
	rrAlice := postLoopback(t, h, func(r *http.Request) {
		r.Header.Set(mcpserver.HeaderJenkinsMCPToken, canaryHTTPToken)
		r.Header.Set("Authorization", "Bearer jwt:"+aliceLabel+":ops,dev")
		r.Header.Set(mcpserver.HeaderMCPSessionID, sessionID)
		r.Header.Set(mcpserver.HeaderLabTenant, "tid-jwt")
	})
	if rrAlice.Code == http.StatusUnauthorized {
		t.Fatalf("alice jwt-sim establish: %s", rrAlice.Body.String())
	}

	// Same subject, same groups different order → OK.
	rrSame := postLoopback(t, h, func(r *http.Request) {
		r.Header.Set(mcpserver.HeaderJenkinsMCPToken, canaryHTTPToken)
		r.Header.Set("Authorization", "Bearer jwt:"+aliceLabel+":dev,ops")
		r.Header.Set(mcpserver.HeaderMCPSessionID, sessionID)
		r.Header.Set(mcpserver.HeaderLabTenant, "tid-jwt")
	})
	if rrSame.Code == http.StatusUnauthorized {
		t.Fatalf("alice same fingerprint order-stable: %s", rrSame.Body.String())
	}

	// Bob JWT-sim on same session → 401.
	rrBob := postLoopback(t, h, func(r *http.Request) {
		r.Header.Set(mcpserver.HeaderJenkinsMCPToken, canaryHTTPToken)
		r.Header.Set("Authorization", "Bearer jwt:"+bobLabel+":ops,dev")
		r.Header.Set(mcpserver.HeaderMCPSessionID, sessionID)
		r.Header.Set(mcpserver.HeaderLabTenant, "tid-jwt")
	})
	assertHOST001Rebind401Canary(t, rrBob, aliceLabel, bobLabel, "ops", "dev", "tid-jwt")

	// Alice group claim change (same sub) → 401.
	const sessionG = "sess-host001-jwt-sim-groups"
	rrG1 := postLoopback(t, h, func(r *http.Request) {
		r.Header.Set(mcpserver.HeaderJenkinsMCPToken, canaryHTTPToken)
		r.Header.Set("Authorization", "Bearer jwt:"+aliceLabel+":ops")
		r.Header.Set(mcpserver.HeaderMCPSessionID, sessionG)
	})
	if rrG1.Code == http.StatusUnauthorized {
		t.Fatalf("group establish: %s", rrG1.Body.String())
	}
	rrG2 := postLoopback(t, h, func(r *http.Request) {
		r.Header.Set(mcpserver.HeaderJenkinsMCPToken, canaryHTTPToken)
		r.Header.Set("Authorization", "Bearer jwt:"+aliceLabel+":ops,admins")
		r.Header.Set(mcpserver.HeaderMCPSessionID, sessionG)
	})
	assertHOST001Rebind401Canary(t, rrG2, aliceLabel, "ops", "admins")
}
