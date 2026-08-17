package fleetmcp_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/fleetmcp"
)

// Regression: the /fleet/v1/member handler dereferenced cfg.Roster.FleetID /
// cfg.Roster.BundleSeq directly — every sibling handler nil-checks the roster.
// A hand-built Config{Roster: nil} panicked per-connection (net/http recovers
// with a dropped connection). It now answers a secret-free 503 instead.
func TestMemberHandler_NilRosterNoPanic(t *testing.T) {
	t.Parallel()
	mux := fleetmcp.NewPeerMux(fleetmcp.Config{
		MemberID:  "m1",
		MeshToken: "test-mesh-token",
		// Roster deliberately nil.
	}, nil)
	req := httptest.NewRequest(http.MethodGet, "/fleet/v1/member", nil)
	req.Header.Set(fleetmcp.MeshTokenHeader, "test-mesh-token")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req) // must not panic / drop the connection
	if rr.Code == http.StatusOK {
		t.Fatal("nil roster must not answer 200")
	}
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d (%s)", rr.Code, rr.Body.String())
	}
}

// Control: a configured roster answers member info.
func TestMemberHandler_WithRoster(t *testing.T) {
	t.Parallel()
	mux := fleetmcp.NewPeerMux(fleetmcp.Config{
		MemberID:  "m1",
		MeshToken: "test-mesh-token",
		Roster: &fleetmcp.Roster{
			FleetID:   "fleet-1",
			BundleSeq: 3,
			Members:   []fleetmcp.RosterMember{{ID: "m1", ProfileID: "corp"}},
		},
	}, nil)
	req := httptest.NewRequest(http.MethodGet, "/fleet/v1/member", nil)
	req.Header.Set(fleetmcp.MeshTokenHeader, "test-mesh-token")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
}
