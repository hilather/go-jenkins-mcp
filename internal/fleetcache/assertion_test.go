package fleetcache_test

import (
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/fleetcache"
)

func testKey(t *testing.T) []byte {
	t.Helper()
	return fleetcache.DeriveAssertionKey([]byte("mesh-pilot-secret-material!!"), "fleet-cache-assert-v1")
}

func validClaims(t *testing.T) fleetcache.AssertionClaims {
	t.Helper()
	loc, err := fleetcache.NewConsoleLogLocator("fleet", "pool", "ctrl", "job", 1)
	if err != nil {
		t.Fatal(err)
	}
	h, err := loc.Hash()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	return fleetcache.AssertionClaims{
		FleetID:            "fleet",
		RequestingMemberID: "edge-a",
		LocatorHash:        h,
		Operation:          fleetcache.OpRead,
		MaxDecodedBytes:    64 << 10,
		SubjectKeyHash:     "abc123deadbeef",
		PolicyEpoch:        7,
		IssuedAt:           now,
		ExpiresAt:          now.Add(20 * time.Second),
	}
}

func TestIssueVerifyAssertion_OK(t *testing.T) {
	t.Parallel()
	key := testKey(t)
	c := validClaims(t)
	a, err := fleetcache.IssueAssertion(key, c)
	if err != nil {
		t.Fatal(err)
	}
	if a.MAC == "" || a.Claims.Nonce == "" {
		t.Fatalf("%+v", a)
	}
	nonces := fleetcache.NewMemoryNonceStore()
	err = fleetcache.VerifyAssertion(key, a, time.Now().UTC(), fleetcache.Expected{
		FleetID: "fleet", LocatorHash: c.LocatorHash, Operation: fleetcache.OpRead,
		MaxDecodedBytes: 64 << 10, PolicyEpoch: 7,
	}, nonces)
	if err != nil {
		t.Fatal(err)
	}
}

func TestVerifyAssertion_Adversarial(t *testing.T) {
	t.Parallel()
	key := testKey(t)
	c := validClaims(t)
	a, err := fleetcache.IssueAssertion(key, c)
	if err != nil {
		t.Fatal(err)
	}
	nonces := fleetcache.NewMemoryNonceStore()
	now := time.Now().UTC()

	// Happy once.
	if err := fleetcache.VerifyAssertion(key, a, now, fleetcache.Expected{FleetID: "fleet"}, nonces); err != nil {
		t.Fatal(err)
	}
	// Replay.
	if err := fleetcache.VerifyAssertion(key, a, now, fleetcache.Expected{FleetID: "fleet"}, nonces); err == nil {
		t.Fatal("expected replay")
	} else if apperr.CodeOf(err) != apperr.CodeAuthorization {
		t.Fatalf("code %v", err)
	}

	// Fresh for other cases.
	a2, _ := fleetcache.IssueAssertion(key, c)
	// Wrong fleet.
	if err := fleetcache.VerifyAssertion(key, a2, now, fleetcache.Expected{FleetID: "other"}, fleetcache.NewMemoryNonceStore()); err == nil {
		t.Fatal("fleet")
	}
	// Expired.
	a3, _ := fleetcache.IssueAssertion(key, c)
	if err := fleetcache.VerifyAssertion(key, a3, a3.Claims.ExpiresAt.Add(time.Second), fleetcache.Expected{}, fleetcache.NewMemoryNonceStore()); err == nil {
		t.Fatal("expired")
	}
	// Tamper locator after issue.
	a4, _ := fleetcache.IssueAssertion(key, c)
	a4.Claims.LocatorHash = strings.Repeat("0", 64)
	if err := fleetcache.VerifyAssertion(key, a4, now, fleetcache.Expected{}, fleetcache.NewMemoryNonceStore()); err == nil {
		t.Fatal("tamper")
	}
	// Wrong op.
	a5, _ := fleetcache.IssueAssertion(key, c)
	if err := fleetcache.VerifyAssertion(key, a5, now, fleetcache.Expected{Operation: fleetcache.OpFrame}, fleetcache.NewMemoryNonceStore()); err == nil {
		t.Fatal("op")
	}
	// Widen budget rejected by expected cap.
	a6, _ := fleetcache.IssueAssertion(key, c)
	if err := fleetcache.VerifyAssertion(key, a6, now, fleetcache.Expected{MaxDecodedBytes: 1024}, fleetcache.NewMemoryNonceStore()); err == nil {
		t.Fatal("budget widen")
	}
	// Policy epoch.
	a7, _ := fleetcache.IssueAssertion(key, c)
	if err := fleetcache.VerifyAssertion(key, a7, now, fleetcache.Expected{PolicyEpoch: 99}, fleetcache.NewMemoryNonceStore()); err == nil {
		t.Fatal("epoch")
	}
	// Wrong key.
	a8, _ := fleetcache.IssueAssertion(key, c)
	badKey := fleetcache.DeriveAssertionKey([]byte("other-secret-material!!!!"), "fleet-cache-assert-v1")
	if err := fleetcache.VerifyAssertion(badKey, a8, now, fleetcache.Expected{}, fleetcache.NewMemoryNonceStore()); err == nil {
		t.Fatal("wrong key")
	}
}

func TestIssueAssertion_RejectsSecretShapedSubject(t *testing.T) {
	t.Parallel()
	c := validClaims(t)
	c.SubjectKeyHash = "Bearer eyJhbGciOiJIUzI1NiJ9.xx"
	_, err := fleetcache.IssueAssertion(testKey(t), c)
	if err == nil {
		t.Fatal("expected reject")
	}
}

func TestIssueAssertion_ErrorsSecretFree(t *testing.T) {
	t.Parallel()
	c := validClaims(t)
	c.SubjectKeyHash = "password=hunter2"
	err := error(nil)
	_, err = fleetcache.IssueAssertion(testKey(t), c)
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	for _, bad := range []string{"hunter2", "Bearer ", "password=hunter"} {
		if strings.Contains(msg, bad) {
			t.Fatalf("leaked %q in %q", bad, msg)
		}
	}
}
