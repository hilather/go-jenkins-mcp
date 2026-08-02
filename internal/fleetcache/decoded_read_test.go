package fleetcache_test

import (
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/fleetcache"
)

func TestValidateDecodedReadRequest_Forms(t *testing.T) {
	t.Parallel()
	lh := strings.Repeat("ab", 32)
	ok := fleetcache.DecodedReadRequest{LocatorHash: lh, Kind: fleetcache.ReadKindByteRange, Length: 1024}
	if err := fleetcache.ValidateDecodedReadRequest(ok); err != nil {
		t.Fatal(err)
	}
	// Over absolute ceiling.
	bad := fleetcache.DecodedReadRequest{LocatorHash: lh, Kind: fleetcache.ReadKindByteRange, Length: fleetcache.AbsoluteDecodedReadCeiling + 1}
	if err := fleetcache.ValidateDecodedReadRequest(bad); err == nil {
		t.Fatal("expected length over absolute fail")
	}
	// Over request ceiling.
	bad2 := fleetcache.DecodedReadRequest{
		LocatorHash: lh, Kind: fleetcache.ReadKindByteRange,
		Length: 100, MaxDecodedBytes: 50,
	}
	if err := fleetcache.ValidateDecodedReadRequest(bad2); err == nil {
		t.Fatal("expected length over request ceiling")
	}
	// Line range.
	if err := fleetcache.ValidateDecodedReadRequest(fleetcache.DecodedReadRequest{
		LocatorHash: lh, Kind: fleetcache.ReadKindLineRange, StartLine: 0, LineCount: 10,
	}); err != nil {
		t.Fatal(err)
	}
	// Mixed fields.
	if err := fleetcache.ValidateDecodedReadRequest(fleetcache.DecodedReadRequest{
		LocatorHash: lh, Kind: fleetcache.ReadKindByteRange, Length: 1, TailN: 1,
	}); err == nil {
		t.Fatal("expected mixed fields reject")
	}
}

func TestAuthorizeDecodedReadScope_DenyBeforeBody(t *testing.T) {
	t.Parallel()
	lh := strings.Repeat("cd", 32)
	claims := fleetcache.AssertionClaims{
		FleetID: "fleet", RequestingMemberID: "m1", LocatorHash: lh,
		Operation: fleetcache.OpRead, MaxDecodedBytes: 64 << 10,
		IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(20 * time.Second),
		Nonce: "n1",
	}
	req := fleetcache.DecodedReadRequest{LocatorHash: lh, Kind: fleetcache.ReadKindByteRange, Length: 1024}
	if err := fleetcache.AuthorizeDecodedReadScope(claims, req, fleetcache.Expected{
		FleetID: "fleet", LocatorHash: lh, Operation: fleetcache.OpRead, MaxDecodedBytes: 64 << 10,
	}); err != nil {
		t.Fatal(err)
	}
	// Wrong locator.
	reqBad := req
	reqBad.LocatorHash = strings.Repeat("ef", 32)
	if err := fleetcache.AuthorizeDecodedReadScope(claims, reqBad, fleetcache.Expected{FleetID: "fleet"}); err == nil {
		t.Fatal("expected locator deny")
	} else if apperr.CodeOf(err) != apperr.CodeAuthorization {
		t.Fatalf("code %s", apperr.CodeOf(err))
	}
	// Length beyond claim budget.
	small := claims
	small.MaxDecodedBytes = 100
	big := fleetcache.DecodedReadRequest{LocatorHash: lh, Kind: fleetcache.ReadKindByteRange, Length: 200}
	if err := fleetcache.AuthorizeDecodedReadScope(small, big, fleetcache.Expected{FleetID: "fleet"}); err == nil {
		t.Fatal("expected budget deny")
	}
	// Op head not read.
	head := claims
	head.Operation = fleetcache.OpHead
	if err := fleetcache.AuthorizeDecodedReadScope(head, req, fleetcache.Expected{}); err == nil {
		t.Fatal("expected op deny")
	}
}

func TestEffectiveDecodedCeiling(t *testing.T) {
	t.Parallel()
	c, err := fleetcache.EffectiveDecodedCeiling(0, 0)
	if err != nil || c != fleetcache.DefaultDecodedReadCeiling {
		t.Fatalf("%d %v", c, err)
	}
	c, err = fleetcache.EffectiveDecodedCeiling(1000, 2000)
	if err != nil || c != 1000 {
		t.Fatalf("%d %v", c, err)
	}
	c, err = fleetcache.EffectiveDecodedCeiling(5000, 2000)
	if err != nil || c != 2000 {
		t.Fatalf("%d %v", c, err)
	}
	if _, err := fleetcache.EffectiveDecodedCeiling(fleetcache.AbsoluteDecodedReadCeiling+1, 0); err == nil {
		t.Fatal("expected absolute claim reject")
	}
}

func TestEnforceDecodedBodyCeiling(t *testing.T) {
	t.Parallel()
	if err := fleetcache.EnforceDecodedBodyCeiling(100, 100); err != nil {
		t.Fatal(err)
	}
	if err := fleetcache.EnforceDecodedBodyCeiling(101, 100); err == nil {
		t.Fatal("expected over ceiling")
	} else if apperr.CodeOf(err) != apperr.CodeQuota {
		t.Fatalf("code %s", apperr.CodeOf(err))
	}
}

func TestAssertionCodec_RoundTrip(t *testing.T) {
	t.Parallel()
	key := testKey(t)
	c := validClaims(t)
	a, err := fleetcache.IssueAssertion(key, c)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := fleetcache.EncodeAssertionHeader(a)
	if err != nil {
		t.Fatal(err)
	}
	got, err := fleetcache.DecodeAssertionHeader(enc)
	if err != nil {
		t.Fatal(err)
	}
	if got.MAC != a.MAC || got.Claims.LocatorHash != a.Claims.LocatorHash {
		t.Fatalf("%+v vs %+v", got, a)
	}
	nonces := fleetcache.NewMemoryNonceStore()
	if err := fleetcache.VerifyAssertion(key, got, time.Now().UTC(), fleetcache.Expected{
		FleetID: "fleet", Operation: fleetcache.OpRead,
	}, nonces); err != nil {
		t.Fatal(err)
	}
}
