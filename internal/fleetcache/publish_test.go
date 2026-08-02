package fleetcache_test

import (
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/fleetcache"
)

func sealedPublishFixture(t *testing.T) fleetcache.SealedPublishInput {
	t.Helper()
	dec := strings.Repeat("ab", 32)
	zst := strings.Repeat("cd", 32)
	return fleetcache.SealedPublishInput{
		FleetID: "fleet", CachePool: "pool", ControllerID: "ctrl",
		JobFullName: "folder/job", BuildNumber: 9, Sealed: true,
		Frames: []fleetcache.FrameDescriptor{{
			Seq: 0, RawStart: 0, RawEnd: 10, LineStart: 0, LineEnd: 2,
			DecodedSize: 10, DecodedSHA256: dec, ZstdSize: 4, ZstdSHA256: zst,
		}},
	}
}

func TestPublishSealed_Idempotent(t *testing.T) {
	t.Parallel()
	in := sealedPublishFixture(t)
	m1, err := fleetcache.PublishSealed(in)
	if err != nil {
		t.Fatal(err)
	}
	m2, err := fleetcache.PublishSealed(in)
	if err != nil {
		t.Fatal(err)
	}
	if m1.LocatorHash != m2.LocatorHash || m1.ManifestDigest != m2.ManifestDigest {
		t.Fatalf("not idempotent: %+v vs %+v", m1, m2)
	}
	if !m1.Sealed || m1.ProtocolVersion != fleetcache.ProtocolVersionV1 {
		t.Fatalf("%+v", m1)
	}
	// Round-trip validate via parse.
	// digest recompute
	d, err := m1.ToManifestV1().Digest()
	if err != nil {
		t.Fatal(err)
	}
	if d != m1.ManifestDigest {
		t.Fatalf("digest %s vs %s", d, m1.ManifestDigest)
	}
}

func TestPublishSealed_RejectUnsealedAndIncomplete(t *testing.T) {
	t.Parallel()
	in := sealedPublishFixture(t)
	in.Sealed = false
	if _, err := fleetcache.PublishSealed(in); err == nil {
		t.Fatal("unsealed")
	}
	in = sealedPublishFixture(t)
	in.Frames = nil
	if _, err := fleetcache.PublishSealed(in); err == nil {
		t.Fatal("no frames")
	}
	in = sealedPublishFixture(t)
	in.Frames[0].ZstdSHA256 = ""
	if _, err := fleetcache.PublishSealed(in); err == nil {
		t.Fatal("missing wire hash")
	}
}

func TestPublishSealed_ChangesWithBuild(t *testing.T) {
	t.Parallel()
	in := sealedPublishFixture(t)
	m1, _ := fleetcache.PublishSealed(in)
	in.BuildNumber = 10
	m2, err := fleetcache.PublishSealed(in)
	if err != nil {
		t.Fatal(err)
	}
	if m1.LocatorHash == m2.LocatorHash {
		t.Fatal("locator should change with build")
	}
}
