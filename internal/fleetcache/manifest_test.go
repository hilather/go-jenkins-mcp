package fleetcache_test

import (
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/fleetcache"
)

func TestManifestV1_DigestStableAndContentSensitive(t *testing.T) {
	t.Parallel()
	loc, err := fleetcache.NewConsoleLogLocator("f", "p", "c", "job", 1)
	if err != nil {
		t.Fatal(err)
	}
	lh, err := loc.Hash()
	if err != nil {
		t.Fatal(err)
	}
	// 64-char hex digests (not real content; format-valid).
	dec := strings.Repeat("ab", 32)
	zst := strings.Repeat("cd", 32)
	m := fleetcache.ManifestV1{
		LocatorHash:   lh,
		Sealed:        true,
		FormatVersion: 1,
		Codec:         fleetcache.ManifestCodecZstd,
		TotalRawBytes: 10,
		TotalLines:    2,
		Frames: []fleetcache.FrameDescriptor{{
			Seq: 0, RawStart: 0, RawEnd: 10, LineStart: 0, LineEnd: 2,
			DecodedSize: 10, DecodedSHA256: dec, ZstdSize: 4, ZstdSHA256: zst,
		}},
	}
	d1, err := m.Digest()
	if err != nil {
		t.Fatal(err)
	}
	d2, err := m.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if d1 != d2 || len(d1) != 64 {
		t.Fatalf("digest %s", d1)
	}
	// Change decoded hash → different digest.
	m2 := m
	m2.Frames = append([]fleetcache.FrameDescriptor(nil), m.Frames...)
	m2.Frames[0].DecodedSHA256 = strings.Repeat("ef", 32)
	d3, err := m2.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if d3 == d1 {
		t.Fatal("expected content-sensitive digest")
	}
	// Canonical must not include generation/path fields.
	raw, err := m.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, banned := range []string{"generation", "profile", "path=", "/tmp/", "sqlite"} {
		if strings.Contains(strings.ToLower(s), banned) {
			t.Fatalf("banned %q in %s", banned, s)
		}
	}
}

func TestManifestV1_RejectsGapsAndLocalSmuggling(t *testing.T) {
	t.Parallel()
	loc, _ := fleetcache.NewConsoleLogLocator("f", "p", "c", "job", 1)
	lh, _ := loc.Hash()
	dec := strings.Repeat("11", 32)
	zst := strings.Repeat("22", 32)
	bad := fleetcache.ManifestV1{
		LocatorHash: lh, Sealed: true, FormatVersion: 1, Codec: fleetcache.ManifestCodecZstd,
		TotalRawBytes: 10, TotalLines: 1,
		Frames: []fleetcache.FrameDescriptor{{
			Seq:      1, // not from 0
			RawStart: 0, RawEnd: 10, LineStart: 0, LineEnd: 1,
			DecodedSize: 10, DecodedSHA256: dec, ZstdSize: 3, ZstdSHA256: zst,
		}},
	}
	if _, err := bad.Digest(); err == nil {
		t.Fatal("expected seq fail")
	}
	unsealed := bad
	unsealed.Frames[0].Seq = 0
	unsealed.Sealed = false
	if _, err := unsealed.Digest(); err == nil {
		t.Fatal("expected sealed")
	}
}
