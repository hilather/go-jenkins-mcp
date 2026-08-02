package fleetcache_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/fleetcache"
)

func validWireFixture(t *testing.T) []byte {
	t.Helper()
	loc, err := fleetcache.NewConsoleLogLocator("fleet", "pool", "ctrl", "job", 1)
	if err != nil {
		t.Fatal(err)
	}
	lh, err := loc.Hash()
	if err != nil {
		t.Fatal(err)
	}
	dec := strings.Repeat("ab", 32)
	zst := strings.Repeat("cd", 32)
	m := fleetcache.WireManifest{
		ProtocolVersion: fleetcache.ProtocolVersionV1,
		FleetID:         "fleet",
		CachePool:       "pool",
		ControllerID:    "ctrl",
		LocatorHash:     lh,
		Sealed:          true,
		FormatVersion:   1,
		Codec:           fleetcache.ManifestCodecZstd,
		TotalRawBytes:   10,
		TotalLines:      2,
		Frames: []fleetcache.WireFrame{{
			Seq: 0, RawStart: 0, RawEnd: 10, LineStart: 0, LineEnd: 2,
			DecodedSize: 10, DecodedSHA256: dec, ZstdSize: 4, ZstdSHA256: zst,
		}},
	}
	// Fill digest from identity type.
	inner := m.ToManifestV1()
	d, err := inner.Digest()
	if err != nil {
		t.Fatal(err)
	}
	m.ManifestDigest = d
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestParseWireManifestJSON_AcceptsValid(t *testing.T) {
	t.Parallel()
	raw := validWireFixture(t)
	m, err := fleetcache.ParseWireManifestJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !m.Sealed || m.ProtocolVersion != fleetcache.ProtocolVersionV1 {
		t.Fatalf("%+v", m)
	}
	// Digest of converted identity must be stable.
	d, err := m.ToManifestV1().Digest()
	if err != nil {
		t.Fatal(err)
	}
	if d != m.ManifestDigest {
		t.Fatalf("digest mismatch %s vs %s", d, m.ManifestDigest)
	}
}

func TestParseWireManifestJSON_Adversarial(t *testing.T) {
	t.Parallel()
	good := validWireFixture(t)
	var base map[string]any
	if err := json.Unmarshal(good, &base); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		mut  func(map[string]any)
	}{
		{"unsealed", func(m map[string]any) { m["sealed"] = false }},
		{"bad protocol", func(m map[string]any) { m["protocol_version"] = "fleet-cache/9" }},
		{"bad codec", func(m map[string]any) { m["codec"] = "gzip" }},
		{"gap frames", func(m map[string]any) {
			frames := m["frames"].([]any)
			f0 := frames[0].(map[string]any)
			f0["seq"] = 1.0
		}},
		{"local_path field", func(m map[string]any) { m["local_path"] = "/tmp/x" }},
		{"generation_id field", func(m map[string]any) { m["generation_id"] = 99 }},
		{"path in value", func(m map[string]any) { m["note"] = "/tmp/evil" }},
		{"oversize body", func(m map[string]any) { /* handled separately */ }},
	}
	// Unicode-escaped forbidden key must fail (not only plain "path" text scan).
	t.Run("unicode_escaped_path_key", func(t *testing.T) {
		t.Parallel()
		// \u0070ath → "path" after JSON unescape
		raw := []byte(`{"protocol_version":"fleet-cache/1","fleet_id":"f","cache_pool":"p","controller_id":"c","locator_hash":"` +
			strings.Repeat("ab", 32) + `","sealed":true,"format_version":1,"codec":"zstd-independent-v1","total_raw_bytes":1,"total_lines":1,"frames":[{"seq":0,"raw_start":0,"raw_end":1,"line_start":0,"line_end":1,"decoded_size":1,"decoded_sha256":"` +
			strings.Repeat("cd", 32) + `","zstd_size":1,"zstd_sha256":"` + strings.Repeat("ef", 32) + `"}],"\u0070ath":"/smuggled"}`)
		_, err := fleetcache.ParseWireManifestJSON(raw)
		if err == nil {
			t.Fatal("expected reject unicode-escaped path key")
		}
		if apperr.CodeOf(err) != apperr.CodeInvalidArgument {
			t.Fatalf("code: %v", err)
		}
	})
	// Keep original cases loop below.
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if tc.name == "oversize body" {
				big := make([]byte, fleetcache.MaxWireManifestBytes+1)
				for i := range big {
					big[i] = 'a'
				}
				_, err := fleetcache.ParseWireManifestJSON(big)
				if err == nil {
					t.Fatal("expected oversize fail")
				}
				return
			}
			clone := map[string]any{}
			raw0, _ := json.Marshal(base)
			_ = json.Unmarshal(raw0, &clone)
			tc.mut(clone)
			raw, _ := json.Marshal(clone)
			_, err := fleetcache.ParseWireManifestJSON(raw)
			if err == nil {
				t.Fatal("expected error")
			}
			if apperr.CodeOf(err) != apperr.CodeInvalidArgument {
				t.Fatalf("code: %v", err)
			}
		})
	}
}

func TestValidateWireManifest_FrameCap(t *testing.T) {
	t.Parallel()
	loc, _ := fleetcache.NewConsoleLogLocator("f", "p", "c", "j", 1)
	lh, _ := loc.Hash()
	dec := strings.Repeat("11", 32)
	zst := strings.Repeat("22", 32)
	frames := make([]fleetcache.WireFrame, fleetcache.MaxWireFrames+1)
	var rawOff int64
	for i := range frames {
		frames[i] = fleetcache.WireFrame{
			Seq: i, RawStart: rawOff, RawEnd: rawOff + 1, LineStart: int64(i), LineEnd: int64(i + 1),
			DecodedSize: 1, DecodedSHA256: dec, ZstdSize: 1, ZstdSHA256: zst,
		}
		rawOff++
	}
	m := fleetcache.WireManifest{
		ProtocolVersion: fleetcache.ProtocolVersionV1,
		FleetID:         "f", CachePool: "p", ControllerID: "c",
		LocatorHash: lh, Sealed: true, FormatVersion: 1, Codec: fleetcache.ManifestCodecZstd,
		Frames: frames, TotalRawBytes: rawOff, TotalLines: int64(len(frames)),
	}
	if err := fleetcache.ValidateWireManifest(m); err == nil {
		t.Fatal("expected max frames fail")
	}
}
