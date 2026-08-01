package archive

import (
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
)

// QA-001: fuzz OpenPack / seek table / index JSON parsers.
// Must never panic on garbage; error is OK. Input size-capped for CI unit runs.

const fuzzMaxPackBytes = 256 << 10 // 256 KiB

// FuzzOpenPack feeds random bytes to the multi-frame pack opener.
func FuzzOpenPack(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add([]byte{0x28, 0xb5, 0x2f, 0xfd}) // zstd magic LE
	// Skippable magic + zero size.
	sk := make([]byte, 8)
	binary.LittleEndian.PutUint32(sk[0:4], skippableMagicMin)
	binary.LittleEndian.PutUint32(sk[4:8], 0)
	f.Add(sk)
	// Two skippable frames (not enough content frames).
	f.Add(append(append([]byte{}, sk...), sk...))
	// Truncated content magic.
	f.Add([]byte{0x28, 0xb5})
	// Huge claimed skippable size (truncated).
	huge := make([]byte, 8)
	binary.LittleEndian.PutUint32(huge[0:4], skippableMagicMin)
	binary.LittleEndian.PutUint32(huge[4:8], 0xffffffff)
	f.Add(huge)
	// JSON-looking garbage.
	f.Add([]byte(`{"magic":"JMCP-SEEK-V1"}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > fuzzMaxPackBytes {
			return
		}
		p, err := OpenPack(data)
		if err != nil {
			if p != nil {
				t.Fatalf("error with non-nil pack: %v", err)
			}
			// scanFrames alone should also be safe.
			_, _ = scanFrames(data)
			return
		}
		// Successful open: close decoder; table must be non-nil.
		defer p.Close()
		if p.SeekTable() == nil {
			t.Fatal("nil seek table on success")
		}
		_ = p.PackID()
		_ = p.ListMembers()
	})
}

// FuzzParseSeekTable ensures seek-table JSON bind never panics.
func FuzzParseSeekTable(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`{"magic":"JMCP-SEEK-V1","format_version":1}`))
	f.Add([]byte(`{"magic":"NOPE"}`))
	f.Add([]byte(`{"magic":"JMCP-SEEK-V1","format_version":1,"pack_id":"p",` +
		`"tar_size":0,"frames":[],"members":[],"pack_sha256":"abc","min_content_frames":2}`))
	// Valid-looking minimal multi-frame table (may still fail deeper checks).
	good, _ := json.Marshal(SeekTable{
		Magic:            SeekMagic,
		FormatVersion:    FormatVersion,
		PackID:           "fuzz-pack",
		TarSize:          100,
		PackSHA256:       strings.Repeat("a", 64),
		MinContentFrames: 2,
		Frames: []SeekFrame{
			{Index: 0, Kind: FrameKindContent, CompressedOffset: 0, CompressedSize: 10, RawOffset: 0, RawSize: 50, ContentSHA256: strings.Repeat("b", 64), FrameSHA256: strings.Repeat("c", 64)},
			{Index: 1, Kind: FrameKindContent, CompressedOffset: 10, CompressedSize: 10, RawOffset: 50, RawSize: 50, ContentSHA256: strings.Repeat("d", 64), FrameSHA256: strings.Repeat("e", 64)},
		},
		Members: []SeekMember{
			{Name: "log.txt", EntryID: "e1", RawOffset: 0, Size: 100, ContentSHA256: strings.Repeat("f", 64)},
		},
	})
	f.Add(good)
	f.Add([]byte(`{"magic":"JMCP-SEEK-V1","format_version":999,"pack_id":"x","frames":[{},{}]}`))
	f.Add([]byte(strings.Repeat("{", 1000)))
	f.Add([]byte("\x00\x01\xff"))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64<<10 {
			return
		}
		st, err := ParseSeekTable(data)
		if err != nil {
			if st != nil {
				t.Fatalf("error with non-nil table: %v", err)
			}
			return
		}
		// Validate is idempotent on success.
		if err := st.Validate(); err != nil {
			t.Fatalf("Validate after Parse: %v", err)
		}
	})
}

// FuzzParseIndex ensures sidecar pack-index JSON bind never panics.
func FuzzParseIndex(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`{"magic":"JMCP-IDX-V1","index_schema_version":1}`))
	idxJSON, _ := json.Marshal(PackIndex{
		Magic:              IndexMagic,
		IndexSchemaVersion: IndexSchemaVersion,
		PackID:             "p1",
		PackFormatVersion:  FormatVersion,
		PackSizeBytes:      100,
		PackSHA256:         strings.Repeat("a", 64),
		FileSHA256:         strings.Repeat("b", 64),
		MemberCount:        1,
		FrameCount:         2,
		BuiltAt:            "2020-01-01T00:00:00Z",
		Members:            []IndexMember{{EntryID: "e", Name: "n", Size: 1}},
	})
	f.Add(idxJSON)
	f.Add([]byte(`{"magic":"JMCP-IDX-V1","index_schema_version":99,"pack_id":"x"}`))
	f.Add([]byte(strings.Repeat("[", 500)))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64<<10 {
			return
		}
		idx, err := ParseIndex(data)
		if err != nil {
			if idx != nil {
				t.Fatalf("error with non-nil index: %v", err)
			}
			return
		}
		if err := idx.Validate(); err != nil {
			t.Fatalf("Validate after Parse: %v", err)
		}
		// BindMatches with mismatched identity must not panic.
		_ = idx.BindMatches("other", 1, "x", "y", FormatVersion)
		_ = idx.BindMatches(idx.PackID, idx.PackSizeBytes, idx.PackSHA256, idx.FileSHA256, idx.PackFormatVersion)
	})
}

// FuzzScanFrames covers the low-level independent-frame walker.
func FuzzScanFrames(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x28, 0xb5, 0x2f, 0xfd, 0x00})
	sk := make([]byte, 8)
	binary.LittleEndian.PutUint32(sk[0:4], skippableMagicMax)
	binary.LittleEndian.PutUint32(sk[4:8], 4)
	sk = append(sk, 1, 2, 3, 4)
	f.Add(sk)

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > fuzzMaxPackBytes {
			return
		}
		locs, err := scanFrames(data)
		if err != nil {
			return
		}
		// Offsets must be non-decreasing and in-bounds.
		var prev int64 = -1
		for _, l := range locs {
			if l.Offset < 0 || l.Size < 0 {
				t.Fatalf("negative loc: %+v", l)
			}
			if l.Offset <= prev {
				t.Fatalf("offset order: prev=%d got=%d", prev, l.Offset)
			}
			if l.Offset+l.Size > int64(len(data)) {
				t.Fatalf("out of bounds: %+v len=%d", l, len(data))
			}
			prev = l.Offset
		}
	})
}
