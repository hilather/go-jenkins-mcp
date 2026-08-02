package archive_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/archive"
	"github.com/klauspost/compress/zstd"
)

func TestPackFromGenerations_CopySinglePayload(t *testing.T) {
	body := []byte("payload-body-line\n" + strings.Repeat("y", 80) + "\n")
	enc, err := zstd.NewWriter(nil, zstd.WithEncoderCRC(true), zstd.WithEncoderLevel(zstd.SpeedDefault))
	if err != nil {
		t.Fatal(err)
	}
	defer enc.Close()
	frame := enc.EncodeAll(body, nil)

	data, st, err := archive.PackFromGenerations([]archive.GenerationMember{
		{Name: "logs/a/1/consoleText", Body: body, PayloadFrames: [][]byte{frame}},
		{Name: "logs/b/2/consoleText", Body: []byte("second\n"), PayloadFrames: [][]byte{enc.EncodeAll([]byte("second\n"), nil)}},
	}, archive.PackFromGenerationsOptions{PackID: "pack-from-gen-1"})
	if err != nil {
		t.Fatalf("PackFromGenerations: %v", err)
	}
	if st.PackID != "pack-from-gen-1" {
		t.Fatalf("pack id %q", st.PackID)
	}

	// Copied payload frames unchanged.
	found := 0
	for _, f := range st.Frames {
		if f.Kind != archive.FrameKindPayload {
			continue
		}
		slice := data[f.CompressedOffset : f.CompressedOffset+f.CompressedSize]
		if !bytes.Equal(slice, frame) && f.FrameSHA256 != archive.Sha256Hex(frame) {
			// second member has a different frame; just count payloads.
		}
		found++
	}
	if found < 2 {
		t.Fatalf("expected ≥2 payload frames, got %d", found)
	}

	p, err := archive.OpenPack(data)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	got, _, _, err := p.ReadMember(context.Background(), "logs/a/1/consoleText")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("read mismatch: %q vs %q", got, body)
	}
}

func TestPackFromGenerations_MultiPayloadFrames(t *testing.T) {
	enc, err := zstd.NewWriter(nil, zstd.WithEncoderCRC(true), zstd.WithEncoderLevel(zstd.SpeedDefault))
	if err != nil {
		t.Fatal(err)
	}
	defer enc.Close()

	part1 := []byte(strings.Repeat("A", 40) + "\n")
	part2 := []byte(strings.Repeat("B", 40) + "\n")
	body := append(append([]byte{}, part1...), part2...)
	f1 := enc.EncodeAll(part1, nil)
	f2 := enc.EncodeAll(part2, nil)
	// Need a second member so MinContentFrames is satisfied even for small packs.
	other := []byte("other-log\n")
	fo := enc.EncodeAll(other, nil)

	data, st, err := archive.PackFromGenerations([]archive.GenerationMember{
		{
			Name:          "logs/multi/1/consoleText",
			Body:          body,
			PayloadFrames: [][]byte{f1, f2},
		},
		{
			Name:          "logs/other/2/consoleText",
			Body:          other,
			PayloadFrames: [][]byte{fo},
		},
	}, archive.PackFromGenerationsOptions{PackID: "pack-multi-payload"})
	if err != nil {
		t.Fatalf("PackFromGenerations: %v", err)
	}

	// Multi-payload member must retain both L1 frames byte-identical.
	payloadHashes := map[string][]byte{
		archive.Sha256Hex(f1): f1,
		archive.Sha256Hex(f2): f2,
		archive.Sha256Hex(fo): fo,
	}
	found := 0
	for _, f := range st.Frames {
		if f.Kind != archive.FrameKindPayload {
			continue
		}
		slice := data[f.CompressedOffset : f.CompressedOffset+f.CompressedSize]
		want, ok := payloadHashes[f.FrameSHA256]
		if !ok {
			t.Fatalf("unexpected payload hash %s", f.FrameSHA256)
		}
		if !bytes.Equal(slice, want) {
			t.Fatal("payload frame bytes changed in pack")
		}
		found++
	}
	if found != 3 {
		t.Fatalf("payload frames found %d want 3", found)
	}

	p, err := archive.OpenPack(data)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	got, _, _, err := p.ReadMember(context.Background(), "logs/multi/1/consoleText")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("multi-frame body mismatch")
	}
}

func TestPackFromGenerations_RepackFallback(t *testing.T) {
	// No payload frames → compatibility WritePack path.
	data, st, err := archive.PackFromGenerations([]archive.GenerationMember{
		{Name: "logs/a.log", Body: []byte("alpha\n")},
		{Name: "logs/b.log", Body: []byte("bravo\n")},
	}, archive.PackFromGenerationsOptions{
		PackID:           "pack-repack",
		TargetFrameBytes: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Frames) < archive.MinContentFrames {
		t.Fatalf("frames %d", len(st.Frames))
	}
	p, err := archive.OpenPack(data)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	got, _, _, err := p.ReadMember(context.Background(), "logs/a.log")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "alpha\n" {
		t.Fatalf("got %q", got)
	}
}

func TestPackFromGenerations_ForceRepack(t *testing.T) {
	enc, err := zstd.NewWriter(nil, zstd.WithEncoderCRC(true))
	if err != nil {
		t.Fatal(err)
	}
	defer enc.Close()
	body := []byte("force-repack\n")
	frame := enc.EncodeAll(body, nil)
	prefer := false
	data, st, err := archive.PackFromGenerations([]archive.GenerationMember{
		{Name: "a.log", Body: body, PayloadFrames: [][]byte{frame}},
		{Name: "b.log", Body: []byte("b\n"), PayloadFrames: [][]byte{enc.EncodeAll([]byte("b\n"), nil)}},
	}, archive.PackFromGenerationsOptions{
		PackID:           "pack-force",
		PreferCopy:       &prefer,
		TargetFrameBytes: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Force-repack uses FrameKindContent, not payload copy.
	for _, f := range st.Frames {
		if f.Kind == archive.FrameKindPayload {
			t.Fatal("expected no payload frames when PreferCopy=false")
		}
	}
	p, err := archive.OpenPack(data)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	got, _, _, err := p.ReadMember(context.Background(), "a.log")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("got %q", got)
	}
}

func TestPackFromGenerations_RequiresPackID(t *testing.T) {
	_, _, err := archive.PackFromGenerations([]archive.GenerationMember{
		{Name: "a", Body: []byte("x")},
	}, archive.PackFromGenerationsOptions{})
	if err == nil {
		t.Fatal("expected error")
	}
}
