package archive_test

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/archive"
)

func testMembers() []archive.MemberInput {
	return []archive.MemberInput{
		{Name: "logs/root/consoleText", Body: []byte("root log line one\nroot log line two\n"), Mode: 0o644},
		{Name: "logs/stage/build.log", Body: bytes.Repeat([]byte("stage-abcdef\n"), 40), Mode: 0o644},
		{Name: "logs/downstream/job/1.log", Body: []byte("downstream ok\n"), Mode: 0o644},
		{Name: "evidence/empty.txt", Body: []byte{}, Mode: 0o644},
		{Name: "evidence/binary.bin", Body: []byte{0x00, 0x01, 0xff, 0xfe, 'x'}, Mode: 0o600},
	}
}

func writeTestPack(t *testing.T, target int) ([]byte, *archive.SeekTable) {
	t.Helper()
	data, st, err := archive.WritePack(testMembers(), archive.WriteOptions{
		PackID:           "pack-test-1",
		TargetFrameBytes: target,
	})
	if err != nil {
		t.Fatalf("WritePack: %v", err)
	}
	if len(st.Frames) < archive.MinContentFrames {
		t.Fatalf("expected multi-frame, got %d", len(st.Frames))
	}
	return data, st
}

func TestWriteOpenListReadMembers(t *testing.T) {
	data, st := writeTestPack(t, 64)
	p, err := archive.OpenPack(data)
	if err != nil {
		t.Fatalf("OpenPack: %v", err)
	}
	defer p.Close()

	if p.PackID() != "pack-test-1" {
		t.Fatalf("pack id: %q", p.PackID())
	}
	members := p.ListMembers()
	if len(members) != len(st.Members) {
		t.Fatalf("list len %d want %d", len(members), len(st.Members))
	}

	ctx := context.Background()
	for _, m := range testMembers() {
		body, meta, stats, err := p.ReadMember(ctx, m.Name)
		if err != nil {
			t.Fatalf("ReadMember %s: %v", m.Name, err)
		}
		if !bytes.Equal(body, m.Body) {
			t.Fatalf("member %s body mismatch: got %q want %q", m.Name, body, m.Body)
		}
		if meta.Size != int64(len(m.Body)) {
			t.Fatalf("meta size %d want %d", meta.Size, len(m.Body))
		}
		if stats.LogicalBytes != int64(len(m.Body)) {
			t.Fatalf("logical bytes %d", stats.LogicalBytes)
		}
	}
}

func TestRangeReadDoesNotFullPackDecompress(t *testing.T) {
	// Large multi-frame pack; 64 KiB range must open a subset of frames.
	var members []archive.MemberInput
	for i, name := range []string{"a.log", "b.log", "c.log"} {
		body := bytes.Repeat([]byte{byte('A' + i)}, 120_000)
		members = append(members, archive.MemberInput{Name: name, Body: body})
	}
	data, st, err := archive.WritePack(members, archive.WriteOptions{
		PackID:           "pack-range",
		TargetFrameBytes: 8_000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Frames) < 4 {
		t.Fatalf("need many frames, got %d", len(st.Frames))
	}
	p, err := archive.OpenPack(data)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	const want = 64 << 10
	body, meta, stats, err := p.ReadMemberRange(context.Background(), "b.log", 1000, want)
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(body)) != want {
		t.Fatalf("got %d bytes", len(body))
	}
	if meta.FramesOpened >= len(st.Frames) {
		t.Fatalf("64KiB range opened all %d frames (amplification failure); opened %d decompressed %d",
			len(st.Frames), meta.FramesOpened, meta.DecompressedBytes)
	}
	if stats.FramesOpened < 1 {
		t.Fatal("expected at least one frame")
	}
	fullTAR, err := p.SequentialTAR()
	if err != nil {
		t.Fatal(err)
	}
	if stats.DecompressedBytes >= int64(len(fullTAR)) {
		t.Fatalf("range read decompressed entire pack: decomp=%d tar=%d frames_opened=%d/%d",
			stats.DecompressedBytes, len(fullTAR), stats.FramesOpened, len(st.Frames))
	}
	expect := bytes.Repeat([]byte{'B'}, want)
	if !bytes.Equal(body, expect) {
		t.Fatalf("range body mismatch first=%v", body[:min(8, len(body))])
	}
}

func TestSequentialZstdRecoversTAR(t *testing.T) {
	data, _ := writeTestPack(t, 128)
	p, err := archive.OpenPack(data)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	tarBytes, err := p.SequentialTAR()
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zstd.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	got, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, tarBytes) {
		t.Fatalf("sequential zstd != SequentialTAR: %d vs %d", len(got), len(tarBytes))
	}
	if p.SeekTable().TarSize != int64(len(tarBytes)) {
		t.Fatalf("tar_size mismatch")
	}
}

func TestRejectSingleFramePack(t *testing.T) {
	enc, err := zstd.NewWriter(nil, zstd.WithEncoderCRC(true))
	if err != nil {
		t.Fatal(err)
	}
	defer enc.Close()
	single := enc.EncodeAll([]byte("not a real tar but single frame"), nil)
	_, err = archive.OpenPack(single)
	if err == nil {
		t.Fatal("expected reject single-frame pack")
	}
	if apperr.CodeOf(err) != apperr.CodeCorruptCache && apperr.CodeOf(err) != apperr.CodeInvalidArgument {
		t.Fatalf("code %s", apperr.CodeOf(err))
	}
	if !strings.Contains(err.Error(), "frame") {
		t.Fatalf("error should mention frame: %v", err)
	}
}

func TestRejectMissingSeekTable(t *testing.T) {
	enc, err := zstd.NewWriter(nil, zstd.WithEncoderCRC(true))
	if err != nil {
		t.Fatal(err)
	}
	defer enc.Close()
	f0 := enc.EncodeAll([]byte("aaaa"), nil)
	f1 := enc.EncodeAll([]byte("bbbb"), nil)
	_, err = archive.OpenPack(append(f0, f1...))
	if err == nil {
		t.Fatal("expected missing seek table error")
	}
}

func TestCopiedPayloadFrameUnchanged(t *testing.T) {
	body := []byte("payload-body-line\n" + strings.Repeat("x", 100) + "\n")
	enc, err := zstd.NewWriter(nil, zstd.WithEncoderCRC(true), zstd.WithEncoderLevel(zstd.SpeedDefault))
	if err != nil {
		t.Fatal(err)
	}
	defer enc.Close()
	payloadFrame := enc.EncodeAll(body, nil)
	body2 := []byte("second\n")
	pf2 := enc.EncodeAll(body2, nil)

	data, st, err := archive.WritePackWithPayloadFrames(
		[]archive.MemberInput{
			{Name: "logs/a.log", Body: body},
			{Name: "logs/b.log", Body: body2},
		},
		[][]byte{payloadFrame, pf2},
		"pack-copy",
	)
	if err != nil {
		t.Fatal(err)
	}
	wantByHash := map[string][]byte{
		archive.Sha256Hex(payloadFrame): payloadFrame,
		archive.Sha256Hex(pf2):          pf2,
	}
	found := 0
	for _, f := range st.Frames {
		if f.Kind != archive.FrameKindPayload {
			continue
		}
		slice := data[f.CompressedOffset : f.CompressedOffset+f.CompressedSize]
		want, ok := wantByHash[f.FrameSHA256]
		if !ok {
			t.Fatalf("unexpected payload frame hash %s", f.FrameSHA256)
		}
		if !bytes.Equal(slice, want) {
			t.Fatalf("payload frame bytes changed in pack")
		}
		found++
	}
	if found != 2 {
		t.Fatalf("payload frames found %d", found)
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
	if !bytes.Equal(got, body) {
		t.Fatalf("read after copy mismatch")
	}
}

func TestCorruptSeekTableFails(t *testing.T) {
	data, _ := writeTestPack(t, 64)
	// Corrupt the skippable seek payload: zero out a stretch inside the last frame.
	if len(data) < 64 {
		t.Fatal("pack too small")
	}
	// Skippable header is last frame; scramble JSON body so magic/fields break.
	for i := len(data) - 40; i < len(data)-8; i++ {
		data[i] ^= 0xa5
	}
	_, err := archive.OpenPack(data)
	if err == nil {
		t.Fatal("expected corrupt pack error")
	}
}

func TestVerifyContentFrames(t *testing.T) {
	data, _ := writeTestPack(t, 64)
	p, err := archive.OpenPack(data)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if err := p.VerifyContentFrames(); err != nil {
		t.Fatal(err)
	}
	// Tamper one content byte inside first frame payload region.
	data2 := append([]byte(nil), data...)
	// Skip magic/header; flip a middle byte of file early.
	data2[20] ^= 0x55
	p2, err := archive.OpenPack(data2)
	if err == nil {
		// May fail open (checksum) or verify.
		if err := p2.VerifyContentFrames(); err == nil {
			t.Fatal("expected verify failure after tamper")
		}
		p2.Close()
	}
}
