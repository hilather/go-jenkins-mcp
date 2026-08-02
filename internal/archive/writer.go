package archive

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"fmt"
	"hash"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// MemberInput is one TAR member for the test / compatibility pack writer.
type MemberInput struct {
	Name    string
	Body    []byte
	Mode    int64
	EntryID string // defaults to Name
}

// WriteOptions configures the multi-frame compatibility pack writer.
type WriteOptions struct {
	// PackID required opaque id (also stored in seek table).
	PackID string
	// TargetFrameBytes splits the TAR stream into independent frames (default 8 MiB).
	// Tests may use small values to force multi-frame packs.
	TargetFrameBytes int
	// CodecLevel is zstd level (default ~3).
	CodecLevel int
}

// WritePack builds a seekable multi-frame .tar.zst pack (compatibility repack path).
//
// The TAR stream is encoded, then split into independent Zstd frames of about
// TargetFrameBytes uncompressed bytes each. A final skippable frame holds the
// seek table. At least MinContentFrames content frames are required; when the
// TAR is small, the writer splits aggressively so validation still passes.
func WritePack(members []MemberInput, opt WriteOptions) ([]byte, *SeekTable, error) {
	if strings.TrimSpace(opt.PackID) == "" {
		return nil, nil, apperr.New(apperr.CodeInvalidArgument, "pack_id is required")
	}
	if len(members) == 0 {
		return nil, nil, apperr.New(apperr.CodeInvalidArgument, "at least one member is required")
	}
	target := opt.TargetFrameBytes
	if target <= 0 {
		target = DefaultTargetFrameBytes
	}
	level := opt.CodecLevel
	if level == 0 {
		level = 3
	}

	tarBuf, seekMembers, err := buildTAR(members)
	if err != nil {
		return nil, nil, err
	}
	raw := tarBuf.Bytes()
	if len(raw) == 0 {
		return nil, nil, apperr.New(apperr.CodeInternal, "empty tar stream")
	}

	// Ensure multi-frame: if target would produce a single frame, lower target.
	target = ensureMultiFrameTarget(len(raw), target)

	enc, err := zstd.NewWriter(nil,
		zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(level)),
		zstd.WithEncoderCRC(true),
	)
	if err != nil {
		return nil, nil, apperr.Wrap(apperr.CodeInternal, "failed to create zstd encoder", err)
	}
	defer enc.Close()

	var (
		packBuf  bytes.Buffer
		frames   []SeekFrame
		rawOff   int64
		compOff  int64
		packHash = sha256.New()
	)

	for rawOff < int64(len(raw)) {
		end := rawOff + int64(target)
		if end > int64(len(raw)) {
			end = int64(len(raw))
		}
		// Prefer not to leave a tiny final frame if we already have enough frames;
		// but still allow for multi-frame requirement.
		chunk := raw[rawOff:end]
		compressed := enc.EncodeAll(chunk, nil)
		frame := SeekFrame{
			Index:            len(frames),
			Kind:             FrameKindContent,
			CompressedOffset: compOff,
			CompressedSize:   int64(len(compressed)),
			RawOffset:        rawOff,
			RawSize:          int64(len(chunk)),
			ContentSHA256:    sha256Hex(chunk),
			FrameSHA256:      sha256Hex(compressed),
		}
		frames = append(frames, frame)
		packBuf.Write(compressed)
		packHash.Write(compressed)
		rawOff = end
		compOff += int64(len(compressed))
	}

	if len(frames) < MinContentFrames {
		return nil, nil, apperr.New(apperr.CodeInternal,
			fmt.Sprintf("writer produced %d content frames; need ≥ %d", len(frames), MinContentFrames))
	}

	st := &SeekTable{
		Magic:            SeekMagic,
		FormatVersion:    FormatVersion,
		PackID:           opt.PackID,
		TarSize:          int64(len(raw)),
		Frames:           frames,
		Members:          seekMembers,
		PackSHA256:       sha256Hex(packHash.Sum(nil)),
		MinContentFrames: MinContentFrames,
	}
	if err := st.Validate(); err != nil {
		return nil, nil, err
	}
	seekJSON, err := MarshalSeekTable(st)
	if err != nil {
		return nil, nil, err
	}
	skip, err := writeSkippableFrame(seekJSON)
	if err != nil {
		return nil, nil, err
	}
	packBuf.Write(skip)
	return packBuf.Bytes(), st, nil
}

// WritePackWithPayloadFrames builds a pack that embeds pre-compressed payload
// frames unchanged (L1 copy path smoke test). Members must have exactly one
// payload body each; header/padding frames are generated around the copied
// compressed frames. payloadFrames[i] is the compressed zstd frame for members[i].Body
// (EncodeAll of Body). The compressed bytes are copied into the pack as-is.
func WritePackWithPayloadFrames(members []MemberInput, payloadFrames [][]byte, packID string) ([]byte, *SeekTable, error) {
	if strings.TrimSpace(packID) == "" {
		return nil, nil, apperr.New(apperr.CodeInvalidArgument, "pack_id is required")
	}
	if len(members) == 0 || len(members) != len(payloadFrames) {
		return nil, nil, apperr.New(apperr.CodeInvalidArgument, "members and payloadFrames length mismatch")
	}
	enc, err := zstd.NewWriter(nil,
		zstd.WithEncoderLevel(zstd.SpeedDefault),
		zstd.WithEncoderCRC(true),
	)
	if err != nil {
		return nil, nil, apperr.Wrap(apperr.CodeInternal, "failed to create zstd encoder", err)
	}
	defer enc.Close()

	var (
		packBuf  bytes.Buffer
		frames   []SeekFrame
		membersO []SeekMember
		rawOff   int64
		compOff  int64
		packHash hash.Hash = sha256.New()
	)

	appendGen := func(kind string, raw []byte) error {
		if len(raw) == 0 {
			return nil
		}
		compressed := enc.EncodeAll(raw, nil)
		f := SeekFrame{
			Index:            len(frames),
			Kind:             kind,
			CompressedOffset: compOff,
			CompressedSize:   int64(len(compressed)),
			RawOffset:        rawOff,
			RawSize:          int64(len(raw)),
			ContentSHA256:    sha256Hex(raw),
			FrameSHA256:      sha256Hex(compressed),
		}
		frames = append(frames, f)
		packBuf.Write(compressed)
		packHash.Write(compressed)
		rawOff += int64(len(raw))
		compOff += int64(len(compressed))
		return nil
	}

	for i, m := range members {
		name := strings.TrimSpace(m.Name)
		if name == "" {
			return nil, nil, apperr.New(apperr.CodeInvalidArgument, "member name is required")
		}
		mode := m.Mode
		if mode == 0 {
			mode = 0o644
		}
		// Build a one-member tar header+body+padding using archive/tar, then
		// split: we need exact header bytes. Use tar writer into buffer and
		// recover structure via known sizes.
		var one bytes.Buffer
		tw := tar.NewWriter(&one)
		hdr := &tar.Header{
			Name:    name,
			Mode:    mode,
			Size:    int64(len(m.Body)),
			ModTime: time.Unix(0, 0).UTC(),
			Format:  tar.FormatPAX,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, nil, apperr.Wrap(apperr.CodeInternal, "tar header", err)
		}
		if _, err := tw.Write(m.Body); err != nil {
			return nil, nil, apperr.Wrap(apperr.CodeInternal, "tar body", err)
		}
		if err := tw.Flush(); err != nil {
			return nil, nil, apperr.Wrap(apperr.CodeInternal, "tar flush", err)
		}
		// one currently has header + body + padding (no EOF blocks yet).
		block := one.Bytes()
		// Header is 512 bytes for short names; PAX may be longer. Locate body
		// by size: padding = (512 - size%512) % 512 after body.
		pad := (512 - (len(m.Body) % 512)) % 512
		headerLen := len(block) - len(m.Body) - pad
		if headerLen <= 0 || headerLen > len(block) {
			return nil, nil, apperr.New(apperr.CodeInternal, "failed to split tar member frames")
		}
		headerBytes := block[:headerLen]
		padBytes := block[headerLen+len(m.Body):]

		if err := appendGen(FrameKindHeader, headerBytes); err != nil {
			return nil, nil, err
		}

		// Copy pre-compressed payload frame as-is (must decompress to m.Body).
		pf := payloadFrames[i]
		if len(pf) == 0 {
			return nil, nil, apperr.New(apperr.CodeInvalidArgument, "empty payload frame")
		}
		// Verify payload decompresses to body for safety in tests.
		dec, err := zstd.NewReader(nil)
		if err != nil {
			return nil, nil, apperr.Wrap(apperr.CodeInternal, "zstd decoder", err)
		}
		got, err := dec.DecodeAll(pf, nil)
		dec.Close()
		if err != nil {
			return nil, nil, apperr.Wrap(apperr.CodeInvalidArgument, "payload frame is not valid zstd", err)
		}
		if !bytes.Equal(got, m.Body) {
			return nil, nil, apperr.New(apperr.CodeInvalidArgument, "payload frame does not match member body")
		}
		f := SeekFrame{
			Index:            len(frames),
			Kind:             FrameKindPayload,
			CompressedOffset: compOff,
			CompressedSize:   int64(len(pf)),
			RawOffset:        rawOff,
			RawSize:          int64(len(m.Body)),
			ContentSHA256:    sha256Hex(m.Body),
			FrameSHA256:      sha256Hex(pf),
		}
		frames = append(frames, f)
		packBuf.Write(pf)
		packHash.Write(pf)
		// Member body starts at current rawOff (after header).
		entryID := m.EntryID
		if entryID == "" {
			entryID = name
		}
		membersO = append(membersO, SeekMember{
			Name:          name,
			EntryID:       entryID,
			RawOffset:     rawOff,
			Size:          int64(len(m.Body)),
			Mode:          mode,
			ContentSHA256: sha256Hex(m.Body),
			TypeFlag:      byte(tar.TypeReg),
		})
		rawOff += int64(len(m.Body))
		compOff += int64(len(pf))

		if err := appendGen(FrameKindPadding, padBytes); err != nil {
			return nil, nil, err
		}
	}

	// TAR terminator: two zero blocks.
	term := make([]byte, 1024)
	if err := appendGen(FrameKindTerminator, term); err != nil {
		return nil, nil, err
	}

	if len(frames) < MinContentFrames {
		return nil, nil, apperr.New(apperr.CodeInternal, "payload pack has too few frames")
	}

	st := &SeekTable{
		Magic:            SeekMagic,
		FormatVersion:    FormatVersion,
		PackID:           packID,
		TarSize:          rawOff,
		Frames:           frames,
		Members:          membersO,
		PackSHA256:       sha256Hex(packHash.Sum(nil)),
		MinContentFrames: MinContentFrames,
	}
	if err := st.Validate(); err != nil {
		return nil, nil, err
	}
	seekJSON, err := MarshalSeekTable(st)
	if err != nil {
		return nil, nil, err
	}
	skip, err := writeSkippableFrame(seekJSON)
	if err != nil {
		return nil, nil, err
	}
	packBuf.Write(skip)
	return packBuf.Bytes(), st, nil
}

func buildTAR(members []MemberInput) (*bytes.Buffer, []SeekMember, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	var seekMembers []SeekMember

	for _, m := range members {
		name := strings.TrimSpace(m.Name)
		if name == "" {
			return nil, nil, apperr.New(apperr.CodeInvalidArgument, "member name is required")
		}
		mode := m.Mode
		if mode == 0 {
			mode = 0o644
		}
		body := m.Body
		if body == nil {
			body = []byte{}
		}
		hdr := &tar.Header{
			Name:    name,
			Mode:    mode,
			Size:    int64(len(body)),
			ModTime: time.Unix(0, 0).UTC(),
			Format:  tar.FormatPAX,
		}
		// Record body offset: current buffer length is start of this member's header;
		// after WriteHeader, body begins at buf.Len().
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, nil, apperr.Wrap(apperr.CodeInternal, "tar write header", err)
		}
		bodyOff := int64(buf.Len())
		if _, err := tw.Write(body); err != nil {
			return nil, nil, apperr.Wrap(apperr.CodeInternal, "tar write body", err)
		}
		entryID := m.EntryID
		if entryID == "" {
			entryID = name
		}
		seekMembers = append(seekMembers, SeekMember{
			Name:          name,
			EntryID:       entryID,
			RawOffset:     bodyOff,
			Size:          int64(len(body)),
			Mode:          mode,
			ContentSHA256: sha256Hex(body),
			TypeFlag:      byte(tar.TypeReg),
		})
	}
	if err := tw.Close(); err != nil {
		return nil, nil, apperr.Wrap(apperr.CodeInternal, "tar close", err)
	}
	return &buf, seekMembers, nil
}

func ensureMultiFrameTarget(tarLen, target int) int {
	if tarLen <= 0 {
		return target
	}
	// Need at least MinContentFrames frames: max frame size = ceil(tarLen / MinContentFrames)
	// Use floor(tarLen / MinContentFrames) as target so we get ≥ MinContentFrames pieces.
	maxPer := tarLen / MinContentFrames
	if maxPer < 1 {
		maxPer = 1
	}
	if target > maxPer {
		target = maxPer
	}
	// If still single frame (tiny tar), force target=1.
	if (tarLen+target-1)/target < MinContentFrames {
		target = 1
		if tarLen/MinContentFrames >= 1 {
			target = tarLen / MinContentFrames
		}
	}
	if target < 1 {
		target = 1
	}
	return target
}
