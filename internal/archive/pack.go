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
	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// GenerationMember is one sealed log (or evidence blob) to promote into an L2 pack.
//
// When PayloadFrames is non-empty and decompresses in order to Body, those
// compressed frames are copied into the pack (zero-recompression path, pack-format §6).
// Otherwise Body is packed via the compatibility repack writer (WritePack).
type GenerationMember struct {
	// Name is the TAR member path (e.g. logs/job/1/consoleText).
	Name string
	// EntryID is an opaque member id (defaults to Name).
	EntryID string
	// Mode is the TAR mode (default 0o644).
	Mode int64
	// Body is the full uncompressed payload (required; may be empty).
	Body []byte
	// PayloadFrames are optional independent L1 zstd frames in logical order.
	// Concatenated decompression must equal Body for the copy path.
	PayloadFrames [][]byte
}

// PackFromGenerationsOptions configures PackFromGenerations (ARC-005-lite).
type PackFromGenerationsOptions struct {
	// PackID is required and written into the seek table.
	PackID string
	// AffinityGroup is optional catalog metadata (not embedded in pack bytes).
	AffinityGroup string
	// PreferCopy uses PayloadFrames when they cover Body (default true).
	// Set false to force compatibility recompression.
	PreferCopy *bool
	// TargetFrameBytes is used only on the compatibility repack path.
	TargetFrameBytes int
	// CodecLevel for newly compressed frames (default ~3).
	CodecLevel int
}

// PackFromGenerations builds a multi-frame seekable pack from sealed generation
// members (native Go only — no ratarmount). Prefer zero-recompression when L1
// payload frames are supplied and valid; otherwise recompress via WritePack.
//
// Residual full transactional lease/journal publish is ARC-005; this is the
// practical packer used by logmirror.PackCollection and unit tests.
func PackFromGenerations(members []GenerationMember, opt PackFromGenerationsOptions) ([]byte, *SeekTable, error) {
	if strings.TrimSpace(opt.PackID) == "" {
		return nil, nil, apperr.New(apperr.CodeInvalidArgument, "pack_id is required")
	}
	if len(members) == 0 {
		return nil, nil, apperr.New(apperr.CodeInvalidArgument, "at least one generation member is required")
	}
	preferCopy := true
	if opt.PreferCopy != nil {
		preferCopy = *opt.PreferCopy
	}

	// Zero-recompression when every member has valid payload frames.
	if preferCopy && allMembersHavePayloads(members) {
		// Single payload frame per member → existing writer.
		if inputs, frames, ok := prepareSinglePayloadCopy(members); ok {
			return WritePackWithPayloadFrames(inputs, frames, opt.PackID)
		}
		// Multi-frame L1 members: header + N payload frames + padding.
		data, st, err := writePackMultiPayload(members, opt.PackID)
		if err == nil {
			return data, st, nil
		}
		// Fall through to recompress when copy path cannot assemble.
	}

	// Compatibility repack: encode full TAR and split into content frames.
	inputs := make([]MemberInput, 0, len(members))
	for _, m := range members {
		name := strings.TrimSpace(m.Name)
		if name == "" {
			return nil, nil, apperr.New(apperr.CodeInvalidArgument, "member name is required")
		}
		body := m.Body
		if body == nil {
			body = []byte{}
		}
		inputs = append(inputs, MemberInput{
			Name:    name,
			Body:    body,
			Mode:    m.Mode,
			EntryID: m.EntryID,
		})
	}
	return WritePack(inputs, WriteOptions{
		PackID:           opt.PackID,
		TargetFrameBytes: opt.TargetFrameBytes,
		CodecLevel:       opt.CodecLevel,
	})
}

func allMembersHavePayloads(members []GenerationMember) bool {
	for _, m := range members {
		if len(m.PayloadFrames) == 0 {
			return false
		}
	}
	return true
}

// prepareSinglePayloadCopy returns MemberInput + one payload frame each when
// every member has exactly one L1 frame that decompresses to Body.
func prepareSinglePayloadCopy(members []GenerationMember) ([]MemberInput, [][]byte, bool) {
	inputs := make([]MemberInput, 0, len(members))
	frames := make([][]byte, 0, len(members))
	for _, m := range members {
		name := strings.TrimSpace(m.Name)
		if name == "" || len(m.PayloadFrames) != 1 {
			return nil, nil, false
		}
		body := m.Body
		if body == nil {
			body = []byte{}
		}
		if !payloadMatchesBody(m.PayloadFrames[0], body) {
			return nil, nil, false
		}
		inputs = append(inputs, MemberInput{
			Name:    name,
			Body:    body,
			Mode:    m.Mode,
			EntryID: m.EntryID,
		})
		frames = append(frames, m.PayloadFrames[0])
	}
	return inputs, frames, true
}

func payloadMatchesBody(frame, body []byte) bool {
	if len(frame) == 0 {
		return len(body) == 0
	}
	dec, err := zstd.NewReader(nil)
	if err != nil {
		return false
	}
	defer dec.Close()
	got, err := dec.DecodeAll(frame, nil)
	if err != nil {
		return false
	}
	return bytes.Equal(got, body)
}

// writePackMultiPayload emits header + one or more payload frames + padding per
// member (pack-format §6). Used when L1 generations span multiple independent frames.
func writePackMultiPayload(members []GenerationMember, packID string) ([]byte, *SeekTable, error) {
	if strings.TrimSpace(packID) == "" {
		return nil, nil, apperr.New(apperr.CodeInvalidArgument, "pack_id is required")
	}
	enc, err := zstd.NewWriter(nil,
		zstd.WithEncoderLevel(zstd.SpeedDefault),
		zstd.WithEncoderCRC(true),
	)
	if err != nil {
		return nil, nil, apperr.Wrap(apperr.CodeInternal, "failed to create zstd encoder", err)
	}
	defer enc.Close()

	dec, err := zstd.NewReader(nil)
	if err != nil {
		return nil, nil, apperr.Wrap(apperr.CodeInternal, "failed to create zstd decoder", err)
	}
	defer dec.Close()

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

	for _, m := range members {
		name := strings.TrimSpace(m.Name)
		if name == "" {
			return nil, nil, apperr.New(apperr.CodeInvalidArgument, "member name is required")
		}
		if len(m.PayloadFrames) == 0 {
			return nil, nil, apperr.New(apperr.CodeInvalidArgument, "payload frames required for multi-payload path")
		}
		body := m.Body
		if body == nil {
			body = []byte{}
		}
		// Verify frames reassemble to body.
		var reassembled bytes.Buffer
		parts := make([][]byte, 0, len(m.PayloadFrames))
		for i, pf := range m.PayloadFrames {
			if len(pf) == 0 {
				return nil, nil, apperr.New(apperr.CodeInvalidArgument,
					fmt.Sprintf("empty payload frame index %d for %s", i, name))
			}
			got, err := dec.DecodeAll(pf, nil)
			if err != nil {
				return nil, nil, apperr.Wrap(apperr.CodeInvalidArgument,
					fmt.Sprintf("payload frame %d is not valid zstd", i), err)
			}
			parts = append(parts, got)
			reassembled.Write(got)
		}
		if !bytes.Equal(reassembled.Bytes(), body) {
			return nil, nil, apperr.New(apperr.CodeInvalidArgument,
				fmt.Sprintf("payload frames do not reassemble member body for %s", name))
		}

		mode := m.Mode
		if mode == 0 {
			mode = 0o644
		}
		headerBytes, padBytes, err := splitTarMemberFrames(name, body, mode)
		if err != nil {
			return nil, nil, err
		}
		if err := appendGen(FrameKindHeader, headerBytes); err != nil {
			return nil, nil, err
		}

		bodyStart := rawOff
		for i, pf := range m.PayloadFrames {
			part := parts[i]
			f := SeekFrame{
				Index:            len(frames),
				Kind:             FrameKindPayload,
				CompressedOffset: compOff,
				CompressedSize:   int64(len(pf)),
				RawOffset:        rawOff,
				RawSize:          int64(len(part)),
				ContentSHA256:    sha256Hex(part),
				FrameSHA256:      sha256Hex(pf),
			}
			frames = append(frames, f)
			packBuf.Write(pf)
			packHash.Write(pf)
			rawOff += int64(len(part))
			compOff += int64(len(pf))
		}

		entryID := m.EntryID
		if entryID == "" {
			entryID = name
		}
		membersO = append(membersO, SeekMember{
			Name:          name,
			EntryID:       entryID,
			RawOffset:     bodyStart,
			Size:          int64(len(body)),
			Mode:          mode,
			ContentSHA256: sha256Hex(body),
			TypeFlag:      byte(tar.TypeReg),
		})

		if err := appendGen(FrameKindPadding, padBytes); err != nil {
			return nil, nil, err
		}
	}

	term := make([]byte, 1024)
	if err := appendGen(FrameKindTerminator, term); err != nil {
		return nil, nil, err
	}
	if len(frames) < MinContentFrames {
		return nil, nil, apperr.New(apperr.CodeInternal, "multi-payload pack has too few frames")
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

// splitTarMemberFrames returns TAR header bytes and trailing padding for one member
// (same structure as WritePackWithPayloadFrames).
func splitTarMemberFrames(name string, body []byte, mode int64) (header, pad []byte, err error) {
	var one bytes.Buffer
	tw := tar.NewWriter(&one)
	hdr := &tar.Header{
		Name:    name,
		Mode:    mode,
		Size:    int64(len(body)),
		ModTime: time.Unix(0, 0).UTC(),
		Format:  tar.FormatPAX,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return nil, nil, apperr.Wrap(apperr.CodeInternal, "tar header", err)
	}
	if _, err := tw.Write(body); err != nil {
		return nil, nil, apperr.Wrap(apperr.CodeInternal, "tar body", err)
	}
	if err := tw.Flush(); err != nil {
		return nil, nil, apperr.Wrap(apperr.CodeInternal, "tar flush", err)
	}
	block := one.Bytes()
	padLen := (512 - (len(body) % 512)) % 512
	headerLen := len(block) - len(body) - padLen
	if headerLen <= 0 || headerLen > len(block) {
		return nil, nil, apperr.New(apperr.CodeInternal, "failed to split tar member frames")
	}
	return block[:headerLen], block[headerLen+len(body):], nil
}
