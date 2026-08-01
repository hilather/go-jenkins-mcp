package archive

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// SeekTable is the JSON document stored in the final skippable Zstd frame.
type SeekTable struct {
	Magic            string       `json:"magic"`
	FormatVersion    int          `json:"format_version"`
	PackID           string       `json:"pack_id"`
	TarSize          int64        `json:"tar_size"`
	Frames           []SeekFrame  `json:"frames"`
	Members          []SeekMember `json:"members"`
	PackSHA256       string       `json:"pack_sha256"`
	MinContentFrames int          `json:"min_content_frames"`
}

// SeekFrame describes one independent content frame.
type SeekFrame struct {
	Index            int    `json:"index"`
	Kind             string `json:"kind"`
	CompressedOffset int64  `json:"compressed_offset"`
	CompressedSize   int64  `json:"compressed_size"`
	RawOffset        int64  `json:"raw_offset"`
	RawSize          int64  `json:"raw_size"`
	ContentSHA256    string `json:"content_sha256"`
	FrameSHA256      string `json:"frame_sha256"`
	DictID           string `json:"dict_id,omitempty"`
}

// SeekMember describes one TAR member body in the uncompressed stream.
type SeekMember struct {
	Name          string `json:"name"`
	EntryID       string `json:"entry_id"`
	RawOffset     int64  `json:"raw_offset"`
	Size          int64  `json:"size"`
	Mode          int64  `json:"mode"`
	ContentSHA256 string `json:"content_sha256"`
	TypeFlag      byte   `json:"typeflag"`
}

// MarshalSeekTable encodes the seek table as JSON bytes.
func MarshalSeekTable(st *SeekTable) ([]byte, error) {
	if st == nil {
		return nil, apperr.New(apperr.CodeInvalidArgument, "seek table is nil")
	}
	b, err := json.Marshal(st)
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeInternal, "failed to marshal seek table", err)
	}
	if len(b) > MaxSeekTableBytes {
		return nil, apperr.New(apperr.CodeInvalidArgument, "seek table exceeds size limit")
	}
	return b, nil
}

// ParseSeekTable decodes and validates a seek table document.
func ParseSeekTable(data []byte) (*SeekTable, error) {
	if len(data) == 0 {
		return nil, apperr.New(apperr.CodeCorruptCache, "empty seek table")
	}
	if len(data) > MaxSeekTableBytes {
		return nil, apperr.New(apperr.CodeCorruptCache, "seek table exceeds size limit")
	}
	var st SeekTable
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, apperr.Wrap(apperr.CodeCorruptCache, "invalid seek table JSON", err)
	}
	if err := st.Validate(); err != nil {
		return nil, err
	}
	return &st, nil
}

// Validate checks seek-table invariants (pack-format-v1 §7.2).
func (st *SeekTable) Validate() error {
	if st == nil {
		return apperr.New(apperr.CodeCorruptCache, "seek table is nil")
	}
	if st.Magic != SeekMagic {
		return apperr.New(apperr.CodeCorruptCache,
			fmt.Sprintf("seek table magic %q want %q", st.Magic, SeekMagic))
	}
	if st.FormatVersion != FormatVersion {
		return apperr.New(apperr.CodeCorruptCache,
			fmt.Sprintf("unsupported pack format_version %d", st.FormatVersion))
	}
	if strings.TrimSpace(st.PackID) == "" {
		return apperr.New(apperr.CodeCorruptCache, "seek table pack_id is empty")
	}
	minFrames := st.MinContentFrames
	if minFrames <= 0 {
		minFrames = MinContentFrames
	}
	if len(st.Frames) < minFrames {
		return apperr.New(apperr.CodeCorruptCache,
			fmt.Sprintf("pack has %d content frames; need at least %d (single-frame tar.zst is not random-access)",
				len(st.Frames), minFrames))
	}

	var rawEnd int64
	var compEnd int64
	for i, f := range st.Frames {
		if f.Index != 0 && f.Index != i {
			return apperr.New(apperr.CodeCorruptCache,
				fmt.Sprintf("frame index %d at position %d", f.Index, i))
		}
		if f.CompressedOffset != compEnd {
			return apperr.New(apperr.CodeCorruptCache,
				fmt.Sprintf("frame %d compressed_offset gap: got %d want %d", i, f.CompressedOffset, compEnd))
		}
		if f.CompressedSize <= 0 {
			return apperr.New(apperr.CodeCorruptCache, fmt.Sprintf("frame %d has non-positive compressed_size", i))
		}
		if f.RawOffset != rawEnd {
			return apperr.New(apperr.CodeCorruptCache,
				fmt.Sprintf("frame %d raw_offset gap: got %d want %d", i, f.RawOffset, rawEnd))
		}
		if f.RawSize < 0 {
			return apperr.New(apperr.CodeCorruptCache, fmt.Sprintf("frame %d has negative raw_size", i))
		}
		if f.RawSize > MaxFrameUncompressed {
			return apperr.New(apperr.CodeCorruptCache, fmt.Sprintf("frame %d raw_size exceeds limit", i))
		}
		if f.DictID != "" {
			// v1 baseline: no dictionaries; reject unknown dict bindings.
			return apperr.New(apperr.CodeCorruptCache, "dictionary frames are not supported in format v1 baseline")
		}
		compEnd += f.CompressedSize
		rawEnd += f.RawSize
	}
	if st.TarSize != rawEnd {
		return apperr.New(apperr.CodeCorruptCache,
			fmt.Sprintf("tar_size %d != sum of frame raw sizes %d", st.TarSize, rawEnd))
	}

	seen := make(map[string]struct{}, len(st.Members))
	for i, m := range st.Members {
		if m.Name == "" && m.EntryID == "" {
			return apperr.New(apperr.CodeCorruptCache, fmt.Sprintf("member %d has empty name and entry_id", i))
		}
		id := m.EntryID
		if id == "" {
			id = m.Name
		}
		if _, ok := seen[id]; ok {
			return apperr.New(apperr.CodeCorruptCache, fmt.Sprintf("duplicate member entry_id %q", id))
		}
		seen[id] = struct{}{}
		if m.Size < 0 || m.RawOffset < 0 {
			return apperr.New(apperr.CodeCorruptCache, fmt.Sprintf("member %q has negative offset/size", id))
		}
		if m.RawOffset+m.Size > st.TarSize {
			return apperr.New(apperr.CodeCorruptCache, fmt.Sprintf("member %q exceeds tar_size", id))
		}
	}
	return nil
}

// FindMember returns the member matching entryID or name.
func (st *SeekTable) FindMember(entryID string) (SeekMember, bool) {
	if st == nil {
		return SeekMember{}, false
	}
	entryID = strings.TrimSpace(entryID)
	for _, m := range st.Members {
		if m.EntryID == entryID || m.Name == entryID {
			return m, true
		}
	}
	return SeekMember{}, false
}

// FramesIntersectingRaw returns content frames that overlap [start, end) in raw TAR space.
func (st *SeekTable) FramesIntersectingRaw(start, end int64) []SeekFrame {
	if st == nil || end <= start {
		return nil
	}
	var out []SeekFrame
	for _, f := range st.Frames {
		fEnd := f.RawOffset + f.RawSize
		if f.RawOffset < end && fEnd > start {
			out = append(out, f)
		}
	}
	return out
}
