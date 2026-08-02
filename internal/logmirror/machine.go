package logmirror

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/store"
	"golang.org/x/sync/singleflight"
)

// Machine is the progressive log-generation state machine (LOG-002).
//
// It tracks generation id, committed offset, more_data, and build completion;
// detects Jenkins offset regression / rewrite (new generation); seals when
// complete with no more data; and persists metadata via GenerationStore.
//
// When Frames (PayloadStore) is set, progressive bytes stream into independent
// Zstandard frames (STO-003). SQLite jenkins_offset advances only to the durable
// frame end after crash-safe commit (STO-004). In-process AcceptedEnd drives the
// next progressive fetch so buffered-but-uncommitted bytes are not re-fetched.
//
// Concurrent Poll/Append for the same LogKey is single-flighted so concurrent
// readers do not trigger duplicate remote fetches for the same advance.
type Machine struct {
	meta   GenerationStore
	source ProgressiveSource

	// Frames when non-nil streams Append data into L1 independent frames.
	Frames PayloadStore
	// Reader serves LOG-003 reads from committed frames (optional).
	Reader *store.LogReader
	// ArchiveRoot is the profile archives/ directory for L2 pack fallback reads
	// after L1 release (ARC-005 residual). Empty disables L2 fallback.
	ArchiveRoot string

	// FetchBytes is the max progressive body per Poll (default DefaultFetchBytes).
	FetchBytes int

	mu       sync.Mutex
	inflight map[string]*sync.Mutex
	sf       singleflight.Group

	// bytesFetched counts progressive body bytes accepted per generation
	// (in-process; used to assert once-per-generation download in tests).
	bytesFetched map[string]int64

	// accepted offsets per generation id when Frames is set (also on Frames).
	// When Frames is nil, SQLite offset is the sole source of truth.
}

// NewMachine builds a Machine. meta is required; source may be nil if only
// Append (injected segments) is used.
func NewMachine(meta GenerationStore, source ProgressiveSource) *Machine {
	return &Machine{
		meta:         meta,
		source:       source,
		FetchBytes:   DefaultFetchBytes,
		inflight:     make(map[string]*sync.Mutex),
		bytesFetched: make(map[string]int64),
	}
}

// BytesFetched returns progressive body bytes accepted for key's latest
// generation in this process (0 after restart).
func (m *Machine) BytesFetched(key LogKey) int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.bytesFetched[key.String()]
}

// State loads the latest generation without creating one.
func (m *Machine) State(ctx context.Context, key LogKey) (State, error) {
	if err := key.Validate(); err != nil {
		return State{}, err
	}
	g, err := m.meta.GetLatestGeneration(ctx, key)
	if err != nil {
		return State{}, err
	}
	if g == nil {
		return State{}, nil
	}
	return m.stateFromGen(ctx, g)
}

// Append commits segment into the active generation, starting generation 1 if
// needed, or a new generation when offset regression/rewrite is detected.
func (m *Machine) Append(ctx context.Context, key LogKey, segment Segment) (State, error) {
	if err := key.Validate(); err != nil {
		return State{}, err
	}
	unlock := m.lockKey(key)
	defer unlock()
	return m.appendLocked(ctx, key, segment)
}

// Poll fetches one progressive range from source at the committed offset and Appends it.
// buildComplete should be true when the Jenkins build is finished.
// Sealed generations are returned without a remote fetch.
// Concurrent Poll calls for the same key are coalesced (single-flight).
func (m *Machine) Poll(ctx context.Context, key LogKey, buildComplete bool) (State, error) {
	if err := key.Validate(); err != nil {
		return State{}, err
	}
	if m.source == nil {
		return State{}, apperr.New(apperr.CodeInternal, "progressive source is not configured")
	}
	// Coalesce concurrent polls so duplicate remote fetches are avoided.
	// buildComplete is part of the flight key so a complete transition is not lost.
	flightKey := key.String()
	if buildComplete {
		flightKey += "|complete"
	}
	v, err, _ := m.sf.Do(flightKey, func() (any, error) {
		return m.pollOnce(ctx, key, buildComplete)
	})
	if err != nil {
		return State{}, err
	}
	st, _ := v.(State)
	return st, nil
}

func (m *Machine) pollOnce(ctx context.Context, key LogKey, buildComplete bool) (State, error) {
	unlock := m.lockKey(key)
	defer unlock()

	st, err := m.ensureOpenLocked(ctx, key)
	if err != nil {
		return State{}, err
	}
	if st.Sealed {
		// Sealed logs stop polling (LOG-002 acceptance).
		return st, nil
	}

	maxBytes := m.FetchBytes
	if maxBytes <= 0 {
		maxBytes = DefaultFetchBytes
	}

	data, reportedNext, moreData, err := m.source.Fetch(ctx, key.Job, key.Build, st.CommittedOffset, maxBytes)
	if err != nil {
		return st, mapFetchErr(err)
	}

	seg := Segment{
		Data:               data,
		ReportedNextOffset: reportedNext,
		MoreData:           moreData,
		BuildComplete:      buildComplete,
	}
	return m.appendLocked(ctx, key, seg)
}

// Seal seals the active generation when build is complete and no more data.
// If more data remains, Seal fails closed rather than losing a suffix.
// With Frames, any buffered bytes are flushed to a final frame first.
func (m *Machine) Seal(ctx context.Context, key LogKey) (State, error) {
	if err := key.Validate(); err != nil {
		return State{}, err
	}
	unlock := m.lockKey(key)
	defer unlock()

	g, err := m.meta.GetLatestGeneration(ctx, key)
	if err != nil {
		return State{}, err
	}
	if g == nil {
		return State{}, apperr.New(apperr.CodeNotFound, "no log generation to seal")
	}
	if g.Sealed {
		return m.stateFromGen(ctx, g)
	}
	if g.MoreData {
		st, _ := m.stateFromGen(ctx, g)
		return st, apperr.New(apperr.CodeInvalidArgument,
			"cannot seal generation while more_data is true")
	}
	if m.Frames != nil {
		res, err := m.Frames.Flush(ctx, g.ID)
		if err != nil {
			return State{}, err
		}
		if res.DurableEnd > g.JenkinsOffset {
			if err := m.meta.UpdateGenerationOffset(ctx, g.ID, res.DurableEnd, false, true, false); err != nil {
				return State{}, err
			}
			g.JenkinsOffset = res.DurableEnd
		}
	}
	if err := m.meta.SealGeneration(ctx, g.ID); err != nil {
		return State{}, err
	}
	g.Sealed = true
	g.MoreData = false
	g.BuildComplete = true
	return m.stateFromGen(ctx, g)
}

// ReadRange implements LOG-003 bounded local byte-range reads from committed frames.
// After L1 release, falls back to the verified L2 pack member when ArchiveRoot is set.
func (m *Machine) ReadRange(ctx context.Context, key LogKey, start, length int64) (store.ReadResult, error) {
	if err := key.Validate(); err != nil {
		return store.ReadResult{}, err
	}
	g, err := m.meta.GetLatestGeneration(ctx, key)
	if err != nil {
		return store.ReadResult{}, err
	}
	if g == nil {
		return store.ReadResult{}, apperr.New(apperr.CodeNotFound, "no log generation")
	}
	if g.L1Released {
		return m.readRangeL2(ctx, g, start, length)
	}
	if m.Reader == nil {
		return store.ReadResult{}, apperr.New(apperr.CodeInternal, "log reader is not configured")
	}
	res, err := m.Reader.ReadRange(ctx, g.ID, start, length)
	if err != nil {
		return res, err
	}
	res.Generation = g.Generation
	res.GenerationID = g.ID
	res.Sealed = g.Sealed
	return res, nil
}

// ReadLineRange returns a line range from committed frames (LOG-003).
func (m *Machine) ReadLineRange(ctx context.Context, key LogKey, startLine, lineCount int64) (store.ReadResult, error) {
	if err := key.Validate(); err != nil {
		return store.ReadResult{}, err
	}
	if m.Reader == nil {
		return store.ReadResult{}, apperr.New(apperr.CodeInternal, "log reader is not configured")
	}
	g, err := m.meta.GetLatestGeneration(ctx, key)
	if err != nil {
		return store.ReadResult{}, err
	}
	if g == nil {
		return store.ReadResult{}, apperr.New(apperr.CodeNotFound, "no log generation")
	}
	res, err := m.Reader.ReadLineRange(ctx, g.ID, startLine, lineCount)
	if err != nil {
		return res, err
	}
	res.Generation = g.Generation
	res.GenerationID = g.ID
	res.Sealed = g.Sealed
	return res, nil
}

// TailBytes returns the last n durable bytes (LOG-003).
// After L1 release, falls back to the L2 pack member when ArchiveRoot is set.
func (m *Machine) TailBytes(ctx context.Context, key LogKey, n int64) (store.ReadResult, error) {
	if err := key.Validate(); err != nil {
		return store.ReadResult{}, err
	}
	g, err := m.meta.GetLatestGeneration(ctx, key)
	if err != nil {
		return store.ReadResult{}, err
	}
	if g == nil {
		return store.ReadResult{}, apperr.New(apperr.CodeNotFound, "no log generation")
	}
	if g.L1Released {
		return m.tailBytesL2(ctx, g, n)
	}
	if m.Reader == nil {
		return store.ReadResult{}, apperr.New(apperr.CodeInternal, "log reader is not configured")
	}
	res, err := m.Reader.TailBytes(ctx, g.ID, n)
	if err != nil {
		return res, err
	}
	res.Generation = g.Generation
	res.GenerationID = g.ID
	res.Sealed = g.Sealed
	return res, nil
}

func (m *Machine) readRangeL2(ctx context.Context, g *store.LogGeneration, start, length int64) (store.ReadResult, error) {
	if strings.TrimSpace(m.ArchiveRoot) == "" {
		return store.ReadResult{}, apperr.New(apperr.CodeInternal,
			"L1 released but archive root is not configured for L2 fallback")
	}
	return ReadRangeFromPack(ctx, m.ArchiveRoot, g, start, length)
}

func (m *Machine) tailBytesL2(ctx context.Context, g *store.LogGeneration, n int64) (store.ReadResult, error) {
	if strings.TrimSpace(m.ArchiveRoot) == "" {
		return store.ReadResult{}, apperr.New(apperr.CodeInternal,
			"L1 released but archive root is not configured for L2 fallback")
	}
	return TailBytesFromPack(ctx, m.ArchiveRoot, g, n)
}

// TailLines returns the last n durable lines (LOG-003).
func (m *Machine) TailLines(ctx context.Context, key LogKey, n int64) (store.ReadResult, error) {
	if err := key.Validate(); err != nil {
		return store.ReadResult{}, err
	}
	if m.Reader == nil {
		return store.ReadResult{}, apperr.New(apperr.CodeInternal, "log reader is not configured")
	}
	g, err := m.meta.GetLatestGeneration(ctx, key)
	if err != nil {
		return store.ReadResult{}, err
	}
	if g == nil {
		return store.ReadResult{}, apperr.New(apperr.CodeNotFound, "no log generation")
	}
	res, err := m.Reader.TailLines(ctx, g.ID, n)
	if err != nil {
		return res, err
	}
	res.Generation = g.Generation
	res.GenerationID = g.ID
	res.Sealed = g.Sealed
	return res, nil
}

// --- internal ---

func mapFetchErr(err error) error {
	if err == nil {
		return nil
	}
	if apperr.IsCancelled(err) || apperr.IsTimeout(err) {
		return err
	}
	var ae *apperr.Error
	if errors.As(err, &ae) && ae != nil {
		return err
	}
	return apperr.Wrap(apperr.CodeUpstreamProtocol, "progressive fetch failed", err)
}

func (m *Machine) lockKey(key LogKey) func() {
	k := key.String()
	m.mu.Lock()
	lm, ok := m.inflight[k]
	if !ok {
		lm = &sync.Mutex{}
		m.inflight[k] = lm
	}
	m.mu.Unlock()
	lm.Lock()
	return lm.Unlock
}

func (m *Machine) ensureOpenLocked(ctx context.Context, key LogKey) (State, error) {
	g, err := m.meta.GetLatestGeneration(ctx, key)
	if err != nil {
		return State{}, err
	}
	if g == nil {
		g = &store.LogGeneration{
			Profile:       key.Profile,
			Job:           key.Job,
			Build:         key.Build,
			Generation:    1,
			JenkinsOffset: 0,
			MoreData:      true,
		}
		if err := m.meta.InsertGeneration(ctx, g); err != nil {
			return State{}, err
		}
		m.resetBytes(key)
	}
	return m.stateFromGen(ctx, g)
}

func (m *Machine) appendLocked(ctx context.Context, key LogKey, segment Segment) (State, error) {
	st, err := m.ensureOpenLocked(ctx, key)
	if err != nil {
		return State{}, err
	}
	// Normalize unset size: non-empty body cannot have total size 0.
	if len(segment.Data) > 0 && segment.ReportedNextOffset == 0 {
		segment.ReportedNextOffset = -1
	}

	// Detect truncation / rewrite relative to committed offset, or activity after seal.
	if st.Sealed {
		if len(segment.Data) == 0 && !segment.MoreData {
			return st, nil
		}
		// Non-empty rewrite after seal → new generation (body not trusted for old offset).
		return m.startNewGeneration(ctx, key, st.Generation)
	}
	if needsNewGeneration(st.CommittedOffset, segment) {
		// Drop segment body: it was fetched for the old offset / old log prefix.
		return m.startNewGeneration(ctx, key, st.Generation)
	}

	// Empty poll: refresh flags; seal when complete && !more.
	if len(segment.Data) == 0 {
		more := segment.MoreData
		if segment.ReportedNextOffset > st.CommittedOffset {
			more = true
		}
		complete := segment.BuildComplete || st.BuildComplete
		// Flush remaining frames before seal so durable matches accepted.
		if complete && !more && m.Frames != nil {
			res, err := m.Frames.Flush(ctx, st.GenerationID)
			if err != nil {
				return State{}, err
			}
			if res.DurableEnd > st.DurableOffset {
				st.DurableOffset = res.DurableEnd
			}
			st.CommittedOffset = res.AcceptedEnd
			if res.AcceptedEnd == 0 {
				st.CommittedOffset = res.DurableEnd
			}
		}
		durable := st.DurableOffset
		if m.Frames == nil {
			durable = st.CommittedOffset // no frames: logical == durable meta
		}
		// Persist durable offset + flags. With frames, never advance past durable frames.
		persistOff := durable
		if m.Frames == nil {
			persistOff = st.CommittedOffset
		}
		sealed := complete && !more
		if err := m.meta.UpdateGenerationOffset(ctx, st.GenerationID, persistOff, more, complete, sealed); err != nil {
			return State{}, err
		}
		st.MoreData = more
		st.BuildComplete = complete
		st.Sealed = sealed
		return st, nil
	}

	// Accept body: advance by exactly len(data); never skip unread gaps.
	nextAccepted := st.CommittedOffset + int64(len(segment.Data))
	if segment.ReportedNextOffset >= 0 && segment.ReportedNextOffset < nextAccepted {
		// Server total smaller than bytes we just received → rewrite.
		return m.startNewGeneration(ctx, key, st.Generation)
	}

	more := segment.MoreData
	if segment.ReportedNextOffset > nextAccepted {
		more = true
	}
	if segment.ReportedNextOffset == nextAccepted && !segment.MoreData {
		more = false
	}
	complete := segment.BuildComplete || st.BuildComplete

	durable := st.DurableOffset
	if m.Frames != nil {
		res, err := m.Frames.Append(ctx, st.GenerationID, segment.Data)
		// Persist any frames that committed even if a later cut failed.
		if res.DurableEnd > durable {
			durable = res.DurableEnd
		}
		if res.AcceptedEnd > 0 {
			nextAccepted = res.AcceptedEnd
		}
		if err != nil {
			_ = m.meta.UpdateGenerationOffset(ctx, st.GenerationID, durable, more, complete, false)
			return State{}, err
		}
		// On seal path (complete && !more), flush tail frame so all bytes are durable.
		if complete && !more {
			res, err = m.Frames.Flush(ctx, st.GenerationID)
			if res.DurableEnd > durable {
				durable = res.DurableEnd
			}
			if res.AcceptedEnd > 0 {
				nextAccepted = res.AcceptedEnd
			}
			if err != nil {
				_ = m.meta.UpdateGenerationOffset(ctx, st.GenerationID, durable, more, complete, false)
				return State{}, err
			}
		}
	} else {
		// Metadata-only mode (tests / pre-frame): logical offset is durable.
		durable = nextAccepted
	}

	sealed := complete && !more
	// Crash-safe: SQLite offset never points past durable frames.
	if err := m.meta.UpdateGenerationOffset(ctx, st.GenerationID, durable, more, complete, sealed); err != nil {
		return State{}, err
	}
	m.addBytes(key, int64(len(segment.Data)))

	st.CommittedOffset = nextAccepted
	st.DurableOffset = durable
	st.MoreData = more
	st.BuildComplete = complete
	st.Sealed = sealed
	return st, nil
}

// startNewGeneration abandons the open previous generation and inserts nextGen at offset 0.
// The caller must Poll again to download the new log from the beginning.
func (m *Machine) startNewGeneration(ctx context.Context, key LogKey, prevGeneration int64) (State, error) {
	prev, err := m.meta.GetLatestGeneration(ctx, key)
	if err != nil {
		return State{}, err
	}
	if prev != nil && !prev.Sealed {
		// Flush whatever is durable; abandon uncommitted buffer.
		if m.Frames != nil {
			_, _ = m.Frames.Flush(ctx, prev.ID)
			m.Frames.Forget(prev.ID)
		}
		// Abandon: seal at current durable offset so it is not active.
		off := prev.JenkinsOffset
		if m.Frames != nil {
			if d, err := m.Frames.DurableEnd(ctx, prev.ID); err == nil {
				off = d
			}
		}
		if err := m.meta.UpdateGenerationOffset(ctx, prev.ID, off, false, true, true); err != nil {
			// Fallback seal if update path rejects.
			_ = m.meta.SealGeneration(ctx, prev.ID)
		}
	}

	nextGen := prevGeneration + 1
	if prev != nil && prev.Generation >= nextGen {
		nextGen = prev.Generation + 1
	}
	g := &store.LogGeneration{
		Profile:       key.Profile,
		Job:           key.Job,
		Build:         key.Build,
		Generation:    nextGen,
		JenkinsOffset: 0,
		MoreData:      true,
		BuildComplete: false,
		Sealed:        false,
	}
	if err := m.meta.InsertGeneration(ctx, g); err != nil {
		return State{}, err
	}
	m.resetBytes(key)
	return m.stateFromGen(ctx, g)
}

// needsNewGeneration reports truncation/rewrite relative to committed offset.
func needsNewGeneration(committed int64, segment Segment) bool {
	// Jenkins total size behind our committed offset → log truncated/rewritten.
	if segment.ReportedNextOffset >= 0 && committed > 0 && segment.ReportedNextOffset < committed {
		return true
	}
	return false
}

func (m *Machine) stateFromGen(ctx context.Context, g *store.LogGeneration) (State, error) {
	st := State{
		Generation:      g.Generation,
		GenerationID:    g.ID,
		CommittedOffset: g.JenkinsOffset,
		DurableOffset:   g.JenkinsOffset,
		MoreData:        g.MoreData,
		BuildComplete:   g.BuildComplete,
		Sealed:          g.Sealed,
	}
	if m.Frames != nil && g.ID > 0 && !g.Sealed {
		if acc, err := m.Frames.AcceptedEnd(ctx, g.ID); err == nil && acc > st.CommittedOffset {
			st.CommittedOffset = acc
		}
		if dur, err := m.Frames.DurableEnd(ctx, g.ID); err == nil {
			st.DurableOffset = dur
		}
	}
	return st, nil
}

func (m *Machine) addBytes(key LogKey, n int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bytesFetched[key.String()] += n
}

func (m *Machine) resetBytes(key LogKey) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bytesFetched[key.String()] = 0
}

// Ensure Machine implements LogStore.
var _ LogStore = (*Machine)(nil)

// String for debugging (no secrets).
func (s State) String() string {
	return fmt.Sprintf("gen=%d id=%d offset=%d durable=%d more=%v complete=%v sealed=%v",
		s.Generation, s.GenerationID, s.CommittedOffset, s.DurableOffset, s.MoreData, s.BuildComplete, s.Sealed)
}
