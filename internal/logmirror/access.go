package logmirror

import (
	"context"
	"sync/atomic"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/store"
)

// LocalReadMeta describes a local-frame log read for MCP tool mapping (LOG-003/004).
type LocalReadMeta struct {
	Offset     int
	Length     int
	TotalSize  int
	HasMore    bool
	Generation int64
	Sealed     bool
}

// EnsureOptions bounds a single-log EnsureMirrored / multi-log acquireOne.
type EnsureOptions struct {
	// MaxBytes caps progressive body bytes accepted for this log (0 ⇒ 16 MiB).
	MaxBytes int64
	// MaxPolls caps Poll iterations (0 ⇒ 256).
	MaxPolls int
	// Status optional build completion probe.
	Status BuildStatusSource
	// TotalCounter / TotalLimit coordinate multi-log total budgets (optional).
	TotalCounter *atomic.Int64
	TotalLimit   int64
	// OnBudgetHit is called once when TotalLimit is exceeded (optional).
	OnBudgetHit func()
}

func (o EnsureOptions) normalize() EnsureOptions {
	if o.MaxBytes <= 0 {
		o.MaxBytes = 16 << 20
	}
	if o.MaxPolls <= 0 {
		o.MaxPolls = 256
	}
	return o
}

// Access is a single-profile LogStore façade for MCP tools (LOG-004 wiring).
// It polls progressive logs into frames and serves local ReadRange/Tail.
//
// tools.LogAccess is implemented by *Access (method set match) when tools
// use LocalReadMeta; the tools package may wrap with policy CheckStoreRead.
type Access struct {
	// Profile stamps every LogKey (same-profile isolation).
	Profile string
	// Machine is required (Frames + Reader for local reads).
	Machine *Machine
	// Status optional; used by EnsureMirrored to pass buildComplete.
	Status BuildStatusSource
	// Ensure bounds (zero ⇒ defaults).
	MaxBytes int64
	MaxPolls int
}

// NewAccess builds an Access bound to one profile + machine.
func NewAccess(profile string, m *Machine) *Access {
	return &Access{
		Profile:  profile,
		Machine:  m,
		MaxBytes: 16 << 20,
		MaxPolls: 256,
	}
}

// EnsureMirrored polls until the log generation is sealed or budgets/timeout stop
// progress. Committed frames remain recoverable on cancellation.
//
// Running builds may return nil with a non-sealed generation when progressive
// data is durable enough for subsequent local reads (partial mirror).
func (a *Access) EnsureMirrored(ctx context.Context, job string, build int64) error {
	if a == nil || a.Machine == nil {
		return apperr.New(apperr.CodeInternal, "log access is not configured")
	}
	key := LogKey{Profile: a.Profile, Job: job, Build: build}
	if err := key.Validate(); err != nil {
		return err
	}
	_, err := ensureMirrored(ctx, a.Machine, key, EnsureOptions{
		MaxBytes: a.MaxBytes,
		MaxPolls: a.MaxPolls,
		Status:   a.Status,
	})
	return err
}

// ReadRange returns a local byte range from committed frames (LOG-003).
// Call EnsureMirrored first when the range may not yet be durable.
func (a *Access) ReadRange(ctx context.Context, job string, build int64, offset, length int64) (string, LocalReadMeta, error) {
	if a == nil || a.Machine == nil {
		return "", LocalReadMeta{}, apperr.New(apperr.CodeInternal, "log access is not configured")
	}
	key := LogKey{Profile: a.Profile, Job: job, Build: build}
	if err := key.Validate(); err != nil {
		return "", LocalReadMeta{}, err
	}
	if offset < 0 || length < 0 {
		return "", LocalReadMeta{}, apperr.New(apperr.CodeInvalidArgument, "offset and length must be non-negative")
	}
	st, err := a.Machine.State(ctx, key)
	if err != nil {
		return "", LocalReadMeta{}, err
	}
	res, err := a.Machine.ReadRange(ctx, key, offset, length)
	if err != nil {
		return "", LocalReadMeta{}, err
	}
	return string(res.Data), metaFromRead(res, st, offset, length), nil
}

// Tail returns the last maxLen durable bytes from committed frames (LOG-003).
func (a *Access) Tail(ctx context.Context, job string, build int64, maxLen int64) (string, LocalReadMeta, error) {
	if a == nil || a.Machine == nil {
		return "", LocalReadMeta{}, apperr.New(apperr.CodeInternal, "log access is not configured")
	}
	key := LogKey{Profile: a.Profile, Job: job, Build: build}
	if err := key.Validate(); err != nil {
		return "", LocalReadMeta{}, err
	}
	if maxLen < 0 {
		return "", LocalReadMeta{}, apperr.New(apperr.CodeInvalidArgument, "max_length must be non-negative")
	}
	st, err := a.Machine.State(ctx, key)
	if err != nil {
		return "", LocalReadMeta{}, err
	}
	res, err := a.Machine.TailBytes(ctx, key, maxLen)
	if err != nil {
		return "", LocalReadMeta{}, err
	}
	// Offset is the absolute start of the tail slice.
	return string(res.Data), metaFromRead(res, st, res.RawStart, maxLen), nil
}

func metaFromRead(res store.ReadResult, st State, requestedStart, requestedLen int64) LocalReadMeta {
	length := len(res.Data)
	offset := int(res.RawStart)
	if res.RawStart == 0 && requestedStart > 0 && length > 0 {
		// Some readers leave RawStart at 0 for empty; prefer requested when set.
		offset = int(requestedStart)
	}
	// TotalSize is the durable exclusive end (authoritative local size).
	total := int(st.DurableOffset)
	if total == 0 && res.RawEnd > 0 {
		total = int(res.RawEnd)
	}
	if total < offset+length {
		total = offset + length
	}
	// HasMore: more remote data may exist, or a longer local range is available.
	hasMore := !st.Sealed
	if st.Sealed && int64(offset+length) < st.DurableOffset {
		hasMore = true // more local bytes beyond this slice
	}
	if !st.Sealed && requestedLen > 0 && int64(length) >= requestedLen {
		hasMore = true
	}
	if st.Sealed && int64(offset+length) >= st.DurableOffset {
		hasMore = false
	}
	return LocalReadMeta{
		Offset:     offset,
		Length:     length,
		TotalSize:  total,
		HasMore:    hasMore,
		Generation: res.Generation,
		Sealed:     res.Sealed || st.Sealed,
	}
}

// ensureMirrored is the shared poll loop for Access and Coordinator.
func ensureMirrored(ctx context.Context, m *Machine, key LogKey, opt EnsureOptions) (State, error) {
	opt = opt.normalize()
	if m == nil {
		return State{}, apperr.New(apperr.CodeInternal, "machine is not configured")
	}
	if err := key.Validate(); err != nil {
		return State{}, err
	}

	// Already sealed → nothing to fetch.
	st, err := m.State(ctx, key)
	if err != nil {
		return State{}, err
	}
	if st.Sealed {
		return st, nil
	}

	startBytes := m.BytesFetched(key)
	var last State
	noProgress := 0

	for poll := 0; poll < opt.MaxPolls; poll++ {
		if err := ctx.Err(); err != nil {
			// Leave committed frames; report cancellation.
			last = flushPartial(ctx, m, key, last, st)
			return last, mapCancel(err)
		}

		// Total budget across a collection.
		if opt.TotalCounter != nil && opt.TotalLimit > 0 {
			if opt.TotalCounter.Load() >= opt.TotalLimit {
				if opt.OnBudgetHit != nil {
					opt.OnBudgetHit()
				}
				last = flushPartial(ctx, m, key, last, st)
				return last, apperr.New(apperr.CodeQuota, "collection total byte budget exhausted")
			}
		}

		// Per-log progressive body budget.
		fetched := m.BytesFetched(key) - startBytes
		if fetched < 0 {
			fetched = 0
		}
		if fetched >= opt.MaxBytes {
			last = flushPartial(ctx, m, key, last, st)
			if last.GenerationID != 0 || last.DurableOffset > 0 || last.Sealed {
				// Partial success: frames are readable even if remote log continues.
				return last, apperr.New(apperr.CodeQuota, "per-log byte budget exhausted")
			}
			return last, apperr.New(apperr.CodeQuota, "per-log byte budget exhausted")
		}

		complete := false
		if opt.Status != nil {
			c, err := opt.Status.IsComplete(ctx, key.Job, key.Build)
			if err != nil {
				// Status probe failure is not fatal; continue with complete=false.
				complete = false
			} else {
				complete = c
			}
		}

		beforeOff := last.CommittedOffset
		if last.GenerationID == 0 {
			beforeOff = st.CommittedOffset
		}
		beforeFetched := m.BytesFetched(key)

		st, err = m.Poll(ctx, key, complete)
		if err != nil {
			if apperr.IsCancelled(err) || apperr.IsTimeout(err) {
				last = flushPartial(ctx, m, key, last, st)
				return last, err
			}
			// Return partial state with error when we already have frames.
			last = flushPartial(ctx, m, key, last, st)
			if last.DurableOffset > 0 || last.GenerationID != 0 {
				return last, err
			}
			return st, err
		}
		last = st

		// Account progressive bytes toward collection total.
		delta := m.BytesFetched(key) - beforeFetched
		if delta > 0 && opt.TotalCounter != nil {
			opt.TotalCounter.Add(delta)
			if opt.TotalLimit > 0 && opt.TotalCounter.Load() >= opt.TotalLimit {
				if opt.OnBudgetHit != nil {
					opt.OnBudgetHit()
				}
				// Stop after this poll; flush so durable matches accepted progress.
				last = flushPartial(ctx, m, key, last, st)
				return last, apperr.New(apperr.CodeQuota, "collection total byte budget exhausted")
			}
		}

		if st.Sealed {
			return st, nil
		}

		// Progress detection: stop spinning when sealed path not taken and no growth.
		if st.CommittedOffset == beforeOff && m.BytesFetched(key) == beforeFetched {
			noProgress++
			// If build is complete and no more data, try Seal (empty completion).
			if complete && !st.MoreData {
				sealed, serr := m.Seal(ctx, key)
				if serr == nil {
					return sealed, nil
				}
			}
			// Idle running build or EOF without complete: stop after a few idle polls.
			if noProgress >= 2 {
				// Partial mirror: flush buffered frames so local reads see data.
				return flushPartial(ctx, m, key, st, st), nil
			}
		} else {
			noProgress = 0
		}
	}

	last = flushPartial(ctx, m, key, last, st)
	if last.GenerationID != 0 {
		return last, apperr.New(apperr.CodeQuota, "max polls exceeded while mirroring log")
	}
	return last, apperr.New(apperr.CodeQuota, "max polls exceeded while mirroring log")
}

// flushPartial commits any in-process frame buffer so partial mirrors are readable
// (LOG-003/004: local reads only see durable frames).
func flushPartial(ctx context.Context, m *Machine, key LogKey, last, fallback State) State {
	st := last
	if st.GenerationID == 0 {
		st = fallback
	}
	if m == nil || m.Frames == nil || st.GenerationID == 0 {
		return st
	}
	res, err := m.Frames.Flush(ctx, st.GenerationID)
	if err != nil {
		return st
	}
	if res.DurableEnd > st.DurableOffset {
		st.DurableOffset = res.DurableEnd
	}
	if res.AcceptedEnd > st.CommittedOffset {
		st.CommittedOffset = res.AcceptedEnd
	}
	// Persist durable offset without sealing a running generation.
	if st.DurableOffset > 0 {
		_ = m.meta.UpdateGenerationOffset(ctx, st.GenerationID, st.DurableOffset, st.MoreData, st.BuildComplete, st.Sealed)
	}
	return st
}

// JenkinsBuildStatus adapts *jenkins.Client to BuildStatusSource via GetBuildDetailsByJob.
// Defined in source.go next to JenkinsSource to keep jenkins import localized.
