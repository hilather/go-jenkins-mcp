package logmirror

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// StageLogKeyJob mirrors jenkins.StageLogKeyJob: console job name is never
// reused so stage mirrors cannot corrupt console generations (PIPE-002).
func StageLogKeyJob(job, stageID string) string {
	return strings.TrimSpace(job) + "#stage:" + strings.TrimSpace(stageID)
}

// StageLogKey builds a store LogKey for a stage/node log source.
func StageLogKey(profile, job string, build int64, stageID string) LogKey {
	return LogKey{
		Profile: profile,
		Job:     StageLogKeyJob(job, stageID),
		Build:   build,
	}
}

// MirrorStageLogBytes appends stage log text under a distinct LogKey and seals
// when complete. Empty data is a no-op success. Does not touch the console key.
func (a *Access) MirrorStageLogBytes(ctx context.Context, job string, build int64, stageID string, data []byte) (State, error) {
	if a == nil || a.Machine == nil {
		return State{}, apperr.New(apperr.CodeInternal, "log access is not configured")
	}
	if strings.TrimSpace(stageID) == "" {
		return State{}, apperr.New(apperr.CodeInvalidArgument, "stage id is required for stage log mirror")
	}
	key := StageLogKey(a.Profile, job, build, stageID)
	if err := key.Validate(); err != nil {
		return State{}, err
	}
	// Guard: never write to plain console key via this path.
	if key.Job == strings.TrimSpace(job) {
		return State{}, apperr.New(apperr.CodeInternal, "stage log key collides with console job key")
	}
	if len(data) == 0 {
		st, err := a.Machine.State(ctx, key)
		if err != nil {
			return State{}, err
		}
		return st, nil
	}
	// Push-only source: data is a full fresh snapshot. When the existing
	// generation is sealed, Append's sealed branch would route to
	// startNewGeneration and DROP the body (that path exists for pull-mode
	// rewrite detection, where the body was fetched for the old log's offset).
	// Here the body is authoritative: identical content is a no-op; changed
	// content rotates the generation first so the snapshot is actually written.
	if st, err := a.Machine.State(ctx, key); err != nil {
		return State{}, err
	} else if st.Sealed {
		if rr, rerr := a.Machine.ReadRange(ctx, key, 0, int64(len(data))+1); rerr == nil && bytes.Equal(rr.Data, data) {
			return st, nil // idempotent retry
		}
		if _, err := a.Machine.RotateGeneration(ctx, key); err != nil {
			return State{}, fmt.Errorf("mirror stage log rotate: %w", err)
		}
	}
	st, err := a.Machine.Append(ctx, key, Segment{
		Data:               data,
		ReportedNextOffset: int64(len(data)),
		MoreData:           false,
		BuildComplete:      true,
	})
	if err != nil {
		return State{}, fmt.Errorf("mirror stage log: %w", err)
	}
	// Seal complete stage log generation when no more data.
	if !st.MoreData && st.BuildComplete && !st.Sealed {
		st, err = a.Machine.Seal(ctx, key)
		if err != nil {
			return st, err
		}
	}
	return st, nil
}
