package logmirror

import (
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
	// Push-only source: data is a full fresh snapshot. AppendSnapshot handles
	// the sealed case atomically under the per-key lock (identical content is
	// a no-op; changed content rotates the generation and is written into it).
	// Append's sealed branch deliberately drops bodies — it exists for
	// pull-mode rewrite detection, where the body was fetched for the old
	// log's offset; never call bare Append for push snapshots.
	st, err := a.Machine.AppendSnapshot(ctx, key, Segment{
		Data:               data,
		ReportedNextOffset: int64(len(data)),
		MoreData:           false,
		BuildComplete:      true,
	})
	if err != nil {
		return State{}, fmt.Errorf("mirror stage log: %w", err)
	}
	return st, nil
}
