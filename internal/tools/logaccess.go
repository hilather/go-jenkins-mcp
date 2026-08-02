package tools

import (
	"context"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/jenkins"
	"github.com/hilather/go-jenkins-mcp/internal/logmirror"
	"github.com/hilather/go-jenkins-mcp/internal/policy"
)

// LogReadMeta describes a local or mirrored log slice for MCP tool responses.
type LogReadMeta struct {
	Offset     int
	Length     int
	TotalSize  int
	HasMore    bool
	Generation int64
	Sealed     bool
}

// LogAccess serves build logs from the local logmirror/store when available
// (LOG-004 wiring). Prefer over direct jenkins.Client progressive fetches.
//
// Implementations stream progressive data into independent frames and read
// ranges from committed frames only. Nil LogAccess on RegisterOptions keeps
// the legacy direct-client path for compatibility.
type LogAccess interface {
	// EnsureMirrored polls until sealed or timeout/budget; leaves recoverable frames.
	EnsureMirrored(ctx context.Context, job string, build int64) error
	// ReadRange returns a byte range from local committed frames.
	ReadRange(ctx context.Context, job string, build int64, offset, length int64) (logs string, meta LogReadMeta, err error)
	// Tail returns the last maxLen durable bytes from local committed frames.
	Tail(ctx context.Context, job string, build int64, maxLen int64) (logs string, meta LogReadMeta, err error)
}

// MirrorLogAccess adapts *logmirror.Access to tools.LogAccess.
// Optional Coord enables jenkins_mirror_logs multi-log fan-out (LOG-004).
type MirrorLogAccess struct {
	Inner *logmirror.Access
	// Coord is the multi-log coordinator (same profile/machine as Inner).
	// Nil ⇒ single-log EnsureMirrored only; jenkins_mirror_logs not registered
	// via LogAccess extension (RegisterOptions.MultiLog may still wire it).
	Coord *logmirror.Coordinator
}

// NewMirrorLogAccess wraps a logmirror.Access for RegisterOptions.Logs.
// Coordinator may be attached via WithCoordinator after construction.
func NewMirrorLogAccess(a *logmirror.Access) *MirrorLogAccess {
	if a == nil {
		return nil
	}
	return &MirrorLogAccess{Inner: a}
}

// WithCoordinator attaches a multi-log Coordinator (same profile as Inner).
// Returns m for chaining; no-op when m is nil.
func (m *MirrorLogAccess) WithCoordinator(c *logmirror.Coordinator) *MirrorLogAccess {
	if m == nil {
		return nil
	}
	m.Coord = c
	return m
}

// EnsureMirrored implements LogAccess.
func (m *MirrorLogAccess) EnsureMirrored(ctx context.Context, job string, build int64) error {
	if m == nil || m.Inner == nil {
		return apperr.New(apperr.CodeInternal, "log access is not configured")
	}
	return m.Inner.EnsureMirrored(ctx, job, build)
}

// ReadRange implements LogAccess.
func (m *MirrorLogAccess) ReadRange(ctx context.Context, job string, build int64, offset, length int64) (string, LogReadMeta, error) {
	if m == nil || m.Inner == nil {
		return "", LogReadMeta{}, apperr.New(apperr.CodeInternal, "log access is not configured")
	}
	logs, lm, err := m.Inner.ReadRange(ctx, job, build, offset, length)
	if err != nil {
		return "", LogReadMeta{}, err
	}
	return logs, toLogReadMeta(lm), nil
}

// Tail implements LogAccess.
func (m *MirrorLogAccess) Tail(ctx context.Context, job string, build int64, maxLen int64) (string, LogReadMeta, error) {
	if m == nil || m.Inner == nil {
		return "", LogReadMeta{}, apperr.New(apperr.CodeInternal, "log access is not configured")
	}
	logs, lm, err := m.Inner.Tail(ctx, job, build, maxLen)
	if err != nil {
		return "", LogReadMeta{}, err
	}
	return logs, toLogReadMeta(lm), nil
}

// StageLogMirror optionally appends stage/node log bytes under a distinct key (PIPE-002).
// Console generations are never used. Implemented by *MirrorLogAccess.
type StageLogMirror interface {
	MirrorStageLogBytes(ctx context.Context, job string, build int64, stageID string, data []byte) error
}

// MirrorStageLogBytes implements StageLogMirror via logmirror.Access.
func (m *MirrorLogAccess) MirrorStageLogBytes(ctx context.Context, job string, build int64, stageID string, data []byte) error {
	if m == nil || m.Inner == nil {
		return apperr.New(apperr.CodeInternal, "log access is not configured")
	}
	_, err := m.Inner.MirrorStageLogBytes(ctx, job, build, stageID, data)
	return err
}

// asStageLogMirror returns StageLogMirror when st.logs supports stage mirroring.
func asStageLogMirror(logs LogAccess) StageLogMirror {
	if logs == nil {
		return nil
	}
	if m, ok := logs.(StageLogMirror); ok {
		return m
	}
	return nil
}

// readLogsViaAccess mirrors then reads a range from local frames.
// ok=false means fall back to the direct Jenkins client (mirror not usable).
// A non-nil err is a hard failure (e.g. policy_denial) that must not fall back.
func readLogsViaAccess(ctx context.Context, st regState, job string, build, offset, length int) (jenkins.BuildLogs, bool, error) {
	if st.logs == nil {
		return jenkins.BuildLogs{}, false, nil
	}
	// POL-004: CheckStoreRead before serving cached/mirrored content.
	// Multi-user: per-request subject from context when wired.
	if err := policy.CheckStoreRead(ctx, st.policy, effectiveSubject(st, ctx), job); err != nil {
		return jenkins.BuildLogs{}, false, err
	}
	if err := st.logs.EnsureMirrored(ctx, job, int64(build)); err != nil {
		// Budget/timeout with partial data may still allow a local read; try once.
		// Hard errors fall through to direct client unless policy/cancel.
		if apperr.IsCancelled(err) {
			return jenkins.BuildLogs{}, false, mapToolErr(err)
		}
		// Continue to ReadRange — Ensure may have left durable frames.
	}
	logs, meta, err := st.logs.ReadRange(ctx, job, int64(build), int64(offset), int64(length))
	if err != nil {
		// No local generation yet → fall back.
		if apperr.CodeOf(err) == apperr.CodeNotFound || apperr.CodeOf(err) == apperr.CodeInternal {
			return jenkins.BuildLogs{}, false, nil
		}
		return jenkins.BuildLogs{}, false, mapToolErr(err)
	}
	// Empty mirror with no generation evidence → fall back for first-hit UX.
	if meta.TotalSize == 0 && meta.Generation == 0 && logs == "" && length > 0 {
		return jenkins.BuildLogs{}, false, nil
	}
	return jenkins.BuildLogs{
		JobName:     job,
		BuildNumber: build,
		Offset:      meta.Offset,
		Length:      meta.Length,
		TotalSize:   meta.TotalSize,
		HasMore:     meta.HasMore,
		Logs:        logs,
	}, true, nil
}

// tailLogsViaAccess mirrors then tails from local frames (LOG-004).
func tailLogsViaAccess(ctx context.Context, st regState, job string, build, maxLength int) (jenkins.BuildLogs, bool, error) {
	if st.logs == nil {
		return jenkins.BuildLogs{}, false, nil
	}
	if err := policy.CheckStoreRead(ctx, st.policy, effectiveSubject(st, ctx), job); err != nil {
		return jenkins.BuildLogs{}, false, err
	}
	if err := st.logs.EnsureMirrored(ctx, job, int64(build)); err != nil {
		if apperr.IsCancelled(err) {
			return jenkins.BuildLogs{}, false, mapToolErr(err)
		}
	}
	logs, meta, err := st.logs.Tail(ctx, job, int64(build), int64(maxLength))
	if err != nil {
		if apperr.CodeOf(err) == apperr.CodeNotFound || apperr.CodeOf(err) == apperr.CodeInternal {
			return jenkins.BuildLogs{}, false, nil
		}
		return jenkins.BuildLogs{}, false, mapToolErr(err)
	}
	if meta.TotalSize == 0 && meta.Generation == 0 && logs == "" && maxLength > 0 {
		return jenkins.BuildLogs{}, false, nil
	}
	return jenkins.BuildLogs{
		JobName:     job,
		BuildNumber: build,
		Offset:      meta.Offset,
		Length:      meta.Length,
		TotalSize:   meta.TotalSize,
		HasMore:     meta.HasMore,
		Logs:        logs,
	}, true, nil
}

func toLogReadMeta(lm logmirror.LocalReadMeta) LogReadMeta {
	return LogReadMeta{
		Offset:     lm.Offset,
		Length:     lm.Length,
		TotalSize:  lm.TotalSize,
		HasMore:    lm.HasMore,
		Generation: lm.Generation,
		Sealed:     lm.Sealed,
	}
}

// Ensure *MirrorLogAccess implements LogAccess.
var _ LogAccess = (*MirrorLogAccess)(nil)
