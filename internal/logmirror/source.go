package logmirror

import (
	"context"
	"fmt"

	"github.com/simonfxr/go-jenkins-mcp/internal/jenkins"
)

// JenkinsSource adapts *jenkins.Client to ProgressiveSource (LOG-001 bounds).
type JenkinsSource struct {
	Client *jenkins.Client
}

// Fetch implements ProgressiveSource using GetBuildLogs.
func (s JenkinsSource) Fetch(ctx context.Context, job string, build int64, startOffset int64, maxBytes int) (
	data []byte, reportedNext int64, moreData bool, err error,
) {
	if s.Client == nil {
		return nil, -1, false, context.Canceled
	}
	if startOffset < 0 {
		startOffset = 0
	}
	if maxBytes < 0 {
		maxBytes = 0
	}
	// jenkins.Client uses int offsets (seed API).
	logs, err := s.Client.GetBuildLogs(ctx, job, int(build), int(startOffset), maxBytes)
	if err != nil {
		return nil, -1, false, err
	}
	data = []byte(logs.Logs)
	reportedNext = int64(logs.TotalSize)
	moreData = logs.HasMore
	return data, reportedNext, moreData, nil
}

// JenkinsBuildStatus adapts *jenkins.Client to BuildStatusSource (LOG-004).
type JenkinsBuildStatus struct {
	Client *jenkins.Client
}

// IsComplete reports !Building for the given job/build.
func (s JenkinsBuildStatus) IsComplete(ctx context.Context, job string, build int64) (bool, error) {
	if s.Client == nil {
		return false, context.Canceled
	}
	b, err := s.Client.GetBuildDetailsByJob(ctx, job, int(build))
	if err != nil {
		return false, err
	}
	if b == nil {
		return false, nil
	}
	return !b.Building, nil
}

// FakeBuildStatus is an in-memory BuildStatusSource for unit tests.
// Keys are "job|build". Missing keys use DefaultComplete (true by default).
type FakeBuildStatus struct {
	// Complete maps "job|build" → finished.
	Complete map[string]bool
	// DefaultComplete is used when the key is absent (default true).
	DefaultComplete bool
}

// NewFakeBuildStatus returns a status source where every build is complete.
func NewFakeBuildStatus() *FakeBuildStatus {
	return &FakeBuildStatus{Complete: make(map[string]bool), DefaultComplete: true}
}

// Set marks a job/build as complete or running.
func (f *FakeBuildStatus) Set(job string, build int64, complete bool) {
	if f.Complete == nil {
		f.Complete = make(map[string]bool)
	}
	f.Complete[fmt.Sprintf("%s|%d", job, build)] = complete
}

// IsComplete implements BuildStatusSource.
func (f *FakeBuildStatus) IsComplete(ctx context.Context, job string, build int64) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if f == nil {
		return true, nil
	}
	k := fmt.Sprintf("%s|%d", job, build)
	if f.Complete != nil {
		if v, ok := f.Complete[k]; ok {
			return v, nil
		}
	}
	return f.DefaultComplete, nil
}

// FakeSource is an in-memory progressive log for unit tests (no Jenkins).
// It models progressiveText: Fetch(start) returns log[start:start+max] with
// X-Text-Size=len(log) and MoreData while running or when a suffix remains.
type FakeSource struct {
	// Log is the full console text so far.
	Log []byte
	// Running when true sets MoreData even at EOF (build still writing).
	Running bool
	// FetchCount counts remote-ish fetches (for single-flight tests).
	FetchCount int
	// FailOnce if non-nil is returned once then cleared.
	FailOnce error
	// BeforeFetch runs at the start of each Fetch (tests use it to block/overlap).
	BeforeFetch func()
}

// SetLog replaces the log body (simulates rewrite/truncation when shorter).
func (f *FakeSource) SetLog(b []byte) {
	f.Log = append([]byte(nil), b...)
}

// AppendLog grows the log (running build).
func (f *FakeSource) AppendLog(b []byte) {
	f.Log = append(f.Log, b...)
}

// Fetch implements ProgressiveSource.
func (f *FakeSource) Fetch(ctx context.Context, job string, build int64, startOffset int64, maxBytes int) (
	data []byte, reportedNext int64, moreData bool, err error,
) {
	if err := ctx.Err(); err != nil {
		return nil, -1, false, err
	}
	if f.FailOnce != nil {
		err := f.FailOnce
		f.FailOnce = nil
		return nil, -1, false, err
	}
	// Count before BeforeFetch so overlap tests observe the in-flight fetch.
	f.FetchCount++
	if f.BeforeFetch != nil {
		f.BeforeFetch()
	}
	if err := ctx.Err(); err != nil {
		return nil, -1, false, err
	}
	total := int64(len(f.Log))
	if startOffset < 0 {
		startOffset = 0
	}
	if startOffset > total {
		// Past EOF: empty body, reported size is total (truncation signal if
		// caller had a higher committed offset).
		return nil, total, f.Running, nil
	}
	end := startOffset + int64(maxBytes)
	if maxBytes <= 0 {
		end = startOffset
	}
	if end > total {
		end = total
	}
	data = append([]byte(nil), f.Log[startOffset:end]...)
	moreData = f.Running || end < total
	return data, total, moreData, nil
}
