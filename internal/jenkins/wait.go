package jenkins

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// Adaptive wait defaults (JEN-004).
const (
	defaultQueueWaitTimeoutSec = 30
	defaultBuildWaitTimeoutSec = 600
	maxWaitTimeoutSec          = 3600 // hard cap on any wait
	waitInitialPoll            = 200 * time.Millisecond
	waitMaxPoll                = 5 * time.Second
	waitQueueMaxPoll           = 3 * time.Second
	waitBackoffFactor          = 1.6
	waitJitterFraction         = 0.2 // ±20%
)

// WaitCoordinator demultiplexes concurrent waiters onto shared poll loops (JEN-004).
// Multiple waiters for the same queue item or build do not multiply remote polls linearly.
type WaitCoordinator struct {
	mu    sync.Mutex
	queue map[int]*sharedWait
	build map[string]*sharedWait
}

type sharedWait struct {
	key     string
	refs    int
	ctx     context.Context // loop context; Err() != nil once abandoned/cancelled
	cancel  context.CancelFunc
	done    chan struct{}
	resultQ *WaitForQueueItemToolResponse
	resultB *WaitForRunningBuildToolResponse
	err     error
	polls   int
	kind    string // "queue" | "build"
}

func newWaitCoordinator() *WaitCoordinator {
	return &WaitCoordinator{
		queue: make(map[int]*sharedWait),
		build: make(map[string]*sharedWait),
	}
}

func (opts *Client) ensureWaitCoord() {
	if opts == nil {
		return
	}
	opts.waitOnce.Do(func() {
		opts.waitC = newWaitCoordinator()
	})
}

// WaitPollCountQueue returns remote poll count for a completed shared queue wait (tests).
func (opts *Client) WaitPollCountQueue(queueID int) int {
	if opts == nil {
		return 0
	}
	return opts.lastQueuePolls(queueID)
}

// adaptiveInterval returns the next poll delay with exponential backoff and jitter.
func adaptiveInterval(attempt int, initial, max time.Duration) time.Duration {
	if attempt <= 0 {
		return jitterDuration(initial)
	}
	d := float64(initial)
	for i := 0; i < attempt; i++ {
		d *= waitBackoffFactor
		if time.Duration(d) >= max {
			return jitterDuration(max)
		}
	}
	if time.Duration(d) > max {
		d = float64(max)
	}
	return jitterDuration(time.Duration(d))
}

func jitterDuration(d time.Duration) time.Duration {
	if d <= 0 {
		return waitInitialPoll
	}
	// Independent jitter per call (not crypto); fine for poll spacing.
	frac := (rand.Float64()*2 - 1) * waitJitterFraction // [-j, +j]
	jd := time.Duration(float64(d) * (1 + frac))
	if jd < time.Millisecond {
		jd = time.Millisecond
	}
	return jd
}

func clampTimeoutSeconds(sec, defaultSec int) time.Duration {
	if sec <= 0 {
		sec = defaultSec
	}
	if sec > maxWaitTimeoutSec {
		sec = maxWaitTimeoutSec
	}
	return time.Duration(sec) * time.Second
}

// WaitForQueueItem waits for a queue item with adaptive backoff, cancel
// awareness, max wait cap, and shared polling across concurrent waiters (JEN-004).
//
// Status values: "started", "cancelled" (queue item cancelled), "timeout",
// "context_cancelled" (caller cancelled). Latest known queue item is always
// included when fetchable.
//
// pollIntervalSeconds is treated as a *minimum* floor when >0; adaptive backoff
// still applies above that floor until waitQueueMaxPoll.
func (opts *Client) WaitForQueueItem(ctx context.Context, queueID, timeoutSeconds, pollIntervalSeconds int) (*WaitForQueueItemToolResponse, error) {
	if opts == nil {
		return nil, fmt.Errorf("jenkins client is nil")
	}
	if queueID <= 0 {
		return nil, apperr.New(apperr.CodeInvalidArgument, "queue_id must be positive")
	}
	opts.ensureWaitCoord()
	timeout := clampTimeoutSeconds(timeoutSeconds, defaultQueueWaitTimeoutSec)

	minPoll := waitInitialPoll
	if pollIntervalSeconds > 0 {
		// Allow tests to request faster/slower floors; still adaptive above floor.
		minPoll = time.Duration(pollIntervalSeconds) * time.Second
		if minPoll > waitQueueMaxPoll {
			minPoll = waitQueueMaxPoll
		}
		if minPoll < 50*time.Millisecond {
			minPoll = 50 * time.Millisecond
		}
	}

	return opts.waitQueueShared(ctx, queueID, timeout, minPoll)
}

func (opts *Client) waitQueueShared(ctx context.Context, queueID int, timeout time.Duration, minPoll time.Duration) (*WaitForQueueItemToolResponse, error) {
	c := opts.waitC
	c.mu.Lock()
	if sw, ok := c.queue[queueID]; ok {
		if sw.ctx.Err() == nil {
			sw.refs++
			c.mu.Unlock()
			return opts.awaitQueueShared(ctx, sw)
		}
		// Abandoned loop winding down; replace with a fresh wait so a new
		// caller never joins a cancelled loop.
		delete(c.queue, queueID)
	}
	// Start leader poll loop.
	loopCtx, cancel := context.WithCancel(context.Background())
	sw := &sharedWait{
		key:    fmt.Sprintf("queue:%d", queueID),
		refs:   1,
		ctx:    loopCtx,
		cancel: cancel,
		done:   make(chan struct{}),
		kind:   "queue",
	}
	c.queue[queueID] = sw
	c.mu.Unlock()

	go opts.runQueueWait(loopCtx, sw, queueID, timeout, minPoll)

	return opts.awaitQueueShared(ctx, sw)
}

// releaseQueueWaiter drops one waiter reference; when the last waiter
// abandons, the shared poll loop is cancelled so it stops polling Jenkins
// instead of running to the wait deadline with no listeners (JEN-004).
func (opts *Client) releaseQueueWaiter(sw *sharedWait) {
	c := opts.waitC
	c.mu.Lock()
	sw.refs--
	if sw.refs <= 0 && sw.ctx.Err() == nil {
		sw.cancel()
	}
	c.mu.Unlock()
}

func (opts *Client) awaitQueueShared(ctx context.Context, sw *sharedWait) (*WaitForQueueItemToolResponse, error) {
	select {
	case <-sw.done:
		return cloneQueueWaitResult(sw)
	case <-ctx.Done():
		opts.releaseQueueWaiter(sw)
		// Best-effort latest state.
		item, _ := opts.GetQueueItem(context.Background(), parseQueueKey(sw.key))
		st := "context_cancelled"
		if ctx.Err() == context.DeadlineExceeded {
			st = "timeout"
		}
		return &WaitForQueueItemToolResponse{
			QueueItem: item,
			WaitTime:  0,
			TimedOut:  st == "timeout",
			Status:    st,
		}, nil
	}
}

func parseQueueKey(key string) int {
	var id int
	_, _ = fmt.Sscanf(key, "queue:%d", &id)
	return id
}

func cloneQueueWaitResult(sw *sharedWait) (*WaitForQueueItemToolResponse, error) {
	if sw.err != nil && sw.resultQ == nil {
		return nil, sw.err
	}
	if sw.resultQ == nil {
		return &WaitForQueueItemToolResponse{Status: "timeout", TimedOut: true}, nil
	}
	cp := *sw.resultQ
	return &cp, nil
}

func (opts *Client) runQueueWait(loopCtx context.Context, sw *sharedWait, queueID int, timeout, minPoll time.Duration) {
	defer func() {
		close(sw.done)
		opts.waitC.mu.Lock()
		// Delete only our own entry: an abandoned loop may already have been
		// replaced by a fresh shared wait under the same key.
		if opts.waitC.queue[queueID] == sw {
			delete(opts.waitC.queue, queueID)
		}
		if opts.queuePollSnap == nil {
			opts.queuePollSnap = make(map[int]int)
		}
		opts.queuePollSnap[queueID] = sw.polls
		opts.waitC.mu.Unlock()
	}()

	start := time.Now()
	deadline := start.Add(timeout)
	attempt := 0
	var last *QueueItem

	for {
		// Respect shared loop cancel and overall deadline.
		if err := loopCtx.Err(); err != nil {
			sw.resultQ = &WaitForQueueItemToolResponse{
				QueueItem: last,
				WaitTime:  DurationMS(time.Since(start)),
				TimedOut:  false,
				Status:    "context_cancelled",
			}
			return
		}
		if time.Now().After(deadline) {
			// Final best-effort fetch with background ctx (bounded).
			fetchCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			item, _ := opts.GetQueueItem(fetchCtx, queueID)
			cancel()
			if item != nil {
				last = item
			}
			sw.resultQ = &WaitForQueueItemToolResponse{
				QueueItem: last,
				WaitTime:  DurationMS(time.Since(start)),
				TimedOut:  true,
				Status:    "timeout",
				PollCount: sw.polls,
			}
			return
		}

		fetchCtx, cancel := context.WithTimeout(loopCtx, 5*time.Second)
		item, err := opts.GetQueueItem(fetchCtx, queueID)
		cancel()
		sw.polls++
		if err == nil && item != nil {
			last = item
			if item.Cancelled {
				sw.resultQ = &WaitForQueueItemToolResponse{
					QueueItem: item,
					WaitTime:  DurationMS(time.Since(start)),
					TimedOut:  false,
					Status:    "cancelled",
					PollCount: sw.polls,
				}
				return
			}
			if item.Executable != nil && item.Executable.Number > 0 {
				sw.resultQ = &WaitForQueueItemToolResponse{
					QueueItem: item,
					Build:     item.Executable,
					WaitTime:  DurationMS(time.Since(start)),
					TimedOut:  false,
					Status:    "started",
					PollCount: sw.polls,
				}
				return
			}
		}

		// Adaptive sleep (fast first, then backoff + jitter), never past deadline.
		sleep := adaptiveInterval(attempt, minPoll, waitQueueMaxPoll)
		attempt++
		remaining := time.Until(deadline)
		if remaining <= 0 {
			continue
		}
		if sleep > remaining {
			sleep = remaining
		}
		timer := time.NewTimer(sleep)
		select {
		case <-loopCtx.Done():
			timer.Stop()
			sw.resultQ = &WaitForQueueItemToolResponse{
				QueueItem: last,
				WaitTime:  DurationMS(time.Since(start)),
				Status:    "context_cancelled",
			}
			return
		case <-timer.C:
		}
	}
}

// WaitForRunningBuild waits for a build to complete with adaptive backoff,
// cancel awareness, max wait cap, and shared polling (JEN-004).
//
// Status: success|failure|unstable|aborted|unknown|timeout|context_cancelled.
// Polls immediately on entry (no fixed 5s delay before first check).
func (opts *Client) WaitForRunningBuild(ctx context.Context, jobName string, buildNumber, timeoutSeconds int) (*WaitForRunningBuildToolResponse, error) {
	if opts == nil {
		return nil, fmt.Errorf("jenkins client is nil")
	}
	jobName = strings.TrimSpace(jobName)
	if jobName == "" {
		return nil, apperr.New(apperr.CodeInvalidArgument, "job_name is required")
	}
	if buildNumber <= 0 {
		return nil, apperr.New(apperr.CodeInvalidArgument, "build_number must be positive")
	}
	opts.ensureWaitCoord()
	timeout := clampTimeoutSeconds(timeoutSeconds, defaultBuildWaitTimeoutSec)
	return opts.waitBuildShared(ctx, jobName, buildNumber, timeout)
}

func buildWaitKey(jobName string, buildNumber int) string {
	return fmt.Sprintf("%s#%d", jobName, buildNumber)
}

func (opts *Client) waitBuildShared(ctx context.Context, jobName string, buildNumber int, timeout time.Duration) (*WaitForRunningBuildToolResponse, error) {
	key := buildWaitKey(jobName, buildNumber)
	c := opts.waitC
	c.mu.Lock()
	if sw, ok := c.build[key]; ok {
		if sw.ctx.Err() == nil {
			sw.refs++
			c.mu.Unlock()
			return opts.awaitBuildShared(ctx, sw, jobName, buildNumber)
		}
		// Abandoned loop winding down; replace with a fresh wait.
		delete(c.build, key)
	}
	loopCtx, cancel := context.WithCancel(context.Background())
	sw := &sharedWait{
		key:    key,
		refs:   1,
		ctx:    loopCtx,
		cancel: cancel,
		done:   make(chan struct{}),
		kind:   "build",
	}
	c.build[key] = sw
	c.mu.Unlock()

	go opts.runBuildWait(loopCtx, sw, jobName, buildNumber, timeout)
	return opts.awaitBuildShared(ctx, sw, jobName, buildNumber)
}

func (opts *Client) awaitBuildShared(ctx context.Context, sw *sharedWait, jobName string, buildNumber int) (*WaitForRunningBuildToolResponse, error) {
	select {
	case <-sw.done:
		return cloneBuildWaitResult(sw)
	case <-ctx.Done():
		opts.releaseBuildWaiter(sw)
		st := "context_cancelled"
		if ctx.Err() == context.DeadlineExceeded {
			st = "timeout"
		}
		return &WaitForRunningBuildToolResponse{
			JobName:     jobName,
			BuildNumber: buildNumber,
			Status:      st,
			TimedOut:    st == "timeout",
		}, nil
	}
}

// releaseBuildWaiter drops one waiter reference; when the last waiter
// abandons, the shared poll loop is cancelled (JEN-004).
func (opts *Client) releaseBuildWaiter(sw *sharedWait) {
	c := opts.waitC
	c.mu.Lock()
	sw.refs--
	if sw.refs <= 0 && sw.ctx.Err() == nil {
		sw.cancel()
	}
	c.mu.Unlock()
}

func cloneBuildWaitResult(sw *sharedWait) (*WaitForRunningBuildToolResponse, error) {
	if sw.err != nil && sw.resultB == nil {
		return nil, sw.err
	}
	if sw.resultB == nil {
		return &WaitForRunningBuildToolResponse{Status: "timeout", TimedOut: true}, nil
	}
	cp := *sw.resultB
	return &cp, nil
}

func (opts *Client) runBuildWait(loopCtx context.Context, sw *sharedWait, jobName string, buildNumber int, timeout time.Duration) {
	key := buildWaitKey(jobName, buildNumber)
	defer func() {
		close(sw.done)
		opts.waitC.mu.Lock()
		// Delete only our own entry: an abandoned loop may already have been
		// replaced by a fresh shared wait under the same key.
		if opts.waitC.build[key] == sw {
			delete(opts.waitC.build, key)
		}
		if opts.buildPollSnap == nil {
			opts.buildPollSnap = make(map[string]int)
		}
		opts.buildPollSnap[key] = sw.polls
		opts.waitC.mu.Unlock()
	}()

	start := time.Now()
	deadline := start.Add(timeout)
	attempt := 0
	jobPath := BuildJobPath(jobName)

	for {
		if err := loopCtx.Err(); err != nil {
			sw.resultB = &WaitForRunningBuildToolResponse{
				JobName:     jobName,
				BuildNumber: buildNumber,
				Status:      "context_cancelled",
				WaitTime:    DurationMS(time.Since(start)),
			}
			return
		}
		if time.Now().After(deadline) {
			sw.resultB = &WaitForRunningBuildToolResponse{
				JobName:     jobName,
				BuildNumber: buildNumber,
				Status:      "timeout",
				WaitTime:    DurationMS(time.Since(start)),
				TimedOut:    true,
				PollCount:   sw.polls,
			}
			return
		}

		// Prefer path-based fetch (origin-pinned); avoids absolute URL join issues.
		fetchCtx, cancel := context.WithTimeout(loopCtx, 5*time.Second)
		build, err := opts.GetBuildDetailsByJob(fetchCtx, jobName, buildNumber)
		cancel()
		sw.polls++
		_ = jobPath
		if err == nil && build != nil && !build.Building {
			status := mapBuildResultStatus(build.Result)
			sw.resultB = &WaitForRunningBuildToolResponse{
				JobName:     jobName,
				BuildNumber: buildNumber,
				Status:      status,
				Result:      build.Result,
				Duration:    build.Duration,
				WaitTime:    DurationMS(time.Since(start)),
				TimedOut:    false,
				PollCount:   sw.polls,
			}
			return
		}

		sleep := adaptiveInterval(attempt, waitInitialPoll, waitMaxPoll)
		attempt++
		remaining := time.Until(deadline)
		if remaining <= 0 {
			continue
		}
		if sleep > remaining {
			sleep = remaining
		}
		timer := time.NewTimer(sleep)
		select {
		case <-loopCtx.Done():
			timer.Stop()
			sw.resultB = &WaitForRunningBuildToolResponse{
				JobName:     jobName,
				BuildNumber: buildNumber,
				Status:      "context_cancelled",
				WaitTime:    DurationMS(time.Since(start)),
			}
			return
		case <-timer.C:
		}
	}
}

func mapBuildResultStatus(result string) string {
	switch strings.ToUpper(strings.TrimSpace(result)) {
	case "SUCCESS":
		return "success"
	case "FAILURE":
		return "failure"
	case "UNSTABLE":
		return "unstable"
	case "ABORTED":
		return "aborted"
	default:
		return "unknown"
	}
}

func (opts *Client) lastQueuePolls(queueID int) int {
	if opts == nil || opts.waitC == nil {
		return 0
	}
	opts.waitC.mu.Lock()
	defer opts.waitC.mu.Unlock()
	if opts.queuePollSnap == nil {
		return 0
	}
	return opts.queuePollSnap[queueID]
}

// WaitPollCountBuild returns remote poll count for a completed shared build wait (tests).
func (opts *Client) WaitPollCountBuild(jobName string, buildNumber int) int {
	if opts == nil || opts.waitC == nil {
		return 0
	}
	opts.waitC.mu.Lock()
	defer opts.waitC.mu.Unlock()
	if opts.buildPollSnap == nil {
		return 0
	}
	return opts.buildPollSnap[buildWaitKey(jobName, buildNumber)]
}
