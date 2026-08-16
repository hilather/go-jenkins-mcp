package jenkins

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
)

// MaxLogReadBytes is the hard server-side ceiling for a single log read
// (LOG-001 / MCP-001). Callers may request less; larger requests are clamped
// (never silently over-read into memory — the response budget runs after the
// bytes are buffered, so the cap must live at the read). HasMore / Offset /
// TotalSize keep the clamp honest.
const MaxLogReadBytes = 1 << 20 // 1 MiB

// GetBuildLogTail fetches the tail of build logs from the Jenkins progressiveText API (LOG-001).
//
// When X-Text-Size is present on the size probe, the probe body is not read into
// memory; only start=max(0,size-maxLength) is fetched with a hard LimitReader cap.
// Residual (KD-002 reduced): if X-Text-Size is missing, a true tail cannot be
// computed without scanning; we bound the probe read to maxLength and return that
// prefix (not a true tail). The size-probe connection is closed promptly; Jenkins
// may still generate response bytes on the wire until close (documented residual).
func (opts *Client) GetBuildLogTail(ctx context.Context, jobName string, buildNumber, maxLength int) (*BuildLogs, error) {
	client := opts.LogsClient
	if maxLength < 0 {
		return nil, fmt.Errorf("max_length must be >= 0")
	}
	if maxLength > MaxLogReadBytes {
		maxLength = MaxLogReadBytes
	}

	jobPath := BuildJobPath(jobName)

	// Size probe: need X-Text-Size without downloading the log body (LOG-001 / KD-002).
	// Jenkins progressiveText with start past EOF returns an empty body and still
	// sets X-Text-Size to the full length — so we deliberately probe with a huge
	// start instead of start=0 (which would offer the entire remainder).
	probeCtx, probeCancel := context.WithCancel(ctx)
	defer probeCancel()
	const sizeProbeStart = 1 << 30 // 1 GiB; body empty whenever real size is smaller
	sizePath := fmt.Sprintf("%s/%d/logText/progressiveText?start=%d", jobPath, buildNumber, sizeProbeStart)
	resp, err := opts.callJenkins(probeCtx, client, http.MethodGet, sizePath, nil, map[string]string{"Accept": "text/plain"}, true)
	if err != nil {
		return nil, fmt.Errorf("failed to make size request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("job '%s' build #%d not found", jobName, buildNumber)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jenkins api returned status %d: %s", resp.StatusCode, readLimitedErrBody(resp.Body))
	}

	totalSize := 0
	if textSizeHeader := resp.Header.Get("X-Text-Size"); textSizeHeader != "" {
		if size, err := strconv.Atoi(textSizeHeader); err == nil {
			totalSize = size
		}
	}

	if totalSize > 0 {
		// Do not download the full log for sizing (LOG-001 / KD-002). Cancel + close
		// abandons the socket instead of slurping. Residual: some bytes may already
		// be in flight until TCP close.
		probeCancel()
		_ = resp.Body.Close()

		if maxLength == 0 {
			return &BuildLogs{
				JobName:     jobName,
				BuildNumber: buildNumber,
				Offset:      totalSize,
				Length:      0,
				TotalSize:   totalSize,
				HasMore:     false,
				Logs:        "",
			}, nil
		}

		offset := max(0, totalSize-maxLength)
		want := min(maxLength, totalSize-offset)
		return opts.fetchProgressiveRange(ctx, client, jobName, buildNumber, jobPath, offset, want, totalSize)
	}

	// Residual: X-Text-Size missing — cannot seek to a true tail without a full
	// scan. Bound the probe read so application buffers stay ≤ maxLength.
	body, err := readLimited(resp.Body, progressiveLimit(maxLength))
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	probeCancel()
	_ = resp.Body.Close()
	// If the limited read returned less than maxLength, treat as full log.
	// If it filled maxLength, we only have a prefix (not a tail).
	logs := string(body)
	return &BuildLogs{
		JobName:     jobName,
		BuildNumber: buildNumber,
		Offset:      0,
		Length:      len(logs),
		TotalSize:   len(logs),
		HasMore:     maxLength > 0 && len(logs) == maxLength,
		Logs:        logs,
	}, nil
}

// GetBuildLogs fetches build logs from the Jenkins progressiveText API with a
// hard client-side byte cap (LOG-001). Application buffers never exceed `length`
// bytes; the body is closed after the limited read so the transport can stop
// pulling more. Residual: Jenkins progressiveText often generates the full
// remainder server-side until the connection closes — wire may exceed `length`
// until close, but memory and returned payload stay bounded.
func (opts *Client) GetBuildLogs(ctx context.Context, jobName string, buildNumber, offset, length int) (*BuildLogs, error) {
	client := opts.LogsClient
	var err error
	offset, length, err = validateNonNegativeOffsetLength(offset, length)
	if err != nil {
		return nil, err
	}
	if length > MaxLogReadBytes {
		length = MaxLogReadBytes
	}

	jobPath := BuildJobPath(jobName)
	return opts.fetchProgressiveRange(ctx, client, jobName, buildNumber, jobPath, offset, length, -1)
}

// fetchProgressiveRange performs one progressiveText GET at start=offset and
// reads at most length bytes into memory (LOG-001).
// knownTotal, when >= 0, is used as TotalSize; otherwise X-Text-Size / estimate.
func (opts *Client) fetchProgressiveRange(
	ctx context.Context,
	client *http.Client,
	jobName string,
	buildNumber int,
	jobPath string,
	offset, length, knownTotal int,
) (*BuildLogs, error) {
	// Cancelable child context: after the limited read we cancel so the transport
	// aborts the socket promptly instead of any residual body activity.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	apiPath := fmt.Sprintf("%s/%d/logText/progressiveText?start=%d", jobPath, buildNumber, offset)
	// closeConn=true: after LimitReader, Body.Close must not keep-alive-slurp the
	// remainder (that would reintroduce KD-001 into application drains).
	resp, err := opts.callJenkins(ctx, client, http.MethodGet, apiPath, nil, map[string]string{"Accept": "text/plain"}, true)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("job '%s' build #%d not found", jobName, buildNumber)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jenkins api returned status %d: %s", resp.StatusCode, readLimitedErrBody(resp.Body))
	}

	capN := progressiveLimit(length)
	logData, err := readLimited(resp.Body, capN)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	// Abort socket then close: application buffers stay ≤ length; residual wire
	// is limited to what was already in flight in kernel/httptest buffers.
	cancel()
	_ = resp.Body.Close()

	logs := string(logData)
	if length >= 0 && len(logs) > length {
		logs = logs[:length]
	}

	hasMore := false
	totalSize := offset + len(logData)
	if knownTotal >= 0 {
		totalSize = knownTotal
		hasMore = offset+len(logs) < totalSize
	} else if textSizeHeader := resp.Header.Get("X-Text-Size"); textSizeHeader != "" {
		if size, err := strconv.Atoi(textSizeHeader); err == nil {
			totalSize = size
			hasMore = offset+len(logs) < totalSize
		}
	} else {
		// No header: more data may exist if we filled the entire request length.
		hasMore = length > 0 && len(logs) == length
	}

	if resp.Header.Get("X-More-Data") == "true" {
		hasMore = true
	}

	return &BuildLogs{
		JobName:     jobName,
		BuildNumber: buildNumber,
		Offset:      offset,
		Length:      len(logs),
		TotalSize:   totalSize,
		HasMore:     hasMore,
		Logs:        logs,
	}, nil
}
