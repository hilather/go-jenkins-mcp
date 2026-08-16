package jenkins

import (
	"context"
	"testing"
)

// Regression (LOG-001 / MCP-001): GetBuildLogs / GetBuildLogTail accepted an
// unbounded caller length and read up to `length` bytes into memory before any
// response budget ran — a budget-after-work bypass (a 10 GiB length on a
// multi-GiB console log would buffer GiBs in the MCP process). Both entry
// points now hard-cap at MaxLogReadBytes; HasMore/Offset preserve honesty.
func TestGetBuildLogs_LengthHardCapped(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	const logSize = 4 << 20 // 4 MiB
	f.setLogSize(BuildJobPath("demo"), 7, logSize)

	logs, err := f.opts().GetBuildLogs(context.Background(), "demo", 7, 0, 10<<20) // ask 10 MiB
	if err != nil {
		t.Fatal(err)
	}
	if len(logs.Logs) > MaxLogReadBytes {
		t.Fatalf("returned %d bytes, want <= MaxLogReadBytes (%d)", len(logs.Logs), MaxLogReadBytes)
	}
	if len(logs.Logs) != MaxLogReadBytes {
		t.Fatalf("returned %d bytes, want exactly the cap %d (log is larger)", len(logs.Logs), MaxLogReadBytes)
	}
	if !logs.HasMore {
		t.Fatal("HasMore must be true when the read was capped short of the log")
	}
	if logs.TotalSize != logSize {
		t.Fatalf("TotalSize=%d, want %d", logs.TotalSize, logSize)
	}
}

func TestGetBuildLogTail_MaxLengthHardCapped(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	const logSize = 4 << 20 // 4 MiB
	f.setLogSize(BuildJobPath("demo"), 7, logSize)

	logs, err := f.opts().GetBuildLogTail(context.Background(), "demo", 7, 10<<20) // ask 10 MiB tail
	if err != nil {
		t.Fatal(err)
	}
	if len(logs.Logs) > MaxLogReadBytes {
		t.Fatalf("tail returned %d bytes, want <= MaxLogReadBytes (%d)", len(logs.Logs), MaxLogReadBytes)
	}
	// Capped tail of a 4 MiB log returns the last MaxLogReadBytes bytes.
	if logs.Offset != logSize-MaxLogReadBytes {
		t.Fatalf("tail offset=%d, want %d", logs.Offset, logSize-MaxLogReadBytes)
	}
}

// Small requests are unaffected by the ceiling.
func TestGetBuildLogs_SmallLengthUnchanged(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	const logSize = 1 << 20
	f.setLogSize(BuildJobPath("demo"), 7, logSize)

	logs, err := f.opts().GetBuildLogs(context.Background(), "demo", 7, 0, 8192)
	if err != nil {
		t.Fatal(err)
	}
	if len(logs.Logs) != 8192 {
		t.Fatalf("returned %d bytes, want 8192", len(logs.Logs))
	}
}
