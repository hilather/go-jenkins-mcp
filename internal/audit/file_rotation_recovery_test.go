package audit_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/audit"
)

// Regression: a rotation failure permanently killed the file sink.
// rotateLocked closed and nil'ed the active file BEFORE renaming; a failed
// rename/reopen left s.f nil, the write failed, and every later Emit returned
// "audit: sink closed" — one transient filesystem hiccup disabled the AUD-001
// audit trail until process restart. Rotation now keeps the old handle open
// until the fresh file is opened, so the sink keeps recording (and retries
// rotation on the next Emit).
func TestFileSink_RotationFailureDoesNotKillSink(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	auditDir := filepath.Join(dir, "audit")
	// Tiny MaxBytes so the second emit triggers rotation (first emit is exempt
	// via the s.size > 0 guard).
	f, err := audit.NewFile(audit.FileConfig{Dir: auditDir, MaxBytes: 64, MaxRotated: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	ctx := context.Background()

	emit := func() error {
		return f.Emit(ctx, audit.Event{Type: audit.TypeToolDeny, Decision: audit.DecisionDeny})
	}

	// Fill past the rotation threshold.
	if err := emit(); err != nil {
		t.Fatal(err)
	}
	// Make the audit directory read-only so the rotation rename fails.
	if err := os.Chmod(auditDir, 0o500); err != nil {
		t.Fatal(err)
	}
	// Restore writability before TempDir cleanup regardless of outcome.
	t.Cleanup(func() { _ = os.Chmod(auditDir, 0o700) })
	// This emit triggers rotation, which fails; the event must still be
	// written (to the still-open active handle), not dropped.
	if err := emit(); err != nil {
		t.Fatalf("emit during failed rotation must still record: %v", err)
	}
	// Restore writability; the sink must recover and keep recording.
	if err := os.Chmod(auditDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := emit(); err != nil {
		t.Fatalf("sink must recover after transient rotation failure: %v", err)
	}
	if err := emit(); err != nil {
		t.Fatalf("sink must keep recording: %v", err)
	}

	// All events are on disk somewhere (active or rotated) — none dropped.
	total := 0
	entries, err := os.ReadDir(auditDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(auditDir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(data), "\n") {
			if strings.TrimSpace(line) != "" {
				total++
			}
		}
	}
	if total != 4 {
		t.Fatalf("recorded %d events, want 4 (no event may be dropped)", total)
	}
}
