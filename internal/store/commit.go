package store

import (
	"os"
	"path/filepath"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// CommitStage identifies a step in the crash-safe frame commit pipeline (STO-004).
// Fault injection hooks may fail at any stage; recovery must leave state old-or-new.
type CommitStage int

const (
	// StageAfterTmpWrite: payload written to *.zst.tmp (not yet fsynced).
	StageAfterTmpWrite CommitStage = iota + 1
	// StageAfterTmpFsync: tmp file durable; rename not done.
	StageAfterTmpFsync
	// StageAfterRename: final path exists; parent dir may not be fsynced; meta not written.
	StageAfterRename
	// StageBeforeMeta: files durable; SQLite insert about to run.
	StageBeforeMeta
)

// CommitHook is invoked at the named stage; a non-nil error aborts the commit
// (simulating a crash). Production code leaves Hook nil.
type CommitHook func(stage CommitStage) error

// writeFileAtomic writes data to finalPath via tmp + fsync + rename + dir fsync.
// On any failure after creating tmp, best-effort cleanup of the tmp file is done
// unless the failure is after successful rename (then tmp is already gone).
func writeFileAtomic(finalPath string, data []byte, hook CommitHook) error {
	dir := filepath.Dir(finalPath)
	if err := EnsureDir(dir); err != nil {
		return err
	}
	tmpPath := finalPath + ".tmp"
	// Prefer canonical FrameTmpExt naming: final is foo.zst → foo.zst.tmp
	// When finalPath ends with .zst, use .zst.tmp not .zst.tmp from suffix above.
	// finalPath + ".tmp" yields "x.zst.tmp" which matches FrameTmpExt. Good.

	// Remove stale tmp if present.
	_ = os.Remove(tmpPath)

	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, FrameFilePerm)
	if err != nil {
		return apperr.Wrap(apperr.CodeInternal, "failed to create frame temp file", err)
	}
	tmpClosed := false
	defer func() {
		if !tmpClosed {
			_ = f.Close()
		}
	}()

	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		tmpClosed = true
		_ = os.Remove(tmpPath)
		return apperr.Wrap(apperr.CodeInternal, "failed to write frame temp file", err)
	}
	if err := f.Chmod(FrameFilePerm); err != nil {
		// Non-fatal on some FS; still try to continue.
		_ = err
	}
	if hook != nil {
		if err := hook(StageAfterTmpWrite); err != nil {
			_ = f.Close()
			tmpClosed = true
			_ = os.Remove(tmpPath)
			return err
		}
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		tmpClosed = true
		_ = os.Remove(tmpPath)
		return apperr.Wrap(apperr.CodeInternal, "failed to fsync frame temp file", err)
	}
	if err := f.Close(); err != nil {
		tmpClosed = true
		_ = os.Remove(tmpPath)
		return apperr.Wrap(apperr.CodeInternal, "failed to close frame temp file", err)
	}
	tmpClosed = true

	if hook != nil {
		if err := hook(StageAfterTmpFsync); err != nil {
			_ = os.Remove(tmpPath)
			return err
		}
	}

	if err := os.Rename(tmpPath, finalPath); err != nil {
		_ = os.Remove(tmpPath)
		return apperr.Wrap(apperr.CodeInternal, "failed to rename frame file", err)
	}

	if hook != nil {
		if err := hook(StageAfterRename); err != nil {
			// Orphan final path left for recovery to reconcile (no meta yet).
			return err
		}
	}

	if err := syncDir(dir); err != nil {
		// Rename already happened; report but leave file for recovery/meta.
		return apperr.Wrap(apperr.CodeInternal, "failed to fsync frame directory", err)
	}

	if hook != nil {
		if err := hook(StageBeforeMeta); err != nil {
			return err
		}
	}
	return nil
}

// syncDir fsyncs a directory (durability of rename on Unix).
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		// Some filesystems (e.g. some network FS) reject directory sync; treat as
		// best-effort only when not supported — still fail closed for real errors.
		if isErrNotSupported(err) {
			return nil
		}
		return err
	}
	return nil
}

func isErrNotSupported(err error) bool {
	if err == nil {
		return false
	}
	// syscall.ENOTSUP / EINVAL on exotic FS — match by string to avoid OS tags here.
	msg := err.Error()
	return containsAny(msg, "not supported", "invalid argument", "operation not supported")
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(sub) == 0 {
			continue
		}
		for i := 0; i+len(sub) <= len(s); i++ {
			if equalFoldASCII(s[i:i+len(sub)], sub) {
				return true
			}
		}
	}
	return false
}

func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
