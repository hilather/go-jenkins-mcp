package auth

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// BrowserOpener opens a URL in the user's browser (or a test stub).
// Implementations must not log URL query parameters that may contain OAuth state
// (state is not a secret but still sensitive for CSRF analysis).
type BrowserOpener func(ctx context.Context, rawURL string) error

// OpenSystemBrowser launches the platform browser for rawURL.
// Preference order: $BROWSER (if set), then xdg-open on Linux.
// macOS and Windows are out of scope (ADR 0008); fails closed.
func OpenSystemBrowser(ctx context.Context, rawURL string) error {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return apperr.New(apperr.CodeInvalidArgument, "browser URL is required")
	}
	if err := ctx.Err(); err != nil {
		return apperr.Wrap(apperr.CodeCancelled, "open browser cancelled", err)
	}

	if b := strings.TrimSpace(os.Getenv("BROWSER")); b != "" {
		// $BROWSER may be a command with args (common on Unix).
		// Use sh -c only when it contains spaces; otherwise exec directly.
		var cmd *exec.Cmd
		if strings.Contains(b, " ") {
			cmd = exec.CommandContext(ctx, "sh", "-c", b+" \"$1\"", "sh", rawURL)
		} else {
			cmd = exec.CommandContext(ctx, b, rawURL)
		}
		if err := cmd.Start(); err != nil {
			return apperr.Wrap(apperr.CodeInternal, "failed to open browser via $BROWSER", err)
		}
		// Do not wait — browser is long-lived.
		_ = cmd.Process.Release()
		return nil
	}

	if runtime.GOOS != "linux" {
		return apperr.New(apperr.CodeCapabilityMissing,
			"system browser open is unsupported on this platform (supported platforms: Rocky Linux and Ubuntu only)")
	}
	cmd := exec.CommandContext(ctx, "xdg-open", rawURL)
	if err := cmd.Start(); err != nil {
		return apperr.Wrap(apperr.CodeInternal, "failed to open system browser", err)
	}
	_ = cmd.Process.Release()
	return nil
}

// NoopBrowser is a BrowserOpener that does nothing (tests inject authorize via httptest).
func NoopBrowser(_ context.Context, _ string) error {
	return nil
}
