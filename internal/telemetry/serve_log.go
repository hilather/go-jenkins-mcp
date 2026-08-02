package telemetry

import (
	"fmt"
	"log"

	"github.com/hilather/go-jenkins-mcp/internal/redact"
)

// SafeServeLog formats like log.Printf, redacts the result with layered secret
// detectors, then emits via the standard library logger (call depth 2 for file:line).
//
// Prefer installing redact.NewWriter on log.SetOutput once at serve start so all
// log.Printf sites are covered without call-site rewrites. SafeServeLog is for
// explicit safe call sites and unit tests of the format-then-redact path (KD-004).
func SafeServeLog(format string, args ...any) {
	msg := redact.RedactText(fmt.Sprintf(format, args...))
	_ = log.Output(2, msg)
}
