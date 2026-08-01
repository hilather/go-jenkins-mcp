// Package fleet implements privacy-preserving fleet health telemetry (MGR-002).
//
// Events carry only approved aggregate counters, pseudonymous identifiers,
// version/os/arch (goos/goarch), auth method enums, read_only bool, and stable
// apperr error_code classes. Free-text logs, prompts, API tokens, OAuth refresh
// tokens, Authorization headers, artifact content, raw job parameters, and
// credential-bearing URLs are never exported.
//
// Telemetry is disabled by default. Enable with JENKINS_MCP_TELEMETRY=1 and
// optionally set JENKINS_MCP_TELEMETRY_URL for HTTPS-only export (no redirects,
// body caps). Empty export URL keeps a local queue only. Network failures
// never block or fail the MCP serve path. Central analytics is not
// production-ready without operator privacy review.
package fleet
