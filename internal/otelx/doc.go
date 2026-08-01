// Package otelx provides OpenTelemetry correlation helpers for Jenkins build
// metadata (INT-002 MVP).
//
// This package extracts well-known trace/span/service identifiers from
// parameters already present on a Jenkins build. It does **not**:
//
//   - Export spans or logs over OTLP
//   - Query a remote observability backend
//   - Send log text to telemetry services
//
// Full OTLP backend adapters remain residual (see docs/observability.md and
// docs/adapters/README.md). Integration is disabled by default at the tools
// registration layer; this package is pure and safe to import always.
package otelx
