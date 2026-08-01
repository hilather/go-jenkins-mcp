// Package telemetry provides structured diagnostic logging and in-process
// metrics for local observability (OBS-001).
//
// Labels and log fields must not contain secrets; string values are redacted.
// Fleet health export (MGR-002) lives in subpackage fleet and is disabled by
// default. Build-metadata OTEL correlation lite is internal/otelx (INT-002);
// full OTLP export / remote collectors remain residual.
// Doctor/status consume Registry.Snapshot (OPS-001).
//
// SafeServeLog (KD-004) formats then redacts before the standard logger;
// serve also installs redact.NewWriter on log.SetOutput process-wide.
package telemetry
