// Package contracts defines stable internal reference types shared across
// packages (profile, job, build, queue, logs, stages, tests, artifacts, nodes).
//
// Prefer these typed refs over ad hoc strings at package boundaries (FND-005).
// Public MCP/JSON field names remain snake_case where tool schemas require it;
// Go identifiers stay idiomatic.
//
// MCP-002 tool-facing forms (stable JSON field names on seed tools):
//
//   - job:      job_name / name  → full Jenkins job path string → JobRef
//   - build:    job_name + build_number → BuildRef
//   - queue:    queue_id (+ optional profile) → QueueItemRef
//   - log:      job_name + build_number + offset/length or generation → LogEvidenceRef
//
// Absolute http(s) URLs and path-traversal segments ("." / "..") are rejected
// by ParseJobFullName (SSRF / path-escape reduction; Wave 31). Aligns with
// policy.NormalizeJobFullName which also fails closed on ".." for Match/Target.
// This package must not import Jenkins HTTP or the MCP SDK.
package contracts
