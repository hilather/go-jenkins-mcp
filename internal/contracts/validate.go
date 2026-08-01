package contracts

import (
	"fmt"
	"strings"
)

// Stable allowed-form descriptions for validation errors (MCP-002).
// These appear in model-visible invalid_argument messages.
const (
	// AllowedJobForm is the human-readable form for job full-name fields.
	// Wire JSON still uses job_name / name strings (not http URLs).
	// Relative folder/job paths only: no absolute URL/path, no empty segments,
	// no "." / ".." path segments (Wave 31 / fail closed before Jenkins).
	AllowedJobForm = "Jenkins job full name path such as \"job\" or \"folder/sub/job\" (relative; not an http(s) URL or absolute path; no \".\" or \"..\" segments)"
	// AllowedBuildForm describes build identity fields.
	AllowedBuildForm = "job full name plus positive build_number"
	// AllowedQueueForm describes queue item identity fields.
	AllowedQueueForm = "positive queue_id (optional profile id)"
	// AllowedLogEvidenceForm describes log range / generation evidence.
	AllowedLogEvidenceForm = "job full name, positive build_number, non-negative offset, positive length; or build + generation handle"
)

// FieldError is a structured validation failure that identifies the invalid
// field and the allowed form (MCP-002 acceptance: actionable errors).
type FieldError struct {
	Field   string
	Message string
	Allowed string
}

// Error implements error.
func (e *FieldError) Error() string {
	if e == nil {
		return "invalid argument"
	}
	msg := e.Message
	if e.Field != "" {
		msg = fmt.Sprintf("%s: %s", e.Field, e.Message)
	}
	if e.Allowed != "" {
		msg = msg + "; allowed form: " + e.Allowed
	}
	return msg
}

// IsAbsoluteHTTPURL reports whether s looks like an absolute http(s) URL or a
// protocol-relative URL. Used to reject model-constructed Jenkins page URLs in
// job_name / name tool fields (SSRF reduction / MCP-002).
//
// This is intentionally syntactic and does not perform network I/O. It must
// not live in the Jenkins HTTP client package (contracts stays HTTP-free).
func IsAbsoluteHTTPURL(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	lower := strings.ToLower(s)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		return true
	}
	// Protocol-relative //host/...
	if strings.HasPrefix(s, "//") {
		return true
	}
	return false
}

// looksLikeSchemeURL catches non-http absolute URL forms models sometimes pass
// instead of a job full name (file:, jenkins:, etc.). Only known URL-like
// schemes are rejected so rare job names containing ':' remain accepted.
func looksLikeSchemeURL(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	if IsAbsoluteHTTPURL(s) {
		return true
	}
	lower := strings.ToLower(s)
	// Known URL / SSRF-relevant schemes (with or without //).
	for _, p := range []string{
		"file:",
		"jenkins:",
		"ftp:",
		"ftps:",
		"data:",
		"javascript:",
		"ws:",
		"wss:",
	} {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
}

// ParseJobFullName validates a tool-facing job full name and returns a JobRef.
// field is the JSON field name used in error messages (e.g. "job_name", "name").
//
// Accepts: "demo", "folder/job", "folder/sub/job", multibranch-style names
// without path-traversal segments.
//
// Rejects: empty; absolute http(s)/scheme URLs; control characters; absolute
// path forms (leading "/"); empty path segments ("//" or trailing "/"); any
// path segment equal to "." or ".." (Wave 31 fail closed — handlers must never
// call Jenkins with a traversal segment).
//
// Alignment with policy.NormalizeJobFullName: Match/Target normalize also fails
// closed on ".." (returns empty JobName). Parse is the tool-input gate and
// returns a clear FieldError (invalid_argument) instead of accepting ".." and
// relying on later policy normalize.
func ParseJobFullName(field, raw string) (JobRef, error) {
	if field == "" {
		field = "job_name"
	}
	name := strings.TrimSpace(raw)
	if name == "" {
		return JobRef{}, &FieldError{
			Field:   field,
			Message: "missing or empty",
			Allowed: AllowedJobForm,
		}
	}
	if IsAbsoluteHTTPURL(name) || looksLikeSchemeURL(name) {
		return JobRef{}, &FieldError{
			Field:   field,
			Message: "absolute or scheme URL is not allowed (pass the Jenkins job full name, not a browser URL)",
			Allowed: AllowedJobForm,
		}
	}
	// Reject control characters and NULs that break path construction.
	for _, r := range name {
		if r == 0 || (r < 0x20 && r != '\t') {
			return JobRef{}, &FieldError{
				Field:   field,
				Message: "contains control characters",
				Allowed: AllowedJobForm,
			}
		}
	}
	// Absolute path form (leading /). Protocol-relative "//host/..." is already
	// rejected by IsAbsoluteHTTPURL above.
	if strings.HasPrefix(name, "/") {
		return JobRef{}, &FieldError{
			Field:   field,
			Message: "absolute path form is not allowed (pass a relative job full name such as \"folder/job\")",
			Allowed: AllowedJobForm,
		}
	}
	// Segment checks: reject empty segments and "." / ".." (fail closed).
	// Do not collapse — empty segments are invalid tool input.
	for _, seg := range strings.Split(name, "/") {
		if seg == "" {
			return JobRef{}, &FieldError{
				Field:   field,
				Message: "empty path segment is not allowed (use a single \"/\" between folder and job names; no leading or trailing slash)",
				Allowed: AllowedJobForm,
			}
		}
		if seg == "." || seg == ".." {
			return JobRef{}, &FieldError{
				Field:   field,
				Message: "path segment \".\" or \"..\" is not allowed (pass a relative job full name without path traversal)",
				Allowed: AllowedJobForm,
			}
		}
	}
	return JobRef{FullName: name}, nil
}

// ParseJobRef validates job.FullName (and optional profile) the same way as
// ParseJobFullName. Profile may be empty.
func ParseJobRef(field string, job JobRef) (JobRef, error) {
	if field == "" {
		field = "job"
	}
	parsed, err := ParseJobFullName(field, job.FullName)
	if err != nil {
		return JobRef{}, err
	}
	parsed.Profile = job.Profile
	return parsed, nil
}

// ParseBuildRef validates job full name + positive build number into a BuildRef.
// jobField and numberField name the JSON fields for errors.
func ParseBuildRef(jobField, jobName string, numberField string, number int64) (BuildRef, error) {
	if jobField == "" {
		jobField = "job_name"
	}
	if numberField == "" {
		numberField = "build_number"
	}
	job, err := ParseJobFullName(jobField, jobName)
	if err != nil {
		return BuildRef{}, err
	}
	if number <= 0 {
		return BuildRef{}, &FieldError{
			Field:   numberField,
			Message: "must be a positive integer",
			Allowed: AllowedBuildForm,
		}
	}
	return BuildRef{Job: job, Number: number}, nil
}

// ParseQueueItemRef validates a positive queue id into a QueueItemRef.
func ParseQueueItemRef(idField string, id int64, profile ProfileID) (QueueItemRef, error) {
	if idField == "" {
		idField = "queue_id"
	}
	if id <= 0 {
		return QueueItemRef{}, &FieldError{
			Field:   idField,
			Message: "must be a positive integer",
			Allowed: AllowedQueueForm,
		}
	}
	return QueueItemRef{Profile: profile, ID: id}, nil
}

// LogEvidenceRef identifies a byte-range or generation handle of a build log
// for tool schemas (MCP-002). Wire tools may flatten this into job_name,
// build_number, offset, length (and optional generation).
type LogEvidenceRef struct {
	Build      BuildRef `json:"build"`
	Offset     int64    `json:"offset,omitempty"`
	Length     int64    `json:"length,omitempty"`
	Generation string   `json:"generation,omitempty"`
}

// String returns a stable display form.
func (l LogEvidenceRef) String() string {
	if l.Generation != "" {
		return fmt.Sprintf("%s/log:%s@%d+%d", l.Build.String(), l.Generation, l.Offset, l.Length)
	}
	return fmt.Sprintf("%s/log@%d+%d", l.Build.String(), l.Offset, l.Length)
}

// Valid reports whether build is valid and either generation is set or length is positive.
func (l LogEvidenceRef) Valid() bool {
	if !l.Build.Valid() {
		return false
	}
	if l.Generation != "" {
		return true
	}
	return l.Length > 0 && l.Offset >= 0
}

// ParseLogEvidenceRef validates flattened log-evidence tool fields.
// lengthDefault is used when length <= 0 (seed default is typically 8192).
// When generation is non-empty, offset/length may be zero (handle form).
func ParseLogEvidenceRef(jobField, jobName, numberField string, number int64, offset, length int64, generation string, lengthDefault int64) (LogEvidenceRef, error) {
	build, err := ParseBuildRef(jobField, jobName, numberField, number)
	if err != nil {
		return LogEvidenceRef{}, err
	}
	generation = strings.TrimSpace(generation)
	if offset < 0 {
		return LogEvidenceRef{}, &FieldError{
			Field:   "offset",
			Message: "must be >= 0",
			Allowed: AllowedLogEvidenceForm,
		}
	}
	if generation != "" {
		return LogEvidenceRef{
			Build:      build,
			Offset:     offset,
			Length:     length,
			Generation: generation,
		}, nil
	}
	if length <= 0 {
		if lengthDefault <= 0 {
			return LogEvidenceRef{}, &FieldError{
				Field:   "length",
				Message: "must be a positive integer (or provide generation)",
				Allowed: AllowedLogEvidenceForm,
			}
		}
		length = lengthDefault
	}
	return LogEvidenceRef{
		Build:  build,
		Offset: offset,
		Length: length,
	}, nil
}
