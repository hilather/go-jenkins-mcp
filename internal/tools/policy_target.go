package tools

import (
	"path"
	"reflect"
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/policy"
)

// policyTargetFromArgs builds a policy.Target from typed MCP tool arguments
// (POL-004 lite + Wave 35/36/37 non-job resources). Populates JobName /
// BuildNumber when args expose job_name and build_number JSON fields (or
// JobName / BuildNumber field names). Populates NodeName from node_name /
// NodeName and ViewName from view_name / ViewName (or seed view / View when
// ViewName empty). Populates ArtifactPath from path / Path or artifact_path /
// ArtifactPath (Wave 36; e.g. jenkins_get_artifact_text). path never overwrites
// JobName. Populates BranchName from branch_name / BranchName (or seed branch /
// Branch when BranchName empty) (Wave 37).
//
// Seed tools that still use JSON "name" / field Name for the job full name
// (e.g. jenkins_get_job) are also bound: when JobName is still empty after
// scanning job_name, a string field with json:"name" or Go name Name fills it.
// Explicit job_name always wins over name when both are present.
//
// JobName / NodeName / ViewName / BranchName are normalized via
// policy.NormalizeJobFullName before return (Wave 30/35/37): empty segments and
// leading/trailing "/" are collapsed so Target matches MatchDenyJobPattern and
// stays stable for audit target hashing. Path traversal ("..") fails closed to
// an empty field.
//
// ArtifactPath uses a lighter normalize (Wave 36): trim, collapse "//", reject
// ".." and absolute-like ("/" prefix, "://") to empty (fail closed no-match
// rather than rewriting absolute into a relative deny target). Relative paths
// like reports/out.txt are preserved.
//
// Registration-time evaluation still uses an empty Target so resource-scoped
// denies do not hide tools from discovery. Call-time evaluation uses this
// target so deny_job_prefixes / deny_node_names / deny_view_names /
// deny_artifact_paths / deny_branch_names fail closed before the handler runs.
//
// Non-struct args, missing fields, and empty resource names yield a zero Target
// (tool-name and subject rules still apply).
func policyTargetFromArgs(args any) policy.Target {
	if args == nil {
		return policy.Target{}
	}
	v := reflect.ValueOf(args)
	for v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return policy.Target{}
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return policy.Target{}
	}
	t := v.Type()
	var out policy.Target
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.PkgPath != "" { // unexported
			continue
		}
		jsonName := jsonFieldName(f)
		fv := v.Field(i)
		switch {
		case jsonName == "job_name" || f.Name == "JobName":
			if fv.Kind() == reflect.String {
				// Prefer non-empty job_name over legacy name. Do not clear a
				// previously bound name with an empty job_name alias field.
				if s := strings.TrimSpace(fv.String()); s != "" {
					out.JobName = s
				}
			}
		case jsonName == "build_number" || f.Name == "BuildNumber":
			switch fv.Kind() {
			case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
				n := fv.Int()
				if n > 0 {
					out.BuildNumber = n
				}
			case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
				n := fv.Uint()
				if n > 0 && n <= uint64(^uint64(0)>>1) {
					out.BuildNumber = int64(n)
				}
			}
		case jsonName == "node_name" || f.Name == "NodeName":
			if fv.Kind() == reflect.String {
				if s := strings.TrimSpace(fv.String()); s != "" {
					out.NodeName = s
				}
			}
		case jsonName == "view_name" || f.Name == "ViewName":
			if fv.Kind() == reflect.String {
				if s := strings.TrimSpace(fv.String()); s != "" {
					out.ViewName = s
				}
			}
		case jsonName == "view" || f.Name == "View":
			// Seed jenkins_list_jobs uses json:"view". Only when ViewName still empty
			// so explicit view_name wins when both appear.
			if out.ViewName == "" && fv.Kind() == reflect.String {
				if s := strings.TrimSpace(fv.String()); s != "" {
					out.ViewName = s
				}
			}
		case jsonName == "artifact_path" || f.Name == "ArtifactPath":
			if fv.Kind() == reflect.String {
				if s := strings.TrimSpace(fv.String()); s != "" {
					out.ArtifactPath = s
				}
			}
		case jsonName == "path" || f.Name == "Path":
			// jenkins_get_artifact_text / jenkins_inspect_artifact use json:"path".
			// Only when ArtifactPath still empty so explicit artifact_path wins.
			// Never copies into JobName.
			if out.ArtifactPath == "" && fv.Kind() == reflect.String {
				if s := strings.TrimSpace(fv.String()); s != "" {
					out.ArtifactPath = s
				}
			}
		case jsonName == "branch_name" || f.Name == "BranchName":
			// Wave 37: multibranch/matrix branch resource.
			if fv.Kind() == reflect.String {
				if s := strings.TrimSpace(fv.String()); s != "" {
					out.BranchName = s
				}
			}
		case jsonName == "branch" || f.Name == "Branch":
			// Optional seed alias. Only when BranchName still empty so explicit
			// branch_name wins when both appear. Never copies into JobName.
			if out.BranchName == "" && fv.Kind() == reflect.String {
				if s := strings.TrimSpace(fv.String()); s != "" {
					out.BranchName = s
				}
			}
		case jsonName == "name" || f.Name == "Name":
			// Legacy seed field (jenkins_get_job). Only when JobName still empty
			// so non-empty job_name wins if both appear, and Name+json:"job_name"
			// is already handled by the job_name case above.
			if out.JobName == "" && fv.Kind() == reflect.String {
				if s := strings.TrimSpace(fv.String()); s != "" {
					out.JobName = s
				}
			}
		}
	}
	// Wave 30/35/37: normalize resource names for deny match + audit hash stability.
	if out.JobName != "" {
		if norm, ok := policy.NormalizeJobFullName(out.JobName); ok {
			out.JobName = norm
		} else {
			// Traversal / empty-after-collapse: fail closed to no job target.
			out.JobName = ""
		}
	}
	if out.NodeName != "" {
		if norm, ok := policy.NormalizeJobFullName(out.NodeName); ok {
			out.NodeName = norm
		} else {
			out.NodeName = ""
		}
	}
	if out.ViewName != "" {
		if norm, ok := policy.NormalizeJobFullName(out.ViewName); ok {
			out.ViewName = norm
		} else {
			out.ViewName = ""
		}
	}
	if out.BranchName != "" {
		if norm, ok := policy.NormalizeJobFullName(out.BranchName); ok {
			out.BranchName = norm
		} else {
			// Traversal / empty-after-collapse: fail closed to no branch target.
			out.BranchName = ""
		}
	}
	// Wave 36: artifact path — relative only; absolute-like / ".." → empty.
	if out.ArtifactPath != "" {
		out.ArtifactPath = normalizeArtifactPathForTarget(out.ArtifactPath)
	}
	return out
}

// normalizeArtifactPathForTarget aligns Target.ArtifactPath with
// jenkins.SanitizeArtifactPath / path.Clean so deny patterns cannot be bypassed
// via "." segments (e.g. exact/./creds.txt → exact/creds.txt). Rejects
// absolute-like and ".." by returning "" (no ArtifactPath target; client still
// rejects escapes). Does not rewrite absolute into relative.
func normalizeArtifactPathForTarget(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	// Absolute / URL-like → empty (no-match, not rewritten).
	if strings.HasPrefix(p, "/") || strings.Contains(p, "://") || strings.HasPrefix(p, "//") {
		return ""
	}
	// Normalize separators; re-check absolute after backslash conversion.
	p = strings.ReplaceAll(p, "\\", "/")
	if strings.HasPrefix(p, "/") {
		return ""
	}
	// Reject ".." segments before Clean (Clean would drop them).
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return ""
		}
	}
	// Collapse empty segments and "." the same way as path.Clean / Sanitize.
	raw := strings.Split(p, "/")
	segs := make([]string, 0, len(raw))
	for _, s := range raw {
		if s == "" || s == "." {
			continue
		}
		if s == ".." {
			return ""
		}
		segs = append(segs, s)
	}
	if len(segs) == 0 {
		return ""
	}
	cleaned := path.Clean(strings.Join(segs, "/"))
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") || strings.HasPrefix(cleaned, "/") {
		return ""
	}
	return cleaned
}

func jsonFieldName(f reflect.StructField) string {
	tag := f.Tag.Get("json")
	if tag == "" || tag == "-" {
		return tag
	}
	name, _, _ := strings.Cut(tag, ",")
	return name
}
