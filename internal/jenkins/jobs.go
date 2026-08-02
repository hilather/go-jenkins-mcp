package jenkins

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// Discovery bounds (JEN-002 / MCP budgets).
const (
	// DefaultListJobsLimit is the default page size for jenkins_list_jobs.
	DefaultListJobsLimit = 50
	// MaxListJobsLimit is the hard upper bound for list_jobs pagination limit.
	MaxListJobsLimit = 200
	// DefaultListJobsDepth is the default folder recursion depth.
	DefaultListJobsDepth = 4
	// MaxListJobsDepth is the hard upper bound for folder recursion depth.
	MaxListJobsDepth = 8
	// MaxListJobsScanNodes is the hard stop on folder walk node count.
	MaxListJobsScanNodes = 2000

	maxJobsAPIBodyBytes    = 4 << 20
	listJobsTreeLeafFields = "name,fullName,url,color,buildable,description,_class," +
		"lastBuild[number,url,building,result,timestamp,duration,estimatedDuration,displayName]"
)

// Job class / type labels used for multibranch and matrix awareness.
const (
	JobKindJob         = "job"
	JobKindFolder      = "folder"
	JobKindMultibranch = "multibranch"
	JobKindMatrix      = "matrix"
	JobKindOrgFolder   = "org_folder"
	JobKindBranch      = "branch"
	JobKindMatrixChild = "matrix_child"
	JobKindUnknown     = "unknown"
)

// ListJobsToolArgs are arguments for jenkins_list_jobs (JEN-002).
type ListJobsToolArgs struct {
	// FolderPrefix restricts results to jobs under this folder path (typed full name).
	FolderPrefix string `json:"folder_prefix,omitempty" jsonschema:"Optional folder path prefix filter (e.g. team/app); not an http URL"`
	// NameContains is a case-insensitive substring filter on the job name or full name.
	NameContains string `json:"name_contains,omitempty" jsonschema:"Optional case-insensitive substring filter on name/fullName"`
	// View is an optional Jenkins view name; when set, discovery starts from that view.
	View string `json:"view,omitempty" jsonschema:"Optional Jenkins view name (not a URL)"`
	// Offset is the zero-based pagination offset into the filtered list.
	// Prefer page_token for continuation; when both are set, page_token wins.
	Offset int `json:"offset,omitempty" jsonschema:"Zero-based offset into the filtered result (default 0; ignored when page_token is set)" default:"0"`
	// Limit is the maximum number of jobs to return (default 50, max 200).
	// When page_token is set, the token's limit is used (still hard-capped at 200).
	Limit int `json:"limit,omitempty" jsonschema:"Maximum jobs to return (default 50, max 200; page_token wins when set)" default:"50"`
	// PageToken is an opaque continuation from a prior next_page_token (MCP-001).
	// Invalid/tampered/non-matching-filter tokens fail closed as invalid_argument.
	PageToken string `json:"page_token,omitempty" jsonschema:"Opaque page token from a prior next_page_token; wins over offset/limit when set"`
	// MaxDepth is how many folder levels to recurse (default 4, max 8).
	MaxDepth int `json:"max_depth,omitempty" jsonschema:"Folder recursion depth (default 4, max 8)" default:"4"`
	// IncludeFolders when true includes folder/org/multibranch container nodes in results.
	IncludeFolders bool `json:"include_folders,omitempty" jsonschema:"When true, include folder/multibranch/org container nodes"`
}

// JobSummary is a lightweight discovery entry with typed full names (no nested graphs).
type JobSummary struct {
	// FullName is the Jenkins full name path (folders separated by /).
	FullName string `json:"fullName"`
	// Name is the leaf job/folder name.
	Name string `json:"name"`
	// Kind is a stable classification: job, folder, multibranch, matrix, org_folder, branch, matrix_child.
	Kind string `json:"kind"`
	// Class is the raw Jenkins _class when available.
	Class string `json:"class,omitempty"`
	// Color is Jenkins status color (blue, red, …).
	Color string `json:"color,omitempty"`
	// Buildable reports whether the job can be built.
	Buildable bool `json:"buildable"`
	// Disabled is true when color indicates disabled or buildable is false for non-folders.
	Disabled bool `json:"disabled,omitempty"`
	// Description is a short job description (may be empty).
	Description string `json:"description,omitempty"`
	// LastBuild is an optional last-build summary (selective fields only).
	LastBuild *Build `json:"lastBuild,omitempty"`
}

// ListJobsToolResponse is the paginated job discovery payload.
type ListJobsToolResponse struct {
	Jobs          []JobSummary `json:"jobs"`
	Offset        int          `json:"offset"`
	Limit         int          `json:"limit"`
	Total         int          `json:"total"` // filtered total before pagination
	Scanned       int          `json:"scanned"`
	Truncated     bool         `json:"truncated,omitempty"`       // hit scan/depth bounds
	Source        string       `json:"source,omitempty"`          // root | view | folder
	NextPageToken string       `json:"next_page_token,omitempty"` // opaque; pass as page_token for next page
	// Message is an optional non-secret operator hint (e.g. collection capped
	// under policy filter). Never includes credentials, tokens, or denied names.
	Message string `json:"message,omitempty"`
	// PolicyFiltered is true when MCP deny patterns omitted at least one row
	// from the collected list (Wave 37 deny_branch_names / deny_job_prefixes;
	// Wave 39 collect+filter+repaginate when patterns are live).
	PolicyFiltered bool `json:"policy_filtered,omitempty"`
	// PolicyOmittedCount is how many rows were dropped by MCP policy over the
	// full filtered collection (stable across pages; integer only; denied
	// names never listed).
	PolicyOmittedCount int `json:"policy_omitted_count,omitempty"`
}

// ListJobsFilterFingerprint returns the opaque page-token fingerprint for
// jenkins_list_jobs user filters (folder/name/view/depth/include_folders).
// Callers must pass already-normalized folderPrefix (trimmed slashes),
// lowercased nameContains, trimmed view, and clamped maxDepth.
//
// Optional extraParts are appended after the user-filter fields (Wave 40:
// live MCP deny_job_prefixes / deny_branch_names on the collect path so
// mid-session policy tighten invalidates old page tokens fail-closed).
// Never pass secrets into extraParts.
func ListJobsFilterFingerprint(folderPrefix, nameContains, view string, maxDepth int, includeFolders bool, extraParts ...string) [pageTokenFPBytes]byte {
	parts := []string{
		"list_jobs",
		folderPrefix,
		nameContains,
		view,
		FormatFilterInt(maxDepth),
		FormatFilterBool(includeFolders),
	}
	if len(extraParts) > 0 {
		parts = append(parts, extraParts...)
	}
	return FilterFingerprint(parts...)
}

// ListJobs discovers jobs with selective tree fields, local filters, and pagination (JEN-002).
// Nested folder full names (including spaces/special characters) are preserved as typed paths.
// Multibranch and matrix parents/children are classified via Jenkins _class.
func (opts *Client) ListJobs(ctx context.Context, args ListJobsToolArgs) (*ListJobsToolResponse, error) {
	if opts == nil {
		return nil, fmt.Errorf("jenkins client is nil")
	}
	maxDepth := args.MaxDepth
	if maxDepth <= 0 {
		maxDepth = DefaultListJobsDepth
	}
	if maxDepth > MaxListJobsDepth {
		maxDepth = MaxListJobsDepth
	}

	folderPrefix := strings.Trim(strings.TrimSpace(args.FolderPrefix), "/")
	nameContains := strings.ToLower(strings.TrimSpace(args.NameContains))
	view := strings.TrimSpace(args.View)

	// Filter fingerprint binds continuation tokens to the same filter set.
	filterFP := ListJobsFilterFingerprint(folderPrefix, nameContains, view, maxDepth, args.IncludeFolders)
	offset, limit, err := ResolveListPagination(
		args.PageToken, args.Offset, args.Limit,
		DefaultListJobsLimit, MaxListJobsLimit, filterFP,
	)
	if err != nil {
		return nil, err
	}

	// Starting API path: view, folder prefix, or root.
	var (
		startPath string
		source    string
		startFull string
	)
	switch {
	case view != "":
		if strings.Contains(view, "://") || strings.HasPrefix(view, "/") {
			return nil, apperr.New(apperr.CodeInvalidArgument, "view must be a view name, not a URL or path")
		}
		startPath = "/view/" + url.PathEscape(view)
		source = "view"
		startFull = ""
	case folderPrefix != "":
		if strings.Contains(folderPrefix, "://") {
			return nil, apperr.New(apperr.CodeInvalidArgument, "folder_prefix must be a typed path, not a URL")
		}
		startPath = BuildJobPath(folderPrefix)
		source = "folder"
		startFull = folderPrefix
	default:
		startPath = ""
		source = "root"
		startFull = ""
	}

	type rawJob struct {
		Name        string `json:"name"`
		FullName    string `json:"fullName"`
		URL         string `json:"url"`
		Color       string `json:"color"`
		Buildable   bool   `json:"buildable"`
		Description string `json:"description"`
		Class       string `json:"_class"`
		LastBuild   *Build `json:"lastBuild"`
		// Nested jobs present only when Jenkins returns depth/tree for containers.
		Jobs []rawJob `json:"jobs"`
	}

	// tree: one level of jobs with selective fields (no deep nested graph by default).
	tree := "jobs[" + listJobsTreeLeafFields + "]"
	var (
		all       []JobSummary
		scanned   int
		truncated bool
	)

	// parentKind is the container kind of the path we are listing (empty at root).
	// Used so WorkflowJob children under multibranch are classified as kind=branch
	// (Wave 37 deny_branch_names list privacy).
	var walk func(ctx context.Context, apiBase, parentFull, parentKind string, depth int) error
	walk = func(ctx context.Context, apiBase, parentFull, parentKind string, depth int) error {
		if scanned >= MaxListJobsScanNodes {
			truncated = true
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		apiPath := apiBase + "/api/json?tree=" + url.QueryEscape(tree)
		// Root uses leading slash only.
		if apiBase == "" {
			apiPath = "/api/json?tree=" + url.QueryEscape(tree)
		}
		resp, err := opts.CallJenkins(ctx, opts.Client, http.MethodGet, apiPath, nil, nil)
		if err != nil {
			return fmt.Errorf("failed to list jobs: %w", err)
		}
		body, err := readLimited(resp.Body, maxJobsAPIBodyBytes)
		_ = resp.Body.Close()
		if err != nil {
			return fmt.Errorf("failed to read jobs response: %w", err)
		}
		if resp.StatusCode == http.StatusNotFound {
			return apperr.New(apperr.CodeNotFound, "jobs listing path not found")
		}
		if resp.StatusCode == http.StatusForbidden {
			return apperr.New(apperr.CodeAuthorization, "not authorized to list jobs")
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("jenkins api returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
		}

		var payload struct {
			Jobs []rawJob `json:"jobs"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			return fmt.Errorf("failed to decode jobs response: %w", err)
		}

		for _, j := range payload.Jobs {
			scanned++
			if scanned > MaxListJobsScanNodes {
				truncated = true
				return nil
			}
			full := resolveJobFullName(j.FullName, j.Name, parentFull)
			kind := classifyJobClass(j.Class, j.Name, full)
			// Multibranch children are WorkflowJob class but represent branches.
			if parentKind == JobKindMultibranch && (kind == JobKindJob || kind == JobKindUnknown) {
				kind = JobKindBranch
			}
			// Matrix axis configurations may already be matrix_child via class.
			if parentKind == JobKindMatrix && kind == JobKindJob {
				kind = JobKindMatrixChild
			}
			disabled := isDisabledColor(j.Color) || (!j.Buildable && !isContainerKind(kind))

			// Local filters.
			passName := nameContains == "" ||
				strings.Contains(strings.ToLower(j.Name), nameContains) ||
				strings.Contains(strings.ToLower(full), nameContains)
			passFolder := folderPrefix == "" || full == folderPrefix ||
				strings.HasPrefix(full, folderPrefix+"/")

			include := passName && passFolder
			if isContainerKind(kind) && !args.IncludeFolders {
				// Still recurse into containers; omit from result unless requested.
				include = false
			}

			if include {
				sum := JobSummary{
					FullName:    full,
					Name:        j.Name,
					Kind:        kind,
					Class:       j.Class,
					Color:       j.Color,
					Buildable:   j.Buildable,
					Disabled:    disabled,
					Description: j.Description,
					LastBuild:   j.LastBuild,
				}
				// Strip URL from last build for typed-path model surface (MCP-002).
				if sum.LastBuild != nil {
					lb := *sum.LastBuild
					lb.URL = ""
					sum.LastBuild = &lb
				}
				all = append(all, sum)
			}

			// Recurse into containers within depth.
			if isContainerKind(kind) && depth < maxDepth {
				childBase := BuildJobPath(full)
				if err := walk(ctx, childBase, full, kind, depth+1); err != nil {
					return err
				}
				if truncated {
					return nil
				}
			}
		}
		return nil
	}

	if err := walk(ctx, startPath, startFull, "", 0); err != nil {
		return nil, err
	}

	// Stable order: fullName ascending.
	sort.SliceStable(all, func(i, j int) bool {
		return all[i].FullName < all[j].FullName
	})

	total := len(all)
	if offset > total {
		offset = total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	page := all[offset:end]
	if page == nil {
		page = []JobSummary{}
	}

	return &ListJobsToolResponse{
		Jobs:          page,
		Offset:        offset,
		Limit:         limit,
		Total:         total,
		Scanned:       scanned,
		Truncated:     truncated,
		Source:        source,
		NextPageToken: NextPageTokenIfMore(offset, limit, len(page), total, filterFP),
	}, nil
}

func resolveJobFullName(apiFull, name, parentFull string) string {
	apiFull = strings.TrimSpace(apiFull)
	// Jenkins fullName may use " » " separators in older UI-oriented payloads.
	if apiFull != "" {
		apiFull = strings.ReplaceAll(apiFull, " » ", "/")
		apiFull = strings.ReplaceAll(apiFull, "»", "/")
		return strings.Trim(apiFull, "/")
	}
	name = strings.TrimSpace(name)
	if parentFull == "" {
		return name
	}
	if name == "" {
		return parentFull
	}
	return parentFull + "/" + name
}

func classifyJobClass(class, name, fullName string) string {
	c := strings.ToLower(class)
	switch {
	case strings.Contains(c, "workflowmultibranchproject"):
		return JobKindMultibranch
	case strings.Contains(c, "organizationfolder"):
		return JobKindOrgFolder
	case strings.Contains(c, "folder"):
		return JobKindFolder
	case strings.Contains(c, "matrixproject"):
		return JobKindMatrix
	case strings.Contains(c, "matrixconfiguration"):
		return JobKindMatrixChild
	case strings.Contains(c, "workflowjob") && strings.Count(fullName, "/") >= 1:
		// Branch jobs under multibranch often have WorkflowJob class.
		// Heuristic only when class alone is ambiguous; parent walk classifies multibranch.
		_ = name
		return JobKindJob
	case class == "":
		return JobKindUnknown
	default:
		return JobKindJob
	}
}

func isContainerKind(kind string) bool {
	switch kind {
	case JobKindFolder, JobKindMultibranch, JobKindOrgFolder, JobKindMatrix:
		return true
	default:
		return false
	}
}

func isDisabledColor(color string) bool {
	c := strings.ToLower(strings.TrimSpace(color))
	return strings.Contains(c, "disabled")
}
