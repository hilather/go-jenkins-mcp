// Route matrix for TST-001 (machine-readable Jenkins API surface used by MCP).
//
// Source of truth is this Go file. Golden JSON under docs/tst/route-matrix.json
// is validated by route_matrix_test.go. Adding a CallJenkins path without a
// matching matrix entry fails the inventory test.
package jenkins

import (
	"encoding/json"
	"sort"
	"strings"
)

// RouteClass matches POL-004 / ClassifyJenkinsRequest classes used in the matrix.
type RouteClass string

const (
	RouteClassAuth     RouteClass = "auth"
	RouteClassRead     RouteClass = "read"
	RouteClassMutation RouteClass = "mutation"
)

// RouteMatrixVersion is the schema version of the exported JSON document.
const RouteMatrixVersion = 1

// RouteEntry is one Jenkins HTTP route pattern used (or classified) by the MCP.
type RouteEntry struct {
	// ID is a stable machine id (snake_case).
	ID string `json:"id"`
	// PathPattern is a documented path template (may include {job}, {n}, …).
	PathPattern string `json:"path_pattern"`
	// PathPrefixes are concrete prefixes/suffix markers used to match live paths
	// and to validate that code CallJenkins targets are covered.
	PathPrefixes []string `json:"path_prefixes"`
	// Methods are HTTP methods used for this route.
	Methods []string `json:"methods"`
	// Class is auth | read | mutation (policy classification).
	Class RouteClass `json:"class"`
	// Tools lists MCP tool names that call this route (may be empty for guard-only).
	Tools []string `json:"tools"`
	// AuthSchemeNotes describes expected Jenkins auth for the route.
	AuthSchemeNotes string `json:"auth_scheme_notes"`
	// FixtureCovered is true when internal/jenkins httptest fixtures exercise the route.
	FixtureCovered bool `json:"fixture_covered"`
	// FixtureNotes optional residual / fixture detail (no secrets).
	FixtureNotes string `json:"fixture_notes,omitempty"`
	// SourceFiles lists primary implementation files (relative to module root).
	SourceFiles []string `json:"source_files,omitempty"`
}

// FixtureCell describes one fixture inventory cell vs residual live matrix need.
type FixtureCell struct {
	// ID stable inventory id.
	ID string `json:"id"`
	// Description human-readable cell description.
	Description string `json:"description"`
	// Status: covered | partial | residual_live
	Status string `json:"status"`
	// Routes related route ids (optional).
	Routes []string `json:"routes,omitempty"`
	// Notes residual / how to cover later.
	Notes string `json:"notes,omitempty"`
}

// RouteMatrixDocument is the machine-readable TST-001 export.
type RouteMatrixDocument struct {
	Version          int           `json:"version"`
	Task             string        `json:"task"`
	Description      string        `json:"description"`
	AuthSchemes      []string      `json:"auth_schemes"`
	Routes           []RouteEntry  `json:"routes"`
	FixtureInventory []FixtureCell `json:"fixture_inventory"`
	Residuals        []string      `json:"residuals"`
}

// KnownRouteMatrix returns the closed set of Jenkins routes the MCP uses or
// classifies for RO/mutation enforcement (TST-001).
func KnownRouteMatrix() RouteMatrixDocument {
	return RouteMatrixDocument{
		Version: RouteMatrixVersion,
		Task:    "TST-001",
		Description: "Machine-readable Jenkins route matrix for go-jenkins-mcp. " +
			"Offline MVP: httptest fixtures cover most cells; disposable live Jenkins smoke is opt-in (make live-jenkins-test).",
		AuthSchemes: []string{
			"api_token_basic", // username + personal API token (Authorization: Basic)
			"oidc_bearer",     // external-IdP access token for Jenkins audience (Authorization: Bearer)
			"agentcore_obo",   // managed gateway residual
			"csrf_crumb",      // Jenkins crumbIssuer for POST mutations
		},
		Routes: []RouteEntry{
			{
				ID:              "whoami",
				PathPattern:     "/whoAmI/api/json",
				PathPrefixes:    []string{"/whoami/api/json", "/whoAmI/api/json"},
				Methods:         []string{"GET"},
				Class:           RouteClassRead,
				Tools:           []string{"jenkins_doctor" /* login/status/doctor CLI */},
				AuthSchemeNotes: "Personal Basic API token or Jenkins-audience Bearer; identity bind (AUTH-004).",
				FixtureCovered:  true,
				FixtureNotes:    "bearer_auth_test + whoami path via CallJenkins; fixture may 404 root-only setups.",
				SourceFiles:     []string{"internal/jenkins/whoami.go"},
			},
			{
				ID:              "crumb_issuer",
				PathPattern:     "/crumbIssuer/api/json",
				PathPrefixes:    []string{"/crumbissuer/"},
				Methods:         []string{"GET"},
				Class:           RouteClassAuth,
				Tools:           []string{"jenkins_start_job", "jenkins_stop_build"},
				AuthSchemeNotes: "CSRF crumb; RequestAuth — allowed under global read-only.",
				FixtureCovered:  true,
				FixtureNotes:    "Fixture returns 404 (crumb optional); mutation tests still POST.",
				SourceFiles:     []string{"internal/jenkins/client.go", "internal/jenkins/requestclass.go"},
			},
			{
				ID:           "root_api_json",
				PathPattern:  "/api/json",
				PathPrefixes: []string{"/api/json"},
				Methods:      []string{"GET"},
				Class:        RouteClassRead,
				Tools: []string{
					"jenkins_get_jobs", "jenkins_list_jobs", "jenkins_list_views",
					"jenkins_get_capabilities",
					"jenkins_controller_health", "jenkins_explain_queue_delay",
				},
				AuthSchemeNotes: "Basic or Bearer; tree= query varies by caller.",
				FixtureCovered:  true,
				SourceFiles: []string{
					"internal/jenkins/jobs.go", "internal/jenkins/views.go",
					"internal/jenkins/capabilities.go", "internal/jenkins/mode.go",
				},
			},
			{
				ID:           "job_api_json",
				PathPattern:  "/job/{segments}/api/json",
				PathPrefixes: []string{"/job/"},
				Methods:      []string{"GET"},
				Class:        RouteClassRead,
				Tools: []string{
					"jenkins_get_job", "jenkins_list_builds", "jenkins_search_builds",
					"jenkins_resolve_baseline", "jenkins_list_jobs",
				},
				AuthSchemeNotes: "Folder/multibranch path segments via BuildJobPath; Basic or Bearer.",
				FixtureCovered:  true,
				FixtureNotes:    "Fixture handles /job/*/api/json including nested folders.",
				SourceFiles:     []string{"internal/jenkins/jobs.go", "internal/jenkins/builds.go", "internal/jenkins/client_jobs.go"},
			},
			{
				ID:           "build_api_json",
				PathPattern:  "/job/{segments}/{n}/api/json",
				PathPrefixes: []string{"/job/"},
				Methods:      []string{"GET"},
				Class:        RouteClassRead,
				Tools: []string{
					"jenkins_get_build", "jenkins_get_build_graph", "jenkins_get_build_changes",
					"jenkins_list_artifacts", "jenkins_compare_builds", "jenkins_diagnose_build",
					"jenkins_trace_failure_graph", "jenkins_find_regression_window",
					"jenkins_survey_recent_failures",
				},
				AuthSchemeNotes: "Build number path; tree= for SCM/artifacts/graph fields.",
				FixtureCovered:  true,
				SourceFiles:     []string{"internal/jenkins/client_builds.go", "internal/jenkins/graph.go", "internal/jenkins/scm.go", "internal/jenkins/artifacts.go"},
			},
			{
				ID:           "progressive_text",
				PathPattern:  "/job/{segments}/{n}/logText/progressiveText",
				PathPrefixes: []string{"/logtext/progressivetext", "logText/progressiveText"},
				Methods:      []string{"GET"},
				Class:        RouteClassRead,
				Tools: []string{
					"jenkins_get_build_logs", "jenkins_get_build_log_tail", "jenkins_search_logs",
					"jenkins_diagnose_build",
				},
				AuthSchemeNotes: "Bounded progressive read (LOG-001); start= query; Basic or Bearer.",
				FixtureCovered:  true,
				FixtureNotes:    "Large/growing log fixtures; early close residual on wire.",
				SourceFiles:     []string{"internal/jenkins/client_logs.go"},
			},
			{
				ID:              "build_with_parameters",
				PathPattern:     "/job/{segments}/buildWithParameters",
				PathPrefixes:    []string{"/buildwithparameters", "/build"},
				Methods:         []string{"POST"},
				Class:           RouteClassMutation,
				Tools:           []string{"jenkins_start_job"},
				AuthSchemeNotes: "Requires crumb when enabled; denied under global RO / MCP deny.",
				FixtureCovered:  true,
				SourceFiles:     []string{"internal/jenkins/client_mutations.go"},
			},
			{
				ID:              "stop_build",
				PathPattern:     "/job/{segments}/{n}/stop",
				PathPrefixes:    []string{"/stop"},
				Methods:         []string{"POST"},
				Class:           RouteClassMutation,
				Tools:           []string{"jenkins_stop_build"},
				AuthSchemeNotes: "Crumb + RO gate; classifier also matches /kill /term.",
				FixtureCovered:  true,
				SourceFiles:     []string{"internal/jenkins/client_mutations.go", "internal/jenkins/requestclass.go"},
			},
			{
				ID:           "queue_api",
				PathPattern:  "/queue/api/json",
				PathPrefixes: []string{"/queue/api/json"},
				Methods:      []string{"GET"},
				Class:        RouteClassRead,
				Tools: []string{
					"jenkins_get_running_builds", "jenkins_queue_pressure",
					"jenkins_explain_queue_delay", "jenkins_controller_health",
				},
				AuthSchemeNotes: "Basic or Bearer.",
				FixtureCovered:  true,
				SourceFiles:     []string{"internal/jenkins/client_builds.go", "internal/jenkins/queue_pressure.go", "internal/jenkins/queue_delay.go"},
			},
			{
				ID:           "queue_item",
				PathPattern:  "/queue/item/{id}/api/json",
				PathPrefixes: []string{"/queue/item/"},
				Methods:      []string{"GET"},
				Class:        RouteClassRead,
				Tools: []string{
					"jenkins_get_queue_item", "jenkins_wait_for_queue_item",
					"jenkins_explain_queue_delay", "jenkins_start_job",
				},
				AuthSchemeNotes: "Queue id path; start_job polls executable.",
				FixtureCovered:  true,
				SourceFiles:     []string{"internal/jenkins/client_mutations.go", "internal/jenkins/queue_delay.go", "internal/jenkins/wait.go"},
			},
			{
				ID:           "computer_api",
				PathPattern:  "/computer/api/json",
				PathPrefixes: []string{"/computer/api/json"},
				Methods:      []string{"GET"},
				Class:        RouteClassRead,
				Tools: []string{
					"jenkins_get_nodes", "jenkins_get_running_builds",
					"jenkins_controller_health", "jenkins_explain_queue_delay",
				},
				AuthSchemeNotes: "Basic or Bearer; may 403 under restricted Jenkins ACLs.",
				FixtureCovered:  true,
				SourceFiles:     []string{"internal/jenkins/nodes.go", "internal/jenkins/client_builds.go"},
			},
			{
				ID:           "computer_node",
				PathPattern:  "/computer/{name}/api/json",
				PathPrefixes: []string{"/computer/"},
				Methods:      []string{"GET"},
				Class:        RouteClassRead,
				Tools:        []string{"jenkins_get_node"},
				AuthSchemeNotes: "Single node; path name URL-encoded ((master) → %28master%29). " +
					"Basic or Bearer; 404 not_found; 403 authorization.",
				FixtureCovered: true,
				SourceFiles:    []string{"internal/jenkins/nodes.go"},
			},
			{
				ID:              "plugin_manager",
				PathPattern:     "/pluginManager/api/json",
				PathPrefixes:    []string{"/pluginmanager/api/json", "/pluginManager/api/json"},
				Methods:         []string{"GET"},
				Class:           RouteClassRead,
				Tools:           []string{"jenkins_get_capabilities", "jenkins_controller_health"},
				AuthSchemeNotes: "May require Overall/Administer on some controllers; fail soft when denied.",
				FixtureCovered:  true,
				SourceFiles:     []string{"internal/jenkins/capabilities.go"},
			},
			{
				ID:           "descriptor_by_name",
				PathPattern:  "/descriptorByName/{class}/api/json",
				PathPrefixes: []string{"/descriptorbyname/", "/descriptorByName/"},
				Methods:      []string{"GET"},
				Class:        RouteClassRead,
				Tools:        []string{"jenkins_get_capabilities"},
				AuthSchemeNotes: "Capability probes for WorkflowJob, JUnit, Pipeline REST RunExt; " +
					"Basic or Bearer.",
				FixtureCovered: true,
				SourceFiles:    []string{"internal/jenkins/capabilities.go"},
			},
			{
				ID:              "pipeline_wfapi_describe",
				PathPattern:     "/job/{segments}/{n}/wfapi/describe",
				PathPrefixes:    []string{"/wfapi/describe"},
				Methods:         []string{"GET"},
				Class:           RouteClassRead,
				Tools:           []string{"jenkins_get_pipeline_stages", "jenkins_get_stage_log"},
				AuthSchemeNotes: "Requires pipeline-stage-view / workflow-api REST; capability gated.",
				FixtureCovered:  true,
				SourceFiles:     []string{"internal/jenkins/pipeline.go", "internal/jenkins/stagelog.go"},
			},
			{
				ID:              "pipeline_node_wfapi",
				PathPattern:     "/job/{segments}/{n}/execution/node/{id}/wfapi/{describe|log}",
				PathPrefixes:    []string{"/execution/node/", "/wfapi/log"},
				Methods:         []string{"GET"},
				Class:           RouteClassRead,
				Tools:           []string{"jenkins_get_pipeline_stages", "jenkins_get_stage_log"},
				AuthSchemeNotes: "Stage/node log + nested describe; capability gated.",
				FixtureCovered:  true,
				SourceFiles:     []string{"internal/jenkins/pipeline.go", "internal/jenkins/stagelog.go"},
			},
			{
				ID:              "test_report",
				PathPattern:     "/job/{segments}/{n}/testReport/api/json",
				PathPrefixes:    []string{"/testreport/api/json", "/testReport/api/json"},
				Methods:         []string{"GET"},
				Class:           RouteClassRead,
				Tools:           []string{"jenkins_get_test_report", "jenkins_analyze_tests"},
				AuthSchemeNotes: "JUnit plugin testReport action; Basic or Bearer.",
				FixtureCovered:  true,
				SourceFiles:     []string{"internal/jenkins/testreport.go", "internal/jenkins/testanalyze.go"},
			},
			{
				ID:              "artifact_bytes",
				PathPattern:     "/job/{segments}/{n}/artifact/{path}",
				PathPrefixes:    []string{"/artifact/"},
				Methods:         []string{"GET"},
				Class:           RouteClassRead,
				Tools:           []string{"jenkins_get_artifact_text", "jenkins_inspect_artifact"},
				AuthSchemeNotes: "Bounded download; path sanitized against zip-slip (ART-001/002).",
				FixtureCovered:  true,
				SourceFiles:     []string{"internal/jenkins/artifacts.go", "internal/jenkins/artifact_inspect.go"},
			},
			// Classifier-only mutation paths (not currently issued by MCP client,
			// but must remain classified mutate for fail-closed RO guards).
			{
				ID:              "classifier_kill_term",
				PathPattern:     "/job/{segments}/{n}/kill|/term",
				PathPrefixes:    []string{"/kill", "/term"},
				Methods:         []string{"POST"},
				Class:           RouteClassMutation,
				Tools:           []string{},
				AuthSchemeNotes: "Not issued by MCP today; ClassifyJenkinsRequest → mutate under RO.",
				FixtureCovered:  false,
				FixtureNotes:    "Unit-tested in requestclass_test only.",
				SourceFiles:     []string{"internal/jenkins/requestclass.go"},
			},
			{
				ID:              "classifier_cancel_item",
				PathPattern:     "/queue/cancelItem|/…/cancel",
				PathPrefixes:    []string{"/cancelitem", "/cancel"},
				Methods:         []string{"POST"},
				Class:           RouteClassMutation,
				Tools:           []string{"jenkins_cancel_queue_item"},
				AuthSchemeNotes: "Crumb + RO gate; MUT-003 preview/confirm; no POST auto-retry.",
				FixtureCovered:  true,
				FixtureNotes:    "httptest cancelItem success/404/403/crumb; tool wrong-state tests.",
				SourceFiles:     []string{"internal/jenkins/client_mutations.go", "internal/jenkins/requestclass.go", "internal/tools/mutation_tools.go"},
			},
			{
				ID:              "classifier_do_delete",
				PathPattern:     "/…/doDelete",
				PathPrefixes:    []string{"/dodelete"},
				Methods:         []string{"POST"},
				Class:           RouteClassMutation,
				Tools:           []string{},
				AuthSchemeNotes: "Destructive path classified mutate (fail closed under RO).",
				FixtureCovered:  false,
				SourceFiles:     []string{"internal/jenkins/requestclass.go"},
			},
		},
		FixtureInventory: []FixtureCell{
			{
				ID:          "httptest_core_api",
				Description: "Root/job/build api/json, progressiveText, queue, computer, crumb, start/stop/cancel",
				Status:      "covered",
				Routes:      []string{"root_api_json", "job_api_json", "build_api_json", "progressive_text", "queue_api", "queue_item", "computer_api", "crumb_issuer", "build_with_parameters", "stop_build", "classifier_cancel_item"},
			},
			{
				ID:          "httptest_pipeline_test_artifact",
				Description: "wfapi describe/log, testReport, artifact bytes, descriptors, pluginManager",
				Status:      "covered",
				Routes:      []string{"pipeline_wfapi_describe", "pipeline_node_wfapi", "test_report", "artifact_bytes", "descriptor_by_name", "plugin_manager"},
			},
			{
				ID:          "auth_schemes_live",
				Description: "API-token Basic vs OIDC Bearer vs JWT filter on reverse-proxy",
				Status:      "partial",
				Routes:      []string{"whoami", "root_api_json"},
				Notes:       "Unit tests cover AuthProvider Basic/Bearer headers; live API-token Basic smoke via make live-jenkins-test; jwt-auth-filter / OIDC residual (OAUTH-009).",
			},
			{
				ID:          "rbac_inaccessible",
				Description: "Jenkins ACL 403/404 for inaccessible jobs vs MCP deny",
				Status:      "partial",
				Notes:       "Fixture can return 403 on computer/queue; full matrix of Jenkins roles needs disposable Jenkins.",
			},
			{
				ID:          "reverse_proxy_prefix",
				Description: "Controller behind /jenkins path prefix + origin pin",
				Status:      "partial",
				Notes:       "NormalizeBaseURL + origin pin unit tests; live reverse-proxy residual.",
			},
			{
				ID:          "multibranch_matrix_folders",
				Description: "Multibranch, matrix projects, deep folders, parameters, views",
				Status:      "residual_live",
				Notes:       "BuildJobPath supports nested /job/ segments; deterministic freestyle/pipeline fixtures only offline.",
			},
			{
				ID:          "oauth_required_no_fallback",
				Description: "OAuth-required Jenkins routes without Basic fallback (anti-fallback)",
				Status:      "residual_live",
				Notes:       "Acceptance: adding OAuth-required route without anti-fallback coverage must fail CI once live harness lands.",
			},
			{
				ID:          "disposable_jenkins_lts",
				Description: "Ephemeral LTS + plugins (Pipeline, folders, JUnit, artifacts) with destroy",
				Status:      "partial",
				Notes:       "MVP harness: testdata/jenkins-compose + internal/jenkins/live (-tags=live_jenkins) + make live-jenkins-test. Smoke: whoAmI, list jobs, get build, progressive tail, capabilities. Full plugin/proxy/OIDC matrix residual.",
			},
		},
		Residuals: []string{
			"Full CI matrix of Jenkins LTS majors + reverse-proxy remains residual (manual/dispatch only; default CI is offline).",
			"Live smoke uses ephemeral API tokens via compose init; broader RBAC/role-strategy matrix residual.",
			"Growing/truncated log fixtures exist offline; live multi-GiB progressive residual.",
			"JWT auth filter / OIDC UI realm qualification pins residual (docs/auth).",
			"Classifier-only mutation paths have unit coverage but no MCP tool issuance (by design under RO).",
		},
	}
}

// KnownAPIPathMarkers is the closed set of path markers that production CallJenkins
// call sites (and the request classifier) must keep in the route matrix.
// When adding a new Jenkins endpoint, add a matrix entry AND a marker here.
func KnownAPIPathMarkers() []string {
	return []string{
		"/whoAmI/api/json",
		"/crumbIssuer/api/json",
		"/api/json",
		"/job/",
		"/logText/progressiveText",
		"/buildWithParameters",
		"/stop",
		"/queue/api/json",
		"/queue/item/",
		"/computer/api/json",
		"/pluginManager/api/json",
		"/descriptorByName/",
		"/wfapi/describe",
		"/execution/node/",
		"/wfapi/log",
		"/testReport/api/json",
		"/artifact/",
		// Classifier-only:
		"/kill",
		"/term",
		"/cancelItem",
		"/doDelete",
	}
}

// RouteMatrixJSON returns canonical indented JSON for the matrix document.
func RouteMatrixJSON() ([]byte, error) {
	doc := KnownRouteMatrix()
	// Stable sort route ids (document already ordered; re-sort for safety).
	sort.SliceStable(doc.Routes, func(i, j int) bool {
		return doc.Routes[i].ID < doc.Routes[j].ID
	})
	return json.MarshalIndent(doc, "", "  ")
}

// MatrixCoversMarker reports whether any route's path pattern/prefixes cover marker.
func MatrixCoversMarker(doc RouteMatrixDocument, marker string) bool {
	m := strings.ToLower(strings.TrimSpace(marker))
	if m == "" {
		return false
	}
	for _, r := range doc.Routes {
		if strings.Contains(strings.ToLower(r.PathPattern), m) {
			return true
		}
		for _, p := range r.PathPrefixes {
			pl := strings.ToLower(p)
			if pl == m || strings.Contains(m, pl) || strings.Contains(pl, m) {
				return true
			}
		}
	}
	return false
}

// ClassifyPathPattern returns the matrix class for a method+path using the
// same classifier as production (POL-004), for matrix self-consistency checks.
func ClassifyPathPattern(method, path string) RouteClass {
	switch ClassifyJenkinsRequest(method, path) {
	case RequestAuth:
		return RouteClassAuth
	case RequestRead:
		return RouteClassRead
	case RequestMutate:
		return RouteClassMutation
	default:
		// Unclassified writes are treated as mutation-class for matrix purposes.
		if RequiresMutationPermission(ClassifyJenkinsRequest(method, path)) {
			return RouteClassMutation
		}
		return RouteClassRead
	}
}
