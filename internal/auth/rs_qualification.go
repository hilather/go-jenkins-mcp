package auth

import (
	"fmt"
	"strings"
)

// OAUTH-009 — jwt-auth-filter (or approved proxy) resource-server qualification
// contracts. Human source: docs/auth/jwt-auth-filter-qualification.md
//
// These named constants and evaluators encode fail-closed expectations so
// offline contract tests and operator probes cannot drift from the written
// qualification matrix. Live Jenkins lab evidence remains residual until
// TST-001 / operator sign-off fills version pins.

// FallthroughMustDeny is the production contract for OAuth-required deployments:
// when a client sends Authorization: Bearer and validation fails, Jenkins must
// deny the request. It must not silently fall through to Basic, API token,
// UI session cookie, or anonymous success.
const FallthroughMustDeny = true

// JWKS outage behavior labels (resource-server side).
const (
	// JWKSOutageFailClosed — deny verification when JWKS is unreachable/unusable.
	JWKSOutageFailClosed = "fail_closed"
	// JWKSOutageFailOpen — accept tokens without signature check (unacceptable).
	JWKSOutageFailOpen = "fail_open"
)

// RequiredJWKSOutageBehavior is the only acceptable production setting.
const RequiredJWKSOutageBehavior = JWKSOutageFailClosed

// Threat IDs for residual tracking (docs + doctor output).
const (
	ThreatInvalidBearerFallthrough = "invalid_bearer_fallthrough"
	ThreatIncompleteRouteCoverage  = "incomplete_route_coverage"
	ThreatJWKSOutage               = "jwks_outage"
	ThreatMultiIssuer              = "multi_issuer"
	ThreatAlgNone                  = "alg_none"
)

// RSRouteCategory groups MCP→Jenkins route surfaces that must be RS-protected.
type RSRouteCategory string

const (
	RSRouteIdentity    RSRouteCategory = "identity"
	RSRouteRESTAPI     RSRouteCategory = "rest_api"
	RSRouteProgressive RSRouteCategory = "progressive_log"
	RSRouteArtifact    RSRouteCategory = "artifact"
	RSRoutePipeline    RSRouteCategory = "pipeline_wfapi"
	RSRouteQueue       RSRouteCategory = "queue"
	RSRouteComputer    RSRouteCategory = "computer"
	RSRouteCrumb       RSRouteCategory = "crumb"
	RSRoutePlugin      RSRouteCategory = "plugin_manager"
)

// RequiredRSRoute is one Jenkins path shape the MCP uses that must be covered
// by bearer resource-server auth (not only /**/api/**).
type RequiredRSRoute struct {
	// ID is a stable probe / inventory key.
	ID string
	// PathPattern is a documentation-oriented pattern (Ant-style or concrete).
	PathPattern string
	// ExamplePath is a concrete path suitable for lab probes.
	ExamplePath string
	// Category groups related surfaces.
	Category RSRouteCategory
	// OutsideAPIGlob is true when the path is outside classic /**/api/** matching
	// (progressiveText, raw artifact, some wfapi) and is commonly missed.
	OutsideAPIGlob bool
	// Why explains MCP tool / client dependence.
	Why string
}

// RequiredMCPRoutes is the inventory of Jenkins routes the MCP may call that
// must fail closed under invalid/missing/wrong-audience bearer on OAuth-required
// controllers. Protecting only /mcp/** or only /**/api/** is insufficient.
var RequiredMCPRoutes = []RequiredRSRoute{
	{
		ID:          "whoami",
		PathPattern: "/whoAmI/api/json",
		ExamplePath: "/whoAmI/api/json",
		Category:    RSRouteIdentity,
		Why:         "AUTH-004 identity bind; doctor and login verify",
	},
	{
		ID:          "root_api",
		PathPattern: "/api/json",
		ExamplePath: "/api/json?tree=nodeName,mode",
		Category:    RSRouteRESTAPI,
		Why:         "controller health, job tree roots, capability probes",
	},
	{
		ID:          "job_api",
		PathPattern: "/**/job/*/api/json",
		ExamplePath: "/job/demo/api/json",
		Category:    RSRouteRESTAPI,
		Why:         "jenkins_get_job / builds / search",
	},
	{
		ID:          "build_api",
		PathPattern: "/**/job/*/<n>/api/json",
		ExamplePath: "/job/demo/1/api/json",
		Category:    RSRouteRESTAPI,
		Why:         "jenkins_get_build, SCM, test report metadata",
	},
	{
		ID:             "progressive_text",
		PathPattern:    "/**/logText/progressiveText",
		ExamplePath:    "/job/demo/1/logText/progressiveText?start=0",
		Category:       RSRouteProgressive,
		OutsideAPIGlob: true,
		Why:            "LOG-001 progressive logs — often outside /**/api/** matchers",
	},
	{
		ID:             "artifact_download",
		PathPattern:    "/**/artifact/**",
		ExamplePath:    "/job/demo/1/artifact/report.txt",
		Category:       RSRouteArtifact,
		OutsideAPIGlob: true,
		Why:            "ART-001/002 artifact download/inspect — not /api/json",
	},
	{
		ID:             "wfapi_describe",
		PathPattern:    "/**/wfapi/describe",
		ExamplePath:    "/job/demo/1/wfapi/describe",
		Category:       RSRoutePipeline,
		OutsideAPIGlob: true,
		Why:            "PIPE-001 pipeline stage graph",
	},
	{
		ID:             "wfapi_node_log",
		PathPattern:    "/**/execution/node/*/wfapi/log",
		ExamplePath:    "/job/demo/1/execution/node/12/wfapi/log",
		Category:       RSRoutePipeline,
		OutsideAPIGlob: true,
		Why:            "PIPE-002 stage log text",
	},
	{
		ID:          "queue_api",
		PathPattern: "/queue/api/json",
		ExamplePath: "/queue/api/json",
		Category:    RSRouteQueue,
		Why:         "queue pressure / list",
	},
	{
		ID:          "queue_item",
		PathPattern: "/queue/item/*/api/json",
		ExamplePath: "/queue/item/42/api/json",
		Category:    RSRouteQueue,
		Why:         "jenkins_get_queue_item / wait",
	},
	{
		ID:          "computer_api",
		PathPattern: "/computer/api/json",
		ExamplePath: "/computer/api/json",
		Category:    RSRouteComputer,
		Why:         "node executors / health",
	},
	{
		ID:          "crumb_issuer",
		PathPattern: "/crumbIssuer/api/json",
		ExamplePath: "/crumbIssuer/api/json",
		Category:    RSRouteCrumb,
		Why:         "mutation CSRF crumb when mutations enabled",
	},
	{
		ID:          "plugin_manager",
		PathPattern: "/pluginManager/api/json",
		ExamplePath: "/pluginManager/api/json?depth=1",
		Category:    RSRoutePlugin,
		Why:         "capability discovery; operator RS plugin presence",
	},
}

// RequiredOutsideAPIGlobRoutes returns routes commonly missed by /**/api/** only.
func RequiredOutsideAPIGlobRoutes() []RequiredRSRoute {
	var out []RequiredRSRoute
	for _, r := range RequiredMCPRoutes {
		if r.OutsideAPIGlob {
			out = append(out, r)
		}
	}
	return out
}

// RSThreatStatus is the residual checklist state for a known RS threat.
type RSThreatStatus string

const (
	// RSThreatContractTested — offline contract / simulated fixture covers the threat.
	RSThreatContractTested RSThreatStatus = "contract_tested"
	// RSThreatResidualLab — still needs live Jenkins + plugin version evidence.
	RSThreatResidualLab RSThreatStatus = "residual_live_lab"
	// RSThreatMitigated — production-approved (requires lab sign-off; not claimed offline).
	RSThreatMitigated RSThreatStatus = "mitigated"
)

// RSThreat is one qualification residual row.
type RSThreat struct {
	ID          string
	Summary     string
	Status      RSThreatStatus
	Mitigation  string
	OperatorTip string
}

// DefaultRSThreatChecklist is the OAUTH-009 residual checklist (status reflects
// what this repo can prove offline; live lab remains residual).
func DefaultRSThreatChecklist() []RSThreat {
	return []RSThreat{
		{
			ID:          ThreatInvalidBearerFallthrough,
			Summary:     "Invalid/malformed/expired/wrong-aud bearer falls through to Basic, session cookie, or anonymous",
			Status:      RSThreatContractTested,
			Mitigation:  "jwt-auth-filter (or proxy) must deny when Authorization Bearer is present and invalid; no alternate authenticator success",
			OperatorTip: "Probe with Authorization: Bearer invalid and optional JSESSIONID; expect HTTP 401/403 on all RequiredMCPRoutes",
		},
		{
			ID:          ThreatIncompleteRouteCoverage,
			Summary:     "Protected path matcher covers only /**/api/** or /mcp/** and misses progressiveText/artifacts/wfapi",
			Status:      RSThreatContractTested,
			Mitigation:  "Expand path includes to RequiredMCPRoutes (especially OutsideAPIGlob=true)",
			OperatorTip: "Run oauth probe-rs online; fail any 200 on outside-api-glob examples with invalid bearer",
		},
		{
			ID:          ThreatJWKSOutage,
			Summary:     "JWKS fetch/cache outage fails open or caches forever without revalidation",
			Status:      RSThreatContractTested, // MCP ValidateAccessToken + EvaluateJWKSOutage*; Jenkins RS cache TTL still live residual
			Mitigation:  "Fail closed on JWKS unreachable for new tokens; bounded cache with rotation-aware refresh",
			OperatorTip: "Block JWKS URL; valid-looking tokens must not authenticate; document cache TTL (live RS residual)",
		},
		{
			ID:          ThreatMultiIssuer,
			Summary:     "Multi-issuer / multi-tenant JWKS selects wrong key or accepts foreign iss",
			Status:      RSThreatContractTested,
			Mitigation:  "Exact iss match + kid selection; never accept signature alone without iss/aud",
			OperatorTip: "Mint token for issuer B signed by issuer A keys; must deny",
		},
		{
			ID:          ThreatAlgNone,
			Summary:     "alg=none or empty algorithm accepted",
			Status:      RSThreatContractTested,
			Mitigation:  "Reject alg=none and non-allowlisted algorithms (RS256/ES256 MVP)",
			OperatorTip: "Send compact JWT with alg=none; must 401 at RS and fail MCP ValidateAccessToken",
		},
	}
}

// RSProbeReport is the offline/online resource-server qualification summary
// printed by doctor and oauth probe-rs.
type RSProbeReport struct {
	// AuthMethod is the profile auth method (api_token, oidc_bearer, …).
	AuthMethod string
	// PluginRole is PluginRoleBearerResourceServer for jwt-auth-filter.
	PluginRole PluginRole
	// PathLevel is CapLevelConditional for jwt_auth_filter.
	PathLevel string
	// FallthroughMustDeny echoes the contract constant.
	FallthroughMustDeny bool
	// JWKSOutageBehavior is the required behavior label.
	JWKSOutageBehavior string
	// JWKSOutageAcceptable is true when JWKSOutageBehavior is fail_closed.
	JWKSOutageAcceptable bool
	// RequiredRouteCount is len(RequiredMCPRoutes).
	RequiredRouteCount int
	// OutsideAPIGlobCount is how many routes sit outside /**/api/**.
	OutsideAPIGlobCount int
	// InventoryOK is true when ValidateRequiredMCPRoutesInventory is empty.
	InventoryOK bool
	// InventoryIssueCount is len(inventory issues); non-zero is a code defect.
	InventoryIssueCount int
	// Threats is the residual checklist snapshot.
	Threats []RSThreat
	// ThreatsContractTested / ThreatsResidualLab count checklist rows by status.
	ThreatsContractTested int
	ThreatsResidualLab    int
	// Notes are operator-facing non-secret lines.
	Notes []string
	// Warnings are elevated notes (e.g. oic-auth only).
	Warnings []string
	// Residuals call out live-lab gaps.
	Residuals []string
	// OfflineAutomated lists contracts covered without live Jenkins.
	OfflineAutomated []string
	// OnlineBearerWhoAmIOK is set when an online probe succeeded with bearer.
	OnlineBearerWhoAmIOK *bool
	// OnlineFallthroughOK is set when online invalid-bearer probes denied.
	OnlineFallthroughOK *bool
}

// OfflineRSQualificationSummary is a compact secret-free snapshot for
// doctor / security self-check JSON (OAUTH-009 expand / Wave 33).
type OfflineRSQualificationSummary struct {
	FallthroughMustDeny      bool     `json:"fallthrough_must_deny"`
	JWKSOutageBehavior       string   `json:"jwks_outage_behavior"`
	JWKSOutageAcceptable     bool     `json:"jwks_outage_acceptable"`
	RequiredRouteCount       int      `json:"required_route_count"`
	OutsideAPIGlobCount      int      `json:"outside_api_glob_count"`
	InventoryOK              bool     `json:"inventory_ok"`
	ThreatsContractTested    int      `json:"threats_contract_tested"`
	ThreatsResidualLab       int      `json:"threats_residual_lab"`
	FallthroughFixtureCount  int      `json:"fallthrough_fixture_count"`
	ClassifierMatrixDoneStar bool     `json:"classifier_matrix_done_star"`
	LiveLabStillRequired     bool     `json:"live_lab_still_required"`
	OfflineAutomated         []string `json:"offline_automated"`
	LiveLabResiduals         []string `json:"live_lab_residuals"`
	Doc                      string   `json:"doc"`
}

// BuildOfflineRSQualificationSummary returns the operator residual summary
// without network or secrets (self-check / doctor JSON).
func BuildOfflineRSQualificationSummary(authMethod string) OfflineRSQualificationSummary {
	rep := BuildOfflineRSProbe(authMethod)
	fixtures := OfflineFallthroughFixtures()
	return OfflineRSQualificationSummary{
		FallthroughMustDeny:      rep.FallthroughMustDeny,
		JWKSOutageBehavior:       rep.JWKSOutageBehavior,
		JWKSOutageAcceptable:     rep.JWKSOutageAcceptable,
		RequiredRouteCount:       rep.RequiredRouteCount,
		OutsideAPIGlobCount:      rep.OutsideAPIGlobCount,
		InventoryOK:              rep.InventoryOK,
		ThreatsContractTested:    rep.ThreatsContractTested,
		ThreatsResidualLab:       rep.ThreatsResidualLab,
		FallthroughFixtureCount:  len(fixtures),
		ClassifierMatrixDoneStar: len(fixtures) > 0 && rep.FallthroughMustDeny,
		LiveLabStillRequired:     true, // production pin always residual offline
		OfflineAutomated:         append([]string(nil), rep.OfflineAutomated...),
		LiveLabResiduals:         append([]string(nil), rep.Residuals...),
		Doc:                      "docs/auth/jwt-auth-filter-qualification.md",
	}
}

// BuildOfflineRSProbe builds a report from profile auth method without network.
//
// oidc_bearer profiles get warnings that production needs qualified RS
// (jwt-auth-filter / proxy) and that only-oic-auth is not MCP 3LO.
// api_token profiles get a note that RS qualification is N/A for the pilot path
// but still relevant if the controller also accepts bearer.
func BuildOfflineRSProbe(authMethod string) RSProbeReport {
	method := strings.TrimSpace(authMethod)
	outside := RequiredOutsideAPIGlobRoutes()
	invIssues := ValidateRequiredMCPRoutesInventory()
	jwksEval := EvaluateJWKSOutageBehavior(RequiredJWKSOutageBehavior)
	threats := DefaultRSThreatChecklist()
	var contractN, residualN int
	for _, th := range threats {
		switch th.Status {
		case RSThreatContractTested:
			contractN++
		case RSThreatResidualLab:
			residualN++
		}
	}
	rep := RSProbeReport{
		AuthMethod:            method,
		PluginRole:            PluginRoleBearerResourceServer,
		PathLevel:             CapabilityMatrixPathLevel[PathJWTAuthFilter],
		FallthroughMustDeny:   FallthroughMustDeny,
		JWKSOutageBehavior:    RequiredJWKSOutageBehavior,
		JWKSOutageAcceptable:  jwksEval.Acceptable,
		RequiredRouteCount:    len(RequiredMCPRoutes),
		OutsideAPIGlobCount:   len(outside),
		InventoryOK:           len(invIssues) == 0,
		InventoryIssueCount:   len(invIssues),
		Threats:               threats,
		ThreatsContractTested: contractN,
		ThreatsResidualLab:    residualN,
	}
	rep.OfflineAutomated = []string{
		"FallthroughMustDeny + ClassifyFallthroughProbe (status/WWW-Authenticate/body class) Done*",
		"OfflineFallthroughFixtures matrix (empty body, HTML error/login, Bearer WWW-Authenticate, authn fail-closed)",
		"JWKS outage fail-closed (EvaluateJWKSOutage* + ValidateAccessToken nil/empty JWKS)",
		"RequiredMCPRoutes inventory (unique IDs, progressive_text OutsideAPIGlob)",
		"RFC 9728 protected resource metadata parser + edge validation (fixture-only; no live fetch)",
		"JWT iss/aud/alg multi-issuer contracts (ValidateAccessToken)",
		"Simulated RS invalid Bearer + session → 401",
	}
	rep.Notes = append(rep.Notes,
		"jwt-auth-filter is a bearer resource server only (not an authorization server)",
		fmt.Sprintf("contract FallthroughMustDeny=%v", FallthroughMustDeny),
		fmt.Sprintf("JWKS outage must be %s (acceptable=%v)", RequiredJWKSOutageBehavior, jwksEval.Acceptable),
		fmt.Sprintf("%d MCP routes require RS coverage (%d outside /**/api/**); inventory_ok=%v",
			len(RequiredMCPRoutes), len(outside), rep.InventoryOK),
		fmt.Sprintf("threats: %d contract_tested, %d residual_live_lab", contractN, residualN),
		"see docs/auth/jwt-auth-filter-qualification.md",
	)
	rep.Residuals = append(rep.Residuals,
		"live Jenkins LTS + jwt-auth-filter version pins (lab residual)",
		"operator-approved JCasC/proxy config and go/no-go sign-off",
		"Jenkins RS JWKS cache TTL / rotation under load (MCP client fail-closed is offline-tested)",
		"live invalid-bearer fallthrough on all RequiredMCPRoutes",
		"RFC 9728 metadata publication on controller (parser only offline)",
	)

	switch method {
	case string(MethodOIDC), "oidc_bearer":
		// MethodOIDC == "oidc"; profile authMethod uses "oidc_bearer".
		rep.Warnings = append(rep.Warnings,
			"oidc_bearer requires qualified Jenkins RS (jwt-auth-filter or approved proxy) with exact Jenkins audience",
			"browser UI realm alone (oic-auth) is not MCP API 3LO — use api_token fallback or bearer RS",
		)
	case string(MethodAPIToken):
		rep.Notes = append(rep.Notes,
			"profile uses api_token pilot path; RS lab still required before enabling oidc_bearer against this controller",
		)
	default:
		if method == "" {
			rep.Warnings = append(rep.Warnings, "profile authMethod empty; cannot classify RS readiness")
		} else {
			rep.Notes = append(rep.Notes, "authMethod "+method+": consult capability matrix")
		}
	}
	return rep
}

// WarnOnlyOICAuthWithoutRS is the fixed operator message when a deployment has
// only oic-auth (browser realm) and no bearer RS filter (OAUTH-008 / OAUTH-009).
const WarnOnlyOICAuthWithoutRS = "only oic-auth (browser security realm) detected or assumed — not MCP API 3LO; use api_token or install/qualify jwt-auth-filter (or approved proxy) for bearer"

// FormatRSProbeText renders a compact operator report (no secrets).
// When includeClassifierMatrix is desired, callers also print
// FormatFallthroughClassifierMatrix (probe-rs --offline does both).
func FormatRSProbeText(rep RSProbeReport) string {
	var b strings.Builder
	b.WriteString("jwt-auth-filter / resource-server qualification (OAUTH-009)\n")
	b.WriteString(fmt.Sprintf("  authMethod:            %s\n", nonEmpty(rep.AuthMethod, "(unset)")))
	b.WriteString(fmt.Sprintf("  rs_plugin_role:        %s\n", rep.PluginRole))
	b.WriteString(fmt.Sprintf("  path_level:            %s (%s)\n", PathJWTAuthFilter, rep.PathLevel))
	b.WriteString(fmt.Sprintf("  fallthrough_must_deny: %v\n", rep.FallthroughMustDeny))
	b.WriteString(fmt.Sprintf("  jwks_outage:           %s (acceptable=%v)\n", rep.JWKSOutageBehavior, rep.JWKSOutageAcceptable))
	b.WriteString(fmt.Sprintf("  required_routes:       %d (%d outside api glob; inventory_ok=%v)\n",
		rep.RequiredRouteCount, rep.OutsideAPIGlobCount, rep.InventoryOK))
	b.WriteString(fmt.Sprintf("  threats_summary:       contract_tested=%d residual_live_lab=%d\n",
		rep.ThreatsContractTested, rep.ThreatsResidualLab))
	b.WriteString(fmt.Sprintf("  classifier_fixtures:   %d (Done* offline; live lab still required for production pin)\n",
		len(OfflineFallthroughFixtures())))
	if rep.OnlineBearerWhoAmIOK != nil {
		b.WriteString(fmt.Sprintf("  online_bearer_whoami:  %v\n", *rep.OnlineBearerWhoAmIOK))
	}
	if rep.OnlineFallthroughOK != nil {
		b.WriteString(fmt.Sprintf("  online_fallthrough_ok: %v\n", *rep.OnlineFallthroughOK))
	}
	b.WriteString("  threats:\n")
	for _, t := range rep.Threats {
		b.WriteString(fmt.Sprintf("    - %s [%s] %s\n", t.ID, t.Status, t.Summary))
	}
	if len(rep.OfflineAutomated) > 0 {
		b.WriteString("  offline_automated:\n")
		for _, n := range rep.OfflineAutomated {
			b.WriteString("    - " + n + "\n")
		}
	}
	if len(rep.Notes) > 0 {
		b.WriteString("  notes:\n")
		for _, n := range rep.Notes {
			b.WriteString("    - " + n + "\n")
		}
	}
	if len(rep.Warnings) > 0 {
		b.WriteString("  warnings:\n")
		for _, w := range rep.Warnings {
			b.WriteString("    - " + w + "\n")
		}
	}
	if len(rep.Residuals) > 0 {
		b.WriteString("  residuals:\n")
		for _, r := range rep.Residuals {
			b.WriteString("    - " + r + "\n")
		}
	}
	return b.String()
}

func nonEmpty(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}
