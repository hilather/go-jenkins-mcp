// Package policy enforces MCP-side RBAC and the global read-only kill switch.
//
// Effective access is always the intersection (never union):
//
//	Jenkins allow AND global read-only AND MCP policy AND operation budgets
//
// MCP policy is deny-only: it can only restrict further. It never grants access
// Jenkins denied and never synthesizes credentials (ADR 0004 / architecture §7).
// There is no grant_jenkins / allow_tools elevation API.
//
//	POL-001: global read-only gate (readonly.go).
//	CFG-002: enterprise policy overlay loader (overlay.go).
//	MGR-001: signed policy bundles (bundle.go, ed25519.go, keys.go, lastgood.go).
//	POL-002: deny-only RBAC evaluator (rbac.go); job pattern glob-lite (jobpattern.go).
//	POL-003: subjects bound to verified principals (subject.go).
//	POL-004: multi-layer PEPs — CheckToolAccess, ReadOnlyMutationGuard,
//	         CheckStoreRead, Jenkins request classification (enforce.go);
//	         call-time job Target + deny_job_prefixes (tools middleware + Document).
//	POL-005: adversarial conformance tests (conformance_test.go).
//	Wave 24: mid-session overlay/bundle hot-reload (reload.go) — last-good on
//	         load failure; deny-tools / job prefixes live.
//	Wave 25: DynamicForce + LiveHardMax hot-apply force_read_only and only-lower
//	         max_result_bytes via Reloadable OnSuccess (ListTools residual remains).
//	Wave 26: deny_job_prefixes glob-lite — trailing /** and single-segment *
//	         (jobpattern.go); overly broad * /** rejected at Validate.
//	Wave 29: mid-path **/ (zero-or-more segments) in deny_job_prefixes
//	         (jobpattern.go); DP-bounded match; bare * /** still rejected.
//	Wave 30: limited brace expansion {a,b,c} in deny_job_prefixes
//	         (jobpattern.go); cartesian product bounded (≤8 alts/group, ≤32
//	         expanded).
//	Wave 31: character classes […] in deny_job_prefixes (jobpattern.go);
//	         [abc]/[a-z]/[0-9]/optional [^…]; match-time one-byte checks
//	         (not expanded); compose with braces (* expand braces first);
//	         fail closed on empty/unclosed/inverted-range classes.
//	         NormalizeJobFullName exported for Target binding + MatchDenyJobPattern.
//	Wave 32: bounded nested braces in deny_job_prefixes (jobpattern.go);
//	         matching-depth `}` + top-level commas; nest ≤4; same product
//	         budgets (≤8 alts/group, ≤32 expanded); fail closed on deeper
//	         nesting, empty/single alts, explosion.
//	Wave 35: non-job resource deny patterns — overlay deny_node_names /
//	         deny_view_names (same Validate/Match language as jobs);
//	         Target.NodeName / ViewName; Evaluate resource_pattern_deny;
//	         policyTargetFromArgs binds node_name / view_name / view.
//	Wave 36: deny_artifact_paths (Target.ArtifactPath; path/artifact_path bind);
//	         jenkins_get_node named-node tool (node_name call-time deny);
//	         jenkins_get_nodes list-row filter (listfilter.go + tools filter).
//	Wave 37: deny_branch_names (Target.BranchName; branch_name/branch bind);
//	         list_jobs privacy: deny_job_prefixes + deny_branch_names page filter;
//	         list_artifacts privacy: deny_artifact_paths page filter;
//	         serve --hard-max-bytes / JENKINS_MCP_HARD_MAX_BYTES bootstrap ceiling.
//	Wave 38: deny_branch_names also matches multi-segment JobName leaf (and full
//	         JobName) when BranchName is empty — tools that only pass job_name
//	         (e.g. jenkins_get_job on team/mb/main) fail closed. Single-segment
//	         JobName alone does not apply branch deny (root freestyle "main").
//	         jenkins_list_views + deny_view_names list-row filter;
//	         AbsoluteMaxHardMaxBytes (64 MiB) fail-closed on serve bootstrap.
//	Wave 39: BranchDenyCandidates — intermediate path segments and multi-segment
//	         suffixes of multi-segment JobName also match deny_branch_names
//	         (e.g. team/mb/release/1.2 matches release/* and exact release).
//	         Slashy BranchName (≥2 segments) matches leaf + path candidates too.
//	         Residual: page-level Total/page_token sizing for some list tools;
//	         list_jobs full collect+filter; compare artifact privacy.
//	Wave 40: list_artifacts hard-cap fetch when deny_artifact_paths live;
//	list_jobs collect page tokens fingerprint live deny patterns; incomplete Message.
package policy
