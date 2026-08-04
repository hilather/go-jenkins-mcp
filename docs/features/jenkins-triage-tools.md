# Feature — Jenkins triage tools

**Support status:** Supported (read-only set) · Opt-in for mutations

## Setup

Default `serve` registers read-only `jenkins_*` tools subject to policy.

Representative RO tools (not exhaustive — see [tool-contracts.md](../tool-contracts.md)):

- `jenkins_list_jobs`, `jenkins_get_job`, `jenkins_list_builds`, `jenkins_get_build`
- `jenkins_get_build_logs`, `jenkins_get_console_log`, `jenkins_search_logs`
- `jenkins_get_test_report`, `jenkins_analyze_tests`
- `jenkins_diagnose_build`, `jenkins_compare_builds`, `jenkins_find_regression_window`
- `jenkins_list_artifacts`, `jenkins_get_artifact_text`, `jenkins_inspect_artifact`
- Queue / nodes / views / pipeline stage helpers

## Verification

```text
ListTools → jenkins_* present
Call jenkins_list_jobs or jenkins_get_job → secret-free JSON
```

## Security / limits / rollback

Policy denials and budgets apply. Disable via policy overlay or stop serve.
Mutations: [mutations.md](mutations.md).
