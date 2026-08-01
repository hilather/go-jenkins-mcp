package diagnostics

import (
	"context"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/adapter"
)

// checkAdapterFrameworkResidual is Wave 43 / INT-001 residual honesty:
// proves offline that the adapter framework denies-by-default (empty enable
// list loads nothing), that built-in factories exist, and that a noop enable
// path can Start/Health without panic — while documenting that production
// OTLP / Splunk / ELK / Jira SaaS clients are not implemented.
//
// Pure offline: no network, no credentials, no keyring. Uses adapter.Host
// with no Logger (silent) and a fixed clock for determinism.
//
// Status OK when default-deny and noop lifecycle hold; Details mark
// production_otlp / production_ext_logs_saas false (residual).
func checkAdapterFrameworkResidual() SelfCheckItem {
	const (
		name    = "adapter_framework_residual"
		control = "INT-001"
	)
	fail := func(msg string) SelfCheckItem {
		return SelfCheckItem{
			Name:    name,
			Status:  SelfCheckFail,
			Message: msg,
			Control: control,
		}
	}

	// --- Deny by default: empty Config loads nothing ---
	empty := adapter.NewRegistry(adapter.Config{})
	if err := empty.RegisterEnabled(); err != nil {
		return fail("empty adapter Config RegisterEnabled must succeed")
	}
	if empty.Len() != 0 {
		return fail("empty adapter Config must register zero adapters (deny by default)")
	}
	// Health of a non-registered id must be disabled (no panic).
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	hDisabled := empty.Health(ctx, adapter.IDNoop)
	if hDisabled.Status != adapter.HealthDisabled {
		return fail("unregistered adapter Health must be disabled")
	}

	// --- Built-in factories present (catalog closed set) ---
	cat := adapter.DefaultCatalog()
	if len(cat) == 0 {
		return fail("DefaultCatalog must not be empty")
	}
	for _, id := range adapter.BuiltinIDs {
		if id == "" {
			return fail("BuiltinIDs contains empty id")
		}
		if !adapter.IsBuiltin(id) {
			return fail("BuiltinIDs entry not reported as builtin")
		}
		if _, ok := cat[id]; !ok {
			return fail("DefaultCatalog missing builtin factory")
		}
	}
	// Required framework / residual stubs (secret-free ids only).
	for _, id := range []string{
		adapter.IDNoop,
		adapter.IDClock,
		adapter.IDOtelCorrelate,
		adapter.IDOtelExport,
		adapter.IDExtLogs,
		adapter.IDWorkItems,
	} {
		if _, ok := cat[id]; !ok {
			return fail("DefaultCatalog missing required builtin: " + id)
		}
	}

	// --- Optional enable noop: Start + Health without panic ---
	fixedNow := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	reg := adapter.NewRegistry(adapter.Config{
		EnabledIDs: []string{adapter.IDNoop},
		Host: adapter.Host{
			Now: func() time.Time { return fixedNow },
			// Logger intentionally nil — no I/O, no secrets.
		},
	})
	if err := reg.RegisterEnabled(); err != nil {
		return fail("noop RegisterEnabled failed")
	}
	if reg.Len() != 1 {
		return fail("noop enable must register exactly one adapter")
	}
	if err := reg.StartAll(ctx); err != nil {
		return fail("noop StartAll failed")
	}
	h := reg.Health(ctx, adapter.IDNoop)
	if h.Status != adapter.HealthHealthy {
		return fail("noop Health after Start must be healthy (no panic)")
	}
	// Stop is best-effort cleanup for process isolation in canary.
	_ = reg.StopAll(ctx)

	// Residual honesty: production SaaS backends not in-tree (bools only).
	// Do not claim OTLP protobuf, Splunk/ELK SaaS, or Jira SaaS clients exist.
	return SelfCheckItem{
		Name:    name,
		Status:  SelfCheckOK,
		Message: "adapter framework deny-by-default and builtins present; production OTLP/Splunk/ELK/Jira SaaS clients not implemented",
		Control: control,
		Details: map[string]any{
			"default_deny":               true,
			"empty_registry_len":         0,
			"builtins_present":           true,
			"noop_health_ok":             true,
			"production_otlp":            false, // residual: no OTLP protobuf collector client
			"production_ext_logs_saas":   false, // residual: no Splunk/ELK SaaS client
			"production_work_items_saas": false, // residual: no Jira/SaaS ticket client
			"residual_note":              "production_otlp_splunk_elk_jira_saas_not_implemented",
		},
	}
}
