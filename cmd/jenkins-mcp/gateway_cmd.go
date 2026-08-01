package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/diagnostics"
	"github.com/simonfxr/go-jenkins-mcp/internal/gateway"
	"github.com/simonfxr/go-jenkins-mcp/internal/gateway/qualify"
)

// runGateway dispatches gateway operator commands (GWY-003 lite + HOST-009 vault).
func runGateway(args []string) error {
	if len(args) < 1 {
		return apperr.New(apperr.CodeInvalidArgument,
			"gateway subcommand required: qualify | residual-status | consent-residual | consent-purge | consent-expire | vault | vault-put | vault-delete")
	}
	switch args[0] {
	case "qualify":
		return runGatewayQualify(args[1:])
	case "residual-status":
		return runGatewayResidualStatus(args[1:])
	case "consent-residual":
		return runGatewayConsentResidual(args[1:])
	case "consent-purge", "consent-expire":
		// OAUTH-010 residual: purge expired consent metadata (or --session-id / --all).
		return runGatewayConsentPurge(args[1:])
	case "vault":
		return runGatewayVault(args[1:])
	case "vault-put":
		// Legacy alias for `gateway vault put` (HOST-009).
		return runGatewayVaultPut(args[1:])
	case "vault-delete":
		// Legacy alias for `gateway vault delete` (HOST-009).
		return runGatewayVaultDelete(args[1:])
	default:
		return apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("unknown gateway subcommand %q (qualify|residual-status|consent-residual|consent-purge|consent-expire|vault|vault-put|vault-delete)", args[0]))
	}
}

// runGatewayQualify runs the offline security/performance qualification suite.
//
//	jenkins-mcp gateway qualify --offline
//
// Prints a JSON summary with no secrets. Exit 0 when all cases pass; 1 on failure.
func runGatewayQualify(args []string) error {
	fs := flag.NewFlagSet("gateway qualify", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	offline := fs.Bool("offline", false, "Run in-process mock suite (no live AgentCore/Entra network)")
	if err := fs.Parse(reorderFlagArgs(args, map[string]bool{
		"offline": true,
	})); err != nil {
		return apperr.New(apperr.CodeInvalidArgument, err.Error())
	}
	if !*offline {
		return apperr.New(apperr.CodeInvalidArgument,
			"gateway qualify requires --offline (live AgentCore pin is residual; see docs/gateway/qualification.md)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	sum := qualify.RunOffline(ctx)

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(sum); err != nil {
		return apperr.Wrap(apperr.CodeInternal, "failed to encode qualify summary", err)
	}
	if !sum.OK {
		// Non-zero exit via fatal in main; return typed error for consistency.
		return apperr.New(apperr.CodeInternal,
			fmt.Sprintf("gateway offline qualify failed: %d passed, %d failed", sum.Passed, sum.Failed))
	}
	return nil
}

// residualStatusHonestyNote is the unified operator residual honesty sentence
// (never tokens/subjects). Points operators at the live pin runbook.
const residualStatusHonestyNote = "unified gateway residual snapshot (env/static honesty only): offline Mode A/B/C foundations Done*; live Entra / jwt-auth-filter / AgentCore / multi-replica HA residual — never production GO from this CLI; see docs/gateway/live-pin-blockers.md"

// residualStatusDoc is the primary operator pointer for residual honesty.
const residualStatusDoc = "docs/gateway/live-pin-blockers.md"

// runGatewayResidualStatus prints one secret-free JSON snapshot combining mode
// matrix residual (A/B/C), multi-user / HA / multi-pod residual, progressive
// consent residual, subject-rate knobs, and principal_cache entry count.
// Env/static only — no Obtain, vault open, or browser. Never tokens or subjects.
//
//	jenkins-mcp gateway residual-status
func runGatewayResidualStatus(args []string) error {
	fs := flag.NewFlagSet("gateway residual-status", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return apperr.New(apperr.CodeInvalidArgument, err.Error())
	}
	out := buildGatewayResidualStatus(os.Getenv)
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		return apperr.Wrap(apperr.CodeInternal, "failed to encode residual-status", err)
	}
	return nil
}

// buildGatewayResidualStatus assembles the unified residual snapshot map.
// getenv nil → os.Getenv. Secret-free: never vault bytes, tokens, or subjects.
func buildGatewayResidualStatus(getenv func(string) string) map[string]any {
	if getenv == nil {
		getenv = os.Getenv
	}

	multiUser := gateway.MultiUserEnabled(getenv)
	rateEnabled, ratePerMinute, rateBurst := gateway.SubjectRateConfigFromEnviron(getenv)
	mp := diagnostics.MultiPodResidualFromEnviron(getenv)
	pc := gateway.NewProgressiveConsentResidual()

	modeA, modeB, modeC := false, false, false
	modeResidual := ""
	enabledIDs := []string{}
	primary := ""
	var modeMatrix map[string]any
	if mx, err := gateway.ModeMatrixFromEnviron(getenv); err == nil {
		primary = string(mx.Primary)
		modeResidual = mx.Residual
		for _, m := range mx.Enabled {
			enabledIDs = append(enabledIDs, string(m))
			switch m {
			case gateway.CredentialModeAPITokenVault:
				modeA = true
			case gateway.CredentialModeJWTRSBearer:
				modeB = true
			case gateway.CredentialModeAgentCore:
				modeC = true
			}
		}
		modeMatrix = map[string]any{
			"primary":  primary,
			"enabled":  enabledIDs,
			"residual": modeResidual,
		}
	} else {
		// Soft residual when matrix invalid: still surface primary intent without secrets.
		mode := string(gateway.CredentialModeFromEnviron(getenv))
		if !gateway.CredentialMode(mode).Valid() {
			mode = ""
		}
		primary = mode
		switch gateway.CredentialMode(mode) {
		case gateway.CredentialModeAPITokenVault:
			modeA = true
		case gateway.CredentialModeJWTRSBearer:
			modeB = true
		case gateway.CredentialModeAgentCore:
			modeC = true
		}
		if mode != "" {
			enabledIDs = []string{mode}
		}
		modeResidual = "mode matrix invalid or incomplete — fix JENKINS_MCP_GATEWAY_CREDENTIAL_MODE / ENABLED_MODES; live mode pins residual"
		modeMatrix = map[string]any{
			"primary":  primary,
			"enabled":  enabledIDs,
			"residual": modeResidual,
			"valid":    false,
		}
	}

	// Structured residual ids (REL lite honesty; never claim production GO).
	// Mode B residual id oauth009_offline is always advertised for operator
	// grepping; mode_b_enabled reflects env enablement only.
	residualIDs := []string{
		"multi_user_offline",
		"oauth009_offline",
		"oauth010_offline",
		"progressive_consent_offline",
		"host008_single_replica",
		"gateway_modes_live",
	}

	out := map[string]any{
		"mode_matrix":                     modeMatrix,
		"mode_matrix_residual":            modeResidual,
		"mode_a_enabled":                  modeA,
		"mode_b_enabled":                  modeB,
		"mode_c_enabled":                  modeC,
		"mode_a_live_obtain_qualified":    false,
		"mode_b_live_rs_qualified":        false,
		"mode_c_live_agentcore_qualified": false,
		// Mode B residual id (OAUTH-009) — offline foundation only.
		"residual_id":                  "oauth009_offline",
		"oauth009_offline":             true,
		"oauth009_offline_only":        true,
		"residual_ids":                 residualIDs,
		"multi_user_enabled":           multiUser,
		"gateway_ready":                false, // CLI residual: Ready only on serve /readyz
		"ha_multi_replica":             false, // HOST-008 Tier A single-replica default
		"session_affinity_recommended": multiUser,
		// HOST-008 multi-pod residual (diagnostics helper; always vault residual true).
		"multi_pod_vault_residual":      mp.MultiPodVaultResidual,
		"kubernetes_env_detected":       mp.KubernetesEnvDetected,
		"vault_path_emptydir_heuristic": mp.VaultEmptyDirHeuristic,
		"replicas_env_residual":         mp.ReplicasEnvResidual,
		// Progressive consent residual (OAUTH-010 / GWY-001).
		"progressive_consent": pc.StatusMap(),
		// HOST-006 subject rate knobs (admin health field names; process-local only).
		"rateEnabled":   rateEnabled,
		"ratePerMinute": ratePerMinute,
		"rateBurst":     rateBurst,
		// Process-local principal cache entry count only (never subjects/tokens).
		"principal_cache_entries": gateway.ProcessPrincipalCache().Len(),
		"residual_note":           residualStatusHonestyNote,
		"doc":                     residualStatusDoc,
	}
	if mp.Checklist != "" {
		out["multi_pod_residual_checklist"] = mp.Checklist
	}
	if modeC {
		out["progressive_consent_residual"] = pc.ResidualNote
		out["progressive_consent_surfaces"] = pc.Surfaces
	}
	return out
}

// runGatewayConsentResidual prints Mode C progressive consent residual honesty
// (OAUTH-010 / GWY-001). Secret-free JSON: browser 3LO not automated; metadata
// path Done*; process-local consent metadata store Done* (optional file under
// XDG data for crash recovery of metadata only); never tokens. Does not perform
// Obtain or open a browser. Prefer residual-status for the unified operator snapshot.
//
// When a consent metadata file is present (default XDG path or
// JENKINS_MCP_CONSENT_STORE_PATH), lists last consent session metadata via
// secret-free StatusMap entries (session_id, authorization_host, timestamps —
// never access/refresh tokens).
//
//	jenkins-mcp gateway consent-residual
func runGatewayConsentResidual(args []string) error {
	fs := flag.NewFlagSet("gateway consent-residual", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return apperr.New(apperr.CodeInvalidArgument, err.Error())
	}
	pc := gateway.NewProgressiveConsentResidual()
	// Optional Mode C enablement from env (honesty only; no secrets).
	modeC := false
	if mx, err := gateway.ModeMatrixFromEnviron(os.Getenv); err == nil {
		for _, m := range mx.Enabled {
			if m == gateway.CredentialModeAgentCore {
				modeC = true
				break
			}
		}
	} else if gateway.CredentialModeFromEnviron(os.Getenv) == gateway.CredentialModeAgentCore {
		modeC = true
	}
	out := map[string]any{
		"progressive_consent": pc.StatusMap(),
		"mode_c_enabled":      modeC,
		"doc":                 "docs/gateway/README.md § progressive consent residual",
	}
	if modeC {
		out["mode_matrix_residual"] = gateway.ModeMatrixResidualNote(
			gateway.CredentialModeAgentCore, []gateway.CredentialMode{gateway.CredentialModeAgentCore})
	}

	// List last consent metadata from process-local / file-backed store when
	// present (metadata only; secret-free StatusMap rows). Residual honesty:
	// not multi-replica shared store; browser 3LO not automated.
	store, storeErr := gateway.OpenConsentSessionStoreForCLI(os.Getenv)
	if storeErr != nil {
		out["consent_store_error"] = "consent metadata store unavailable (see logs; never embeds secrets)"
	} else if store != nil {
		out["consent_store"] = store.StatusMap()
		recs := store.List()
		rows := make([]map[string]any, 0, len(recs))
		for _, rec := range recs {
			rows = append(rows, rec.StatusMap())
		}
		out["consent_sessions"] = rows
		out["consent_sessions_count"] = len(rows)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		return apperr.Wrap(apperr.CodeInternal, "failed to encode consent residual", err)
	}
	return nil
}

// runGatewayConsentPurge expires/deletes process-local consent metadata
// (OAUTH-010 residual). Metadata only — never tokens (store has none).
//
// Default: purge TTL-expired sessions.
//
//	jenkins-mcp gateway consent-purge
//	jenkins-mcp gateway consent-purge --session-id SESS
//	jenkins-mcp gateway consent-purge --all
//	jenkins-mcp gateway consent-expire   # alias
//
// Path: --path or JENKINS_MCP_CONSENT_STORE_PATH or XDG default.
// Secret-free JSON summary: deleted_count, remaining_count, action, path residual.
func runGatewayConsentPurge(args []string) error {
	fs := flag.NewFlagSet("gateway consent-purge", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	all := fs.Bool("all", false, "Clear all consent metadata (requires explicit --all; not the default)")
	sessionID := fs.String("session-id", "", "Delete one consent session by id (metadata only)")
	pathFlag := fs.String("path", "", "Consent metadata file path (else JENKINS_MCP_CONSENT_STORE_PATH / XDG default)")
	if err := fs.Parse(reorderFlagArgs(args, map[string]bool{
		// --all is a bool flag (no value). session-id and path take values.
		"session-id": true,
		"path":       true,
	})); err != nil {
		return apperr.New(apperr.CodeInvalidArgument, err.Error())
	}
	sid := strings.TrimSpace(*sessionID)
	if *all && sid != "" {
		return apperr.New(apperr.CodeInvalidArgument,
			"consent-purge: --all and --session-id are mutually exclusive")
	}

	store, err := gateway.OpenConsentSessionStoreForPurge(strings.TrimSpace(*pathFlag), os.Getenv)
	if err != nil {
		return err
	}

	action := "purge_expired"
	deleted := 0
	switch {
	case *all:
		action = "clear_all"
		// Honest deleted_count includes expired + live entries present before clear.
		deleted = store.EntryCount()
		store.Clear()
	case sid != "":
		action = "delete_session"
		if store.DeleteSession(sid) {
			deleted = 1
		}
	default:
		action = "purge_expired"
		deleted = store.PurgeExpired()
	}

	remaining := len(store.List())
	// Path residual: basename only (never dump full path that may embed home).
	filePath := strings.TrimSpace(store.FilePath)
	fileBasename := ""
	if filePath != "" {
		if i := strings.LastIndexAny(filePath, `/\`); i >= 0 && i+1 < len(filePath) {
			fileBasename = filePath[i+1:]
		} else {
			fileBasename = filePath
		}
	}

	out := map[string]any{
		"action":                           action,
		"deleted_count":                    deleted,
		"remaining_count":                  remaining,
		"metadata_only":                    true,
		"stores_tokens":                    false,
		"process_local":                    true,
		"multi_replica_shared":             false,
		"browser_3lo_automated":            false,
		"durable_agentcore_vault_residual": true,
		"file_backed":                      filePath != "",
		"file_basename":                    fileBasename,
		"residual_note":                    "consent metadata purge only (OAUTH-010 residual); never tokens; not multi-replica HA; browser 3LO not automated",
		"doc":                              "docs/gateway/README.md § progressive consent residual",
	}
	// Defense: never echo session id value if it looks secret-shaped (CLI still accepts ids for delete).
	// Summary omits session_id entirely to keep residual-status style secret-free.

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		return apperr.Wrap(apperr.CodeInternal, "failed to encode consent-purge summary", err)
	}
	return nil
}
