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

// runGateway dispatches gateway operator commands (GWY-003 lite + HOST-009/010 vaults).
func runGateway(args []string) error {
	if len(args) < 1 {
		return apperr.New(apperr.CodeInvalidArgument,
			"gateway subcommand required: qualify | residual-status | consent-residual | consent-purge | consent-expire | subject-invalidate | vault | jwt-vault | vault-put | vault-delete")
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
	case "subject-invalidate", "invalidate-subject":
		// GWY-002 / HOST-003 force re-auth residual lite.
		return runGatewaySubjectInvalidate(args[1:])
	case "vault":
		return runGatewayVault(args[1:])
	case "jwt-vault", "jwtvault":
		// HOST-010 Mode B Jenkins-audience access-token vault.
		return runGatewayJWTVault(args[1:])
	case "vault-put":
		// Legacy alias for `gateway vault put` (HOST-009).
		return runGatewayVaultPut(args[1:])
	case "vault-delete":
		// Legacy alias for `gateway vault delete` (HOST-009).
		return runGatewayVaultDelete(args[1:])
	default:
		return apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("unknown gateway subcommand %q (qualify|residual-status|consent-residual|consent-purge|consent-expire|subject-invalidate|vault|jwt-vault|vault-put|vault-delete)", args[0]))
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

// runGatewayResidualStatus prints one secret-free JSON snapshot combining mode
// matrix residual (A/B/C), multi-user / HA / multi-pod residual, progressive
// consent residual, subject-rate knobs, and principal_cache entry count.
// Env/static only — no Obtain, vault open, or browser. Never tokens or subjects.
// Shared assembly: diagnostics.BuildGatewayResidualStatus (admin BFF parity).
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

// buildGatewayResidualStatus is a thin CLI wrapper over the shared residual
// snapshot (diagnostics.BuildGatewayResidualStatus). Kept for gateway_cmd tests.
func buildGatewayResidualStatus(getenv func(string) string) map[string]any {
	return diagnostics.BuildGatewayResidualStatus(getenv)
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

// subjectInvalidateDoc points operators at force re-auth residual honesty.
const subjectInvalidateDoc = "docs/gateway/README.md § force re-auth residual lite"

// runGatewaySubjectInvalidate clears process-local multi-user caches for one
// subject so the next Obtain re-fetches (GWY-002 / HOST-003 force re-auth residual lite).
//
//	jenkins-mcp gateway subject-invalidate --subject-key tenant|sub|profile
//	jenkins-mcp gateway subject-invalidate --tenant T --subject-id S --profile P
//
// Alias: gateway invalidate-subject
//
// Clears principals for the subject key: ProcessPrincipalCache in THIS process,
// or FilePrincipalCache when JENKINS_MCP_GATEWAY_PRINCIPAL_CACHE_PATH is set
// (same-host flock lite shared with serve). When
// JENKINS_MCP_GATEWAY_TOKEN_CACHE_PATH is set, also deletes matching
// FileTokenCache entries. Serve process-local MemoryTokenCache is not reachable
// from this CLI unless path is shared — residual note says so.
// Never tokens; never live Entra revocation; multi-pod residual remains.
func runGatewaySubjectInvalidate(args []string) error {
	fs := flag.NewFlagSet("gateway subject-invalidate", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	subjectKeyFlag := fs.String("subject-key", "", "Subject key tenant|subject|profile")
	subjectFlag := fs.String("subject", "", "Alias of --subject-key (full key)")
	tenant := fs.String("tenant", "", "Tenant when composing subject key")
	subjectID := fs.String("subject-id", "", "Subject (user) id when composing subject key")
	profile := fs.String("profile", "", "Profile id when composing subject key")
	workload := fs.String("workload", "", "Optional workload for exact CacheKey fallback (usually unused with FileTokenCache subject purge)")
	if err := fs.Parse(reorderFlagArgs(args, map[string]bool{
		"subject-key": true,
		"subject":     true,
		"tenant":      true,
		"subject-id":  true,
		"profile":     true,
		"workload":    true,
	})); err != nil {
		return apperr.New(apperr.CodeInvalidArgument, err.Error())
	}

	// Prefer --subject-key; --subject is an alias for vault-style operators.
	explicit := strings.TrimSpace(*subjectKeyFlag)
	if explicit == "" {
		explicit = strings.TrimSpace(*subjectFlag)
	}
	sk, err := resolveVaultSubjectKey(explicit, *tenant, *subjectID, *profile)
	if err != nil {
		// Rephrase vault wording for this command.
		if explicit == "" && strings.TrimSpace(*subjectID) == "" {
			return apperr.New(apperr.CodeInvalidArgument,
				"gateway subject-invalidate requires --subject-key KEY or --subject-id (optionally --tenant/--profile)")
		}
		return err
	}
	// Force re-auth keys must be tenant|subject|profile (exactly three fields).
	if _, _, _, err := gateway.SplitSubjectKey(sk); err != nil {
		return err
	}

	// Principal cache: process-local ProcessPrincipalCache, or FilePrincipalCache
	// when PRINCIPAL_CACHE_PATH is set (same-host share with serve).
	var principals gateway.PrincipalStore
	principalPath := strings.TrimSpace(os.Getenv(gateway.EnvGatewayPrincipalCachePath))
	principalPathConfigured := principalPath != ""
	if principalPathConfigured {
		fpc, ferr := gateway.NewFilePrincipalCache(principalPath)
		if ferr != nil {
			return apperr.Wrap(apperr.CodeInvalidArgument, "gateway subject-invalidate principal cache path", ferr)
		}
		principals = fpc
	} else {
		principals = gateway.ProcessPrincipalCache()
	}

	// Optional same-host FileTokenCache when env path is set.
	var tokens gateway.TokenCache
	tokenPath := strings.TrimSpace(os.Getenv(gateway.EnvGatewayTokenCachePath))
	tokenPathConfigured := tokenPath != ""
	if tokenPathConfigured {
		ftc, ferr := gateway.NewFileTokenCache(tokenPath, 0)
		if ferr != nil {
			return apperr.Wrap(apperr.CodeInvalidArgument, "gateway subject-invalidate token cache path", ferr)
		}
		tokens = ftc
	}

	res, ierr := gateway.InvalidateSubjectKeyLocal(sk, *workload, principals, tokens)
	if ierr != nil {
		return ierr
	}

	out := res.StatusMap()
	out["doc"] = subjectInvalidateDoc
	out["token_cache_path_configured"] = tokenPathConfigured
	out["principal_cache_path_configured"] = principalPathConfigured
	// Never print path values; only whether env was set.
	if !tokenPathConfigured {
		out["token_cache_cli_note"] = "JENKINS_MCP_GATEWAY_TOKEN_CACHE_PATH unset — serve MemoryTokenCache not reachable from CLI"
	} else {
		out["token_cache_cli_note"] = "FileTokenCache subject-namespace purge attempted (same-host flock lite; multi-pod residual)"
	}
	if principalPathConfigured {
		out["principal_process_note"] = "FilePrincipalCache Delete attempted (same-host flock lite shared with serve when path matches; multi-pod residual)"
	} else {
		out["principal_process_note"] = "PrincipalCache clear is process-local to this CLI invocation; set JENKINS_MCP_GATEWAY_PRINCIPAL_CACHE_PATH to share with serve (HOST-008 lite)"
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		return apperr.Wrap(apperr.CodeInternal, "failed to encode subject-invalidate result", err)
	}
	return nil
}

// consentClearAllConfirmToken is the exact --confirm value required with --all
// (HOST-007 residual lite; parity with admin BFF confirm:"CLEAR_ALL" / cache EVICT).
const consentClearAllConfirmToken = "CLEAR_ALL"

// runGatewayConsentPurge expires/deletes process-local consent metadata
// (OAUTH-010 residual). Metadata only — never tokens (store has none).
//
// Default: purge TTL-expired sessions.
//
//	jenkins-mcp gateway consent-purge
//	jenkins-mcp gateway consent-purge --session-id SESS
//	jenkins-mcp gateway consent-purge --all --confirm=CLEAR_ALL
//	jenkins-mcp gateway consent-expire   # alias
//
// Path: --path or JENKINS_MCP_CONSENT_STORE_PATH or XDG default.
// Secret-free JSON summary: deleted_count, remaining_count, action, path residual.
// Destructive --all requires --confirm=CLEAR_ALL (exact); purge_expired / --session-id unchanged.
func runGatewayConsentPurge(args []string) error {
	fs := flag.NewFlagSet("gateway consent-purge", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	all := fs.Bool("all", false, "Clear all consent metadata (requires --confirm=CLEAR_ALL; not the default)")
	confirm := fs.String("confirm", "", `Required with --all; must be exactly CLEAR_ALL (parity with admin clear_all confirm)`)
	sessionID := fs.String("session-id", "", "Delete one consent session by id (metadata only)")
	pathFlag := fs.String("path", "", "Consent metadata file path (else JENKINS_MCP_CONSENT_STORE_PATH / XDG default)")
	if err := fs.Parse(reorderFlagArgs(args, map[string]bool{
		// --all is a bool flag (no value). session-id, path, and confirm take values.
		"session-id": true,
		"path":       true,
		"confirm":    true,
	})); err != nil {
		return apperr.New(apperr.CodeInvalidArgument, err.Error())
	}
	sid := strings.TrimSpace(*sessionID)
	if *all && sid != "" {
		return apperr.New(apperr.CodeInvalidArgument,
			"consent-purge: --all and --session-id are mutually exclusive")
	}
	// Destructive clear_all only: require exact confirm token (fail closed).
	// Default TTL purge and --session-id delete do not need --confirm.
	// Exact match (no trim) — same as admin body confirm:"CLEAR_ALL" / cache EVICT.
	if *all && *confirm != consentClearAllConfirmToken {
		return apperr.New(apperr.CodeInvalidArgument,
			`consent-purge: --all requires --confirm=CLEAR_ALL`)
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
		// Fail closed: do not report success when file-backed persist fails.
		if err := store.Clear(); err != nil {
			return err
		}
	case sid != "":
		action = "delete_session"
		ok, err := store.DeleteSession(sid)
		if err != nil {
			return err
		}
		if ok {
			deleted = 1
		}
	default:
		action = "purge_expired"
		n, err := store.PurgeExpired()
		if err != nil {
			return err
		}
		deleted = n
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
		// Honesty: file-backed consent store reloads under flock before every
		// mutate/write (OAUTH-010 same-host Done* lite) so CLI purge is not
		// resurrected by a concurrent serve Put of stale memory. Multi-pod /
		// multi-replica shared store still residual (HOST-008). Memory-only
		// serve (no FilePath) is a separate process and is not cleared by CLI.
		"residual_note": "consent metadata purge only (OAUTH-010 residual); never tokens; same-host file reload-before-persist Done* lite (CLI purge not resurrected by serve Put); not multi-replica HA; browser 3LO not automated; memory-only serve process not cleared by CLI",
		"doc":           "docs/gateway/README.md § progressive consent residual",
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
