package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/adapter"
	"github.com/simonfxr/go-jenkins-mcp/internal/app"
	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/audit"
	"github.com/simonfxr/go-jenkins-mcp/internal/auth"
	"github.com/simonfxr/go-jenkins-mcp/internal/config"
	"github.com/simonfxr/go-jenkins-mcp/internal/contracts"
	"github.com/simonfxr/go-jenkins-mcp/internal/diagnostics"
	"github.com/simonfxr/go-jenkins-mcp/internal/gateway"
	"github.com/simonfxr/go-jenkins-mcp/internal/jenkins"
	"github.com/simonfxr/go-jenkins-mcp/internal/keyring"
	"github.com/simonfxr/go-jenkins-mcp/internal/logmirror"
	"github.com/simonfxr/go-jenkins-mcp/internal/mcpserver"
	"github.com/simonfxr/go-jenkins-mcp/internal/mutation"
	"github.com/simonfxr/go-jenkins-mcp/internal/policy"
	"github.com/simonfxr/go-jenkins-mcp/internal/profile"
	"github.com/simonfxr/go-jenkins-mcp/internal/redact"
	"github.com/simonfxr/go-jenkins-mcp/internal/search"
	"github.com/simonfxr/go-jenkins-mcp/internal/store"
	"github.com/simonfxr/go-jenkins-mcp/internal/telemetry"
	"github.com/simonfxr/go-jenkins-mcp/internal/telemetry/fleet"
	"github.com/simonfxr/go-jenkins-mcp/internal/tools"
	"golang.org/x/term"
)

// Build metadata (FND-002).
var (
	version   = "dev"
	commit    = "unknown"
	buildTime = "unknown"
)

func main() {
	if len(os.Args) < 2 {
		printUsage(os.Stderr)
		os.Exit(2)
	}

	// Global version flags before subcommands (plain text for flag forms).
	if os.Args[1] == "-version" || os.Args[1] == "--version" {
		printVersion()
		return
	}
	if os.Args[1] == "-h" || os.Args[1] == "--help" || os.Args[1] == "help" {
		printUsage(os.Stdout)
		return
	}

	// Subcommand dispatch.
	switch os.Args[1] {
	case "version":
		if err := runVersion(os.Args[2:]); err != nil {
			fatal(err)
		}
	case "update-check":
		if err := runUpdateCheck(os.Args[2:]); err != nil {
			fatal(err)
		}
	case "release-evidence":
		if err := runReleaseEvidence(os.Args[2:]); err != nil {
			fatal(err)
		}
	case "oauth":
		if err := runOAuth(os.Args[2:]); err != nil {
			fatal(err)
		}
	case "profile":
		if err := runProfile(os.Args[2:]); err != nil {
			fatal(err)
		}
	case "login":
		if err := runLogin(os.Args[2:]); err != nil {
			fatal(err)
		}
	case "logout":
		if err := runLogout(os.Args[2:]); err != nil {
			fatal(err)
		}
	case "status":
		if err := runStatus(os.Args[2:]); err != nil {
			fatal(err)
		}
	case "doctor":
		if err := runDoctor(os.Args[2:]); err != nil {
			fatal(err)
		}
	case "support-bundle":
		if err := runSupportBundle(os.Args[2:]); err != nil {
			fatal(err)
		}
	case "cache":
		if err := runCache(os.Args[2:]); err != nil {
			fatal(err)
		}
	case "pilot-check":
		if err := runPilotCheck(os.Args[2:]); err != nil {
			fatal(err)
		}
	case "gateway":
		if err := runGateway(os.Args[2:]); err != nil {
			fatal(err)
		}
	case "policy":
		if err := runPolicy(os.Args[2:]); err != nil {
			fatal(err)
		}
	case "telemetry":
		if err := runTelemetry(os.Args[2:]); err != nil {
			fatal(err)
		}
	case "update":
		if err := runUpdate(os.Args[2:]); err != nil {
			fatal(err)
		}
	case "security":
		if err := runSecurity(os.Args[2:]); err != nil {
			fatal(err)
		}
	case "redact":
		if err := runRedact(os.Args[2:]); err != nil {
			fatal(err)
		}
	case "serve":
		if err := runServe(os.Args[2:]); err != nil {
			fatal(err)
		}
	case "admin":
		if err := runAdmin(os.Args[2:]); err != nil {
			fatal(err)
		}
	default:
		// Legacy: flags-only invocation defaults to serve (seed compatibility).
		if strings.HasPrefix(os.Args[1], "-") {
			if err := runServe(os.Args[1:]); err != nil {
				fatal(err)
			}
			return
		}
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		printUsage(os.Stderr)
		os.Exit(2)
	}
}

type multiString []string

func (m *multiString) String() string {
	if m == nil {
		return ""
	}
	return strings.Join(*m, ",")
}

func (m *multiString) Set(v string) error {
	*m = append(*m, v)
	return nil
}

func printVersion() {
	fmt.Printf("jenkins-mcp %s commit=%s built=%s\n", version, commit, buildTime)
}

func printUsage(w *os.File) {
	fmt.Fprintf(w, `jenkins-mcp — enterprise Jenkins MCP (stdio default)

Usage:
  jenkins-mcp version [--json]
  jenkins-mcp update-check [--channel stable] [--json]
  jenkins-mcp update verify-manifest --file PATH [--keys PATH]
  jenkins-mcp update download --channel stable [--outdir DIR] [--json]
  jenkins-mcp update verify-lkg [--json] [--file PATH]
  jenkins-mcp update show-lkg [--json]
  jenkins-mcp release-evidence [--offline] [--profile <id>] [--output PATH]
  jenkins-mcp profile add <id> --url <jenkins-url> [--display-name NAME]
  jenkins-mcp profile list
  jenkins-mcp profile show <id>
  jenkins-mcp profile remove <id>
  jenkins-mcp login --profile <id> [--user USER] [--method api-token|oidc] [--oidc]
  jenkins-mcp logout --profile <id>
  jenkins-mcp status --profile <id>
  jenkins-mcp doctor --profile <id> [--offline] [--bundle|--bundle-preview]
  jenkins-mcp support-bundle --profile <id> [--preview] [--offline]
  jenkins-mcp cache status --profile <id>
  jenkins-mcp cache verify --profile <id> [--full] [--sample N]
  jenkins-mcp cache repair --profile <id> [--index-only]
  jenkins-mcp cache key init --profile <id>
  jenkins-mcp cache key rotate --profile <id>
  jenkins-mcp cache key status --profile <id>
  jenkins-mcp cache pin generation --profile <id> --generation <id>
  jenkins-mcp cache unpin generation --profile <id> --generation <id>
  jenkins-mcp cache pin pack --profile <id> --pack <id>
  jenkins-mcp cache unpin pack --profile <id> --pack <id>
  jenkins-mcp cache pins --profile <id> [--json]
  jenkins-mcp cache eviction-plan --profile <id> [--json] [--target-bytes N]
  jenkins-mcp cache evict --profile <id> [--json] [--target-bytes N] [--confirm|--yes]
  jenkins-mcp cache eviction-apply --profile <id> [--json] [--target-bytes N] [--confirm|--yes]
  jenkins-mcp cache quota --profile <id> [--json]
  jenkins-mcp oauth validate-profile --profile <id> [--offline]
  jenkins-mcp oauth probe-rs --profile <id> [--offline] --profile <id> [--offline]
  jenkins-mcp telemetry status [--json]
  jenkins-mcp telemetry show [--json]
  jenkins-mcp security self-check [--json] [--profile <id>]
  jenkins-mcp redact validate-patterns --file PATH [--json]
  jenkins-mcp pilot-check --profile <id> [--offline] [--sample N]
  jenkins-mcp gateway qualify --offline
  jenkins-mcp gateway vault put|set (--subject KEY | --tenant T --subject-id S [--profile P]) --user U [--token-env VAR] [--vault-path PATH]
  jenkins-mcp gateway vault delete|revoke (--subject KEY | --tenant T --subject-id S [--profile P]) [--vault-path PATH]
  jenkins-mcp gateway vault list [--vault-path PATH]
  jenkins-mcp gateway vault status|exists (--subject KEY | --tenant T --subject-id S [--profile P]) [--vault-path PATH]
  jenkins-mcp policy verify --file PATH [--keys PATH] [--json]
  jenkins-mcp policy show-effective --profile <id> [--json]
  jenkins-mcp policy sign --file OVERLAY.json --key KEY.pem --key-id ID --out BUNDLE.json  # dev-only
  jenkins-mcp policy sign --file OVERLAY.json --key a.pem --key-id a --key b.pem --key-id b --out BUNDLE.json  # multi-sig dev
  jenkins-mcp policy sign --file OVERLAY.json --keys-dir DIR --out BUNDLE.json  # multi-sig dev
  jenkins-mcp policy sign-multi  # alias of multi-key policy sign
  jenkins-mcp serve --profile <id> [--stdio] [--http ADDR] [--read-only] [--gateway]
  jenkins-mcp serve --profile <id> [--http ADDR] [--http-allow-non-local]
  jenkins-mcp serve --profile <id> [--http ADDR] [--http-token-env=VAR | --http-token-file=PATH]
  jenkins-mcp serve --profile <id> [--http ADDR] [--http-require-token]
  jenkins-mcp serve --profile <id> [--http ADDR] [--http-max-body-bytes N]
  jenkins-mcp serve --profile <id> [--enable-adapter=ID]... [--adapter-allowlist PATH]
  jenkins-mcp serve --profile <id> [--ca-bundle PATH] [--proxy URL]
  jenkins-mcp serve --profile <id> [--identity-reverify-ttl=30s]
  jenkins-mcp serve --profile <id> [--hard-max-bytes N]
  jenkins-mcp serve --profile <id> [--target-bytes N]
  jenkins-mcp serve --profile <id> [--list-jobs-collect-max-pages N]
  jenkins-mcp serve --profile <id> [--nodes-collect-max-pages N] [--views-collect-max-pages N]
  jenkins-mcp serve --profile <id> [--artifacts-hard-cap N]
  jenkins-mcp serve --profile <id> [--artifacts-list-body-bytes N]
  jenkins-mcp serve --profile <id> [--max-json-body-bytes N]
  jenkins-mcp serve --profile <id> [--max-retries N]
  jenkins-mcp serve --profile <id> [--circuit-failure-threshold N]
  jenkins-mcp serve --profile <id> [--circuit-open-duration DURATION]
  jenkins-mcp serve --profile <id> [--max-concurrent N]
  jenkins-mcp serve --profile <id> [--initial-backoff DURATION] [--max-backoff DURATION]
  jenkins-mcp serve --profile <id> [--allow-mutations] [--mutation-confirm-cooldown DURATION]
  jenkins-mcp serve --profile <id> [--mutation-max-previews-per-minute N]
  jenkins-mcp serve --profile <id> [--mutation-token-ttl DURATION]
  jenkins-mcp serve --profile <id> [--log-level debug|info|warn|error]
  jenkins-mcp admin serve --addr 127.0.0.1:8787 [--profile ID]
  jenkins-mcp admin serve [--admin-token-env=VAR | --admin-token-file=PATH]
  jenkins-mcp admin serve [--admin-role viewer|operator|policy_admin]
  jenkins-mcp admin serve [--assets-dir PATH] [--require-token] [--admin-allow-non-local]
  jenkins-mcp serve --url URL --auth user:token   # deprecated bootstrap (KD-003)

Read-only is the pilot default (POL-001). Cursor should pass --read-only or
JENKINS_MCP_READ_ONLY=true. Use --allow-mutations only for tests (blocked by stronger RO).
Mutation confirm cooldown (MUT-001): --mutation-confirm-cooldown / JENKINS_MCP_MUTATION_CONFIRM_COOLDOWN
(default 5s; min 1s; absolute max 5m; empty/0/"0s" → default; cannot disable via 0).
Mutation Preview rate (MUT-001): --mutation-max-previews-per-minute / JENKINS_MCP_MUTATION_MAX_PREVIEWS_PER_MINUTE
(default 30; absolute max 300; empty/0 → default; not unlimited on operator path).
Mutation token TTL (MUT-001): --mutation-token-ttl / JENKINS_MCP_MUTATION_TOKEN_TTL
(default 2m; min 10s; absolute max 15m; empty/0/"0s" → default; cannot disable via 0).

HTTP mode (--http) is optional and not the pilot default (ADR 0002). Bind is
loopback-only unless --http-allow-non-local (tests / residual advanced use).
Shared secret is optional on loopback by default (local pilot residual) and is a
transport gate only — not multi-user identity (HOST-001 / KD-008). Fail closed
with --http-require-token, JENKINS_MCP_HTTP_REQUIRE_TOKEN=1, or
JENKINS_MCP_HTTP_DENY_ANONYMOUS=1 (alias; same RequireToken path). Non-local
bind always requires a token, --http-allowed-origin, --http-allowed-host, and a
per-request subject (RequireSubject). Gateway mode and --http-require-subject /
JENKINS_MCP_HTTP_REQUIRE_SUBJECT reject non-health requests without subject.
Lab-only subject header X-Jenkins-MCP-Lab-Subject when JENKINS_MCP_LAB_IDENTITY=1
(fail closed otherwise; not default). Production JWT subject path (HOST-001):
JENKINS_MCP_HTTP_JWKS_URL + JENKINS_MCP_HTTP_JWT_ISSUER +
JENKINS_MCP_HTTP_JWT_AUDIENCE (secret-free); optional JENKINS_MCP_HTTP_JWT_REQUIRED=1
implies require-subject. Shared transport secret is never treated as subject.
Request body cap defaults to
4 MiB; raise with --http-max-body-bytes / JENKINS_MCP_HTTP_MAX_BODY_BYTES
(absolute fail-closed 16 MiB). Residual:
mid-session subject rebind / JWKS rotation under load; prefer stdio for pilot
(ADR 0002).

TLS/proxy (NET-004): profile may set caBundlePath, proxyURL, noProxy, clientCertFile,
clientKeyFile (paths only — never private keys in profile JSON). CLI --ca-bundle /
--proxy override profile. Certificate verification is always on by default.
Diagnostic-only skip requires --diag-insecure-tls AND JENKINS_MCP_DIAG_INSECURE_TLS=1
(never a silent production or profile default).

Linux (Tier-1): credentials live in Secret Service; profiles under
$XDG_CONFIG_HOME/jenkins-mcp/profiles/. Windows is out of scope.

Environment (deprecated bootstrap only):
  JENKINS_MCP_AUTH=user:token

Login non-interactive (tests / automation only — never for production secrets in CI logs):
  JENKINS_MCP_LOGIN_USER / JENKINS_MCP_LOGIN_TOKEN

Enterprise: prefer profile + login (keyring). Legacy -auth / JENKINS_MCP_AUTH
emit a warning and are bootstrap-only (KD-003).
`)
}

func fatal(err error) {
	// Model-safe message; never print raw secrets.
	msg := apperr.ModelMessage(err)
	if msg == "" {
		msg = err.Error()
	}
	fmt.Fprintln(os.Stderr, "Error:", msg)
	os.Exit(1)
}

func profileStore() (*profile.Store, error) {
	paths, err := config.Resolve()
	if err != nil {
		return nil, err
	}
	return profile.NewStore(paths), nil
}

// testKeyring, when non-nil, is returned by keyringStore (tests only).
// Production paths leave this nil so Default() (Secret Service) is used.
// Guarded by testKeyringMu so parallel package tests cannot race the pointer.
var (
	testKeyringMu sync.RWMutex
	testKeyring   *keyring.Store
)

func keyringStore() *keyring.Store {
	// Production default: OS Secret Service. Tests inject Memory via testKeyring.
	testKeyringMu.RLock()
	kr := testKeyring
	testKeyringMu.RUnlock()
	if kr != nil {
		return kr
	}
	return keyring.Default()
}

// --- profile ---

func runProfile(args []string) error {
	if len(args) < 1 {
		return apperr.New(apperr.CodeInvalidArgument, "profile subcommand required: add|list|show|remove")
	}
	switch args[0] {
	case "add":
		return runProfileAdd(args[1:])
	case "list":
		return runProfileList(args[1:])
	case "show":
		return runProfileShow(args[1:])
	case "remove", "rm", "delete":
		return runProfileRemove(args[1:])
	default:
		return apperr.New(apperr.CodeInvalidArgument, "unknown profile subcommand (add|list|show|remove)")
	}
}

func runProfileAdd(args []string) error {
	fs := flag.NewFlagSet("profile add", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	urlFlag := fs.String("url", "", "Jenkins base URL (required)")
	display := fs.String("display-name", "", "Optional display name")
	authMethod := fs.String("auth-method", string(profile.AuthMethodAPIToken), "Auth method (api_token)")
	caBundle := fs.String("ca-bundle", "", "Optional absolute path to PEM CA bundle (NET-004)")
	proxyURL := fs.String("proxy", "", "Optional proxy URL or direct/none (NET-004)")
	clientCert := fs.String("client-cert", "", "Optional absolute path to mTLS client cert PEM")
	clientKey := fs.String("client-key", "", "Optional absolute path to mTLS client key PEM")
	// Allow `profile add corp --url URL` (flags after positionals).
	if err := fs.Parse(reorderFlagArgs(args, map[string]bool{
		"url": true, "display-name": true, "auth-method": true,
		"ca-bundle": true, "proxy": true, "client-cert": true, "client-key": true,
	})); err != nil {
		return apperr.New(apperr.CodeInvalidArgument, err.Error())
	}
	if fs.NArg() != 1 {
		return apperr.New(apperr.CodeInvalidArgument, "usage: profile add <id> --url URL")
	}
	id := fs.Arg(0)
	store, err := profileStore()
	if err != nil {
		return err
	}
	if store.Exists(id) {
		return apperr.New(apperr.CodeInvalidArgument, fmt.Sprintf("profile %q already exists", id))
	}
	p := &profile.Profile{
		ConfigVersion:  profile.CurrentConfigVersion,
		ID:             contracts.ProfileID(id),
		DisplayName:    *display,
		JenkinsURL:     *urlFlag,
		AuthMethod:     profile.AuthMethod(*authMethod),
		CABundlePath:   strings.TrimSpace(*caBundle),
		ProxyURL:       strings.TrimSpace(*proxyURL),
		ClientCertFile: strings.TrimSpace(*clientCert),
		ClientKeyFile:  strings.TrimSpace(*clientKey),
	}
	if err := store.Save(p); err != nil {
		return err
	}
	fmt.Printf("profile %q saved (%s)\n", p.ID, p.JenkinsURL)
	return nil
}

func runProfileList(args []string) error {
	fs := flag.NewFlagSet("profile list", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return apperr.New(apperr.CodeInvalidArgument, err.Error())
	}
	store, err := profileStore()
	if err != nil {
		return err
	}
	ids, err := store.List()
	if err != nil {
		return err
	}
	if len(ids) == 0 {
		fmt.Println("(no profiles)")
		return nil
	}
	for _, id := range ids {
		p, err := store.Load(id)
		if err != nil {
			fmt.Printf("%s\t(error loading)\n", id)
			continue
		}
		label := p.DisplayName
		if label == "" {
			label = string(p.ID)
		}
		fmt.Printf("%s\t%s\t%s\t%s\n", p.ID, label, p.JenkinsURL, p.AuthMethod)
	}
	return nil
}

func runProfileShow(args []string) error {
	fs := flag.NewFlagSet("profile show", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return apperr.New(apperr.CodeInvalidArgument, err.Error())
	}
	if fs.NArg() != 1 {
		return apperr.New(apperr.CodeInvalidArgument, "usage: profile show <id>")
	}
	store, err := profileStore()
	if err != nil {
		return err
	}
	p, err := store.Load(fs.Arg(0))
	if err != nil {
		return err
	}
	// Secret-free structured text (paths only for TLS/proxy; never keys or tokens).
	fmt.Printf("id:            %s\n", p.ID)
	fmt.Printf("displayName:   %s\n", p.DisplayName)
	fmt.Printf("configVersion: %d\n", p.ConfigVersion)
	fmt.Printf("jenkinsURL:    %s\n", p.JenkinsURL)
	fmt.Printf("authMethod:    %s\n", p.AuthMethod)
	fmt.Printf("username:      %s\n", p.Username)
	fmt.Printf("readOnly:      %v\n", p.EffectiveReadOnly())
	fmt.Printf("dataDir:       %s\n", p.DataDir)
	fmt.Printf("caBundlePath:  %s\n", p.CABundlePath)
	fmt.Printf("proxyURL:      %s\n", p.ProxyURL)
	if len(p.NoProxy) > 0 {
		fmt.Printf("noProxy:       %s\n", strings.Join(p.NoProxy, ","))
	} else {
		fmt.Printf("noProxy:       \n")
	}
	fmt.Printf("clientCert:    %s\n", p.ClientCertFile)
	fmt.Printf("clientKey:     %s\n", p.ClientKeyFile)
	return nil
}

func runProfileRemove(args []string) error {
	fs := flag.NewFlagSet("profile remove", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return apperr.New(apperr.CodeInvalidArgument, err.Error())
	}
	if fs.NArg() != 1 {
		return apperr.New(apperr.CodeInvalidArgument, "usage: profile remove <id>")
	}
	id := fs.Arg(0)
	store, err := profileStore()
	if err != nil {
		return err
	}
	// Best-effort logout before delete when username is known.
	if p, err := store.Load(id); err == nil && p.Username != "" {
		prov, _ := auth.NewProvider(p.AuthMethod, keyringStore())
		if prov != nil {
			_ = prov.Logout(context.Background(), auth.ProfileFrom(p))
		}
	}
	if err := store.Delete(id); err != nil {
		return err
	}
	fmt.Printf("profile %q removed\n", id)
	return nil
}

// --- login / logout / status ---

func runLogin(args []string) error {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	profileFlag := fs.String("profile", "", "Profile id (required)")
	userFlag := fs.String("user", "", "Jenkins username (optional if set via env; api-token)")
	methodFlag := fs.String("method", "", "Auth method: api-token | oidc (default: profile authMethod)")
	oidcFlag := fs.Bool("oidc", false, "Use external-IdP Authorization Code + PKCE (OAUTH-002)")
	if err := fs.Parse(reorderFlagArgs(args, map[string]bool{
		"profile": true, "user": true, "method": true, "oidc": true,
	})); err != nil {
		return apperr.New(apperr.CodeInvalidArgument, err.Error())
	}
	if *profileFlag == "" {
		return apperr.New(apperr.CodeInvalidArgument, "--profile is required")
	}

	method := strings.ToLower(strings.TrimSpace(*methodFlag))
	useOIDC := *oidcFlag || method == "oidc" || method == "oidc_bearer"
	useAPIToken := method == "api-token" || method == "api_token"
	if useOIDC && useAPIToken {
		return apperr.New(apperr.CodeInvalidArgument, "specify only one of --oidc / --method oidc or --method api-token")
	}
	if method != "" && !useOIDC && !useAPIToken {
		return apperr.New(apperr.CodeInvalidArgument,
			"unsupported --method (use api-token or oidc)")
	}

	store, err := profileStore()
	if err != nil {
		return err
	}
	p, err := store.Load(*profileFlag)
	if err != nil {
		return err
	}

	if !useOIDC && !useAPIToken {
		// Auto from profile (oidc_bearer → browser PKCE; else api-token).
		if p.AuthMethod == profile.AuthMethodOIDC {
			useOIDC = true
		} else {
			useAPIToken = true
		}
	}
	if useOIDC {
		return runOIDCLogin(p)
	}
	return runAPITokenLogin(store, p, *userFlag)
}

// runOIDCLogin performs external-IdP Authorization Code + PKCE (OAUTH-002).
// Never prints tokens. Full JWT claim validation / Jenkins bearer whoAmI is residual.
func runOIDCLogin(p *profile.Profile) error {
	if p.AuthMethod != profile.AuthMethodOIDC {
		return apperr.New(apperr.CodeInvalidArgument,
			"profile authMethod must be oidc_bearer for OIDC login (or use --method api-token)")
	}
	if err := auth.ValidateOIDCProfileOffline(p); err != nil {
		return err
	}
	client, err := discoveryHTTPClient(p)
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Starting external IdP browser login (Authorization Code + PKCE)...")
	fmt.Fprintln(os.Stderr, "Complete corporate sign-in in the browser; waiting for loopback callback...")

	ctx := context.Background()
	epochStore, epochErr := sessionEpochStoreForProfile(p)
	if epochErr != nil {
		// Non-fatal for login if data dir cannot be created yet; tokens still store.
		// Cross-process invalidation requires a successful epoch bump when available.
		log.Printf("session epoch store unavailable at login: %v", epochErr)
	}
	result, err := auth.LoginOIDC(ctx, p, auth.LoginOptions{
		HTTPClient:  client,
		OpenBrowser: auth.OpenSystemBrowser,
		TokenStore:  auth.NewKeyringTokenStore(keyringStore()),
		Epoch:       epochStore,
		Timeout:     auth.DefaultOIDCLoginTimeout,
	})
	if err != nil {
		return err
	}
	// Never print access/refresh/id tokens. Non-secret status only.
	// JWT-shaped access tokens were validated offline (OAUTH-003) inside LoginOIDC.
	// Live Jenkins jwt-auth-filter / bearer principal binding is OAUTH-005/009 residual.
	fmt.Printf("oidc login complete for profile %q method=oidc issuer=%q has_refresh=%v\n",
		p.ID, result.Issuer, result.HasRefresh)
	if !result.Session.ExpiresAt.IsZero() {
		fmt.Printf("access_token_expires: %s\n", result.Session.ExpiresAt.UTC().Format(time.RFC3339))
	}
	fmt.Fprintln(os.Stderr, "Note: live Jenkins bearer RS (OAUTH-005) and jwt-auth-filter lab (OAUTH-009) remain residual.")
	return nil
}

func runAPITokenLogin(store *profile.Store, p *profile.Profile, userFlag string) error {
	if p.AuthMethod == profile.AuthMethodOIDC {
		return apperr.New(apperr.CodeInvalidArgument,
			"profile authMethod is oidc_bearer; use --oidc (or omit --method) for browser login")
	}

	user := strings.TrimSpace(userFlag)
	if user == "" {
		user = strings.TrimSpace(os.Getenv("JENKINS_MCP_LOGIN_USER"))
	}
	if user == "" {
		user = p.Username
	}
	if user == "" {
		fmt.Fprint(os.Stderr, "Jenkins username: ")
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil {
			return apperr.Wrap(apperr.CodeInvalidArgument, "failed to read username", err)
		}
		user = strings.TrimSpace(line)
	}
	if user == "" {
		return apperr.New(apperr.CodeInvalidArgument, "username is required")
	}

	token := strings.TrimSpace(os.Getenv("JENKINS_MCP_LOGIN_TOKEN"))
	if token == "" {
		fmt.Fprint(os.Stderr, "Jenkins API token: ")
		tokBytes, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return apperr.New(apperr.CodeInvalidArgument,
				"failed to read token (set JENKINS_MCP_LOGIN_TOKEN for non-interactive tests only)")
		}
		token = strings.TrimSpace(string(tokBytes))
	}
	if token == "" {
		return apperr.New(apperr.CodeInvalidArgument, "api token is required")
	}

	// AUTH-004: verify against Jenkins before storing (fail closed; no retain on failure).
	// NET-004: use profile TLS/proxy settings so enterprise custom CA/mTLS works at login.
	pr := auth.Profile{
		ID:   p.ID,
		URL:  p.JenkinsURL,
		User: user,
	}
	ephemeral := auth.Session{
		ProfileID: p.ID,
		Method:    auth.MethodAPIToken,
		User:      user,
		Secret:    token,
	}
	tcfg := transportConfigFromProfile(p, "", "", false)
	hc, err := jenkins.NewHTTPClients(tcfg)
	if err != nil {
		return apperr.Wrap(apperr.CodeInvalidArgument, "TLS/proxy configuration", err)
	}
	principal, err := auth.VerifyIdentityHTTP(context.Background(), pr, ephemeral, hc.API)
	if err != nil {
		// Do not write keyring or profile credentials on failed verification.
		// Surface TLS chain/hostname guidance without suggesting permanent skip.
		if tlsMsg := jenkins.FormatTLSError(err); tlsMsg != "" && tlsMsg != err.Error() {
			return apperr.Wrap(apperr.CodeOf(err), tlsMsg, err)
		}
		return err
	}

	// Token only after verify; then non-secret profile fields (username + principal).
	prov := auth.NewAPITokenProvider(keyringStore())
	p.Username = user
	if err := prov.StoreAPIToken(auth.ProfileFrom(p), token); err != nil {
		return err
	}
	p.VerifiedPrincipalID = principal.ID
	p.VerifiedFullName = principal.FullName
	if err := store.Save(p); err != nil {
		// Keyring has the token; profile metadata missing is recoverable via status/re-login.
		return err
	}
	// Never print token. Status/identity only (KD-004).
	fmt.Print(formatAPITokenLoginStatus(string(p.ID), user, principal.ID))
	return nil
}

// formatAPITokenLoginStatus is the non-secret login success line.
// Parameters are profile id, username, and verified principal id only — never a token.
func formatAPITokenLoginStatus(profileID, user, principalID string) string {
	return fmt.Sprintf("login verified for profile %q user %q principal %q (keyring)\n",
		profileID, user, principalID)
}

func runLogout(args []string) error {
	fs := flag.NewFlagSet("logout", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	profileFlag := fs.String("profile", "", "Profile id (required)")
	if err := fs.Parse(args); err != nil {
		return apperr.New(apperr.CodeInvalidArgument, err.Error())
	}
	if *profileFlag == "" {
		return apperr.New(apperr.CodeInvalidArgument, "--profile is required")
	}
	store, err := profileStore()
	if err != nil {
		return err
	}
	p, err := store.Load(*profileFlag)
	if err != nil {
		return err
	}
	kr := keyringStore()
	prov, err := auth.NewProvider(p.AuthMethod, kr)
	if err != nil {
		return err
	}
	pr := auth.ProfileFrom(p)
	// OAUTH-007: OIDC best-effort IdP revocation when endpoint is known.
	if oidc, ok := prov.(*auth.OIDCProvider); ok {
		// Cross-process: bump session.epoch so running serve fail-closes immediately.
		if es, err := sessionEpochStoreForProfile(p); err == nil {
			oidc.Epoch = es
		}
		// Prefer discovery revocation_endpoint when profile has issuer (best-effort network).
		if pr.OIDCRevocationEndpoint == "" && p.OIDC != nil && strings.TrimSpace(p.OIDC.Issuer) != "" {
			if client, err := discoveryHTTPClient(p); err == nil {
				oidc.HTTP = client
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				if doc, err := auth.FetchDiscovery(ctx, client, p.OIDC.Issuer); err == nil {
					pr.OIDCRevocationEndpoint = doc.RevocationEndpoint
					if pr.OIDCTokenEndpoint == "" {
						pr.OIDCTokenEndpoint = doc.TokenEndpoint
					}
				}
				cancel()
			}
		}
		details, err := oidc.LogoutDetailed(context.Background(), pr)
		if err != nil {
			return err
		}
		// Clear non-secret identity fields from the profile document (session hygiene).
		p.Username = ""
		p.VerifiedPrincipalID = ""
		p.VerifiedFullName = ""
		_ = store.Save(p)
		fmt.Printf("logout complete for profile %q (local credentials cleared)\n", p.ID)
		if details.RevocationAttempted {
			if details.RevocationOK {
				fmt.Printf("idp_revocation:  ok (best-effort)\n")
			} else {
				// Local logout already succeeded; distinguish IdP failure clearly.
				msg := details.RevocationMessage
				if msg == "" {
					msg = "identity provider revocation failed"
				}
				fmt.Printf("idp_revocation:  failed (%s); local session is cleared\n", msg)
			}
		} else {
			fmt.Printf("idp_revocation:  skipped (no revocation_endpoint or no token material)\n")
		}
		return nil
	}
	if err := prov.Logout(context.Background(), pr); err != nil {
		return err
	}
	// Clear non-secret identity fields from the profile document (session hygiene).
	p.Username = ""
	p.VerifiedPrincipalID = ""
	p.VerifiedFullName = ""
	_ = store.Save(p)
	fmt.Printf("logout complete for profile %q\n", p.ID)
	return nil
}

func runStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	profileFlag := fs.String("profile", "", "Profile id (required)")
	if err := fs.Parse(args); err != nil {
		return apperr.New(apperr.CodeInvalidArgument, err.Error())
	}
	if *profileFlag == "" {
		return apperr.New(apperr.CodeInvalidArgument, "--profile is required")
	}
	store, err := profileStore()
	if err != nil {
		return err
	}
	p, err := store.Load(*profileFlag)
	if err != nil {
		return err
	}
	prov, err := auth.NewProvider(p.AuthMethod, keyringStore())
	if err != nil {
		return err
	}
	st, err := prov.Status(context.Background(), auth.ProfileFrom(p))
	if err != nil {
		return err
	}
	// Merge last-verified principal from the profile document (offline, non-secret).
	if st.PrincipalID == "" {
		st.PrincipalID = p.VerifiedPrincipalID
		st.PrincipalFullName = p.VerifiedFullName
	}
	printStatus(st)
	return nil
}

// printStatus emits sanitized status fields only (AUTH-003 / OAUTH-007): never a token.
func printStatus(st auth.Status) {
	fmt.Printf("profile:         %s\n", st.ProfileID)
	fmt.Printf("method:          %s\n", st.Method)
	fmt.Printf("authenticated:   %v\n", st.Authenticated)
	fmt.Printf("has_credential:  %v\n", st.HasCredential)
	// OAUTH-007: has_refresh is bool-only metadata (OIDC); always print for stable CLI shape.
	fmt.Printf("has_refresh:     %v\n", st.HasRefresh)
	fmt.Printf("username:        %s\n", st.User)
	if st.PrincipalID != "" {
		fmt.Printf("principal_id:    %s\n", st.PrincipalID)
	}
	if st.PrincipalFullName != "" {
		fmt.Printf("principal_name:  %s\n", st.PrincipalFullName)
	}
	if !st.ExpiresAt.IsZero() {
		fmt.Printf("expires_at:      %s\n", st.ExpiresAt.UTC().Format(time.RFC3339))
	}
	if st.ErrorCode != "" {
		fmt.Printf("errorCode:       %s\n", st.ErrorCode)
		fmt.Printf("error:           %s\n", st.ErrorMessageSafe)
	}
	if st.RecoveryHint != "" {
		fmt.Printf("recovery:        %s\n", st.RecoveryHint)
	}
}

// --- serve ---

func runServe(args []string) error {
	// KD-004 / Wave 22: scrub accidental tokens in standard-library log lines for
	// the serve process lifetime. Username and non-secret status remain visible.
	log.SetOutput(redact.NewWriter(os.Stderr))

	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	profileFlag := fs.String("profile", "", "Connection profile id (preferred)")
	jenkinsURL := fs.String("url", "", "Jenkins base URL (legacy; prefer --profile)")
	authFlag := fs.String("auth", "", "Deprecated: user:api_token (prefer login + keyring)")
	httpAddr := fs.String("http", "", "If set, serve MCP Streamable HTTP at this address (loopback only by default)")
	httpAllowNonLocal := fs.Bool("http-allow-non-local", false, "Allow --http to bind non-loopback interfaces (tests / residual; requires --http-allowed-origin, --http-allowed-host, and shared secret; not production)")
	httpTokenEnv := fs.String("http-token-env", "", "Env var name holding optional HTTP shared secret (value never on argv; do not pass token on command line)")
	httpTokenFile := fs.String("http-token-file", "", "Path to file with optional HTTP shared secret (mode 0600; read once; never put token on argv)")
	httpRequireToken := fs.Bool("http-require-token", false, "Fail closed if HTTP mode has no shared secret (also JENKINS_MCP_HTTP_REQUIRE_TOKEN=1 or JENKINS_MCP_HTTP_DENY_ANONYMOUS=1; always on with --http-allow-non-local)")
	// HOST-001: per-request subject for gateway / multi-user HTTP (shared secret is not identity).
	httpRequireSubject := fs.Bool("http-require-subject", false, "Fail closed if HTTP requests lack trusted subject identity (also --gateway, JENKINS_MCP_HTTP_REQUIRE_SUBJECT=1; always on with --http-allow-non-local; transport secret alone is not identity)")
	// Wave 44 Track C: Streamable HTTP request body cap (absolute fail-closed 16 MiB).
	httpMaxBodyBytesFlag := fs.String("http-max-body-bytes", "", "Streamable HTTP request body cap in bytes (empty/0=default 4MiB; env JENKINS_MCP_HTTP_MAX_BODY_BYTES fallback; flag wins; max 16MiB absolute fail-closed)")
	var httpAllowedOrigins multiString
	fs.Var(&httpAllowedOrigins, "http-allowed-origin", "Exact Origin allow-list entry for non-GET when using --http (repeatable; required with --http-allow-non-local)")
	var httpAllowedHosts multiString
	fs.Var(&httpAllowedHosts, "http-allowed-host", "Exact Host allow-list entry (hostname/IP, optional :port; case-insensitive; repeatable; required with --http-allow-non-local)")
	useStdio := fs.Bool("stdio", true, "Serve MCP over stdio (default)")
	showVer := fs.Bool("version", false, "Print version and exit")
	readOnly := fs.Bool("read-only", false, "Force global read-only (omit mutation tools; POL-001)")
	gatewayMode := fs.Bool("gateway", false, "Managed-gateway / AgentCore mode (GWY-001/002); requires AS URL + audience; HTTP also requires per-request subject (HOST-001)")
	var enableAdapters multiString
	fs.Var(&enableAdapters, "enable-adapter", "Enable an approved adapter by id (repeatable; default none). Built-ins: noop, clock, otel-correlate, otel-export, ext-logs, work-items")
	adapterAllowlist := fs.String("adapter-allowlist", "", "Path to adapter allowlist JSON (required for non-builtin adapters; optional Ed25519 signature when JENKINS_MCP_ADAPTER_ALLOWLIST_TRUSTED_KEYS is set)")
	adapterAllowlistMinSigs := fs.String("adapter-allowlist-min-signatures", "", "Multi-sig dual-control lite floor for adapter allowlist signatures[] (empty/0=default 1; env JENKINS_MCP_ADAPTER_ALLOWLIST_MIN_SIGNATURES fallback; flag wins; max 16 absolute fail-closed; single-sig path ignores)")
	extLogsBackend := fs.String("adapter-ext-logs-backend", "noop", "ext-logs backend when enabled: noop|mock|http (default noop; no secrets)")
	extLogsBaseURL := fs.String("adapter-ext-logs-base-url", "", "HTTPS origin/path for ext-logs http backend (paths only; no credentials in URL)")
	otelExportBackend := fs.String("adapter-otel-export-backend", "noop", "otel-export backend when enabled: noop|mock|http (default noop; metadata-only; no secrets)")
	otelExportBaseURL := fs.String("adapter-otel-export-base-url", "", "HTTPS origin/path for otel-export http backend (paths only; no credentials in URL)")
	allowMutations := fs.Bool("allow-mutations", false, "Test/PILOT ONLY: allow mutation tools when no stronger read-only source is set")
	// Wave 52 Track A / MUT-001: confirm cooldown (default 5s; min 1s; absolute 5m; 0 → default).
	mutationConfirmCooldownFlag := fs.String("mutation-confirm-cooldown", "", "Mutation confirm cooldown per target (Go duration; empty/0=default 5s; env JENKINS_MCP_MUTATION_CONFIRM_COOLDOWN fallback; flag wins; min 1s; max 5m absolute fail-closed; 0 means default; cannot disable via 0)")
	// Wave 52 Track C / MUT-001: process-local Preview sliding-window rate (default 30; absolute 300 fail-closed; 0 → default, not unlimited).
	mutationMaxPreviewsPerMinuteFlag := fs.String("mutation-max-previews-per-minute", "", "Mutation Preview rate per sliding minute (empty/0=default 30; env JENKINS_MCP_MUTATION_MAX_PREVIEWS_PER_MINUTE fallback; flag wins; max 300 absolute fail-closed; 0 means default — not unlimited)")
	// Wave 53 Track A / MUT-001: confirmation token TTL (default 2m; min 10s; absolute 15m; 0 → default).
	mutationTokenTTLFlag := fs.String("mutation-token-ttl", "", "Mutation confirmation token TTL (Go duration; empty/0=default 2m; env JENKINS_MCP_MUTATION_TOKEN_TTL fallback; flag wins; min 10s; max 15m absolute fail-closed; 0 means default; cannot disable via 0)")
	// OBS-001 / pilot: structured JSON log minimum level (tool dispatch + registry).
	logLevelFlag := fs.String("log-level", "", "Minimum structured log level for serve (debug|info|warn|error; empty=default info; env JENKINS_MCP_LOG_LEVEL fallback; flag wins; invalid fail-closed). Debug emits tool_dispatch_start/ok JSON lines for offline pilot analysis")
	caBundle := fs.String("ca-bundle", "", "PEM CA bundle path (overrides profile caBundlePath; NET-004)")
	proxyURL := fs.String("proxy", "", "HTTP(S) proxy URL or direct/none (overrides profile; NET-004)")
	diagInsecureTLS := fs.Bool("diag-insecure-tls", false, "DIAGNOSTIC ONLY: skip TLS verify; also requires JENKINS_MCP_DIAG_INSECURE_TLS=1")
	noCacheMaint := fs.Bool("no-cache-maintenance", false, "Disable background cache quota/compaction loop (tests)")
	cacheMaintInterval := fs.String("cache-maintenance-interval", "", "Cache maintenance tick interval (default 5m; env JENKINS_MCP_CACHE_MAINTENANCE_INTERVAL; min 30s max 1h absolute fail-closed)")
	identityReverifyTTL := fs.String("identity-reverify-ttl", "", "Mid-serve whoAmI re-verify TTL (default 5m; min 10s max 30m; env JENKINS_MCP_IDENTITY_REVERIFY_TTL; flag overrides env)")
	// Wave 37: bootstrap MCP result hard-max ceiling (absolute; overlay may only lower).
	hardMaxBytesFlag := fs.String("hard-max-bytes", "", "Bootstrap MCP result hard-max ceiling in bytes (empty/0=default 1MiB; env JENKINS_MCP_HARD_MAX_BYTES fallback; flag wins; max 64MiB absolute fail-closed; overlay max_result_bytes may only lower within this ceiling)")
	// Wave 47 Track B / Wave 51 Track C: soft structured-result target (ADR 0010;
	// absolute fail-closed AbsoluteMaxTargetBytes = AbsoluteMaxHardMaxBytes 64 MiB;
	// clamped to live hard max at enforce time).
	targetBytesFlag := fs.String("target-bytes", "", "Soft MCP structured-result target in bytes (empty/0=default 64KiB; env JENKINS_MCP_TARGET_BYTES fallback; flag wins; max 64MiB absolute fail-closed; clamped to live hard max at enforce time)")
	// Wave 41: list_jobs policy-collect safety page cap (absolute fail-closed).
	listJobsCollectMaxPagesFlag := fs.String("list-jobs-collect-max-pages", "", "list_jobs policy-collect safety page cap (empty/0=default 50; env JENKINS_MCP_LIST_JOBS_COLLECT_MAX_PAGES fallback; flag wins; max 200 absolute fail-closed)")
	// Wave 42: nodes/views policy-collect safety page caps (absolute fail-closed).
	nodesCollectMaxPagesFlag := fs.String("nodes-collect-max-pages", "", "get_nodes policy-collect safety page cap (empty/0=default 50; env JENKINS_MCP_NODES_COLLECT_MAX_PAGES fallback; flag wins; max 200 absolute fail-closed)")
	viewsCollectMaxPagesFlag := fs.String("views-collect-max-pages", "", "list_views policy-collect safety page cap (empty/0=default 50; env JENKINS_MCP_VIEWS_COLLECT_MAX_PAGES fallback; flag wins; max 200 absolute fail-closed)")
	// Wave 42: jenkins_list_artifacts hard cap when deny_artifact_paths force hard-cap fetch.
	artifactsHardCapFlag := fs.String("artifacts-hard-cap", "", "jenkins_list_artifacts process hard cap (empty/0=default 500; env JENKINS_MCP_ARTIFACTS_HARD_CAP fallback; flag wins; max 2000 absolute fail-closed; used for deny_artifact_paths hard-cap fetch and max_artifacts upper bound)")
	// Wave 43: ListArtifacts JSON body bound (default 2 MiB; absolute 8 MiB fail-closed).
	artifactsListBodyBytesFlag := fs.String("artifacts-list-body-bytes", "", "jenkins_list_artifacts JSON body bound in bytes (empty/0=default 2097152; env JENKINS_MCP_ARTIFACTS_LIST_BODY_BYTES fallback; flag wins; max 8388608 absolute fail-closed)")
	// Wave 46 Track A / NET-003: Jenkins API JSON/decoded body cap (default 32 MiB; absolute 128 MiB fail-closed).
	// Does not wrap progressive log paths (LOG-001).
	maxJSONBodyBytesFlag := fs.String("max-json-body-bytes", "", "Jenkins API JSON/decoded response body cap in bytes (empty/0=default 32MiB; env JENKINS_MCP_MAX_JSON_BODY_BYTES fallback; flag wins; max 128MiB absolute fail-closed; not progressive logs)")
	// Wave 47 Track A / NET-003: extra GET/HEAD auto-retries (default 2; absolute 10; 0 disables GET/HEAD auto-retry; POST never).
	maxRetriesFlag := fs.String("max-retries", "", "Extra GET/HEAD auto-retries after first attempt (empty=default 2; env JENKINS_MCP_MAX_RETRIES fallback; flag wins; 0 disables GET/HEAD auto-retry; max 10 absolute fail-closed; POST never auto-retried)")
	// Wave 48 Track A / NET-003: circuit failure threshold (default 5; absolute 50; 0 → default, cannot disable).
	circuitFailureThresholdFlag := fs.String("circuit-failure-threshold", "", "Jenkins circuit breaker consecutive failure threshold (empty/0=default 5; env JENKINS_MCP_CIRCUIT_FAILURE_THRESHOLD fallback; flag wins; max 50 absolute fail-closed; 0 means default)")
	// Wave 49 Track A / NET-003: circuit open duration (default 15s; min 1s; absolute 5m; 0 → default).
	circuitOpenDurationFlag := fs.String("circuit-open-duration", "", "Jenkins circuit breaker open duration before half-open (Go duration; empty/0=default 15s; env JENKINS_MCP_CIRCUIT_OPEN_DURATION fallback; flag wins; min 1s; max 5m absolute fail-closed; 0 means default)")
	// Wave 50 Track A / NET-003: per-client concurrency semaphore (default 0=unlimited; absolute 256; 0=unlimited).
	maxConcurrentFlag := fs.String("max-concurrent", "", "Jenkins per-client max concurrent requests (empty=default 0 unlimited; env JENKINS_MCP_MAX_CONCURRENT fallback; flag wins; 0=unlimited; max 256 absolute fail-closed; contrast --max-retries 0 which disables GET/HEAD auto-retry)")
	// Wave 51 Track A / NET-003: GET/HEAD retry initial backoff (default 100ms; min 10ms; absolute 2s; 0 → default).
	initialBackoffFlag := fs.String("initial-backoff", "", "Jenkins GET/HEAD retry initial backoff (Go duration; empty/0=default 100ms; env JENKINS_MCP_INITIAL_BACKOFF fallback; flag wins; min 10ms; max 2s absolute fail-closed; 0 means default; must be ≤ --max-backoff)")
	// Wave 51 Track A / NET-003: GET/HEAD retry max backoff (default 5s; min 100ms; absolute 1m; 0 → default; must be ≥ initial).
	maxBackoffFlag := fs.String("max-backoff", "", "Jenkins GET/HEAD retry max backoff / Retry-After cap (Go duration; empty/0=default 5s; env JENKINS_MCP_MAX_BACKOFF fallback; flag wins; min 100ms; max 1m absolute fail-closed; 0 means default; must be ≥ --initial-backoff)")
	// Bool flags take no value; only string flags are listed as taking values.
	if err := fs.Parse(reorderFlagArgs(args, map[string]bool{
		"profile": true, "url": true, "auth": true, "http": true,
		"ca-bundle": true, "proxy": true, "cache-maintenance-interval": true,
		"identity-reverify-ttl": true, "hard-max-bytes": true, "target-bytes": true,
		"list-jobs-collect-max-pages":      true,
		"nodes-collect-max-pages":          true,
		"views-collect-max-pages":          true,
		"artifacts-hard-cap":               true,
		"artifacts-list-body-bytes":        true,
		"max-json-body-bytes":              true,
		"max-retries":                      true,
		"circuit-failure-threshold":        true,
		"circuit-open-duration":            true,
		"max-concurrent":                   true,
		"initial-backoff":                  true,
		"max-backoff":                      true,
		"mutation-confirm-cooldown":        true,
		"mutation-max-previews-per-minute": true,
		"mutation-token-ttl":               true,
		"log-level":                        true,
		"adapter-allowlist":                true, "adapter-allowlist-min-signatures": true,
		"adapter-ext-logs-backend": true, "adapter-ext-logs-base-url": true,
		"adapter-otel-export-backend": true, "adapter-otel-export-base-url": true,
		"enable-adapter": true, "http-allowed-origin": true, "http-allowed-host": true,
		"http-token-env": true, "http-token-file": true,
		"http-max-body-bytes": true,
	})); err != nil {
		return apperr.New(apperr.CodeInvalidArgument, err.Error())
	}
	if *showVer {
		printVersion()
		return nil
	}

	// SEC-002 Wave 27: optional enterprise redact patterns (count only on success).
	// Invalid file fails closed before client/store open.
	if n, err := applyServeEnterpriseRedactPatterns(); err != nil {
		return err
	} else if n > 0 {
		log.Printf("enterprise redact patterns loaded: count=%d", n)
	}

	var (
		baseURL    string
		sess       auth.Session
		usedLegacy bool
		authPr     auth.Profile
		profDoc    *profile.Profile
		// oidcProv retained for mid-serve live credential refresh (wave 14).
		oidcProv *auth.OIDCProvider
	)

	if *profileFlag != "" {
		store, err := profileStore()
		if err != nil {
			return err
		}
		p, err := store.Load(*profileFlag)
		if err != nil {
			return err
		}
		profDoc = p
		baseURL = p.JenkinsURL
		authPr = auth.ProfileFrom(p)
		prov, err := auth.NewProvider(p.AuthMethod, keyringStore())
		if err != nil {
			return err
		}
		// OAUTH-004: OIDC session load may need IdP refresh — inject TLS/proxy-aware HTTP client.
		if oidc, ok := prov.(*auth.OIDCProvider); ok {
			oidcProv = oidc
			if client, err := discoveryHTTPClient(p); err == nil {
				oidc.HTTP = client
			}
		}
		sess, err = prov.Authenticate(context.Background(), authPr)
		if err != nil {
			// Bootstrap: allow deprecated -auth / env only when keyring has no credential.
			// OIDC profiles must not fall through to Basic legacy bootstrap.
			if p.AuthMethod == profile.AuthMethodOIDC {
				return err
			}
			legacyRaw := *authFlag
			if legacyRaw == "" {
				legacyRaw = os.Getenv(auth.LegacyEnvVar)
			}
			if legacyRaw != "" {
				fmt.Fprintln(os.Stderr, "warning: using deprecated -auth / JENKINS_MCP_AUTH bootstrap (KD-003); prefer jenkins-mcp login --profile")
				sess, err = auth.LegacySessionFromString(p.ID, legacyRaw)
				if err != nil {
					return err
				}
				usedLegacy = true
			} else {
				return err
			}
		}
	} else {
		// Fully legacy path: -url + -auth/env without profile.
		baseURL = *jenkinsURL
		if baseURL == "" {
			baseURL = "http://localhost:8080"
		}
		legacyRaw := *authFlag
		if legacyRaw == "" {
			legacyRaw = os.Getenv(auth.LegacyEnvVar)
		}
		if legacyRaw == "" {
			return apperr.New(apperr.CodeAuthentication,
				"authentication required: use --profile after login, or deprecated -auth / JENKINS_MCP_AUTH")
		}
		fmt.Fprintln(os.Stderr, "warning: serving without --profile using deprecated -auth / JENKINS_MCP_AUTH (KD-003)")
		var err error
		sess, err = auth.LegacySessionFromString("", legacyRaw)
		if err != nil {
			return err
		}
		usedLegacy = true
		authPr = auth.Profile{URL: baseURL, User: sess.User}
	}

	// GWY-001/002: detect gateway mode early (provider required before serve continues).
	profileGateway := profDoc != nil && profDoc.GatewayMode
	useGateway := gateway.ModeEnabled(*gatewayMode, profileGateway)
	var gatewayProv gateway.CredentialProvider
	if useGateway {
		var gerr error
		gatewayProv, gerr = requireGatewayProvider(baseURL)
		if gerr != nil {
			return gerr
		}
		st := gatewayProv.Status(context.Background())
		log.Printf("Gateway mode enabled provider_configured=%v ready=%v mode=%s",
			st.Configured, st.Ready, st.Mode)
		if !st.Ready {
			// Mode C / AgentCore: Live=false until TokenFetcher wire (GWY-001 residual).
			// Local keyring/OIDC session remains the Jenkins HTTP path; Obtain stays
			// fail-closed (capability_missing) so no shared SA is ever substituted.
			log.Printf("Gateway credential obtain is not live (capability_missing until AgentCore pin); Jenkins HTTP uses local session")
		} else if st.Mode == gateway.ModeAPITokenVault {
			// HOST-009 + HOST-003: Mode A Ready → per-request Obtain AuthProvider
			// (Basic personal token; never shared SA / ambient keyring fallthrough).
			log.Printf("Gateway mode A (api_token_vault) Obtain Ready; Jenkins HTTP will use per-request vault credentials")
		} else {
			// Mode B/C Ready (mock/live Fetcher): Obtain → Bearer AuthProvider.
			log.Printf("Gateway Obtain Ready mode=%s; Jenkins HTTP will use per-request Obtain credentials", st.Mode)
		}
	}

	// NET-004: build shared TLS/proxy transport for identity verify + API client.
	tcfg := transportConfigFromProfile(profDoc, *caBundle, *proxyURL, *diagInsecureTLS)
	hc, err := jenkins.NewHTTPClients(tcfg)
	if err != nil {
		return apperr.Wrap(apperr.CodeInvalidArgument, "TLS/proxy configuration", err)
	}

	// Wave 14: JWT-shaped OIDC tokens re-validate at serve start (exact audience)
	// before whoAmI / tool registration. Opaque tokens skip local JWT parse.
	tokenRes, groupExtract, err := validateServeOIDCAccess(context.Background(), sess, profDoc, baseURL, hc.API)
	if err != nil {
		return err
	}

	// AUTH-004 Wave 24: configurable mid-serve whoAmI re-verify TTL (fail closed).
	// Flag --identity-reverify-ttl overrides env JENKINS_MCP_IDENTITY_REVERIFY_TTL;
	// empty/zero → DefaultIdentityCacheTTL (5m). Bounds: min 10s, max 30m.
	// Residual by design: not continuous every-call whoAmI — only on TTL expiry.
	reverifyTTL, err := auth.ParseIdentityReverifyTTL(*identityReverifyTTL, os.Getenv(auth.EnvIdentityReverifyTTL))
	if err != nil {
		return err
	}

	// AUTH-004: verify and bind Jenkins principal at serve start (fail closed).
	idCache := auth.NewIdentityCache(reverifyTTL)
	principal, err := auth.VerifyIdentityCachedHTTP(context.Background(), authPr, sess, idCache, hc.API)
	if err != nil {
		if tlsMsg := jenkins.FormatTLSError(err); tlsMsg != "" && tlsMsg != err.Error() {
			return apperr.Wrap(apperr.CodeOf(err), tlsMsg, err)
		}
		return err
	}
	sess = auth.BindPrincipal(sess, principal)
	// Persist last-verified non-secret identity when we have a profile store.
	if profDoc != nil && (profDoc.VerifiedPrincipalID != principal.ID || profDoc.VerifiedFullName != principal.FullName) {
		profDoc.VerifiedPrincipalID = principal.ID
		profDoc.VerifiedFullName = principal.FullName
		if st, err := profileStore(); err == nil {
			_ = st.Save(profDoc)
		}
	}

	// Wave 14/15: SessionGuard + LiveSessionSource after identity bind (OIDC only).
	// Epoch file under profile data dir enables cross-process logout → fail-closed serve.
	// Serve only watches the file (SessionEpochWatcher); it must not Bump via
	// OIDCProvider.Epoch — bumps are login/logout CLI responsibility.
	var epochStore *auth.SessionEpochStore
	if profDoc != nil && sess.Method == auth.MethodOIDC {
		if es, err := sessionEpochStoreForProfile(profDoc); err == nil {
			epochStore = es
		} else {
			log.Printf("session epoch store unavailable: %v", err)
		}
	}
	oidcSess := bindServeOIDCSession(sess, authPr, profDoc, oidcProv, principal, tokenRes, groupExtract, hc.API, epochStore)
	sessionGuard := oidcSess.Guard

	creds := auth.SessionCredentialsFrom(sess)
	// NET-002/003/004 + OAUTH-005: Basic (api_token) or Bearer (OIDC).
	scheme := jenkins.AuthSchemeBasic
	if creds.Scheme == auth.HTTPAuthBearer {
		scheme = jenkins.AuthSchemeBearer
	}
	client, err := jenkins.NewClientWithTransportScheme(baseURL, creds.User, creds.Secret, scheme, tcfg)
	if err != nil {
		return apperr.Wrap(apperr.CodeInvalidArgument, "TLS/proxy configuration", err)
	}
	// Wave 46–51 / NET-003: operator MaxJSONBodyBytes, MaxRetries,
	// CircuitFailureThreshold, CircuitOpenDuration, MaxConcurrent,
	// InitialBackoff, MaxBackoff.
	// Always reinstall resilience so resolved values are the live client bound.
	// Progressive logs stay on LOG-001 caps only. POST never auto-retried.
	// Circuit threshold/open-duration/backoff 0 → default (cannot disable via 0).
	// MaxConcurrent 0 = unlimited (contrast MaxRetries 0 which disables retry).
	// MaxBackoff must be ≥ InitialBackoff after both resolve (fail closed).
	maxJSONBodyBytes, err := jenkins.ResolveMaxJSONBodyBytes(*maxJSONBodyBytesFlag, os.Getenv(jenkins.EnvMaxJSONBodyBytes))
	if err != nil {
		return err
	}
	maxRetries, err := jenkins.ResolveMaxRetries(*maxRetriesFlag, os.Getenv(jenkins.EnvMaxRetries))
	if err != nil {
		return err
	}
	circuitThreshold, err := jenkins.ResolveCircuitFailureThreshold(*circuitFailureThresholdFlag, os.Getenv(jenkins.EnvCircuitFailureThreshold))
	if err != nil {
		return err
	}
	circuitOpenDuration, err := jenkins.ResolveCircuitOpenDuration(*circuitOpenDurationFlag, os.Getenv(jenkins.EnvCircuitOpenDuration))
	if err != nil {
		return err
	}
	maxConcurrent, err := jenkins.ResolveMaxConcurrent(*maxConcurrentFlag, os.Getenv(jenkins.EnvMaxConcurrent))
	if err != nil {
		return err
	}
	initialBackoff, err := jenkins.ResolveInitialBackoff(*initialBackoffFlag, os.Getenv(jenkins.EnvInitialBackoff))
	if err != nil {
		return err
	}
	maxBackoff, err := jenkins.ResolveMaxBackoff(*maxBackoffFlag, os.Getenv(jenkins.EnvMaxBackoff))
	if err != nil {
		return err
	}
	if err := jenkins.EnsureMaxBackoffAtLeastInitial(initialBackoff, maxBackoff); err != nil {
		return err
	}
	// Wave 52 Track A / MUT-001: mutation confirm cooldown (after other caps).
	// empty/0/"0s" → default 5s; min 1s; absolute max 5m fail closed; cannot disable via 0.
	mutationConfirmCooldown, err := mutation.ResolveConfirmCooldown(*mutationConfirmCooldownFlag, os.Getenv(mutation.EnvConfirmCooldown))
	if err != nil {
		return err
	}
	mutation.SetConfirmCooldown(mutationConfirmCooldown)
	// Wave 52 Track C / MUT-001: Preview rate (default 30; absolute 300; 0 → default).
	// Set process live before tool registration so NewManager(Config{…0…}) picks it up.
	mutationMaxPreviews, err := mutation.ResolveMaxPreviewsPerMinute(*mutationMaxPreviewsPerMinuteFlag, os.Getenv(mutation.EnvMaxPreviewsPerMinute))
	if err != nil {
		return err
	}
	mutation.SetMaxPreviewsPerMinute(mutationMaxPreviews)
	// Wave 53 Track A / MUT-001: confirmation token TTL (default 2m; min 10s; absolute 15m; 0 → default).
	mutationTokenTTL, err := mutation.ResolveTokenTTL(*mutationTokenTTLFlag, os.Getenv(mutation.EnvTokenTTL))
	if err != nil {
		return err
	}
	mutation.SetTokenTTL(mutationTokenTTL)
	rcfg := jenkins.DefaultResilienceConfig()
	rcfg.MaxJSONBodyBytes = maxJSONBodyBytes
	rcfg.MaxRetries = maxRetries
	rcfg.CircuitFailureThreshold = circuitThreshold
	rcfg.CircuitOpenDuration = circuitOpenDuration
	rcfg.MaxConcurrent = maxConcurrent
	rcfg.InitialBackoff = initialBackoff
	rcfg.MaxBackoff = maxBackoff
	client.WithResilience(rcfg)
	// Non-secret counts only — never credentials or tokens.
	// max_concurrent=0 means unlimited (log as number only).
	log.Printf("max_json_body_bytes=%d max_retries=%d circuit_failure_threshold=%d circuit_open_duration=%s max_concurrent=%d initial_backoff=%s max_backoff=%s mutation_confirm_cooldown=%s mutation_token_ttl=%s mutation_max_previews_per_minute=%d",
		maxJSONBodyBytes, maxRetries, circuitThreshold, circuitOpenDuration, maxConcurrent, initialBackoff, maxBackoff, mutationConfirmCooldown, mutationTokenTTL, mutationMaxPreviews)

	// POL-003 / GWY-002: resolve profile id early so gateway subject bind can
	// precede AuthProvider install (HOST-003: Obtain needs bound Caller).
	profileID := sess.ProfileID
	if profileID == "" && *profileFlag != "" {
		profileID = contracts.ProfileID(*profileFlag)
	}
	if profileID == "" && principal.ID != "" {
		profileID = contracts.ProfileID("_legacy")
	}

	// Mid-serve credentials (HOST-003):
	//   gateway + Ready → Obtain AuthProvider (Mode A Basic / B+C Bearer); never keyring fallthrough
	//   gateway + !Ready → residual local session (Mode C AgentCore stub) via OIDC Live or static
	//   non-gateway → OIDC LiveSessionSource refresh; api_token leaves provider nil
	var subject policy.Subject
	var gatewayObtainWired bool
	if useGateway {
		gwSubject, err := bindGatewaySubject(profileID, principal.ID)
		if err != nil {
			return err
		}
		subject = gwSubject
		log.Printf("Gateway policy subject profile=%s external=%s jenkins=%s tenant_set=%v workload_set=%v verified=%v",
			subject.ProfileID, subject.ExternalSubject, subject.JenkinsUserID,
			subject.Tenant != "", subject.WorkloadID != "", subject.Verified)
		if gatewayObtainReady(gatewayProv) {
			caller := gateway.CallerFromBoundSubject(subject)
			attachGatewayObtainAuthProvider(client, gatewayProv, caller)
			gatewayObtainWired = true
			log.Printf("Gateway Jenkins AuthProvider: Obtain mode=%s (no keyring fallthrough)", gatewayProv.Mode())
		} else {
			// Mode C residual: Obtain not Ready; keep local keyring/OIDC path.
			attachLiveAuthProvider(client, oidcSess.Live)
			log.Printf("Gateway Obtain not Ready; Jenkins AuthProvider uses local session residual")
		}
	} else {
		attachLiveAuthProvider(client, oidcSess.Live)
	}

	log.Printf("Using Jenkins URL: %s", client.URL)
	// Log verified principal id only (username) — never token (KD-004 residual for broader redact).
	log.Printf("Using Jenkins auth for user: %s", principal.ID)
	if principal.FullName != "" {
		log.Printf("Jenkins principal fullName: %s", principal.FullName)
	}
	if usedLegacy {
		log.Printf("auth source: deprecated legacy bootstrap")
	} else if gatewayObtainWired {
		log.Printf("auth source: gateway Obtain mode=%s profile=%s", gatewayProv.Mode(), sess.ProfileID)
	} else {
		log.Printf("auth source: keyring profile=%s method=%s", sess.ProfileID, sess.Method)
	}
	// idCache is retained for the serve lifetime: AUTH-004 IdentityReverifyGate
	// reuses the TTL so tool dispatch whoAmI is not repeated every call.
	// Mid-serve OIDC credential refresh uses LiveSessionSource separately.
	if _, ok := idCache.Get(); !ok {
		return apperr.New(apperr.CodeInternal, "identity cache not populated after verification")
	}
	log.Printf("Identity re-verify TTL: %s (min %s max %s; not every-call whoAmI)",
		idCache.TTL(), auth.MinIdentityReverifyTTL, auth.MaxIdentityReverifyTTL)
	// Logout residual: when serve ends, disable the in-process guard so any
	// late tool dispatch cannot use a stale Client secret. Cross-process CLI
	// logout also bumps session.epoch (LiveSessionSource checks before each
	// Credentials call); keyring clear + refresh fail remain the durable path.
	if sessionGuard != nil {
		defer sessionGuard.Disable()
	}

	// CFG-002 / MGR-001: enterprise policy overlay or signed bundle (fail closed).
	// LoadFromEnviron uses Ed25519 when trusted keys are present; else pilot Nop.
	polRes, err := policy.LoadFromEnviron()
	if err != nil {
		return err
	}
	// Wave 25: DynamicForce so force_read_only hot-applies on Reloadable OnSuccess.
	// Without an overlay, leave Force nil (no enterprise force source).
	var dynForce *policy.DynamicForce
	var enterpriseForce policy.EnterpriseForce
	if polRes.Overlay != nil {
		dynForce = policy.NewDynamicForceFromOverlay(polRes.Overlay)
		enterpriseForce = dynForce
		log.Printf("Enterprise policy loaded force_read_only=%v mode=%s deny_tools=%d deny_job_prefixes=%d deny_node_names=%d deny_view_names=%d deny_artifact_paths=%d deny_branch_names=%d signature_state=%s",
			polRes.Overlay.ForceReadOnly, polRes.Overlay.NormalizeMode(),
			len(polRes.Overlay.DenyTools), len(polRes.Overlay.DenyJobPrefixes),
			len(polRes.Overlay.DenyNodeNames), len(polRes.Overlay.DenyViewNames),
			len(polRes.Overlay.DenyArtifactPaths), len(polRes.Overlay.DenyBranchNames),
			polRes.SignatureState)
		if polRes.BundleSeq > 0 {
			// key_id only — never log signature bytes or key material.
			log.Printf("Enterprise policy bundle_seq=%d key_id=%s", polRes.BundleSeq, polRes.KeyID)
		}
	}

	// POL-001: global read-only kill switch (most restrictive wins).
	var profileRO *bool
	if *profileFlag != "" {
		if st, err := profileStore(); err == nil {
			if p, err := st.Load(*profileFlag); err == nil {
				v := p.EffectiveReadOnly()
				profileRO = &v
			}
		}
	}
	gate := policy.NewReadOnlyGate(policy.Inputs{
		FlagReadOnly:    *readOnly,
		EnvReadOnly:     policy.EnvReadOnlyFromEnviron(),
		ProfileReadOnly: profileRO,
		Force:           enterpriseForce,
		AllowMutations:  *allowMutations,
	})
	log.Printf("Read-only effective=%v sources=%v", gate.Effective(), gate.Sources())
	client.WithMutationGuard(policy.NewReadOnlyMutationGuard(gate))

	// POL-003: non-gateway subject from verified principal — never tool args.
	// OIDC: attach bounded groups from validated JWT claims (OAUTH-006).
	// Gateway subject was already bound above (HOST-003 AuthProvider order).
	if !useGateway {
		if principal.ID != "" && profileID != "" {
			subject = policy.NewSubject(profileID, principal.ID, true)
			subject = applyOIDCSubjectFields(subject, sess, oidcSess, profDoc)
			log.Printf("Policy subject profile=%s user=%s verified=%v external_set=%v group_count=%d",
				subject.ProfileID, subject.JenkinsUserID, subject.Verified,
				subject.ExternalSubject != "", len(subject.Groups))
		} else {
			log.Printf("Policy subject unbound; RBAC denials apply if evaluator set")
		}
	}

	// Budgets (Wave 25/31/37/47):
	// 1) bootstrap ceiling = ResolveHardMaxBytes (default → env → flag)
	// 2) soft target = ResolveTargetBytes (default → env → flag; absolute ≤ 64 MiB;
	//    still clamped to live hard max at enforce / Normalize)
	// 3) overlay max_result_bytes may only LowerHardMax within that ceiling
	// 4) LiveHardMax.Ceiling freezes the bootstrap ceiling (not the lowered value)
	// Raising the absolute ceiling requires re-serve with higher --hard-max-bytes
	// or JENKINS_MCP_HARD_MAX_BYTES (overlay alone never raises the ceiling).
	bootstrapHardMax, err := tools.ResolveHardMaxBytes(*hardMaxBytesFlag, os.Getenv(tools.EnvHardMaxBytes))
	if err != nil {
		return err
	}
	targetBytes, err := tools.ResolveTargetBytes(*targetBytesFlag, os.Getenv(tools.EnvTargetBytes))
	if err != nil {
		return err
	}
	// Wave 41/42: policy-collect safety page caps (default → env → flag; absolute max 200).
	collectMaxPages, err := tools.ResolveListJobsCollectMaxPages(*listJobsCollectMaxPagesFlag, os.Getenv(tools.EnvListJobsCollectMaxPages))
	if err != nil {
		return err
	}
	tools.SetListJobsCollectMaxPages(collectMaxPages)
	nodesCollectMaxPages, err := tools.ResolveNodesCollectMaxPages(*nodesCollectMaxPagesFlag, os.Getenv(tools.EnvNodesCollectMaxPages))
	if err != nil {
		return err
	}
	tools.SetNodesCollectMaxPages(nodesCollectMaxPages)
	viewsCollectMaxPages, err := tools.ResolveViewsCollectMaxPages(*viewsCollectMaxPagesFlag, os.Getenv(tools.EnvViewsCollectMaxPages))
	if err != nil {
		return err
	}
	tools.SetViewsCollectMaxPages(viewsCollectMaxPages)
	// Wave 42: artifacts list hard cap (default → env → flag; absolute max 2000).
	artifactsHardCap, err := tools.ResolveArtifactsHardCap(*artifactsHardCapFlag, os.Getenv(tools.EnvArtifactsHardCap))
	if err != nil {
		return err
	}
	tools.SetArtifactsHardCap(artifactsHardCap)
	// Wave 43: ListArtifacts JSON body bound (default → env → flag; absolute max 8 MiB).
	artifactsListBodyBytes, err := tools.ResolveArtifactsListBodyBytes(*artifactsListBodyBytesFlag, os.Getenv(tools.EnvArtifactsListBodyBytes))
	if err != nil {
		return err
	}
	jenkins.SetArtifactListBodyBytes(artifactsListBodyBytes)
	budgets := tools.DefaultBudgets()
	budgets.HardMaxBytes = bootstrapHardMax
	budgets.TargetBytes = targetBytes
	// Wave 53 Track C / MCP-001 residual honesty: detect soft-target clamp when
	// ResolveTargetBytes yielded target > bootstrap hard max (before Normalize).
	// Log non-secret fields only (target_bytes_clamped / target_bytes_resolved).
	targetBytesResolved := targetBytes
	targetBytesClamped := tools.SoftTargetClampApplied(targetBytesResolved, bootstrapHardMax)
	budgets = budgets.Normalize() // clamps TargetBytes ≤ HardMaxBytes when needed
	if polRes.Overlay != nil {
		if n, ok := polRes.Overlay.EffectiveMaxResultBytes(); ok {
			budgets = tools.LowerHardMax(budgets, n)
		}
	}
	// Non-secret operator caps only — never credentials or tokens.
	// Wave 53 Track C: target_bytes_clamped / target_bytes_resolved for honesty when
	// resolve soft target exceeded bootstrap hard and Normalize clamped.
	log.Printf("Result budget hard_max_bytes=%d serve_bootstrap_ceiling=%d target_bytes=%d target_bytes_clamped=%t target_bytes_resolved=%d list_jobs_collect_max_pages=%d nodes_collect_max_pages=%d views_collect_max_pages=%d artifacts_hard_cap=%d artifacts_list_body_bytes=%d",
		budgets.HardMaxBytes, bootstrapHardMax, budgets.TargetBytes, targetBytesClamped, targetBytesResolved, collectMaxPages, nodesCollectMaxPages, viewsCollectMaxPages, artifactsHardCap, artifactsListBodyBytes)
	var liveHardMax *tools.LiveHardMax
	if polRes.Overlay != nil {
		// Ceiling = bootstrap absolute; live value may already be overlay-lowered.
		liveHardMax = tools.NewLiveHardMax(bootstrapHardMax)
		if budgets.HardMaxBytes < bootstrapHardMax {
			_ = liveHardMax.LowerTo(budgets.HardMaxBytes)
		}
	}

	// POL Wave 24/25/31/37: hot-reload deny-only evaluator when overlay/bundle is present.
	// Mtime checked on Evaluate (min interval 5s). Load errors keep last-good.
	// OnSuccess: DynamicForce + LiveHardMax.SetWithinCeiling (Wave 31 raise-within-ceiling).
	// Wave 28: deny_tools ListTools filter is live (no restart).
	// Wave 30: with --allow-mutations, mutations register under force RO so
	// force clear re-lists without restart (ListTools/DenyMutation still live).
	// Residual restart: raise absolute hard max above serve-bootstrap ceiling
	// via --hard-max-bytes / JENKINS_MCP_HARD_MAX_BYTES (see docs/policy-rbac.md).
	var evaluator policy.PolicyEvaluator
	if polRes.Overlay != nil {
		evaluator = policy.NewReloadableFromLoadResult(polRes, policy.ReloadableConfig{
			Load: policy.LoadFromEnviron,
			Path: polRes.Path,
			OnSuccess: func(info policy.ReloadInfo) {
				// Counts + bundle_seq only — never signature bytes or key material.
				log.Printf("Enterprise policy reloaded deny_tools=%d deny_job_prefixes=%d deny_node_names=%d deny_view_names=%d deny_artifact_paths=%d deny_branch_names=%d bundle_seq=%d signature_state=%s mode=%s force_read_only=%v max_result_bytes=%d",
					info.DenyToolsCount, info.DenyJobPrefixesCount,
					info.DenyNodeNamesCount, info.DenyViewNamesCount, info.DenyArtifactPathsCount,
					info.DenyBranchNamesCount,
					info.BundleSeq, info.SignatureState, info.Mode, info.ForceReadOnly, info.MaxResultBytes)
				// Wave 25: hot-apply force_read_only into the live gate Force.
				if dynForce != nil {
					dynForce.Set(info.ForceReadOnly, true)
				}
				// Wave 31/37: set live hard max within serve-bootstrap ceiling.
				// MaxResultBytes==0 (overlay omitted field) keeps last live value.
				// Never raises above bootstrapHardMax (LiveHardMax clamps).
				if liveHardMax != nil && info.MaxResultBytes > 0 {
					if liveHardMax.SetWithinCeiling(info.MaxResultBytes) {
						log.Printf("Enterprise policy set result hard max to %d bytes (requested=%d ceiling=%d)",
							liveHardMax.Get(), info.MaxResultBytes, liveHardMax.Ceiling())
					}
				}
			},
			OnError: func(err error) {
				log.Printf("Enterprise policy reload failed (keeping last-good): %v", err)
			},
		})
	}

	// LOG-004: open profile data dir store + logmirror for local log reads.
	// Legacy serve without --profile keeps direct Jenkins client only.
	var logAccess tools.LogAccess
	var logSearch tools.LogSearcher
	var auditFile audit.Sink
	var storeMeta *store.Meta
	var storeFrames *store.Frames
	var profileDataDir string
	var frameCrypto *store.FrameCrypto
	if profDoc != nil {
		dataDir, err := resolveProfileDataDir(profDoc)
		if err != nil {
			return err
		}
		profileDataDir = dataDir
		storeMeta, err = store.Open(dataDir)
		if err != nil {
			return apperr.Wrap(apperr.CodeInternal, "failed to open profile log store", err)
		}
		defer func() { _ = storeMeta.Close() }()
		storeFrames, err = store.NewFrames(storeMeta, dataDir)
		if err != nil {
			return apperr.Wrap(apperr.CodeInternal, "failed to open log frames", err)
		}
		defer func() { _ = storeFrames.Close() }()
		// ARC-009: optional AEAD — fail closed when encryption required but key missing.
		frameCrypto, err = loadProfileFrameCrypto(profDoc)
		if err != nil {
			return err
		}
		if frameCrypto != nil {
			storeFrames.SetCrypto(frameCrypto)
			log.Printf("Cache encryption enabled profile=%s key_version=%d (ARC-009)",
				profDoc.ID, frameCrypto.WriteKeyVersion())
		}
		if _, err := storeFrames.Recover(context.Background()); err != nil {
			return apperr.Wrap(apperr.CodeCorruptCache, "log frame recovery failed", err)
		}
		reader, err := storeFrames.Reader()
		if err != nil {
			return err
		}
		machine := logmirror.NewMachine(storeMeta, logmirror.JenkinsSource{Client: client})
		machine.Frames = storeFrames
		machine.Reader = reader
		// L2 pack fallback after L1 release (ARC-005 residual).
		machine.ArchiveRoot = filepath.Join(dataDir, store.ArchivesDirName)
		access := logmirror.NewAccess(string(profDoc.ID), machine)
		access.Status = logmirror.JenkinsBuildStatus{Client: client}
		// LOG-004 multi-log: Coordinator shares profile + machine; tools expose
		// jenkins_mirror_logs when Coord is set (optional without mirror).
		// Catalog=storeMeta makes collection membership durable across restarts
		// (schema v6; membership/refs only — never log bodies).
		coord := logmirror.NewCoordinator(string(profDoc.ID), machine, logmirror.DefaultCollectionBounds())
		coord.Status = logmirror.JenkinsBuildStatus{Client: client}
		coord.Catalog = storeMeta
		logAccess = tools.NewMirrorLogAccess(access).WithCoordinator(coord)
		log.Printf("Log store open dataDir=%s profile=%s (LOG-004 local reads + multi-log mirror + durable collection catalog)", dataDir, profDoc.ID)

		// AUD-001: file audit under profile data dir; SEARCH-001 engine on same store.
		// Prefer reader that already carries FrameCrypto so search decrypts correctly.
		if sink, err := audit.OpenProfileSink(dataDir); err == nil {
			auditFile = sink
		}
		if eng, err := search.NewWithReader(storeMeta, reader); err == nil {
			logSearch = eng
		} else if eng, err2 := search.New(storeMeta, dataDir); err2 == nil {
			logSearch = eng
		}
	} else {
		log.Printf("Log store skipped (no --profile); log tools use direct Jenkins client")
	}

	// AUD-001 / OBS-001 defaults when no profile store.
	var auditSink audit.Sink = auditFile
	if auditSink == nil {
		auditSink = &audit.Memory{}
	}
	if auditFile != nil {
		defer func() { _ = auditFile.Close() }()
	}
	// OBS-001 / pilot: structured logger min level (debug for offline analysis).
	logLevel, err := telemetry.ResolveLogLevel(*logLevelFlag, os.Getenv(telemetry.EnvLogLevel))
	if err != nil {
		return apperr.New(apperr.CodeInvalidArgument, err.Error())
	}
	profileLogID := ""
	if profDoc != nil {
		profileLogID = profDoc.ID.String()
	}
	serveLogger := telemetry.NewLogger(os.Stderr, logLevel).With(
		"component", "serve",
		"profile", profileLogID,
	)
	metricsReg := telemetry.NewRegistry()
	metricsReg.Logger = serveLogger
	metrics := metricsReg.Metrics
	telemetry.SetGlobal(metricsReg)
	// OBS-001 / Wave 24: Jenkins HTTP request/byte/error counters via package-local
	// MetricsHook (jenkins must not import telemetry).
	if client != nil {
		client.WithMetrics(tools.JenkinsMetricsHook(metrics))
	}
	log.Printf("audit and metrics initialized log_level=%s", logLevel.String())
	serveLogger.Info("serve_observability_ready",
		"log_level", logLevel.String(),
		"read_only", strconv.FormatBool(gate.Effective()),
		"structured_tool_logs", "true",
	)

	// Serve context: cancelled when stdio/http server returns so background
	// cache maintenance (ARC-007/005 residual) stops cleanly.
	serveCtx, serveCancel := context.WithCancel(context.Background())
	defer serveCancel()

	// MGR-002: privacy-preserving fleet health telemetry (disabled by default).
	// Network/export failures never fail serve. Enable with JENKINS_MCP_TELEMETRY=1.
	if paths, perr := config.Resolve(); perr == nil {
		authMeth := ""
		profileID := ""
		if profDoc != nil {
			authMeth = string(profDoc.AuthMethod)
			profileID = profDoc.ID.String()
		}
		if usedLegacy {
			authMeth = fleet.AuthMethodLegacy
		}
		if coll, cerr := fleet.NewCollector(fleet.CollectorConfig{
			Paths:      paths,
			Metrics:    metrics,
			Version:    version,
			ProfileID:  profileID,
			AuthMethod: authMeth,
			ReadOnly:   gate.Effective(),
		}); cerr != nil {
			// Collector construction must never fail serve.
			log.Printf("fleet telemetry: init skipped")
		} else if coll != nil {
			coll.Start(serveCtx)
			log.Printf("fleet telemetry enabled (local queue; export URL %v)", fleet.ExportURLFromEnv() != "")
		}
	}

	// Background QuotaManager + optional L1→L2 compaction when profile data dir is open.
	// Disable with --no-cache-maintenance or JENKINS_MCP_NO_CACHE_MAINTENANCE=1 (tests).
	var maintWG sync.WaitGroup
	if storeMeta != nil && profileDataDir != "" && !disableCacheMaintenance(*noCacheMaint) {
		interval, err := parseCacheMaintenanceInterval(*cacheMaintInterval)
		if err != nil {
			return err
		}
		qm, err := store.NewQuotaManager(storeMeta, profileDataDir, store.QuotaConfig{})
		if err != nil {
			return apperr.Wrap(apperr.CodeInternal, "failed to open quota manager", err)
		}
		mcfg := app.DefaultMaintenanceConfig()
		mcfg.Interval = interval
		maint, err := app.NewMaintainer(qm, storeMeta, profileDataDir, mcfg)
		if err != nil {
			return apperr.Wrap(apperr.CodeInternal, "failed to start cache maintenance", err)
		}
		maint.Logger = metricsReg.Logger
		maint.Metrics = metrics
		maint.FrameCrypto = frameCrypto
		maintWG.Add(1)
		go func() {
			defer maintWG.Done()
			maint.Run(serveCtx)
		}()
		log.Printf("Cache maintenance enabled interval=%s (ARC-007/005 residual)", interval)
		defer func() {
			serveCancel()
			maintWG.Wait()
		}()
	} else if storeMeta != nil {
		log.Printf("Cache maintenance disabled")
	}

	var (
		adapterReg     *adapter.Registry
		externalLogs   tools.ExternalLogQuerier
		traceExporter  tools.TraceExporter
		workItemLookup tools.WorkItemLookuper
	)
	if len(enableAdapters) > 0 {
		// INT-001 / Wave 44–45: optional Ed25519 allowlist provenance lite +
		// multi-sig MinSignatures dual-control lite floor.
		// Keys non-empty ⇒ requireSigned; signed file without keys fails closed.
		// Never log keys or signatures.
		alKeys, err := adapter.LoadAllowlistTrustedKeysFromEnviron()
		if err != nil {
			return err
		}
		minSigs, err := adapter.ResolveAllowlistMinSignatures(
			*adapterAllowlistMinSigs, os.Getenv(adapter.EnvAdapterAllowlistMinSignatures))
		if err != nil {
			return err
		}
		al, err := adapter.LoadAllowlistFileOpts(adapter.LoadAllowlistOptions{
			Path:          *adapterAllowlist,
			Keys:          alKeys,
			RequireSigned: alKeys.Len() > 0,
			MinSignatures: minSigs,
		})
		if err != nil {
			return err
		}
		// Catalog: override ext-logs / otel-export factories when requested.
		cat := adapter.DefaultCatalog()
		extLogsBackendName := adapter.ExtLogsBackendNoop
		extLogsEnabled := false
		otelExportBackendName := adapter.OtelExportBackendNoop
		otelExportEnabled := false
		for _, id := range enableAdapters {
			switch strings.ToLower(strings.TrimSpace(id)) {
			case adapter.IDExtLogs:
				extLogsEnabled = true
				cfg := adapter.ExtLogsConfig{
					Backend: adapter.ExtLogsBackendName(strings.ToLower(strings.TrimSpace(*extLogsBackend))),
					BaseURL: strings.TrimSpace(*extLogsBaseURL),
				}
				if cfg.Backend == "" {
					cfg.Backend = adapter.ExtLogsBackendNoop
				}
				extLogsBackendName = cfg.Backend
				cat[adapter.IDExtLogs] = adapter.ExtLogsFactory(cfg)
			case adapter.IDOtelExport:
				otelExportEnabled = true
				cfg := adapter.OtelExportConfig{
					Backend: adapter.OtelExportBackendName(strings.ToLower(strings.TrimSpace(*otelExportBackend))),
					BaseURL: strings.TrimSpace(*otelExportBaseURL),
				}
				if cfg.Backend == "" {
					cfg.Backend = adapter.OtelExportBackendNoop
				}
				otelExportBackendName = cfg.Backend
				cat[adapter.IDOtelExport] = adapter.OtelExportFactory(cfg)
			}
		}
		// INT-002/003: modest default rate limit when a non-noop backend is used
		// (mock/http). Capacity 0 remains unlimited for noop-only enables.
		var rateCap, rateRefill float64
		if extLogsEnabled {
			c, r := adapter.DefaultRateLimitForExtLogsBackend(extLogsBackendName)
			if c > rateCap {
				rateCap, rateRefill = c, r
			}
			if c > 0 {
				log.Printf("adapter rate limit default: capacity=%.0f refill=%.1f/s (ext-logs backend=%s)",
					c, r, extLogsBackendName)
			}
		}
		if otelExportEnabled {
			c, r := adapter.DefaultRateLimitForOtelExportBackend(otelExportBackendName)
			if c > rateCap {
				rateCap, rateRefill = c, r
			}
			if c > 0 {
				log.Printf("adapter rate limit default: capacity=%.0f refill=%.1f/s (otel-export backend=%s)",
					c, r, otelExportBackendName)
			}
		}
		reg := adapter.NewRegistry(adapter.Config{
			EnabledIDs:     append([]string(nil), enableAdapters...),
			Allowlist:      al,
			Catalog:        cat,
			RateCapacity:   rateCap,
			RateRefillPerS: rateRefill,
			Host: adapter.Host{
				Logger: func(format string, args ...any) {
					log.Printf("adapter: "+format, args...)
				},
			},
		})
		if err := reg.RegisterEnabled(); err != nil {
			return err
		}
		// Start failures mark adapters unhealthy; do not crash serve for partial
		// start, but log loudly. Unknown/unapproved already failed at Register.
		if err := reg.StartAll(serveCtx); err != nil {
			log.Printf("warning: adapter start: %v", err)
		}
		defer func() {
			_ = reg.StopAll(context.Background())
		}()
		adapterReg = reg
		log.Printf("Adapters enabled: %s", strings.Join(reg.IDs(), ","))
	}

	// AuthGate: AUTH-004 mid-serve whoAmI re-verify (api_token + OIDC) plus OIDC
	// LiveSessionSource epoch/guard. Order: epoch/Live first, then whoAmI (MultiGate).
	// Wave 28: optional Audit sink + ProfileID for fail-closed re-verify events
	// (principal drift / 401 / unbound). Emit is best-effort; never elevates.
	reverifyProfileID := string(profileID)
	if reverifyProfileID == "" {
		reverifyProfileID = string(authPr.ID)
	}
	reverifyGate := auth.NewIdentityReverifyGate(auth.IdentityReverifyConfig{
		Profile: authPr,
		Session: func(ctx context.Context) (auth.Session, error) {
			// Prefer live OIDC credentials (post-refresh) when available.
			if oidcSess.Live != nil {
				creds, err := oidcSess.Live.Credentials(ctx)
				if err != nil {
					return auth.Session{}, err
				}
				out := sess
				out.User = creds.User
				if out.User == "" {
					out.User = sess.User
				}
				out.Secret = creds.Secret
				out.Method = auth.MethodOIDC
				return out, nil
			}
			// api_token / static session: copy at call time (secret stays in-memory).
			return sess, nil
		},
		Cache:            idCache,
		HTTP:             hc.API,
		BoundPrincipalID: principal.ID,
		Audit:            auditSink,
		ProfileID:        reverifyProfileID,
	})
	var authGate tools.AuthGate
	switch {
	case oidcSess.Live != nil:
		authGate = auth.MultiGates(oidcSess.Live, reverifyGate)
	case sessionGuard != nil:
		authGate = auth.MultiGates(sessionGuard, reverifyGate)
	default:
		// api_token (and any path without Live/guard): continuous principal binding.
		authGate = reverifyGate
	}
	server := mcpserver.NewServer(mcpserver.DefaultServerName, version)
	// INT-002 / INT-003 / INT-004: optional tools off unless adapters enabled.
	enableTraceRefs := false
	enableChangeCorrelation := false
	for _, id := range enableAdapters {
		switch strings.ToLower(strings.TrimSpace(id)) {
		case adapter.IDOtelCorrelate:
			enableTraceRefs = true
			log.Printf("INT-002: jenkins_get_trace_refs enabled (build-metadata correlation; no OTLP export)")
		case adapter.IDOtelExport:
			if adapterReg != nil {
				if entry := adapterReg.Get(adapter.IDOtelExport); entry != nil {
					if e, ok := entry.Adapter.(adapter.TraceExporter); ok {
						traceExporter = &otelExportBridge{entry: entry, e: e}
						log.Printf("INT-002: jenkins_export_trace_refs enabled (metadata-only export stub; OTLP protobuf residual)")
					}
				}
			}
		case adapter.IDExtLogs:
			if adapterReg != nil {
				if entry := adapterReg.Get(adapter.IDExtLogs); entry != nil {
					if q, ok := entry.Adapter.(adapter.ExternalLogQuery); ok {
						externalLogs = &extLogsBridge{entry: entry, q: q}
						log.Printf("INT-003: jenkins_query_external_logs enabled (job/build query only; SaaS client residual)")
					}
				}
			}
		case adapter.IDWorkItems:
			enableChangeCorrelation = true
			if adapterReg != nil {
				if entry := adapterReg.Get(adapter.IDWorkItems); entry != nil {
					if w, ok := entry.Adapter.(adapter.WorkItemLookup); ok {
						workItemLookup = &workItemsBridge{entry: entry, w: w}
					}
				}
			}
			log.Printf("INT-004: jenkins_get_change_correlation enabled (Jenkins metadata refs only; ticket API residual)")
		}
	}
	// OPS-001 / Wave 32: wire jenkins_doctor with live RO gate (DynamicForce) +
	// circuit/metrics so mutations registration status matches serve posture.
	var doctorFn tools.DoctorFunc
	if profDoc != nil {
		docProf := profDoc
		docGate := gate
		docPol := polRes
		docMetrics := metrics
		docClient := client
		docAllowMut := *allowMutations
		docFlagRO := *readOnly
		doctorFn = func(ctx context.Context, offline bool) (diagnostics.Report, error) {
			paths, perr := config.Resolve()
			if perr != nil {
				return diagnostics.Report{}, perr
			}
			polPtr := &docPol
			return diagnostics.RunDoctor(ctx, diagnostics.DoctorOptions{
				Profile:        docProf,
				Paths:          &paths,
				Keyring:        keyringStore(),
				Version:        version,
				Commit:         commit,
				BuildTime:      buildTime,
				SkipNetwork:    offline,
				PolicyResult:   polPtr,
				FlagReadOnly:   docFlagRO,
				AllowMutations: docAllowMut,
				Gate:           docGate,
				Metrics:        docMetrics,
				Circuit:        docClient,
			})
		}
	}
	tools.Register(server, client, &tools.RegisterOptions{
		Gate:                    gate,
		Budgets:                 budgets,
		LiveHardMax:             liveHardMax,
		Policy:                  evaluator,
		Subject:                 subject,
		AuthGate:                authGate,
		Audit:                   auditSink,
		Metrics:                 metrics,
		Logger:                  serveLogger,
		ProfileID:               string(subject.ProfileID),
		PrincipalID:             subject.JenkinsUserID,
		LogSearch:               logSearch,
		Logs:                    logAccess,
		Meta:                    storeMeta, // durable survey compact cache when profile data dir open
		EnableTraceRefs:         enableTraceRefs,
		TraceExporter:           traceExporter,
		ExternalLogs:            externalLogs,
		EnableChangeCorrelation: enableChangeCorrelation,
		WorkItemLookup:          workItemLookup,
		Doctor:                  doctorFn,
	})
	if *httpAddr != "" {
		cfg := mcpserver.DefaultHTTPConfig()
		cfg.Addr = *httpAddr
		cfg.AllowNonLocal = *httpAllowNonLocal
		cfg.AllowedOrigins = append([]string(nil), httpAllowedOrigins...)
		cfg.AllowedHosts = append([]string(nil), httpAllowedHosts...)
		cfg.RequireToken = resolveHTTPRequireToken(*httpRequireToken)
		// HOST-001 production JWT: secret-free JWKS/iss/aud env (optional).
		jwtEnv, err := parseHTTPJWTEnv(os.Getenv)
		if err != nil {
			return err
		}
		// HOST-001: gateway / --http-require-subject / JWT_REQUIRED / non-local require subject.
		cfg.RequireSubject = resolveHTTPRequireSubject(*httpRequireSubject, useGateway) || jwtEnv.Required
		cfg.LabIdentity = labIdentityEnabled()
		// Wave 44 Track C: explicit positive MaxBodyBytes after resolve (0→default).
		maxBody, err := mcpserver.ResolveHTTPMaxBodyBytes(*httpMaxBodyBytesFlag, os.Getenv(mcpserver.EnvHTTPMaxBodyBytes))
		if err != nil {
			return err
		}
		cfg.MaxBodyBytes = maxBody
		token, err := loadHTTPServeToken(*httpTokenEnv, *httpTokenFile)
		if err != nil {
			return err
		}
		cfg.BearerToken = token
		var jwks *auth.JWKS
		if jwtEnv.Configured() {
			// Fetch once at serve start (fail closed). Mid-session JWKS rebind residual.
			jwks, err = fetchHTTPJWKS(serveCtx, nil, jwtEnv)
			if err != nil {
				return err
			}
		}
		cfg.IdentityResolver = newHTTPIdentityResolver(cfg.LabIdentity, token, jwks, auth.AccessTokenParams{
			Issuer:   jwtEnv.Issuer,
			Audience: jwtEnv.Audience,
		})
		// Never log token values — only required/configured bools and body cap.
		log.Printf("http serve token policy: http_token_required=%v http_token_configured=%v http_subject_required=%v lab_identity=%v http_jwt_configured=%v http_jwt_required=%v max_body_bytes=%d",
			mcpserver.HTTPTokenRequired(cfg), cfg.BearerToken != "",
			mcpserver.HTTPSubjectRequired(cfg), cfg.LabIdentity,
			jwtEnv.Configured(), jwtEnv.Required, cfg.MaxBodyBytes)
		if err := mcpserver.RunHTTP(serveCtx, server, cfg); err != nil {
			return err
		}
		return nil
	}
	if strings.TrimSpace(*httpTokenEnv) != "" || strings.TrimSpace(*httpTokenFile) != "" {
		return apperr.New(apperr.CodeInvalidArgument,
			"--http-token-env / --http-token-file require --http")
	}
	if *httpRequireToken || envHTTPRequireTokenTruthy() || envHTTPDenyAnonymousTruthy() {
		return apperr.New(apperr.CodeInvalidArgument,
			"--http-require-token / JENKINS_MCP_HTTP_REQUIRE_TOKEN / JENKINS_MCP_HTTP_DENY_ANONYMOUS require --http")
	}
	if *httpRequireSubject || envHTTPRequireSubjectTruthy() {
		return apperr.New(apperr.CodeInvalidArgument,
			"--http-require-subject / JENKINS_MCP_HTTP_REQUIRE_SUBJECT require --http")
	}
	if envHTTPJWTConfigured() {
		return apperr.New(apperr.CodeInvalidArgument,
			"JENKINS_MCP_HTTP_JWKS_URL / JENKINS_MCP_HTTP_JWT_* require --http")
	}
	if strings.TrimSpace(*httpMaxBodyBytesFlag) != "" {
		return apperr.New(apperr.CodeInvalidArgument,
			"--http-max-body-bytes require --http")
	}
	if *useStdio {
		log.Printf("Starting MCP server over stdio")
		serveLogger.Info("mcp_transport_start", "transport", "stdio")
		if err := mcpserver.RunStdio(serveCtx, server); err != nil {
			// Surface to operator stderr (redacted) and structured error for pilot capture.
			log.Printf("server error: %v", err)
			serveLogger.Error("mcp_server_stopped",
				"transport", "stdio",
				"error_code", string(apperr.CodeOf(err)),
				"error", apperr.ModelMessage(err),
			)
			return err
		}
		serveLogger.Info("mcp_server_stopped", "transport", "stdio", "clean", "true")
		return nil
	}
	return apperr.New(apperr.CodeInvalidArgument, "no transport selected; use -http or -stdio")
}

// disableCacheMaintenance is true when CLI or env opts out of the serve-time loop.
func disableCacheMaintenance(flagNo bool) bool {
	if flagNo {
		return true
	}
	v := strings.TrimSpace(os.Getenv("JENKINS_MCP_NO_CACHE_MAINTENANCE"))
	return v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes")
}

// parseCacheMaintenanceInterval is a thin main wrapper around
// app.ResolveMaintenanceInterval (default → env → flag; min 30s max 1h fail-closed).
func parseCacheMaintenanceInterval(flagVal string) (time.Duration, error) {
	return app.ResolveMaintenanceInterval(flagVal, os.Getenv(app.EnvCacheMaintenanceInterval))
}

// resolveProfileDataDir returns the secure per-profile data root for log store.
func resolveProfileDataDir(p *profile.Profile) (string, error) {
	if p == nil {
		return "", apperr.New(apperr.CodeInvalidArgument, "profile is required")
	}
	id := string(p.ID)
	if p.DataDir != "" {
		return store.EnsureProfileDataDir(p.DataDir, id)
	}
	paths, err := config.Resolve()
	if err != nil {
		return "", err
	}
	return store.EnsureProfileDataDir(paths.ProfileDataDir(id), id)
}

// sessionEpochStoreForProfile returns a SessionEpochStore under the profile
// data directory (non-secret session.epoch for cross-process logout).
func sessionEpochStoreForProfile(p *profile.Profile) (*auth.SessionEpochStore, error) {
	dir, err := resolveProfileDataDir(p)
	if err != nil {
		return nil, err
	}
	return &auth.SessionEpochStore{Dir: dir}, nil
}

// transportConfigFromProfile merges profile network fields with CLI overrides (NET-004).
// CLI --ca-bundle / --proxy win when non-empty. Diagnostic insecure TLS never comes from profile.
func transportConfigFromProfile(p *profile.Profile, caBundleFlag, proxyFlag string, diagInsecure bool) jenkins.TransportConfig {
	cfg := jenkins.DefaultTransportConfig()
	if p != nil {
		if p.CABundlePath != "" {
			cfg.CABundlePath = p.CABundlePath
		}
		if p.ProxyURL != "" {
			cfg.ProxyURL = p.ProxyURL
		}
		if len(p.NoProxy) > 0 {
			cfg.NoProxy = append([]string(nil), p.NoProxy...)
		}
		if p.ClientCertFile != "" {
			cfg.ClientCertFile = p.ClientCertFile
		}
		if p.ClientKeyFile != "" {
			cfg.ClientKeyFile = p.ClientKeyFile
		}
	}
	if strings.TrimSpace(caBundleFlag) != "" {
		cfg.CABundlePath = strings.TrimSpace(caBundleFlag)
	}
	if strings.TrimSpace(proxyFlag) != "" {
		cfg.ProxyURL = strings.TrimSpace(proxyFlag)
	}
	// Never load DiagnosticInsecureTLS from profile; CLI + env gate only.
	cfg.DiagnosticInsecureTLS = diagInsecure
	return cfg
}

// reorderFlagArgs moves `-flag value` pairs ahead of positionals so stdlib flag
// can parse `cmd positional --flag value` forms.
// valueFlags names long options that take a following argument (without leading dashes).
func reorderFlagArgs(args []string, valueFlags map[string]bool) []string {
	var flags, pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			pos = append(pos, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(a, "-") {
			pos = append(pos, a)
			continue
		}
		flags = append(flags, a)
		// -flag=value already self-contained
		if strings.Contains(a, "=") {
			continue
		}
		name := strings.TrimLeft(a, "-")
		if valueFlags[name] && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
			i++
			flags = append(flags, args[i])
		}
	}
	return append(flags, pos...)
}

// requireGatewayProvider selects the gateway CredentialProvider from env
// (HOST-009 Mode A api_token_vault or Mode C AgentCore; Mode B residual).
//
// Mode A: Live vault provider (per-subject Obtain → Basic AuthProvider, HOST-003).
// Mode C: AgentCore provider with Live=false until TokenFetcher wire; when not
// Ready, serve keeps local keyring/OIDC Jenkins HTTP residual. Never falls back
// to a shared SA. When Ready, attachGatewayObtainAuthProvider wires Obtain.
func requireGatewayProvider(jenkinsBaseURL string) (gateway.CredentialProvider, error) {
	return gateway.CredentialProviderFromEnviron(jenkinsBaseURL, nil)
}

// bindGatewaySubject maps trusted gateway env claims + verified Jenkins principal
// into policy.Subject (GWY-002). Tool arguments never contribute identity.
//
// Env (non-secret labels only):
//
//	JENKINS_MCP_GATEWAY_SUBJECT   (required) Entra/OIDC sub
//	JENKINS_MCP_GATEWAY_TENANT    (required) tenant id
//	JENKINS_MCP_GATEWAY_WORKLOAD  (required) workload id
//	JENKINS_MCP_GATEWAY_JENKINS_PRINCIPAL (optional; defaults to verified whoAmI id)
func bindGatewaySubject(profileID contracts.ProfileID, verifiedJenkinsUser string) (policy.Subject, error) {
	return gateway.BindSubjectFromEnviron(profileID, verifiedJenkinsUser, nil)
}
