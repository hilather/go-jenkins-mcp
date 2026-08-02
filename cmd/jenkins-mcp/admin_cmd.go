package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/hilather/go-jenkins-mcp/internal/admin"
	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/redact"
)

// runAdmin dispatches `jenkins-mcp admin <serve>`.
func runAdmin(args []string) error {
	if len(args) < 1 {
		return apperr.New(apperr.CodeInvalidArgument,
			"admin subcommand required: serve")
	}
	switch args[0] {
	case "serve":
		return runAdminServe(args[1:])
	case "-h", "--help", "help":
		fmt.Fprint(os.Stdout, adminUsage())
		return nil
	default:
		return apperr.New(apperr.CodeInvalidArgument,
			"unknown admin subcommand (serve)")
	}
}

func adminUsage() string {
	return `jenkins-mcp admin — local operator admin console BFF (UI-002 / UI-003 / UI-008 / ADR 0014)

Usage:
  jenkins-mcp admin serve --addr 127.0.0.1:8787 [--profile ID]
      [--admin-token-env VAR | --admin-token-file PATH]
      [--admin-role viewer|operator|policy_admin]
      [--assets-dir PATH] [--require-token] [--admin-allow-non-local]

serve:
  Starts a loopback-only HTTP server exposing secret-free JSON under
  /admin/v1/* (health, version, me, effective policy, metrics, audit, doctor).
  SPA assets (UI-008): --assets-dir, else package path
  /usr/share/jenkins-mcp/admin-ui, else web/admin/dist (dev), else embedded FS.
  Admin HTTP is off until this subcommand is used (default-off).

  Security (UI-008): strict CSP + nosniff/frame deny/referrer/permissions-policy
  on all responses; ReadTimeout 30s / WriteTimeout 60s / IdleTimeout 120s.
  Prefer same-origin reverse proxy that does not strip CSP.

  Default bind: 127.0.0.1:8787 (loopback only).
  Non-loopback requires --admin-allow-non-local AND a shared secret (fail closed).
  When --admin-token-env / --admin-token-file is set, all /admin/v1/* requests
  must present Authorization: Bearer or X-Jenkins-MCP-Admin-Token (constant-time).
  --require-token fails start if no token is configured.
  Token value is never accepted on argv — only env var name or file path.

  --admin-role sets the process-wide console RBAC role (default viewer):
    viewer        read-only admin API
    operator      day-2 ops (future cache destructive; reads same as viewer)
    policy_admin  future policy apply (reads same as viewer; cannot widen
                  enterprise force_read_only)
  Console roles are separate from MCP deny-only subjects.

  Residual: loopback without token is pilot-only (any local process can call
  the API with the configured role); prefer --require-token in shared hosts.
  v1 uses Bearer/header token (not cookies) — CSRF N/A; future cookie sessions
  will require CSRF. No CDN/SRI in v1 (assets self-hosted).

Endpoints:
  GET /admin/v1/health   (includes uiBuild when assets resolved)
  GET /admin/v1/version  (binary + uiBuild)
  GET /admin/v1/me
  GET /admin/v1/metrics
  GET /admin/v1/profiles/{id}/policy/effective
  GET /admin/v1/profiles/{id}/audit?limit=&type=&before=
  GET /admin/v1/profiles/{id}/doctor?offline=1
  GET /  (SPA, embed, or placeholder)
`
}

func runAdminServe(args []string) error {
	// KD-004: redact secrets from process logs for the serve lifetime.
	log.SetOutput(redact.NewWriter(os.Stderr))

	fs := flag.NewFlagSet("admin serve", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	addr := fs.String("addr", admin.DefaultAddr, "Listen address (loopback default 127.0.0.1:8787)")
	profileID := fs.String("profile", "", "Default profile id for /admin/v1/doctor")
	tokenEnv := fs.String("admin-token-env", "", "Env var name holding admin shared secret (not the token value)")
	tokenFile := fs.String("admin-token-file", "", "Path to file holding admin shared secret (mode 0600)")
	adminRole := fs.String("admin-role", string(admin.RoleViewer), "Admin console RBAC role: viewer|operator|policy_admin")
	assetsDir := fs.String("assets-dir", "", "SPA static root (UI-008); empty → package/dev/embed defaults")
	requireToken := fs.Bool("require-token", false, "Fail start if no admin token is configured")
	allowNonLocal := fs.Bool("admin-allow-non-local", false, "Allow non-loopback bind (residual; requires token)")
	if err := fs.Parse(args); err != nil {
		return apperr.New(apperr.CodeInvalidArgument, err.Error())
	}

	token, err := loadAdminToken(*tokenEnv, *tokenFile)
	if err != nil {
		return err
	}
	role, err := admin.ParseRole(*adminRole)
	if err != nil {
		return err
	}

	// POL-007: optional SAML SP from JENKINS_MCP_SAML_CONFIG (multi-fleet file SoT).
	samlOpts, err := admin.LoadSAMLOptionsFromEnviron()
	if err != nil {
		return err
	}

	assets := strings.TrimSpace(*assetsDir)
	// Resolve default assets so UIBuild is stamped into health/version (UI-008).
	resolved := admin.ResolveAssets(assets)

	cfg := admin.Config{
		Addr:            strings.TrimSpace(*addr),
		AllowNonLocal:   *allowNonLocal,
		BearerToken:     token,
		RequireToken:    *requireToken,
		Role:            role,
		AssetsDir:       assets,
		ProfileID:       strings.TrimSpace(*profileID),
		Version:         version,
		Commit:          commit,
		BuildTime:       buildTime,
		UIBuild:         resolved.UIBuild,
		Keyring:         keyringStore(),
		Logger:          log.Default(),
		ShutdownTimeout: 0, // package default
		SAML:            samlOpts,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return admin.Run(ctx, cfg)
}

// loadAdminToken loads the optional admin shared secret.
// Exactly one of envVarName or filePath may be set (both empty → no token gate).
// The secret value is never accepted from a CLI flag value — only the env var
// *name* or file *path* appear on argv. Same rules as Streamable HTTP token.
func loadAdminToken(envVarName, filePath string) (string, error) {
	envVarName = strings.TrimSpace(envVarName)
	filePath = strings.TrimSpace(filePath)
	if envVarName != "" && filePath != "" {
		return "", apperr.New(apperr.CodeInvalidArgument,
			"use only one of --admin-token-env or --admin-token-file (do not pass token on argv)")
	}
	if envVarName == "" && filePath == "" {
		return "", nil
	}
	if envVarName != "" {
		v, ok := os.LookupEnv(envVarName)
		v = strings.TrimSpace(v)
		if !ok || v == "" {
			return "", apperr.New(apperr.CodeInvalidArgument,
				fmt.Sprintf("admin token env %q is empty or unset", envVarName))
		}
		return v, nil
	}
	st, err := os.Stat(filePath)
	if err != nil {
		return "", apperr.Wrap(apperr.CodeInvalidArgument,
			fmt.Sprintf("admin token file %q", filePath), err)
	}
	if st.IsDir() {
		return "", apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("admin token file %q is a directory", filePath))
	}
	if perm := st.Mode().Perm(); perm&0o077 != 0 {
		return "", apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("admin token file %q must be mode 0600 (no group/other access); got %04o",
				filePath, perm))
	}
	raw, err := os.ReadFile(filePath)
	if err != nil {
		return "", apperr.Wrap(apperr.CodeInvalidArgument,
			fmt.Sprintf("read admin token file %q", filePath), err)
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return "", apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("admin token file %q is empty", filePath))
	}
	return token, nil
}
