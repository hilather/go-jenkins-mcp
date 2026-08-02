package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// resolveHTTPRequireToken combines --http-require-token with
// JENKINS_MCP_HTTP_REQUIRE_TOKEN and JENKINS_MCP_HTTP_DENY_ANONYMOUS
// (1/true/yes/on). Either env is an OR alias that sets RequireToken=true
// (same fail-closed ValidateHTTPConfig path). AllowNonLocal always requires
// a token (and AllowedHosts / AllowedOrigins) inside mcpserver.ValidateHTTPConfig.
//
// Default remains off: loopback without require/deny-anonymous still allows
// empty BearerToken (KD-008 residual for local pilot).
func resolveHTTPRequireToken(flagRequire bool) bool {
	if flagRequire {
		return true
	}
	return envHTTPRequireTokenTruthy() || envHTTPDenyAnonymousTruthy()
}

// envHTTPRequireTokenTruthy reports truthy JENKINS_MCP_HTTP_REQUIRE_TOKEN.
func envHTTPRequireTokenTruthy() bool {
	return envHTTPBoolTruthy("JENKINS_MCP_HTTP_REQUIRE_TOKEN")
}

// envHTTPDenyAnonymousTruthy reports truthy JENKINS_MCP_HTTP_DENY_ANONYMOUS.
// Alias of require-token: opt-in fail-closed shared secret on loopback (Wave 41).
func envHTTPDenyAnonymousTruthy() bool {
	return envHTTPBoolTruthy("JENKINS_MCP_HTTP_DENY_ANONYMOUS")
}

// envHTTPBoolTruthy reports whether name is set to a truthy value (1/true/yes/on).
func envHTTPBoolTruthy(name string) bool {
	v := strings.TrimSpace(os.Getenv(name))
	return v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes") || strings.EqualFold(v, "on")
}

// loadHTTPServeToken loads the optional Streamable HTTP shared secret for KD-008 lite.
// Exactly one of envVarName or filePath may be set (both empty → no token gate).
// The secret value is never accepted from a CLI flag value — only the env var
// *name* or file *path* appear on argv.
//
// File requirements: readable, non-empty after trimming trailing newlines, and
// mode with no group/other bits (0600 recommended).
func loadHTTPServeToken(envVarName, filePath string) (string, error) {
	envVarName = strings.TrimSpace(envVarName)
	filePath = strings.TrimSpace(filePath)
	if envVarName != "" && filePath != "" {
		return "", apperr.New(apperr.CodeInvalidArgument,
			"use only one of --http-token-env or --http-token-file (do not pass token on argv)")
	}
	if envVarName == "" && filePath == "" {
		return "", nil
	}
	if envVarName != "" {
		// LookupEnv distinguishes unset vs empty; both are fail-closed when flag set.
		v, ok := os.LookupEnv(envVarName)
		if !ok || v == "" {
			return "", apperr.New(apperr.CodeInvalidArgument,
				fmt.Sprintf("http token env %q is empty or unset", envVarName))
		}
		return v, nil
	}
	// File path mode.
	st, err := os.Stat(filePath)
	if err != nil {
		return "", apperr.Wrap(apperr.CodeInvalidArgument,
			fmt.Sprintf("http token file %q", filePath), err)
	}
	if st.IsDir() {
		return "", apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("http token file %q is a directory", filePath))
	}
	if perm := st.Mode().Perm(); perm&0o077 != 0 {
		return "", apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("http token file %q must be mode 0600 (no group/other access); got %04o",
				filePath, perm))
	}
	raw, err := os.ReadFile(filePath)
	if err != nil {
		return "", apperr.Wrap(apperr.CodeInvalidArgument,
			fmt.Sprintf("read http token file %q", filePath), err)
	}
	// Strip a single trailing newline convention; do not TrimSpace the whole
	// secret (spaces may be intentional). Reject empty after newline strip.
	token := string(raw)
	token = strings.TrimSuffix(token, "\n")
	token = strings.TrimSuffix(token, "\r")
	if token == "" {
		return "", apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("http token file %q is empty", filePath))
	}
	return token, nil
}
