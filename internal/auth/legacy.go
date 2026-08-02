package auth

import (
	"os"
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// LegacyEnvVar is the retired environment variable for user:token bootstrap.
// Presence of this env (or CLI -auth) fails closed — use profile + keyring login.
const LegacyEnvVar = "JENKINS_MCP_AUTH"

// LegacyRetiredMessage is the operator-facing migration text (secret-free).
const LegacyRetiredMessage = "legacy -auth / JENKINS_MCP_AUTH bootstrap is removed; run jenkins-mcp login --profile <id> then serve --profile <id> (credentials in OS Secret Service or JENKINS_MCP_KEYRING_FILE for headless CI)"

// ParseUserToken parses "user:api_token". The token is returned but must not be logged.
// Retained for input validation helpers; serve never accepts this as a bootstrap path.
func ParseUserToken(raw string) (user, token string, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", apperr.New(apperr.CodeAuthentication, "authentication required")
	}
	if !strings.Contains(raw, ":") {
		return "", "", apperr.New(apperr.CodeInvalidArgument, "auth must be in format user:api_token")
	}
	parts := strings.SplitN(raw, ":", 2)
	user = strings.TrimSpace(parts[0])
	token = parts[1]
	if user == "" || token == "" {
		return "", "", apperr.New(apperr.CodeInvalidArgument, "auth must be in format user:api_token")
	}
	return user, token, nil
}

// RejectLegacyBootstrap fails closed when retired CLI -auth or JENKINS_MCP_AUTH is present.
// Call at serve entry so secrets never become a session.
func RejectLegacyBootstrap(authFlag string) error {
	if strings.TrimSpace(authFlag) != "" {
		return apperr.New(apperr.CodeAuthentication, LegacyRetiredMessage)
	}
	if strings.TrimSpace(os.Getenv(LegacyEnvVar)) != "" {
		return apperr.New(apperr.CodeAuthentication, LegacyRetiredMessage)
	}
	return nil
}
