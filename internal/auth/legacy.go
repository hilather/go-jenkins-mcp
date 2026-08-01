package auth

import (
	"os"
	"strings"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/contracts"
)

// LegacyEnvVar is the seed environment variable for user:token (KD-003).
// Deprecated: prefer profile + keyring login. Retained as bootstrap/opt-in only.
const LegacyEnvVar = "JENKINS_MCP_AUTH"

// ParseUserToken parses "user:api_token". The token is returned but must not be logged.
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

// LegacySessionFromEnv builds a Session from JENKINS_MCP_AUTH when set.
// Empty env returns a non-authenticated error. Deprecated bootstrap path only.
func LegacySessionFromEnv(profileID contracts.ProfileID) (Session, error) {
	return LegacySessionFromString(profileID, os.Getenv(LegacyEnvVar))
}

// LegacySessionFromString builds a Session from a raw "user:token" string
// (CLI -auth or env). Deprecated; do not use for enterprise happy path.
func LegacySessionFromString(profileID contracts.ProfileID, raw string) (Session, error) {
	user, token, err := ParseUserToken(raw)
	if err != nil {
		return Session{}, err
	}
	return Session{
		ProfileID: profileID,
		Method:    MethodAPIToken,
		User:      user,
		Secret:    token,
		ExpiresAt: time.Now().Add(12 * time.Hour),
	}, nil
}
