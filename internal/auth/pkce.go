package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// PKCE (RFC 7636) pure helpers for future Authorization Code + S256 browser
// login (OAUTH-002). OAUTH-001 ships helpers only — no browser loop.

const (
	// PKCEVerifierMinBytes is the minimum high-entropy input length before encoding.
	// RFC 7636 requires 43–128 characters of unreserved URL-safe output.
	PKCEVerifierMinBytes = 32
	// PKCEVerifierMaxBytes upper bound for GenerateCodeVerifier input entropy.
	PKCEVerifierMaxBytes = 96
	// DefaultPKCEVerifierBytes is the default entropy size (43-char base64url).
	DefaultPKCEVerifierBytes = 32
)

// GenerateCodeVerifier returns a high-entropy cryptographically random
// code_verifier suitable for S256 (URL-safe base64 without padding).
func GenerateCodeVerifier() (string, error) {
	return GenerateCodeVerifierN(DefaultPKCEVerifierBytes)
}

// GenerateCodeVerifierN generates a verifier from n random bytes (32–96).
func GenerateCodeVerifierN(n int) (string, error) {
	if n < PKCEVerifierMinBytes || n > PKCEVerifierMaxBytes {
		return "", apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("pkce verifier entropy must be %d-%d bytes", PKCEVerifierMinBytes, PKCEVerifierMaxBytes))
	}
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", apperr.Wrap(apperr.CodeInternal, "failed to generate pkce verifier", err)
	}
	v := base64.RawURLEncoding.EncodeToString(buf)
	if err := ValidateCodeVerifier(v); err != nil {
		return "", err
	}
	return v, nil
}

// CodeChallengeS256 returns BASE64URL-ENCODE(SHA256(ASCII(verifier))) without
// padding (RFC 7636 §4.2, method S256).
func CodeChallengeS256(verifier string) (string, error) {
	if err := ValidateCodeVerifier(verifier); err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// ValidateCodeVerifier checks RFC 7636 length and unreserved character set:
// ALPHA / DIGIT / "-" / "." / "_" / "~" and length 43–128.
func ValidateCodeVerifier(verifier string) error {
	n := len(verifier)
	if n < 43 || n > 128 {
		return apperr.New(apperr.CodeInvalidArgument,
			"pkce code_verifier must be 43-128 characters")
	}
	for i := 0; i < n; i++ {
		c := verifier[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '.' || c == '_' || c == '~' {
			continue
		}
		return apperr.New(apperr.CodeInvalidArgument,
			"pkce code_verifier contains invalid characters")
	}
	// Reject accidental whitespace-only after trim mistakes.
	if strings.TrimSpace(verifier) != verifier {
		return apperr.New(apperr.CodeInvalidArgument,
			"pkce code_verifier must not have surrounding whitespace")
	}
	return nil
}
