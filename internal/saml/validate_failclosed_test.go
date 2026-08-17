package saml_test

import (
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/saml"
)

// Regression: an assertion with no expiry (no Conditions.NotOnOrAfter and no
// SubjectConfirmationData.NotOnOrAfter) previously passed time validation
// forever — a captured assertion became a permanent bearer credential.
// Fail closed when no expiry is present.
func TestSAML_FailClosed_MissingExpiry(t *testing.T) {
	t.Parallel()
	priv, pub := testRSA(t)
	cfg := testCfg()
	raw := buildAssertionXML(t, priv, func(body *string) {
		// Strip both NotOnOrAfter attributes.
		s := strings.ReplaceAll(*body, ` NotOnOrAfter="`+time.Now().UTC().Add(10*time.Minute).Format(time.RFC3339)+`"`, "")
		*body = s
	})
	_, err := saml.ValidateAndMap(cfg, raw, saml.ValidateOptions{
		Now:   time.Now().UTC(),
		Trust: saml.TrustMaterial{PublicKey: pub},
	})
	if err == nil || apperr.CodeOf(err) != apperr.CodeAuthentication {
		t.Fatalf("assertion without expiry must fail closed, got %v", err)
	}
}

// Regression: a malformed security timestamp was silently treated as "absent"
// (and absent meant unbounded validity). Malformed NotOnOrAfter / NotBefore
// must fail closed at parse, not degrade to no time bound.
func TestSAML_FailClosed_MalformedTimestamps(t *testing.T) {
	t.Parallel()
	priv, pub := testRSA(t)
	cfg := testCfg()

	mutate := func(tag string) func(*string) {
		return func(body *string) {
			// Corrupt the FIRST occurrence of the named timestamp attribute.
			idx := strings.Index(*body, tag)
			if idx < 0 {
				t.Fatalf("fixture missing %s", tag)
			}
			rest := (*body)[idx:]
			end := strings.Index(rest, `"`)
			if end < 0 {
				t.Fatalf("fixture malformed around %s", tag)
			}
			*body = (*body)[:idx] + tag[:len(tag)-1] + `2026-08-16 12:00:00` + `"` + rest[end+1:]
		}
	}

	for _, tag := range []string{`NotOnOrAfter="`, `NotBefore="`} {
		raw := buildAssertionXML(t, priv, mutate(tag))
		_, err := saml.ValidateAndMap(cfg, raw, saml.ValidateOptions{
			Now:   time.Now().UTC(),
			Trust: saml.TrustMaterial{PublicKey: pub},
		})
		if err == nil {
			t.Fatalf("malformed %s must fail closed", tag)
		}
		if apperr.CodeOf(err) == apperr.CodeInternal {
			t.Fatalf("malformed %s: want auth/invalid-argument class, got %v", tag, err)
		}
	}
}

// Regression: the Recipient check only fired when the assertion *contained* a
// Recipient — a bearer assertion with no SubjectConfirmationData/Recipient was
// accepted even with acs_url configured. The SAML Bearer profile requires
// Recipient presence + equality; fail closed when it is absent.
func TestSAML_FailClosed_MissingRecipient(t *testing.T) {
	t.Parallel()
	priv, pub := testRSA(t)
	cfg := testCfg()
	raw := buildAssertionXML(t, priv, func(body *string) {
		// Remove the Recipient attribute (keep the confirmation element).
		na := time.Now().UTC().Add(10 * time.Minute).Format(time.RFC3339)
		*body = strings.ReplaceAll(*body, ` Recipient="https://mcp.example/admin/v1/saml/acs"`, "")
		_ = na
	})
	_, err := saml.ValidateAndMap(cfg, raw, saml.ValidateOptions{
		Now:   time.Now().UTC(),
		Trust: saml.TrustMaterial{PublicKey: pub},
	})
	if err == nil || !strings.Contains(err.Error(), "recipient") {
		t.Fatalf("missing Recipient must fail closed with recipient error, got %v", err)
	}
}
