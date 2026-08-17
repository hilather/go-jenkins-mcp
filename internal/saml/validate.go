package saml

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// TrustMaterial holds IdP public verification material (no private keys).
type TrustMaterial struct {
	// PublicKey is the IdP RSA public key used to verify assertion signatures.
	PublicKey *rsa.PublicKey
	// Certificate optional leaf for operators (public only).
	Certificate *x509.Certificate
}

// LoadTrustFromPEMFile loads an RSA public key or certificate from PEM.
func LoadTrustFromPEMFile(path string) (TrustMaterial, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return TrustMaterial{}, apperr.New(apperr.CodeInvalidArgument, "saml idp certificate path is empty")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return TrustMaterial{}, apperr.Wrap(apperr.CodeInvalidArgument,
			fmt.Sprintf("saml idp certificate unreadable: %s", baseName(path)), err)
	}
	return LoadTrustFromPEM(raw)
}

// LoadTrustFromPEM parses PEM certificate or PKIX public key.
func LoadTrustFromPEM(pemBytes []byte) (TrustMaterial, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return TrustMaterial{}, apperr.New(apperr.CodeInvalidArgument, "saml idp trust PEM invalid")
	}
	switch block.Type {
	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return TrustMaterial{}, apperr.Wrap(apperr.CodeInvalidArgument, "saml idp certificate parse failed", err)
		}
		pub, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return TrustMaterial{}, apperr.New(apperr.CodeInvalidArgument, "saml idp certificate is not RSA")
		}
		return TrustMaterial{PublicKey: pub, Certificate: cert}, nil
	case "PUBLIC KEY", "RSA PUBLIC KEY":
		pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			// try PKCS1
			pub, err2 := x509.ParsePKCS1PublicKey(block.Bytes)
			if err2 != nil {
				return TrustMaterial{}, apperr.Wrap(apperr.CodeInvalidArgument, "saml idp public key parse failed", err)
			}
			return TrustMaterial{PublicKey: pub}, nil
		}
		pub, ok := pubAny.(*rsa.PublicKey)
		if !ok {
			return TrustMaterial{}, apperr.New(apperr.CodeInvalidArgument, "saml idp public key is not RSA")
		}
		return TrustMaterial{PublicKey: pub}, nil
	default:
		return TrustMaterial{}, apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("unsupported saml trust PEM type %q", block.Type))
	}
}

// ValidateOptions controls time and injected trust for tests.
type ValidateOptions struct {
	Now   time.Time
	Trust TrustMaterial
	// ClockSkew allowed for NotBefore/NotOnOrAfter (default 2m).
	ClockSkew time.Duration
}

// ValidateAndMap parses assertion XML, verifies signature + conditions, maps identity.
func ValidateAndMap(cfg Config, assertionXML []byte, opts ValidateOptions) (Identity, error) {
	if !cfg.Enabled {
		return Identity{}, apperr.New(apperr.CodeAuthentication, "saml is disabled")
	}
	pa, err := ParseAssertionXML(assertionXML)
	if err != nil {
		return Identity{}, err
	}
	if err := ValidateParsed(cfg, pa, opts); err != nil {
		return Identity{}, err
	}
	return MapIdentity(cfg, pa.NameID, pa.Attributes, pa.Issuer)
}

// ValidateParsed checks signature, issuer, audience, recipient, time window.
func ValidateParsed(cfg Config, pa ParsedAssertion, opts ValidateOptions) error {
	if !cfg.Enabled {
		return apperr.New(apperr.CodeAuthentication, "saml is disabled")
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	skew := opts.ClockSkew
	if skew <= 0 {
		skew = 2 * time.Minute
	}

	// Issuer pin
	wantIssuer := strings.TrimSpace(cfg.IdPEntityID)
	if wantIssuer == "" || !strings.EqualFold(strings.TrimSpace(pa.Issuer), wantIssuer) {
		return apperr.New(apperr.CodeAuthentication, "saml assertion issuer is not trusted")
	}

	// Audience = SP entity ID
	wantAud := strings.TrimSpace(cfg.SPEntityID)
	if wantAud == "" || strings.TrimSpace(pa.Audience) != wantAud {
		return apperr.New(apperr.CodeAuthentication, "saml assertion audience mismatch")
	}

	// Recipient = ACS URL. The SAML bearer profile requires the assertion to
	// carry Recipient and for it to equal the ACS URL — a missing Recipient is
	// NOT skipped (that would accept assertions minted for another SP/ACS).
	wantRec := strings.TrimSpace(cfg.ACSURL)
	if wantRec != "" {
		if strings.TrimSpace(pa.Recipient) == "" {
			return apperr.New(apperr.CodeAuthentication, "saml assertion recipient missing")
		}
		if pa.Recipient != wantRec {
			return apperr.New(apperr.CodeAuthentication, "saml assertion recipient mismatch")
		}
	}

	// Time window. An expiry is required: a correctly-signed assertion without
	// NotOnOrAfter is otherwise a permanent bearer credential.
	if pa.NotOnOrAfter.IsZero() {
		return apperr.New(apperr.CodeAuthentication, "saml assertion has no expiry (NotOnOrAfter required)")
	}
	if !pa.NotBefore.IsZero() && now.Add(skew).Before(pa.NotBefore) {
		return apperr.New(apperr.CodeAuthentication, "saml assertion not yet valid")
	}
	if !now.Add(-skew).Before(pa.NotOnOrAfter) {
		// now >= NotOnOrAfter (with skew)
		return apperr.New(apperr.CodeAuthentication, "saml assertion expired")
	}

	// Signature required
	if strings.TrimSpace(pa.SignatureValueB64) == "" {
		return apperr.New(apperr.CodeAuthentication, "saml assertion signature missing")
	}
	if opts.Trust.PublicKey == nil {
		return apperr.New(apperr.CodeAuthentication, "saml idp trust material missing")
	}
	payload := pa.SignedPayload
	if len(payload) == 0 {
		return apperr.New(apperr.CodeAuthentication, "saml signed payload empty")
	}
	if err := verifyRSASHA256(opts.Trust.PublicKey, payload, pa.SignatureValueB64); err != nil {
		return apperr.New(apperr.CodeAuthentication, "saml assertion signature invalid")
	}
	return nil
}

func verifyRSASHA256(pub *rsa.PublicKey, payload []byte, sigB64 string) error {
	sigB64 = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, strings.TrimSpace(sigB64))
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		sig, err = base64.RawStdEncoding.DecodeString(sigB64)
		if err != nil {
			return err
		}
	}
	sum := sha256.Sum256(payload)
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig)
}

// SignPayloadRSASHA256 signs payload for fixtures (tests / mock IdP only).
func SignPayloadRSASHA256(priv *rsa.PrivateKey, payload []byte) (string, error) {
	if priv == nil {
		return "", apperr.New(apperr.CodeInvalidArgument, "private key required")
	}
	sum := sha256.Sum256(payload)
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}
