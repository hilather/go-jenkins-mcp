package profile

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/contracts"
)

// CurrentConfigVersion is the schema version written by this binary.
// Bump only with an explicit migration path and tests.
const CurrentConfigVersion = 1

// AuthMethod is the non-secret authentication method selected for a profile.
type AuthMethod string

const (
	// AuthMethodAPIToken is personal Jenkins username + API token (first path).
	AuthMethodAPIToken AuthMethod = "api_token"
	// AuthMethodOIDC is external IdP OIDC bearer (OAUTH-001 profile + discovery;
	// browser PKCE login is OAUTH-002 residual).
	AuthMethodOIDC AuthMethod = "oidc_bearer"
	// AuthMethodAgentCoreDelegated is reserved for managed-gateway 3LO/OBO.
	AuthMethodAgentCoreDelegated AuthMethod = "agentcore_delegated"
)

// DefaultOIDCScopes is applied when an oidc_bearer profile omits scopes.
var DefaultOIDCScopes = []string{"openid"}

// Valid reports whether m is a known auth method enum value.
func (m AuthMethod) Valid() bool {
	switch m {
	case AuthMethodAPIToken, AuthMethodOIDC, AuthMethodAgentCoreDelegated:
		return true
	default:
		return false
	}
}

// Profile is the versioned, non-secret connection profile persisted on disk.
// It must never contain API tokens, passwords, refresh tokens, or client secrets.
type Profile struct {
	// ConfigVersion is the schema version (required on save; migrated on load).
	ConfigVersion int `json:"configVersion"`

	// ID is the stable profile identifier (filename stem); required.
	ID contracts.ProfileID `json:"id"`

	// DisplayName is an optional human label (may differ from ID).
	DisplayName string `json:"displayName,omitempty"`

	// JenkinsURL is the controller base URL (origin + optional path prefix).
	JenkinsURL string `json:"jenkinsURL"`

	// AuthMethod selects how credentials are obtained (api_token first).
	AuthMethod AuthMethod `json:"authMethod"`

	// Username is the Jenkins principal label for api_token profiles.
	// It is not a secret; the token lives only in the OS keyring.
	Username string `json:"username,omitempty"`

	// VerifiedPrincipalID is the last whoAmI id bound after successful login
	// verification (AUTH-004). Non-secret; never a token.
	VerifiedPrincipalID string `json:"verifiedPrincipalId,omitempty"`

	// VerifiedFullName is the optional whoAmI fullName from last verification.
	VerifiedFullName string `json:"verifiedFullName,omitempty"`

	// ReadOnly requests process-level read-only when true.
	// A stronger true from policy/CLI cannot be disabled by a weaker false (CFG-002).
	ReadOnly *bool `json:"readOnly,omitempty"`

	// DataDir is an optional absolute data root for this profile.
	// Empty means default under XDG data home (config.Paths.ProfileDataDir).
	DataDir string `json:"dataDir,omitempty"`

	// --- NET-004: non-secret TLS / proxy settings (no private keys or tokens) ---

	// CABundlePath is an optional PEM CA bundle path appended to the system trust store.
	CABundlePath string `json:"caBundlePath,omitempty"`

	// ProxyURL is an optional HTTP(S)/SOCKS5 proxy URL. Empty uses process environment
	// (HTTPS_PROXY / HTTP_PROXY). Use "direct" or "none" to disable env proxies.
	// Must not embed secrets in the URL when persisted; prefer a credential-free proxy URL.
	ProxyURL string `json:"proxyURL,omitempty"`

	// NoProxy is a NO_PROXY-style host list (exact host, domain suffix, or "*").
	NoProxy []string `json:"noProxy,omitempty"`

	// ClientCertFile / ClientKeyFile are optional PEM path references for mTLS.
	// Private key bytes are never stored in the profile document — only paths.
	ClientCertFile string `json:"clientCertFile,omitempty"`
	ClientKeyFile  string `json:"clientKeyFile,omitempty"`

	// Note: insecureSkipVerify / DiagnosticInsecureTLS must NEVER be persisted here.
	// Diagnostic TLS disablement requires CLI + JENKINS_MCP_DIAG_INSECURE_TLS=1.

	// --- ARC-009: optional application-level cache encryption (non-secret flags only) ---

	// CacheEncryption enables AES-256-GCM sealing of L1 frame payloads.
	// Default false. Env JENKINS_MCP_CACHE_ENCRYPTION=1 also enables at serve time.
	// Raw key material is never stored here — only in the OS keyring.
	CacheEncryption bool `json:"cacheEncryption,omitempty"`

	GatewayMode bool `json:"gatewayMode,omitempty"`

	// CacheKeyVersion is the active write key version N (reads accept N and N-1).
	// Zero means no key version recorded (encryption off or not yet initialized).
	CacheKeyVersion int `json:"cacheKeyVersion,omitempty"`

	// --- OAUTH-001: external IdP OIDC settings (non-secret only) ---

	// OIDC holds external authorization-server settings for authMethod oidc_bearer.
	// Never includes client_secret, refresh tokens, or access tokens (keyring later).
	// Required when AuthMethod is AuthMethodOIDC; must be nil for api_token.
	OIDC *OIDCConfig `json:"oidc,omitempty"`
}

// OIDCConfig is the non-secret external-IdP profile for Authorization Code + PKCE
// (OAUTH-001). Stock Jenkins is never the authorization server (ADR 0003).
//
// Local public clients have no embedded client secret; confidential-client
// secrets (if ever needed for gateway) belong in the OS keyring, not here.
type OIDCConfig struct {
	// Issuer is the OIDC Issuer Identifier (exact match against discovery "issuer").
	// Must be https (http allowed only for loopback test fixtures).
	Issuer string `json:"issuer"`

	// ClientID is the public OAuth client id at the external IdP.
	ClientID string `json:"clientId"`

	// RedirectURIs is the allowlist of exact redirect URIs for local PKCE
	// (typically loopback). Empty is allowed until OAUTH-002 browser login.
	RedirectURIs []string `json:"redirectUris,omitempty"`

	// Scopes requested from the IdP (default: openid). Must not imply Graph-only
	// audiences; Jenkins API access is governed by JenkinsAudience.
	Scopes []string `json:"scopes,omitempty"`

	// JenkinsAudience is the exact resource/audience value the access token must
	// carry for Jenkins API calls (bearer mode). Required and non-empty for
	// oidc_bearer — never a generic Graph or gateway default.
	JenkinsAudience string `json:"jenkinsAudience"`

	// TenantID is an optional IdP tenant restriction (e.g. Entra tenant GUID).
	// Empty means unrestricted beyond issuer match (enterprise policy may require it).
	TenantID string `json:"tenantId,omitempty"`
}

// idPattern restricts profile ids to safe filesystem / CLI tokens.
var idPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)

// Migrate upgrades a loaded profile document toward CurrentConfigVersion.
// Missing or zero configVersion is treated as pre-versioned and set to current
// after field defaults are applied.
func Migrate(p *Profile) error {
	if p == nil {
		return apperr.New(apperr.CodeInvalidArgument, "profile is nil")
	}
	if p.ConfigVersion < 0 {
		return apperr.New(apperr.CodeInvalidArgument, "configVersion must be non-negative")
	}
	if p.ConfigVersion > CurrentConfigVersion {
		return apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("unsupported configVersion %d (max %d); upgrade jenkins-mcp",
				p.ConfigVersion, CurrentConfigVersion))
	}
	// v0 / missing → v1 defaults.
	if p.ConfigVersion == 0 {
		if p.AuthMethod == "" {
			p.AuthMethod = AuthMethodAPIToken
		}
		p.ConfigVersion = CurrentConfigVersion
	}
	// Future: stepwise migrations for 1→2, etc.
	return nil
}

// Validate checks structural constraints. It does not touch the network or keyring.
func (p *Profile) Validate() error {
	if p == nil {
		return apperr.New(apperr.CodeInvalidArgument, "profile is nil")
	}
	if p.ConfigVersion != CurrentConfigVersion {
		return apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("configVersion must be %d after migration", CurrentConfigVersion))
	}
	id := strings.TrimSpace(string(p.ID))
	if id == "" {
		return apperr.New(apperr.CodeInvalidArgument, "profile id is required")
	}
	if !idPattern.MatchString(id) {
		return apperr.New(apperr.CodeInvalidArgument,
			"profile id must be 1-64 chars: alphanumeric, dot, underscore, hyphen; start alnum")
	}
	p.ID = contracts.ProfileID(id)

	if err := ValidateJenkinsURL(p.JenkinsURL); err != nil {
		return err
	}
	if !p.AuthMethod.Valid() {
		return apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("unsupported authMethod %q (use api_token, oidc_bearer, or agentcore_delegated)", p.AuthMethod))
	}
	// AgentCore delegated remains gateway residual (GWY-* / OAUTH-010+).
	if p.AuthMethod == AuthMethodAgentCoreDelegated {
		return apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("authMethod %q is reserved for managed-gateway deployments; use api_token or oidc_bearer", p.AuthMethod))
	}
	// OIDC profile structural checks (OAUTH-001). Online discovery is separate
	// (auth.ValidateDiscovery / CLI oauth validate-profile).
	if p.AuthMethod == AuthMethodOIDC {
		if err := p.validateOIDC(); err != nil {
			return err
		}
	} else if p.OIDC != nil {
		return apperr.New(apperr.CodeInvalidArgument,
			"oidc settings are only valid when authMethod is oidc_bearer")
	}
	if p.DataDir != "" {
		if !filepath.IsAbs(p.DataDir) {
			return apperr.New(apperr.CodeInvalidArgument, "dataDir must be absolute when set")
		}
		// Reject path traversal markers in the absolute path.
		clean := filepath.Clean(p.DataDir)
		if clean != p.DataDir {
			return apperr.New(apperr.CodeInvalidArgument, "dataDir must be a clean absolute path")
		}
	}
	if err := validateOptionalAbsPath("caBundlePath", p.CABundlePath); err != nil {
		return err
	}
	if err := validateOptionalAbsPath("clientCertFile", p.ClientCertFile); err != nil {
		return err
	}
	if err := validateOptionalAbsPath("clientKeyFile", p.ClientKeyFile); err != nil {
		return err
	}
	if (p.ClientCertFile == "") != (p.ClientKeyFile == "") {
		return apperr.New(apperr.CodeInvalidArgument,
			"clientCertFile and clientKeyFile must both be set or both empty")
	}
	if err := validateOptionalProxyURL(p.ProxyURL); err != nil {
		return err
	}
	if p.CacheEncryption && p.CacheKeyVersion < 1 {
		return apperr.New(apperr.CodeInvalidArgument,
			"cacheEncryption requires cacheKeyVersion >= 1 (run: jenkins-mcp cache key init --profile <id>)")
	}
	if p.CacheKeyVersion < 0 {
		return apperr.New(apperr.CodeInvalidArgument, "cacheKeyVersion must be non-negative")
	}
	return nil
}

// EnvCacheEncryption reports whether JENKINS_MCP_CACHE_ENCRYPTION enables AEAD.
// Accepted truthy values: 1, true, yes (case-insensitive).
func EnvCacheEncryption() bool {
	v := strings.TrimSpace(os.Getenv("JENKINS_MCP_CACHE_ENCRYPTION"))
	switch strings.ToLower(v) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// EffectiveCacheEncryption is true when profile flag or env enables encryption.
func (p *Profile) EffectiveCacheEncryption() bool {
	if p != nil && p.CacheEncryption {
		return true
	}
	return EnvCacheEncryption()
}

func validateOptionalAbsPath(field, path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	if !filepath.IsAbs(path) {
		return apperr.New(apperr.CodeInvalidArgument, field+" must be an absolute path when set")
	}
	if filepath.Clean(path) != path {
		return apperr.New(apperr.CodeInvalidArgument, field+" must be a clean absolute path")
	}
	return nil
}

func validateOptionalProxyURL(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	if strings.EqualFold(raw, "direct") || strings.EqualFold(raw, "none") {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return apperr.New(apperr.CodeInvalidArgument, "proxyURL is not a valid URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "socks5" {
		return apperr.New(apperr.CodeInvalidArgument, "proxyURL scheme must be http, https, or socks5")
	}
	if u.Host == "" {
		return apperr.New(apperr.CodeInvalidArgument, "proxyURL must include a host")
	}
	// Disallow embedding credentials in the persisted profile document.
	if u.User != nil {
		return apperr.New(apperr.CodeInvalidArgument,
			"proxyURL must not embed credentials in the profile; use a credential-free proxy URL or env")
	}
	return nil
}

// validateOIDC checks non-secret OIDC profile fields and rejects Jenkins-as-AS
// misconfiguration (issuer host must not equal Jenkins controller host).
func (p *Profile) validateOIDC() error {
	if p.OIDC == nil {
		return apperr.New(apperr.CodeInvalidArgument,
			"oidc settings are required when authMethod is oidc_bearer")
	}
	cfg := p.OIDC
	issuer := strings.TrimSpace(cfg.Issuer)
	if issuer == "" {
		return apperr.New(apperr.CodeInvalidArgument, "oidc.issuer is required")
	}
	cfg.Issuer = strings.TrimRight(issuer, "/")
	if err := validateOIDCIssuerURL(cfg.Issuer); err != nil {
		return err
	}
	clientID := strings.TrimSpace(cfg.ClientID)
	if clientID == "" {
		return apperr.New(apperr.CodeInvalidArgument, "oidc.clientId is required (public client; no client secret in profile)")
	}
	cfg.ClientID = clientID

	audience := strings.TrimSpace(cfg.JenkinsAudience)
	if audience == "" {
		return apperr.New(apperr.CodeInvalidArgument,
			"oidc.jenkinsAudience is required (exact Jenkins API resource/audience for bearer mode)")
	}
	cfg.JenkinsAudience = audience

	// Normalize scopes; default openid when omitted.
	scopes := make([]string, 0, len(cfg.Scopes))
	for _, s := range cfg.Scopes {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		scopes = append(scopes, s)
	}
	if len(scopes) == 0 {
		scopes = append([]string(nil), DefaultOIDCScopes...)
	}
	cfg.Scopes = scopes

	// Redirect allowlist: validate shape when present (OAUTH-002 fills browser loop).
	for i, raw := range cfg.RedirectURIs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return apperr.New(apperr.CodeInvalidArgument, "oidc.redirectUris must not contain empty entries")
		}
		if err := validateRedirectURI(raw); err != nil {
			return err
		}
		cfg.RedirectURIs[i] = raw
	}

	cfg.TenantID = strings.TrimSpace(cfg.TenantID)

	// Fail closed: stock Jenkins URL must never be the OIDC issuer (ADR 0003).
	if err := RejectJenkinsHostAsASEndpoint(cfg.Issuer, p.JenkinsURL); err != nil {
		return err
	}
	return nil
}

// validateOIDCIssuerURL requires an absolute http(s) issuer with a host and no
// credentials or fragment. Production IdPs should use https; http is permitted
// only so unit tests can use httptest loopback issuers.
func validateOIDCIssuerURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return apperr.New(apperr.CodeInvalidArgument, "oidc.issuer is not a valid URL")
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return apperr.New(apperr.CodeInvalidArgument, "oidc.issuer scheme must be https (or http for test fixtures)")
	}
	if u.Host == "" {
		return apperr.New(apperr.CodeInvalidArgument, "oidc.issuer must include a host")
	}
	if u.User != nil {
		return apperr.New(apperr.CodeInvalidArgument, "oidc.issuer must not embed credentials")
	}
	if u.Fragment != "" {
		return apperr.New(apperr.CodeInvalidArgument, "oidc.issuer must not include a fragment")
	}
	if u.RawQuery != "" {
		return apperr.New(apperr.CodeInvalidArgument, "oidc.issuer must not include a query string")
	}
	return nil
}

func validateRedirectURI(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return apperr.New(apperr.CodeInvalidArgument, "oidc.redirectUris entry is not a valid URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return apperr.New(apperr.CodeInvalidArgument, "oidc.redirectUris scheme must be http or https")
	}
	if u.Host == "" {
		return apperr.New(apperr.CodeInvalidArgument, "oidc.redirectUris must include a host")
	}
	if u.User != nil {
		return apperr.New(apperr.CodeInvalidArgument, "oidc.redirectUris must not embed credentials")
	}
	// Prefer loopback for public local clients (OAUTH-002); https non-loopback
	// is allowed for enterprise-registered redirect hosts.
	return nil
}

// RejectJenkinsHostAsASEndpoint fails when candidateURL's host equals the
// Jenkins controller host. Used by profile OIDC validation so stock Jenkins is
// never treated as the OAuth authorization server (JAS-001 / ADR 0003).
//
// Package auth cannot be imported here (auth → profile). Canonical helper for
// gateway/discovery/doctor is auth.RejectJenkinsAsAuthorizationServer; parity is
// contract-tested. Argument order is (candidate, jenkins) for historical call sites.
func RejectJenkinsHostAsASEndpoint(candidateURL, jenkinsURL string) error {
	candHost, err := urlHost(candidateURL)
	if err != nil {
		return apperr.New(apperr.CodeInvalidArgument, "authorization-server endpoint URL is invalid")
	}
	if candHost == "" {
		return apperr.New(apperr.CodeInvalidArgument, "authorization-server endpoint host is empty")
	}
	jenHost, err := urlHost(jenkinsURL)
	if err != nil {
		return err
	}
	if jenHost == "" {
		return apperr.New(apperr.CodeInvalidArgument, "jenkinsURL host is empty")
	}
	if strings.EqualFold(candHost, jenHost) {
		return apperr.New(apperr.CodeInvalidArgument,
			"authorization-server endpoint host must not equal the Jenkins controller host (Jenkins is not the OAuth AS; see ADR 0003 / docs/auth/jas-no-go.md)")
	}
	return nil
}

// urlHost returns the lowercase host[:port] from an absolute URL with default
// ports stripped (http/80, https/443) so co-hosted AS misconfiguration matches
// auth.RejectJenkinsAsAuthorizationServer.
func urlHost(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", apperr.New(apperr.CodeInvalidArgument, "URL is empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", apperr.New(apperr.CodeInvalidArgument, "URL is not valid")
	}
	if u.Host == "" {
		return "", nil
	}
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		return host + ":" + port, nil
	}
	return host, nil
}

// ValidateJenkinsURL ensures the controller URL is an absolute http(s) URL with a host.
func ValidateJenkinsURL(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return apperr.New(apperr.CodeInvalidArgument, "jenkinsURL is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return apperr.New(apperr.CodeInvalidArgument, "jenkinsURL is not a valid URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return apperr.New(apperr.CodeInvalidArgument, "jenkinsURL scheme must be http or https")
	}
	if u.Host == "" {
		return apperr.New(apperr.CodeInvalidArgument, "jenkinsURL must include a host")
	}
	if u.User != nil {
		return apperr.New(apperr.CodeInvalidArgument, "jenkinsURL must not embed credentials")
	}
	// Fragment is useless for an API base and often indicates paste mistakes.
	if u.Fragment != "" {
		return apperr.New(apperr.CodeInvalidArgument, "jenkinsURL must not include a fragment")
	}
	return nil
}

// NormalizedOrigin returns scheme://host[:port] for namespacing credentials.
// Path prefixes are dropped so keyring entries bind to the controller origin.
func NormalizedOrigin(raw string) (string, error) {
	if err := ValidateJenkinsURL(raw); err != nil {
		return "", err
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", apperr.New(apperr.CodeInvalidArgument, "jenkinsURL is not a valid URL")
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host), nil
}

// EffectiveReadOnly returns whether the profile requests read-only mode.
func (p *Profile) EffectiveReadOnly() bool {
	if p == nil || p.ReadOnly == nil {
		return false
	}
	return *p.ReadOnly
}

// AuthProfile returns the thin auth.Profile view used by credential providers.
// Kept here to avoid auth importing the full profile package for storage types.
func (p *Profile) AuthView() AuthView {
	if p == nil {
		return AuthView{}
	}
	return AuthView{
		ID:       p.ID,
		URL:      p.JenkinsURL,
		Method:   string(p.AuthMethod),
		Username: p.Username,
	}
}

// AuthView is a non-secret subset passed into credential providers without
// creating an import cycle with package auth.
type AuthView struct {
	ID       contracts.ProfileID
	URL      string
	Method   string
	Username string
}
