package saml

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/auth"
)

// EnvSAMLConfig is the optional path to the SP configuration JSON file.
// Empty → SAML disabled.
const EnvSAMLConfig = "JENKINS_MCP_SAML_CONFIG"

// Config is the versioned multi-fleet SAML SP configuration (POL-007).
// Secret-free except optional path to a PEM file for IdP trust material
// (certificate content is loaded from disk, never logged).
type Config struct {
	// SchemaVersion must be 1.
	SchemaVersion int `json:"schema_version"`

	// Enabled turns SAML surfaces on when config is present and valid.
	Enabled bool `json:"enabled"`

	// Require when true fails closed if SAML is not used for gated admin routes
	// (no open loopback API elevation). Default false preserves shared-secret pilot.
	Require bool `json:"require"`

	// SPEntityID is the SP audience / entityID (required when enabled).
	SPEntityID string `json:"sp_entity_id"`

	// ACSURL is the Assertion Consumer Service URL (recipient; required when enabled).
	ACSURL string `json:"acs_url"`

	// IdPEntityID pins the trusted issuer (required when enabled).
	IdPEntityID string `json:"idp_entity_id"`

	// IdPMetadataPath is optional static IdP metadata XML path (secret-free file).
	// When set, IdPEntityID and IdPCertificatePEMPath may be filled from metadata.
	IdPMetadataPath string `json:"idp_metadata_path,omitempty"`

	// IdPCertificatePEMPath is a PEM file of the IdP signing certificate (public).
	// Required when enabled unless tests inject TrustMaterial.
	IdPCertificatePEMPath string `json:"idp_certificate_pem_path,omitempty"`

	// AttributeMap maps assertion attributes → identity fields.
	AttributeMap AttributeMap `json:"attribute_map"`

	// GroupRoles maps IdP group ids → admin console roles (viewer|operator|policy_admin).
	// Empty map means SAML cannot elevate admin roles (fail closed for admin SSO).
	GroupRoles map[string]string `json:"group_roles,omitempty"`

	// MaxGroups caps stored groups (0 → auth.MaxStoredGroups). FailOnOverage is always true for SAML.
	MaxGroups int `json:"max_groups,omitempty"`

	// Tenant optional static tenant pin when assertions do not carry tenant.
	Tenant string `json:"tenant,omitempty"`
}

// AttributeMap names SAML attributes (or NameID) used for identity.
type AttributeMap struct {
	// SubjectAttribute empty → use NameID.
	SubjectAttribute string `json:"subject_attribute,omitempty"`
	// GroupsAttribute is required for group-based RBAC (multi-value).
	GroupsAttribute string `json:"groups_attribute,omitempty"`
	// TenantAttribute optional.
	TenantAttribute string `json:"tenant_attribute,omitempty"`
}

// LoadConfigFile reads and validates a SAML SP config JSON file.
func LoadConfigFile(path string) (Config, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return Config{}, apperr.New(apperr.CodeInvalidArgument, "saml config path is empty")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, apperr.Wrap(apperr.CodeInvalidArgument,
			fmt.Sprintf("saml config unreadable: %s", baseName(path)), err)
	}
	return ParseConfig(raw)
}

// LoadConfigFromEnviron loads config from JENKINS_MCP_SAML_CONFIG when set.
// Empty env → (Config{}, nil) meaning SAML disabled.
func LoadConfigFromEnviron() (Config, error) {
	p := strings.TrimSpace(os.Getenv(EnvSAMLConfig))
	if p == "" {
		return Config{}, nil
	}
	return LoadConfigFile(p)
}

// ParseConfig unmarshals and validates config JSON.
func ParseConfig(raw []byte) (Config, error) {
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return Config{}, apperr.Wrap(apperr.CodeInvalidArgument, "saml config JSON invalid", err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate checks structural constraints (no network).
func (c Config) Validate() error {
	if c.SchemaVersion != 1 {
		return apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("unsupported saml schema_version %d (want 1)", c.SchemaVersion))
	}
	if !c.Enabled {
		return nil
	}
	if strings.TrimSpace(c.SPEntityID) == "" {
		return apperr.New(apperr.CodeInvalidArgument, "saml sp_entity_id is required when enabled")
	}
	if strings.TrimSpace(c.ACSURL) == "" {
		return apperr.New(apperr.CodeInvalidArgument, "saml acs_url is required when enabled")
	}
	if strings.TrimSpace(c.IdPEntityID) == "" {
		return apperr.New(apperr.CodeInvalidArgument, "saml idp_entity_id is required when enabled")
	}
	// Certificate path may be filled after metadata load; allow empty here when
	// TrustMaterial is injected by tests. Production wire checks cert presence.
	for g, role := range c.GroupRoles {
		if strings.TrimSpace(g) == "" {
			return apperr.New(apperr.CodeInvalidArgument, "saml group_roles has empty group key")
		}
		r := strings.TrimSpace(strings.ToLower(role))
		switch r {
		case "viewer", "operator", "policy_admin":
			// ok
		default:
			return apperr.New(apperr.CodeInvalidArgument,
				fmt.Sprintf("saml group_roles[%q] invalid role %q (want viewer|operator|policy_admin)", g, role))
		}
	}
	if c.MaxGroups < 0 {
		return apperr.New(apperr.CodeInvalidArgument, "saml max_groups must be non-negative")
	}
	return nil
}

// EffectiveMaxGroups returns the group cap.
func (c Config) EffectiveMaxGroups() int {
	if c.MaxGroups <= 0 {
		return auth.MaxStoredGroups
	}
	if c.MaxGroups > auth.MaxStoredGroups {
		return auth.MaxStoredGroups
	}
	return c.MaxGroups
}

// StatusMap is secret-free operator status (no certs, paths only as basenames).
func (c Config) StatusMap() map[string]any {
	return map[string]any{
		"enabled":              c.Enabled,
		"require":              c.Require,
		"schema_version":       c.SchemaVersion,
		"has_sp_entity_id":     strings.TrimSpace(c.SPEntityID) != "",
		"has_acs_url":          strings.TrimSpace(c.ACSURL) != "",
		"has_idp_entity_id":    strings.TrimSpace(c.IdPEntityID) != "",
		"has_idp_cert_path":    strings.TrimSpace(c.IdPCertificatePEMPath) != "",
		"has_idp_metadata":     strings.TrimSpace(c.IdPMetadataPath) != "",
		"group_role_bindings":  len(c.GroupRoles),
		"has_groups_attribute": strings.TrimSpace(c.AttributeMap.GroupsAttribute) != "",
		"residual":             "live_entra_okta_adfs_pin",
	}
}

func baseName(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return "(empty)"
	}
	if i := strings.LastIndexAny(p, `/\`); i >= 0 && i+1 < len(p) {
		return p[i+1:]
	}
	return p
}
