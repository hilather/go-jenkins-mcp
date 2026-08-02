// Package saml implements POL-007 SAML 2.0 service-provider identity mapping.
//
// The product is an SP only: Jenkins is never a SAML IdP/AS (ADR 0015 / ADR 0003).
// Configuration (SP settings, attribute map, group→admin role map) is file-based
// for multi-fleet gitops. Secrets (SP keys) come from env/secret store only.
//
// Pure validation + attribute map are unit-testable without a browser. HTTP ACS
// and cookie sessions are wired by the admin BFF. Live Entra/Okta/ADFS pin is residual.
package saml
