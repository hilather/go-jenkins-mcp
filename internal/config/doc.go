// Package config resolves non-secret filesystem locations (XDG config/data/cache)
// for jenkins-mcp. Secrets never live here; see keyring and auth.
//
// CFG-001 / AUTH-* path layout: $XDG_CONFIG_HOME/jenkins-mcp/profiles/<id>.json
package config
