// Package keyring is the OS secret-store adapter.
//
// Tier-1: Linux Secret Service (libsecret / org.freedesktop.secrets) via
// github.com/zalando/go-keyring. macOS Keychain is available when the same
// library is used on darwin (Tier-2, not a release gate). Windows Credential
// Manager is out of scope.
//
// Credentials never appear in CLI args, config files, logs, or MCP output.
// Unit tests use the Memory backend so CI needs no live keyring.
//
// AUTH-002 — OS credential-store backends (API tokens).
// ARC-009 — per-profile cache AEAD keys (Set/Get/Delete/HasCacheKey; method=cache_aead).
// OAUTH-004 — OIDC token blobs (SetOIDCTokens / GetOIDCTokens; method=oidc_tokens).
package keyring
