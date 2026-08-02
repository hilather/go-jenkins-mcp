// Package keyring is the OS secret-store adapter.
//
// Supported platforms (ADR 0008): Linux Secret Service (libsecret /
// org.freedesktop.secrets) via github.com/zalando/go-keyring on Rocky/Ubuntu.
// macOS Keychain and Windows Credential Manager are out of scope.
//
// Credentials never appear in CLI args, config files, logs, or MCP output.
// Unit tests use the Memory backend so CI needs no live keyring.
// Headless CI residual: set JENKINS_MCP_KEYRING_FILE to a path for a file-backed
// store (mode 0600); prefer OS Secret Service for operators.
//
// AUTH-002 — OS credential-store backends (API tokens).
// ARC-009 — per-profile cache AEAD keys (Set/Get/Delete/HasCacheKey; method=cache_aead).
// OAUTH-004 — OIDC token blobs (SetOIDCTokens / GetOIDCTokens; method=oidc_tokens).
package keyring
