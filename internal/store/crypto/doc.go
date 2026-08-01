// Package crypto implements optional application-level AEAD for L1 cache frames
// (ARC-009).
//
// Algorithm: AES-256-GCM (stdlib). Keys are 32-byte random values managed by
// package keyring (Secret Service); this package never persists keys.
//
// On-disk envelope (after zstd compression):
//
//	magic[4] = "JME1"
//	key_version u32 BE
//	nonce[12]
//	ciphertext || tag  (AES-GCM Seal of independent zstd frame)
//
// AAD binds generation id, frame seq, format version, and codec so metadata
// swap/tamper fails authentication before plaintext is returned.
//
// Default is off: callers must opt in via profile/env and supply keys.
// Residual: L2 pack body encryption is out of MVP scope; encrypted L1 frames
// are decrypted to pure zstd for zero-recompression copy into L2 packs.
package crypto
