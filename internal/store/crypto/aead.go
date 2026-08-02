package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// Wire constants for the L1 encrypted frame envelope.
const (
	// Magic identifies AES-256-GCM frame envelopes (v1).
	Magic = "JME1"

	// AlgAES256GCM is the only approved AEAD for ARC-009 MVP.
	AlgAES256GCM = "aes-256-gcm"

	// KeySize is AES-256 key length.
	KeySize = 32

	// NonceSize is the GCM nonce length.
	NonceSize = 12

	// headerLen = magic + key_version + nonce.
	headerLen = 4 + 4 + NonceSize
)

// Key is a versioned AES-256 key. Material must never be logged or serialized
// into config, MCP results, pack manifests, or support bundles.
type Key struct {
	// Version is a positive integer (N for writes; N and N-1 for reads).
	Version int
	// Material is exactly KeySize bytes.
	Material []byte
}

// Envelope holds the write key (N) and optional previous key (N-1) for rotation.
// When Enabled is false, callers leave frames as plain zstd.
type Envelope struct {
	Enabled bool
	// Write is the current key for new frames (version N). Required when Enabled.
	Write Key
	// Prev is optional N-1 for reading frames sealed before rotation.
	Prev *Key
}

// Validate checks key material without revealing it in errors.
func (k Key) Validate() error {
	if k.Version < 1 {
		return apperr.New(apperr.CodeInvalidArgument, "cache key version must be >= 1")
	}
	if len(k.Material) != KeySize {
		return apperr.New(apperr.CodeInvalidArgument, "cache key must be 32 bytes")
	}
	return nil
}

// Validate checks the envelope configuration.
func (e *Envelope) Validate() error {
	if e == nil || !e.Enabled {
		return nil
	}
	if err := e.Write.Validate(); err != nil {
		return err
	}
	if e.Prev != nil {
		if err := e.Prev.Validate(); err != nil {
			return err
		}
		if e.Prev.Version >= e.Write.Version {
			return apperr.New(apperr.CodeInvalidArgument,
				"previous cache key version must be less than write version")
		}
	}
	return nil
}

// KeysForRead returns write and previous keys for Open attempts.
func (e *Envelope) KeysForRead() []Key {
	if e == nil || !e.Enabled {
		return nil
	}
	out := []Key{e.Write}
	if e.Prev != nil {
		out = append(out, *e.Prev)
	}
	return out
}

// GenerateKey creates a cryptographically random AES-256 key at version.
func GenerateKey(version int) (Key, error) {
	if version < 1 {
		return Key{}, apperr.New(apperr.CodeInvalidArgument, "cache key version must be >= 1")
	}
	mat := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, mat); err != nil {
		return Key{}, apperr.Wrap(apperr.CodeInternal, "failed to generate cache key", err)
	}
	return Key{Version: version, Material: mat}, nil
}

// FrameAAD builds additional authenticated data binding frame identity.
// AAD never includes secrets or log payload bytes.
func FrameAAD(generationID int64, seq int, formatVersion int) []byte {
	// Fixed layout so AAD is stable across Go versions.
	// "JME1" | u64 gen | u32 seq | u32 format | "zstd"
	buf := make([]byte, 0, 4+8+4+4+4)
	buf = append(buf, Magic...)
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], uint64(generationID))
	buf = append(buf, tmp[:]...)
	binary.BigEndian.PutUint32(tmp[:4], uint32(seq))
	buf = append(buf, tmp[:4]...)
	binary.BigEndian.PutUint32(tmp[:4], uint32(formatVersion))
	buf = append(buf, tmp[:4]...)
	buf = append(buf, "zstd"...)
	return buf
}

// IsEncrypted reports whether on-disk bytes look like a JME1 envelope.
func IsEncrypted(onDisk []byte) bool {
	return len(onDisk) >= headerLen && string(onDisk[:4]) == Magic
}

// KeyVersionOf returns the key version from an envelope header without decrypting.
func KeyVersionOf(onDisk []byte) (int, error) {
	if !IsEncrypted(onDisk) {
		return 0, apperr.New(apperr.CodeInvalidArgument, "frame is not an encrypted envelope")
	}
	return int(binary.BigEndian.Uint32(onDisk[4:8])), nil
}

// Seal encrypts compressed (zstd) frame bytes under key with AAD.
// Returns the full on-disk envelope (magic|version|nonce|ciphertext+tag).
func Seal(key Key, compressed []byte, aad []byte) ([]byte, error) {
	if err := key.Validate(); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key.Material)
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeInternal, "failed to init AEAD cipher", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeInternal, "failed to init AEAD gcm", err)
	}
	if gcm.NonceSize() != NonceSize {
		return nil, apperr.New(apperr.CodeInternal, "unexpected GCM nonce size")
	}
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, apperr.Wrap(apperr.CodeInternal, "failed to generate AEAD nonce", err)
	}
	ct := gcm.Seal(nil, nonce, compressed, aad)

	out := make([]byte, 0, headerLen+len(ct))
	out = append(out, Magic...)
	var ver [4]byte
	binary.BigEndian.PutUint32(ver[:], uint32(key.Version))
	out = append(out, ver[:]...)
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

// Open decrypts an envelope trying keys in order. On authentication failure it
// returns a clear corrupt_cache / authentication error without plaintext or key material.
func Open(keys []Key, onDisk []byte, aad []byte) (compressed []byte, keyVersion int, err error) {
	if !IsEncrypted(onDisk) {
		return nil, 0, apperr.New(apperr.CodeCorruptCache, "encrypted frame magic missing or invalid")
	}
	if len(keys) == 0 {
		return nil, 0, apperr.New(apperr.CodeAuthentication,
			"cache encryption key required to read encrypted frame")
	}
	ver := int(binary.BigEndian.Uint32(onDisk[4:8]))
	nonce := onDisk[8 : 8+NonceSize]
	ct := onDisk[8+NonceSize:]

	// Prefer the key matching the header version, then fall through.
	ordered := orderKeys(keys, ver)
	var lastAuthFail bool
	for _, k := range ordered {
		if err := k.Validate(); err != nil {
			continue
		}
		pt, openErr := openOne(k.Material, nonce, ct, aad)
		if openErr == nil {
			return pt, k.Version, nil
		}
		lastAuthFail = true
	}
	if lastAuthFail {
		// Never include ciphertext/key/AAD details that could aid offline attacks
		// in model-visible paths beyond a stable class message.
		return nil, 0, apperr.New(apperr.CodeCorruptCache,
			fmt.Sprintf("frame AEAD authentication failed (key_version=%d)", ver))
	}
	return nil, 0, apperr.New(apperr.CodeAuthentication,
		fmt.Sprintf("no usable cache key for encrypted frame (key_version=%d)", ver))
}

func openOne(material, nonce, ct, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(material)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ct, aad)
}

func orderKeys(keys []Key, preferVersion int) []Key {
	var prefer, rest []Key
	for _, k := range keys {
		if k.Version == preferVersion {
			prefer = append(prefer, k)
		} else {
			rest = append(rest, k)
		}
	}
	return append(prefer, rest...)
}
