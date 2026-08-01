package store

import (
	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/store/crypto"
)

// FrameCrypto is the optional AEAD configuration for L1 frames (ARC-009).
// Zero value / nil means encryption is off (default).
type FrameCrypto struct {
	env *crypto.Envelope
}

// NewFrameCrypto builds a FrameCrypto from a validated envelope.
// Returns nil crypto when env is nil or disabled (plaintext path).
func NewFrameCrypto(env *crypto.Envelope) (*FrameCrypto, error) {
	if env == nil || !env.Enabled {
		return nil, nil
	}
	if err := env.Validate(); err != nil {
		return nil, err
	}
	// Defensive copy of material so callers can zero their buffers.
	write := crypto.Key{
		Version:  env.Write.Version,
		Material: append([]byte(nil), env.Write.Material...),
	}
	cp := &crypto.Envelope{Enabled: true, Write: write}
	if env.Prev != nil {
		prev := crypto.Key{
			Version:  env.Prev.Version,
			Material: append([]byte(nil), env.Prev.Material...),
		}
		cp.Prev = &prev
	}
	return &FrameCrypto{env: cp}, nil
}

// Enabled reports whether AEAD write is active.
func (c *FrameCrypto) Enabled() bool {
	return c != nil && c.env != nil && c.env.Enabled
}

// WriteKeyVersion returns the current seal key version (0 when disabled).
func (c *FrameCrypto) WriteKeyVersion() int {
	if !c.Enabled() {
		return 0
	}
	return c.env.Write.Version
}

// sealCompressed encrypts independent zstd frame bytes when crypto is enabled.
// Returns on-disk bytes, enc_alg, enc_key_version.
func (c *FrameCrypto) sealCompressed(generationID int64, seq int, formatVersion int, compressed []byte) (
	onDisk []byte, encAlg string, encKeyVersion int, err error,
) {
	if !c.Enabled() {
		return compressed, "", 0, nil
	}
	aad := crypto.FrameAAD(generationID, seq, formatVersion)
	onDisk, err = crypto.Seal(c.env.Write, compressed, aad)
	if err != nil {
		return nil, "", 0, err
	}
	return onDisk, crypto.AlgAES256GCM, c.env.Write.Version, nil
}

// openToCompressed decrypts an on-disk frame to pure zstd bytes when encrypted.
func (c *FrameCrypto) openToCompressed(generationID int64, seq int, formatVersion int, onDisk []byte, metaEncVer int) ([]byte, error) {
	encrypted := crypto.IsEncrypted(onDisk) || metaEncVer > 0
	if !encrypted {
		return onDisk, nil
	}
	if c == nil || c.env == nil {
		return nil, apperr.New(apperr.CodeAuthentication,
			"cache encryption key required to read encrypted frame")
	}
	aad := crypto.FrameAAD(generationID, seq, formatVersion)
	compressed, _, err := crypto.Open(c.env.KeysForRead(), onDisk, aad)
	if err != nil {
		return nil, err
	}
	return compressed, nil
}
