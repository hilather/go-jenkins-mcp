package store

import (
	"context"
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// PureZstdExport is verified pure compressed frame bytes for peer transfer (FLC-021).
// Never contains AEAD envelope bytes or key material.
type PureZstdExport struct {
	// Bytes is pure independent Zstd frame payload.
	Bytes []byte
	// Size is len(Bytes).
	Size int64
	// SHA256 is lowercase hex of Bytes (wire identity).
	SHA256 string
	// ChunkID is the local SQLite chunk id (not a wire identity).
	ChunkID int64
	// Seq is the local frame sequence.
	Seq int
}

// ExportPureZstd opens the on-disk frame (verifying FrameSHA256), decrypts to pure
// zstd when encrypted, and verifies against ZstdSize/ZstdSHA256 when present.
// Does not treat AEAD ciphertext as portable wire bytes.
func ExportPureZstd(dataDir string, c Chunk, crypto *FrameCrypto) (PureZstdExport, error) {
	zstdBytes, err := OpenFrameCompressed(dataDir, c, crypto)
	if err != nil {
		return PureZstdExport{}, err
	}
	sum := sha256Hex(zstdBytes)
	if c.ZstdSHA256 != "" && !hmacEqualHex(strings.ToLower(c.ZstdSHA256), sum) {
		return PureZstdExport{}, apperr.New(apperr.CodeCorruptCache, "wire zstd checksum mismatch")
	}
	if c.ZstdSize > 0 && c.ZstdSize != int64(len(zstdBytes)) {
		return PureZstdExport{}, apperr.New(apperr.CodeCorruptCache, "wire zstd size mismatch")
	}
	return PureZstdExport{
		Bytes:   zstdBytes,
		Size:    int64(len(zstdBytes)),
		SHA256:  sum,
		ChunkID: c.ID,
		Seq:     c.Seq,
	}, nil
}

// ExportPureZstdEnsured backfills wire hash metadata when missing, then exports.
func (m *Meta) ExportPureZstdEnsured(ctx context.Context, dataDir string, c Chunk, crypto *FrameCrypto) (PureZstdExport, error) {
	if m == nil {
		return PureZstdExport{}, apperr.New(apperr.CodeInternal, "metadata store is closed")
	}
	size, sha, err := m.EnsureChunkWireHash(ctx, dataDir, c, crypto)
	if err != nil {
		return PureZstdExport{}, err
	}
	c.ZstdSize = size
	c.ZstdSHA256 = sha
	return ExportPureZstd(dataDir, c, crypto)
}

func hmacEqualHex(a, b string) bool {
	// Constant-time-ish equality for equal-length hex digests.
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
