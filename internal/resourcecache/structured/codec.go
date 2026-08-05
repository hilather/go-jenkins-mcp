package structured

import (
	"bytes"
	"encoding/json"
	"io"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/klauspost/compress/zstd"
)

// EncodeJSONZstd marshals v as JSON and wraps with zstd.
func EncodeJSONZstd(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeInternal, "marshal structured resource", err)
	}
	enc, err := zstd.NewWriter(nil)
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeInternal, "zstd writer", err)
	}
	out := enc.EncodeAll(raw, make([]byte, 0, len(raw)/2))
	_ = enc.Close()
	return out, nil
}

// DecodeJSONZstd decompresses and unmarshals into dest.
func DecodeJSONZstd(data []byte, dest any) error {
	dec, err := zstd.NewReader(nil)
	if err != nil {
		return apperr.Wrap(apperr.CodeInternal, "zstd reader", err)
	}
	defer dec.Close()
	raw, err := dec.DecodeAll(data, nil)
	if err != nil {
		return apperr.Wrap(apperr.CodeCorruptCache, "zstd decompress structured", err)
	}
	if err := json.Unmarshal(raw, dest); err != nil {
		return apperr.Wrap(apperr.CodeCorruptCache, "unmarshal structured", err)
	}
	return nil
}

// DecodeJSONZstdReader reads all from r then decodes.
func DecodeJSONZstdReader(r io.Reader, dest any) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return apperr.Wrap(apperr.CodeInternal, "read structured object", err)
	}
	return DecodeJSONZstd(data, dest)
}

// EncodeToReader returns a reader over encoded bytes.
func EncodeToReader(v any) (io.ReadCloser, int, error) {
	b, err := EncodeJSONZstd(v)
	if err != nil {
		return nil, 0, err
	}
	return io.NopCloser(bytes.NewReader(b)), len(b), nil
}
