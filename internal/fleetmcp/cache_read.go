package fleetmcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/fleetcache"
	"github.com/hilather/go-jenkins-mcp/internal/store"
)

// Cache assertion HTTP header (FLC-031). Value is base64url(JSON claims+MAC).
const CacheAssertionHeader = "X-Fleet-Cache-Assertion"

// PeerMuxOptions is extended in cache_routes.go; decoded read fields live here for documentation.

// DecodedReadBackend is owner-side resolve + LogReader for bounded peer reads.
type DecodedReadBackend interface {
	fleetcache.SealedObjectResolver
	fleetcache.DecodedLogReader
}

// AssertionAuth provides HMAC key + nonce store for peer assertions.
type AssertionAuth struct {
	Key    []byte
	Nonces fleetcache.NonceStore
	// MaxDecodedBytes server expected budget (0 → absolute).
	MaxDecodedBytes int64
	PolicyEpoch     int64
}

// StoreDecodedBackend adapts store.Meta + LogReader for FLC-031 tests and pilot residual.
// Mapping is an in-memory locator → generation table (schema mapping residual FLC-019).
type StoreDecodedBackend struct {
	Meta   *store.Meta
	Reader *store.LogReader
	// Objects maps locator_hash → local sealed object.
	Objects map[string]fleetcache.LocalSealedObject
}

// ResolveSealed implements fleetcache.SealedObjectResolver.
func (b *StoreDecodedBackend) ResolveSealed(locatorHash string) (fleetcache.LocalSealedObject, bool) {
	if b == nil || b.Objects == nil {
		return fleetcache.LocalSealedObject{}, false
	}
	o, ok := b.Objects[strings.ToLower(strings.TrimSpace(locatorHash))]
	return o, ok
}

// ReadRange implements fleetcache.DecodedLogReader.
func (b *StoreDecodedBackend) ReadRange(ctx context.Context, generationID int64, start, length int64) (fleetcache.DecodedReadResult, error) {
	if b == nil || b.Reader == nil {
		return fleetcache.DecodedReadResult{}, apperr.New(apperr.CodeInternal, "decoded reader nil")
	}
	rr, err := b.Reader.ReadRange(ctx, generationID, start, length)
	return mapStoreRead(rr), err
}

// ReadLineRange implements fleetcache.DecodedLogReader.
func (b *StoreDecodedBackend) ReadLineRange(ctx context.Context, generationID int64, startLine, lineCount int64) (fleetcache.DecodedReadResult, error) {
	if b == nil || b.Reader == nil {
		return fleetcache.DecodedReadResult{}, apperr.New(apperr.CodeInternal, "decoded reader nil")
	}
	rr, err := b.Reader.ReadLineRange(ctx, generationID, startLine, lineCount)
	return mapStoreRead(rr), err
}

// TailBytes implements fleetcache.DecodedLogReader.
func (b *StoreDecodedBackend) TailBytes(ctx context.Context, generationID int64, n int64) (fleetcache.DecodedReadResult, error) {
	if b == nil || b.Reader == nil {
		return fleetcache.DecodedReadResult{}, apperr.New(apperr.CodeInternal, "decoded reader nil")
	}
	rr, err := b.Reader.TailBytes(ctx, generationID, n)
	return mapStoreRead(rr), err
}

// TailLines implements fleetcache.DecodedLogReader.
func (b *StoreDecodedBackend) TailLines(ctx context.Context, generationID int64, n int64) (fleetcache.DecodedReadResult, error) {
	if b == nil || b.Reader == nil {
		return fleetcache.DecodedReadResult{}, apperr.New(apperr.CodeInternal, "decoded reader nil")
	}
	rr, err := b.Reader.TailLines(ctx, generationID, n)
	return mapStoreRead(rr), err
}

func mapStoreRead(rr store.ReadResult) fleetcache.DecodedReadResult {
	return fleetcache.DecodedReadResult{
		Data:              rr.Data,
		RawStart:          rr.RawStart,
		RawEnd:            rr.RawEnd,
		LineStart:         rr.LineStart,
		LineEnd:           rr.LineEnd,
		RequestedBytes:    rr.RequestedBytes,
		DecompressedBytes: rr.DecompressedBytes,
		FramesOpened:      rr.FramesOpened,
		Sealed:            rr.Sealed,
	}
}

// MemoryDecodedBackend is a pure in-memory sealed object + fixed payload for unit tests
// that do not need a real store (scope deny / not materialized paths).
type MemoryDecodedBackend struct {
	Objects map[string]fleetcache.LocalSealedObject
	// Body is the full decoded log for all objects (tests assign per-case).
	Body []byte
	// ReadCalls counts successful LogReader invocations (deny-before-body checks).
	ReadCalls int
	// Lines when non-nil overrides line splitting of Body.
	Lines []string
}

// ResolveSealed implements fleetcache.SealedObjectResolver.
func (b *MemoryDecodedBackend) ResolveSealed(locatorHash string) (fleetcache.LocalSealedObject, bool) {
	if b == nil || b.Objects == nil {
		return fleetcache.LocalSealedObject{}, false
	}
	o, ok := b.Objects[strings.ToLower(strings.TrimSpace(locatorHash))]
	return o, ok
}

func (b *MemoryDecodedBackend) ReadRange(ctx context.Context, generationID int64, start, length int64) (fleetcache.DecodedReadResult, error) {
	if err := ctx.Err(); err != nil {
		return fleetcache.DecodedReadResult{}, err
	}
	b.ReadCalls++
	body := b.Body
	if start < 0 {
		start = 0
	}
	if start > int64(len(body)) {
		return fleetcache.DecodedReadResult{RawStart: start, RawEnd: start}, nil
	}
	end := start + length
	if end > int64(len(body)) {
		end = int64(len(body))
	}
	data := append([]byte(nil), body[start:end]...)
	return fleetcache.DecodedReadResult{
		Data: data, RawStart: start, RawEnd: end,
		RequestedBytes: length, DecompressedBytes: end - start, FramesOpened: 1, Sealed: true,
	}, nil
}

func (b *MemoryDecodedBackend) ReadLineRange(ctx context.Context, generationID int64, startLine, lineCount int64) (fleetcache.DecodedReadResult, error) {
	if err := ctx.Err(); err != nil {
		return fleetcache.DecodedReadResult{}, err
	}
	b.ReadCalls++
	lines := b.lines()
	if startLine < 0 {
		startLine = 0
	}
	if startLine >= int64(len(lines)) || lineCount == 0 {
		return fleetcache.DecodedReadResult{LineStart: startLine, LineEnd: startLine, Sealed: true}, nil
	}
	end := startLine + lineCount
	if end > int64(len(lines)) {
		end = int64(len(lines))
	}
	var out strings.Builder
	for i := startLine; i < end; i++ {
		out.WriteString(lines[i])
		if !strings.HasSuffix(lines[i], "\n") && i < end-1 {
			out.WriteByte('\n')
		}
	}
	data := []byte(out.String())
	return fleetcache.DecodedReadResult{
		Data: data, LineStart: startLine, LineEnd: end,
		RequestedBytes: int64(len(data)), DecompressedBytes: int64(len(data)),
		FramesOpened: 1, Sealed: true,
	}, nil
}

func (b *MemoryDecodedBackend) TailBytes(ctx context.Context, generationID int64, n int64) (fleetcache.DecodedReadResult, error) {
	if err := ctx.Err(); err != nil {
		return fleetcache.DecodedReadResult{}, err
	}
	body := b.Body
	if n <= 0 || len(body) == 0 {
		b.ReadCalls++
		return fleetcache.DecodedReadResult{Sealed: true}, nil
	}
	start := int64(len(body)) - n
	if start < 0 {
		start = 0
	}
	return b.ReadRange(ctx, generationID, start, int64(len(body))-start)
}

func (b *MemoryDecodedBackend) TailLines(ctx context.Context, generationID int64, n int64) (fleetcache.DecodedReadResult, error) {
	if err := ctx.Err(); err != nil {
		return fleetcache.DecodedReadResult{}, err
	}
	lines := b.lines()
	if n <= 0 || len(lines) == 0 {
		b.ReadCalls++
		return fleetcache.DecodedReadResult{Sealed: true}, nil
	}
	start := int64(len(lines)) - n
	if start < 0 {
		start = 0
	}
	return b.ReadLineRange(ctx, generationID, start, int64(len(lines))-start)
}

func (b *MemoryDecodedBackend) lines() []string {
	if b.Lines != nil {
		return b.Lines
	}
	if len(b.Body) == 0 {
		return nil
	}
	// Split keeping newlines on each line for parity with simple tests.
	s := string(b.Body)
	parts := strings.SplitAfter(s, "\n")
	if len(parts) > 0 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	return parts
}

// decodedReadJSON is the POST body for /objects/{lh}/read.
type decodedReadJSON struct {
	Kind            string `json:"kind"`
	Start           int64  `json:"start,omitempty"`
	Length          int64  `json:"length,omitempty"`
	StartLine       int64  `json:"start_line,omitempty"`
	LineCount       int64  `json:"line_count,omitempty"`
	TailN           int64  `json:"tail_n,omitempty"`
	MaxDecodedBytes int64  `json:"max_decoded_bytes,omitempty"`
}

// decodedReadResponseJSON is used when Accept is application/json (tests / small bodies).
type decodedReadResponseJSON struct {
	Status            string `json:"status"`
	Residual          string `json:"residual,omitempty"`
	RawStart          int64  `json:"raw_start"`
	RawEnd            int64  `json:"raw_end"`
	LineStart         int64  `json:"line_start,omitempty"`
	LineEnd           int64  `json:"line_end,omitempty"`
	DecodedBytes      int64  `json:"decoded_bytes"`
	FramesOpened      int    `json:"frames_opened"`
	DecompressedBytes int64  `json:"decompressed_bytes,omitempty"`
	Sealed            bool   `json:"sealed"`
	// DataB64 is base64 std encoding of decoded body (JSON path only).
	DataB64 string `json:"data_b64,omitempty"`
}

// registerCacheRoutes registers manifest lookup, decoded read, and frame export under one
// prefix handler so Go's ServeMux does not double-bind the same path prefix.
func registerCacheRoutes(
	mux *http.ServeMux,
	cfg Config,
	cat ManifestCatalog,
	backend DecodedReadBackend,
	frameBackend FrameExportBackend,
	admission *fleetcache.StreamAdmission,
	authn AssertionAuth,
	auth func(http.HandlerFunc) http.HandlerFunc,
	write func(http.ResponseWriter, any),
) {
	if cat == nil && (backend == nil || len(authn.Key) < 16) && (frameBackend == nil || len(authn.Key) < 16) {
		return
	}
	if authn.Nonces == nil && (backend != nil || frameBackend != nil) {
		authn.Nonces = fleetcache.NewMemoryNonceStore()
	}
	if admission == nil && frameBackend != nil {
		admission = fleetcache.NewStreamAdmission(fleetcache.DefaultMaxPeerStreams)
	}
	mux.HandleFunc(CachePathPrefix+"/objects/", auth(func(w http.ResponseWriter, r *http.Request) {
		rest := strings.TrimPrefix(r.URL.Path, CachePathPrefix+"/objects/")
		parts := strings.Split(strings.Trim(rest, "/"), "/")
		if len(parts) < 2 {
			http.Error(w, `{"error":"not_found"}`, http.StatusNotFound)
			return
		}
		lh := strings.ToLower(strings.TrimSpace(parts[0]))
		if len(lh) != 64 {
			http.Error(w, `{"error":"invalid_locator"}`, http.StatusBadRequest)
			return
		}
		switch {
		case len(parts) == 2 && parts[1] == "manifest":
			if cat == nil {
				http.Error(w, `{"error":"not_found"}`, http.StatusNotFound)
				return
			}
			handleManifestLeaf(w, r, cfg, cat, lh, write)
		case len(parts) == 2 && parts[1] == "read":
			if backend == nil || len(authn.Key) < 16 {
				http.Error(w, `{"error":"not_found"}`, http.StatusNotFound)
				return
			}
			handleDecodedRead(w, r, cfg, backend, authn, lh, write)
		case len(parts) == 3 && parts[1] == "frames":
			if frameBackend == nil || len(authn.Key) < 16 {
				http.Error(w, `{"error":"not_found"}`, http.StatusNotFound)
				return
			}
			seq, err := strconv.Atoi(parts[2])
			if err != nil || seq < 0 {
				http.Error(w, `{"error":"invalid_seq"}`, http.StatusBadRequest)
				return
			}
			handleFrameExport(w, r, cfg, frameBackend, authn, admission, lh, seq)
		default:
			http.Error(w, `{"error":"not_found"}`, http.StatusNotFound)
		}
	}))
}

func handleManifestLeaf(w http.ResponseWriter, r *http.Request, cfg Config, cat ManifestCatalog, lh string, write func(http.ResponseWriter, any)) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	if cat == nil {
		http.Error(w, `{"error":"not_found"}`, http.StatusNotFound)
		return
	}
	m, ok := cat.Get(lh)
	if !ok {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		write(w, map[string]any{"hit": false, "locator_hash": lh})
		return
	}
	if cfg.Roster != nil && cfg.Roster.FleetID != "" && m.FleetID != "" && m.FleetID != cfg.Roster.FleetID {
		http.Error(w, `{"error":"wrong_fleet"}`, http.StatusConflict)
		return
	}
	if r.Method == http.MethodHead {
		w.Header().Set("X-Fleet-Cache-Hit", "1")
		w.Header().Set("X-Fleet-Locator-Hash", lh)
		if m.ManifestDigest != "" {
			w.Header().Set("X-Fleet-Manifest-Digest", m.ManifestDigest)
		}
		w.WriteHeader(http.StatusOK)
		return
	}
	write(w, map[string]any{"hit": true, "manifest": m})
}

func handleDecodedRead(
	w http.ResponseWriter,
	r *http.Request,
	cfg Config,
	backend DecodedReadBackend,
	authn AssertionAuth,
	lh string,
	write func(http.ResponseWriter, any),
) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	// Bound request body (small JSON only).
	body, err := io.ReadAll(io.LimitReader(r.Body, 16<<10))
	if err != nil {
		http.Error(w, `{"error":"invalid_body"}`, http.StatusBadRequest)
		return
	}
	var jr decodedReadJSON
	if len(body) > 0 {
		if err := json.Unmarshal(body, &jr); err != nil {
			http.Error(w, `{"error":"invalid_json"}`, http.StatusBadRequest)
			return
		}
	}
	req := fleetcache.DecodedReadRequest{
		LocatorHash:     lh,
		Kind:            jr.Kind,
		Start:           jr.Start,
		Length:          jr.Length,
		StartLine:       jr.StartLine,
		LineCount:       jr.LineCount,
		TailN:           jr.TailN,
		MaxDecodedBytes: jr.MaxDecodedBytes,
	}
	assertHdr := r.Header.Get(CacheAssertionHeader)
	assertion, err := fleetcache.DecodeAssertionHeader(assertHdr)
	if err != nil {
		writeDecodedErr(w, http.StatusUnauthorized, fleetcache.DecodedReadScopeDenied, "assertion missing or invalid")
		return
	}
	fleetID := ""
	if cfg.Roster != nil {
		fleetID = cfg.Roster.FleetID
	}
	res, err := fleetcache.ServeDecodedRead(r.Context(), backend, backend, req, assertion, fleetcache.ServeDecodedReadOptions{
		AssertionKey:    authn.Key,
		Nonces:          authn.Nonces,
		Now:             time.Now().UTC(),
		FleetID:         fleetID,
		MaxDecodedBytes: authn.MaxDecodedBytes,
		PolicyEpoch:     authn.PolicyEpoch,
	})
	if err != nil || res.Status != fleetcache.DecodedReadOK {
		status := http.StatusForbidden
		switch res.Status {
		case fleetcache.DecodedReadNotFound:
			status = http.StatusNotFound
		case fleetcache.DecodedReadNotMaterialized:
			status = http.StatusConflict
		case fleetcache.DecodedReadOverCeiling, fleetcache.DecodedReadInvalid:
			status = http.StatusBadRequest
		case fleetcache.DecodedReadCancelled:
			status = 499
		case fleetcache.DecodedReadUnavailable:
			status = http.StatusServiceUnavailable
		case fleetcache.DecodedReadScopeDenied:
			status = http.StatusForbidden
		}
		if res.Status == "" && err != nil {
			if apperr.CodeOf(err) == apperr.CodeAuthorization {
				res.Status = fleetcache.DecodedReadScopeDenied
				status = http.StatusForbidden
			} else if apperr.CodeOf(err) == apperr.CodeInvalidArgument {
				res.Status = fleetcache.DecodedReadInvalid
				status = http.StatusBadRequest
			} else if apperr.CodeOf(err) == apperr.CodeQuota {
				res.Status = fleetcache.DecodedReadOverCeiling
				status = http.StatusBadRequest
			} else {
				res.Status = fleetcache.DecodedReadUnavailable
				status = http.StatusServiceUnavailable
			}
		}
		writeDecodedErr(w, status, res.Status, res.Residual)
		return
	}

	// Prefer JSON envelope when Accept includes json (tests); else raw body + headers.
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/json") {
		write(w, decodedReadResponseJSON{
			Status:            string(res.Status),
			RawStart:          res.RawStart,
			RawEnd:            res.RawEnd,
			LineStart:         res.LineStart,
			LineEnd:           res.LineEnd,
			DecodedBytes:      int64(len(res.Data)),
			FramesOpened:      res.FramesOpened,
			DecompressedBytes: res.DecompressedBytes,
			Sealed:            res.Sealed,
			DataB64:           base64.StdEncoding.EncodeToString(res.Data),
		})
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Fleet-Cache-Status", string(res.Status))
	w.Header().Set("X-Fleet-Cache-Raw-Start", strconv.FormatInt(res.RawStart, 10))
	w.Header().Set("X-Fleet-Cache-Raw-End", strconv.FormatInt(res.RawEnd, 10))
	w.Header().Set("X-Fleet-Cache-Decoded-Bytes", strconv.FormatInt(int64(len(res.Data)), 10))
	w.Header().Set("X-Fleet-Cache-Frames-Opened", strconv.Itoa(res.FramesOpened))
	if res.Sealed {
		w.Header().Set("X-Fleet-Cache-Sealed", "1")
	}
	w.Header().Set("X-Fleet-Locator-Hash", lh)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(res.Data)
}

func writeDecodedErr(w http.ResponseWriter, httpStatus int, st fleetcache.DecodedReadStatus, residual string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error":    string(st),
		"residual": residual,
		"status":   string(st),
	})
}

// DecodedReadPath builds the peer path for a locator hash bounded read.
func DecodedReadPath(locatorHash string) string {
	return CachePathPrefix + "/objects/" + strings.ToLower(strings.TrimSpace(locatorHash)) + "/read"
}
