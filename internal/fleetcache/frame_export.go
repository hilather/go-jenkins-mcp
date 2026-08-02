package fleetcache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// Frame export content type (pure independent Zstandard frame bytes; FLC-022).
const (
	// ContentTypePureZstd is the wire content type for one compressed frame.
	ContentTypePureZstd = "application/zstd"
	// FrameExportOverheadBytes is documented max non-frame buffer (headers/JSON errors).
	FrameExportOverheadBytes = 8 << 10 // 8 KiB
)

// FrameExportStatus classifies owner/client frame transfer outcomes.
type FrameExportStatus string

const (
	FrameExportOK          FrameExportStatus = "ok"
	FrameExportNotFound    FrameExportStatus = "not_found"
	FrameExportNotMaterial FrameExportStatus = "not_materialized"
	FrameExportScopeDenied FrameExportStatus = "scope_denied"
	FrameExportOversize    FrameExportStatus = "oversize"
	FrameExportCorrupt     FrameExportStatus = "corrupt"
	FrameExportModeOff     FrameExportStatus = "mode_off"
	FrameExportUnavailable FrameExportStatus = "unavailable"
	FrameExportCancelled   FrameExportStatus = "cancelled"
	FrameExportInvalid     FrameExportStatus = "invalid"
	FrameExportAdmittedOut FrameExportStatus = "admission_denied"
)

// FrameExportRequest is one pure-zstd frame by locator + sequence (no local paths).
type FrameExportRequest struct {
	LocatorHash string
	// Seq is the wire frame sequence (0-based contiguous).
	Seq int
	// DeclaredZstdSize optional client-side cap check (0 = use MaxZstdFrameBytes).
	DeclaredZstdSize int64
	// DeclaredZstdSHA256 optional expected wire hash (lowercase hex); mismatch fails closed.
	DeclaredZstdSHA256 string
}

// FrameExportResult is one verified pure compressed frame for peer transfer.
type FrameExportResult struct {
	Bytes    []byte
	Size     int64
	SHA256   string
	Seq      int
	Status   FrameExportStatus
	Residual string
}

// ValidateFrameExportRequest enforces bounds without disk I/O.
func ValidateFrameExportRequest(req FrameExportRequest) error {
	req.LocatorHash = strings.ToLower(strings.TrimSpace(req.LocatorHash))
	if len(req.LocatorHash) != 64 || !isHex(req.LocatorHash) {
		return apperr.New(apperr.CodeInvalidArgument, "frame export locator_hash invalid")
	}
	if req.Seq < 0 {
		return apperr.New(apperr.CodeInvalidArgument, "frame export seq negative")
	}
	if req.Seq >= MaxWireFrames {
		return apperr.New(apperr.CodeInvalidArgument, "frame export seq out of range")
	}
	if req.DeclaredZstdSize < 0 {
		return apperr.New(apperr.CodeInvalidArgument, "frame export declared size negative")
	}
	if req.DeclaredZstdSize > MaxZstdFrameBytes {
		return apperr.New(apperr.CodeInvalidArgument, "frame export declared size exceeds cap")
	}
	if req.DeclaredZstdSHA256 != "" {
		h := strings.ToLower(strings.TrimSpace(req.DeclaredZstdSHA256))
		if len(h) != 64 || !isHex(h) {
			return apperr.New(apperr.CodeInvalidArgument, "frame export declared sha256 invalid")
		}
	}
	return nil
}

// AuthorizeFrameExportScope checks OpFrame assertion against the request before export I/O.
func AuthorizeFrameExportScope(claims AssertionClaims, req FrameExportRequest, exp Expected) error {
	if err := ValidateFrameExportRequest(req); err != nil {
		return err
	}
	req.LocatorHash = strings.ToLower(strings.TrimSpace(req.LocatorHash))
	if exp.Operation == "" {
		exp.Operation = OpFrame
	}
	if exp.LocatorHash == "" {
		exp.LocatorHash = req.LocatorHash
	}
	if claims.Operation != OpFrame {
		return apperr.New(apperr.CodeAuthorization, "assertion operation not frame")
	}
	if !strings.EqualFold(claims.LocatorHash, req.LocatorHash) {
		return apperr.New(apperr.CodeAuthorization, "assertion locator out of scope")
	}
	if exp.FleetID != "" && claims.FleetID != exp.FleetID {
		return apperr.New(apperr.CodeAuthorization, "assertion fleet mismatch")
	}
	if exp.LocatorHash != "" && !strings.EqualFold(claims.LocatorHash, exp.LocatorHash) {
		return apperr.New(apperr.CodeAuthorization, "assertion locator mismatch")
	}
	if exp.Operation != "" && claims.Operation != exp.Operation {
		return apperr.New(apperr.CodeAuthorization, "assertion operation mismatch")
	}
	if exp.PolicyEpoch > 0 && claims.PolicyEpoch != exp.PolicyEpoch {
		return apperr.New(apperr.CodeAuthorization, "assertion policy epoch mismatch")
	}
	return nil
}

// VerifyPureZstdFrame enforces size/hash on exported pure-zstd bytes (fail closed).
// Does not accept AEAD envelopes (magic check residual: size+hash only; store export already decrypts).
func VerifyPureZstdFrame(bytes []byte, declaredSize int64, declaredSHA string) error {
	if len(bytes) == 0 {
		return apperr.New(apperr.CodeCorruptCache, "frame export empty body")
	}
	if int64(len(bytes)) > MaxZstdFrameBytes {
		return apperr.New(apperr.CodeQuota, "frame export exceeds max zstd frame bytes")
	}
	if declaredSize > 0 && int64(len(bytes)) != declaredSize {
		return apperr.New(apperr.CodeCorruptCache, "frame export size mismatch")
	}
	sum := sha256HexBytes(bytes)
	if declaredSHA != "" && !strings.EqualFold(declaredSHA, sum) {
		return apperr.New(apperr.CodeCorruptCache, "frame export sha256 mismatch")
	}
	return nil
}

// ReadExactFrameBody reads exactly declaredSize bytes and fails closed on early EOF or extra bytes.
// LimitReader+one-byte probe detects trailing junk after the frame.
func ReadExactFrameBody(r io.Reader, declaredSize int64) ([]byte, error) {
	if declaredSize < 1 {
		return nil, apperr.New(apperr.CodeInvalidArgument, "frame body declared size invalid")
	}
	if declaredSize > MaxZstdFrameBytes {
		return nil, apperr.New(apperr.CodeQuota, "frame body declared size exceeds cap")
	}
	// Buffer only one frame (AC: no whole-log buffer).
	buf := make([]byte, declaredSize)
	n, err := io.ReadFull(r, buf)
	if err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return nil, apperr.New(apperr.CodeUpstreamProtocol, "frame body early EOF")
		}
		return nil, apperr.Wrap(apperr.CodeUpstreamProtocol, "frame body read failed", err)
	}
	if int64(n) != declaredSize {
		return nil, apperr.New(apperr.CodeUpstreamProtocol, "frame body short read")
	}
	// Extra-byte probe: any further byte is a size lie / protocol violation.
	var junk [1]byte
	if m, rerr := r.Read(junk[:]); m > 0 {
		return nil, apperr.New(apperr.CodeUpstreamProtocol, "frame body unexpected extra bytes")
	} else if rerr != nil && rerr != io.EOF {
		return nil, apperr.Wrap(apperr.CodeUpstreamProtocol, "frame body trailer read", rerr)
	}
	return buf, nil
}

// StreamAdmission caps concurrent frame export streams (FLC-022 / MaxPeerStreams).
// Acquire fails closed when the cap is full and ctx is cancelled/deadline exceeded;
// optional blocking until a slot frees when ctx allows.
type StreamAdmission struct {
	max int
	sem chan struct{}
	mu  sync.Mutex // guards init
}

// NewStreamAdmission creates a process-local admission gate. max<=0 uses DefaultMaxPeerStreams.
func NewStreamAdmission(max int) *StreamAdmission {
	if max <= 0 {
		max = DefaultMaxPeerStreams
	}
	if max > AbsoluteMaxPeerStreams {
		max = AbsoluteMaxPeerStreams
	}
	return &StreamAdmission{max: max, sem: make(chan struct{}, max)}
}

// Max returns the configured concurrency cap.
func (a *StreamAdmission) Max() int {
	if a == nil {
		return 0
	}
	return a.max
}

// InUse returns currently held slots (approximate).
func (a *StreamAdmission) InUse() int {
	if a == nil || a.sem == nil {
		return 0
	}
	return len(a.sem)
}

// Acquire reserves one stream slot. Release must be called exactly once (safe on cancel after success).
func (a *StreamAdmission) Acquire(ctx context.Context) (release func(), err error) {
	if a == nil || a.sem == nil {
		return func() {}, apperr.New(apperr.CodeInternal, "stream admission nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case a.sem <- struct{}{}:
		var once sync.Once
		return func() {
			once.Do(func() { <-a.sem })
		}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		// Cap full: wait for slot or ctx (fail closed on cancel; no unbounded spin).
		select {
		case a.sem <- struct{}{}:
			var once sync.Once
			return func() {
				once.Do(func() { <-a.sem })
			}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// TryAcquire is non-blocking; returns false when the cap is full.
func (a *StreamAdmission) TryAcquire() (release func(), ok bool) {
	if a == nil || a.sem == nil {
		return nil, false
	}
	select {
	case a.sem <- struct{}{}:
		var once sync.Once
		return func() {
			once.Do(func() { <-a.sem })
		}, true
	default:
		return nil, false
	}
}

// PureZstdFrame is the exporter output surface (store.PureZstdExport adapter).
type PureZstdFrame struct {
	Bytes  []byte
	Size   int64
	SHA256 string
	Seq    int
}

// FrameExporter resolves a sealed object frame to pure zstd bytes (no AEAD on wire).
type FrameExporter interface {
	// ExportFrame returns pure independent Zstd frame bytes for generation+seq.
	// generationID is local-only; never placed on the wire.
	ExportFrame(ctx context.Context, generationID int64, seq int) (PureZstdFrame, error)
}

// ServeFrameExportOptions configures owner-side frame export auth + admission.
type ServeFrameExportOptions struct {
	AssertionKey []byte
	Nonces       NonceStore
	Now          time.Time
	FleetID      string
	PolicyEpoch  int64
	// Admission optional; when set, Acquire before export and Release after.
	Admission *StreamAdmission
}

// ServeFrameExport validates assertion + request, resolves sealed object, admits one stream,
// and exports a single pure-zstd frame (at most one frame in memory + overhead).
func ServeFrameExport(
	ctx context.Context,
	resolver SealedObjectResolver,
	exporter FrameExporter,
	req FrameExportRequest,
	assertion Assertion,
	opts ServeFrameExportOptions,
) (FrameExportResult, error) {
	if resolver == nil || exporter == nil {
		return FrameExportResult{Status: FrameExportUnavailable, Residual: "export backend unavailable"},
			apperr.New(apperr.CodeInternal, "frame export backend nil")
	}
	if err := ctx.Err(); err != nil {
		return FrameExportResult{Status: FrameExportCancelled, Residual: "cancelled"}, err
	}
	req.LocatorHash = strings.ToLower(strings.TrimSpace(req.LocatorHash))
	if err := ValidateFrameExportRequest(req); err != nil {
		return FrameExportResult{Status: FrameExportInvalid, Residual: "invalid request"}, err
	}

	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	exp := Expected{
		FleetID:     opts.FleetID,
		LocatorHash: req.LocatorHash,
		Operation:   OpFrame,
		PolicyEpoch: opts.PolicyEpoch,
	}
	if err := VerifyAssertion(opts.AssertionKey, assertion, now, exp, opts.Nonces); err != nil {
		return FrameExportResult{Status: FrameExportScopeDenied, Residual: "assertion denied"}, err
	}
	if err := AuthorizeFrameExportScope(assertion.Claims, req, exp); err != nil {
		return FrameExportResult{Status: FrameExportScopeDenied, Residual: "scope denied"}, err
	}

	obj, ok := resolver.ResolveSealed(req.LocatorHash)
	if !ok {
		return FrameExportResult{Status: FrameExportNotFound, Residual: "object not found"}, nil
	}
	if opts.FleetID != "" && obj.FleetID != "" && obj.FleetID != opts.FleetID {
		return FrameExportResult{Status: FrameExportNotFound, Residual: "wrong fleet"}, nil
	}
	if !obj.Sealed {
		return FrameExportResult{Status: FrameExportNotFound, Residual: "not sealed"}, nil
	}
	if !obj.Materialized {
		return FrameExportResult{Status: FrameExportNotMaterial, Residual: "not_materialized"}, nil
	}
	if assertion.Claims.ManifestDigest != "" && obj.ManifestDigest != "" &&
		!strings.EqualFold(assertion.Claims.ManifestDigest, obj.ManifestDigest) {
		return FrameExportResult{Status: FrameExportScopeDenied, Residual: "manifest digest mismatch"},
			apperr.New(apperr.CodeAuthorization, "assertion manifest digest mismatch")
	}

	var release func()
	if opts.Admission != nil {
		rel, err := opts.Admission.Acquire(ctx)
		if err != nil {
			st := FrameExportAdmittedOut
			if ctx.Err() != nil {
				st = FrameExportCancelled
			}
			return FrameExportResult{Status: st, Residual: "export admission denied or cancelled"}, err
		}
		release = rel
		defer release()
	}

	if err := ctx.Err(); err != nil {
		return FrameExportResult{Status: FrameExportCancelled, Residual: "cancelled"}, err
	}

	frame, err := exporter.ExportFrame(ctx, obj.GenerationID, req.Seq)
	if err != nil {
		if ctx.Err() != nil {
			return FrameExportResult{Status: FrameExportCancelled, Residual: "cancelled"}, ctx.Err()
		}
		if apperr.CodeOf(err) == apperr.CodeNotFound {
			return FrameExportResult{Status: FrameExportNotFound, Residual: "frame not found"}, nil
		}
		if apperr.CodeOf(err) == apperr.CodeCorruptCache {
			return FrameExportResult{Status: FrameExportCorrupt, Residual: "corrupt frame"}, err
		}
		return FrameExportResult{Status: FrameExportUnavailable, Residual: "export failed"}, err
	}

	// Fail closed on oversize / hash / declared mismatch before returning body.
	if err := VerifyPureZstdFrame(frame.Bytes, frame.Size, frame.SHA256); err != nil {
		return FrameExportResult{Status: FrameExportCorrupt, Residual: "verify failed"}, err
	}
	if req.DeclaredZstdSize > 0 && frame.Size != req.DeclaredZstdSize {
		return FrameExportResult{Status: FrameExportCorrupt, Residual: "declared size mismatch"},
			apperr.New(apperr.CodeCorruptCache, "frame export declared size mismatch")
	}
	if req.DeclaredZstdSHA256 != "" && !strings.EqualFold(req.DeclaredZstdSHA256, frame.SHA256) {
		return FrameExportResult{Status: FrameExportCorrupt, Residual: "declared hash mismatch"},
			apperr.New(apperr.CodeCorruptCache, "frame export declared hash mismatch")
	}
	if int64(len(frame.Bytes)) > MaxZstdFrameBytes {
		return FrameExportResult{Status: FrameExportOversize, Residual: "oversize"},
			apperr.New(apperr.CodeQuota, "frame export oversize")
	}

	return FrameExportResult{
		Bytes:  frame.Bytes,
		Size:   frame.Size,
		SHA256: strings.ToLower(frame.SHA256),
		Seq:    frame.Seq,
		Status: FrameExportOK,
	}, nil
}

func sha256HexBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
