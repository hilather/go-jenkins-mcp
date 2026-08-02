package fleetmcp

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/fleetcache"
	"github.com/hilather/go-jenkins-mcp/internal/store"
)

// FrameExportBackend is owner-side resolve + pure-zstd frame export (FLC-022).
type FrameExportBackend interface {
	fleetcache.SealedObjectResolver
	fleetcache.FrameExporter
}

// StoreFrameBackend adapts store Meta + frames dir for pure-zstd export.
type StoreFrameBackend struct {
	Meta    *store.Meta
	DataDir string
	Crypto  *store.FrameCrypto
	// Objects maps locator_hash → local sealed object (FLC-019 residual).
	Objects map[string]fleetcache.LocalSealedObject
}

// ResolveSealed implements fleetcache.SealedObjectResolver.
func (b *StoreFrameBackend) ResolveSealed(locatorHash string) (fleetcache.LocalSealedObject, bool) {
	if b == nil || b.Objects == nil {
		return fleetcache.LocalSealedObject{}, false
	}
	o, ok := b.Objects[strings.ToLower(strings.TrimSpace(locatorHash))]
	return o, ok
}

// ExportFrame implements fleetcache.FrameExporter via store.ExportPureZstdEnsured.
func (b *StoreFrameBackend) ExportFrame(ctx context.Context, generationID int64, seq int) (fleetcache.PureZstdFrame, error) {
	if b == nil || b.Meta == nil {
		return fleetcache.PureZstdFrame{}, apperr.New(apperr.CodeInternal, "frame export meta nil")
	}
	if err := ctx.Err(); err != nil {
		return fleetcache.PureZstdFrame{}, err
	}
	chunks, err := b.Meta.ListChunks(ctx, generationID)
	if err != nil {
		return fleetcache.PureZstdFrame{}, err
	}
	var found *store.Chunk
	for i := range chunks {
		if chunks[i].Seq == seq {
			found = &chunks[i]
			break
		}
	}
	if found == nil {
		return fleetcache.PureZstdFrame{}, apperr.New(apperr.CodeNotFound, "frame seq not found")
	}
	exp, err := b.Meta.ExportPureZstdEnsured(ctx, b.DataDir, *found, b.Crypto)
	if err != nil {
		return fleetcache.PureZstdFrame{}, err
	}
	return fleetcache.PureZstdFrame{
		Bytes:  exp.Bytes,
		Size:   exp.Size,
		SHA256: exp.SHA256,
		Seq:    exp.Seq,
	}, nil
}

// MemoryFrameBackend is an in-memory sealed object + pure-zstd frames for tests.
type MemoryFrameBackend struct {
	Objects map[string]fleetcache.LocalSealedObject
	Frames  map[string]map[int]fleetcache.PureZstdFrame // locator → seq → frame
	Calls   int
}

// ResolveSealed implements fleetcache.SealedObjectResolver.
func (b *MemoryFrameBackend) ResolveSealed(locatorHash string) (fleetcache.LocalSealedObject, bool) {
	if b == nil || b.Objects == nil {
		return fleetcache.LocalSealedObject{}, false
	}
	o, ok := b.Objects[strings.ToLower(strings.TrimSpace(locatorHash))]
	return o, ok
}

// ExportFrame implements fleetcache.FrameExporter.
// Frames are keyed by locator in Frames[locator][seq]; generation is resolved via Objects.
func (b *MemoryFrameBackend) ExportFrame(ctx context.Context, generationID int64, seq int) (fleetcache.PureZstdFrame, error) {
	if err := ctx.Err(); err != nil {
		return fleetcache.PureZstdFrame{}, err
	}
	b.Calls++
	// Map generation → locator from Objects.
	var lh string
	for k, o := range b.Objects {
		if o.GenerationID == generationID {
			lh = k
			break
		}
	}
	if lh == "" {
		// Fallback: first locator that has this seq (single-object tests).
		for k, bySeq := range b.Frames {
			if _, ok := bySeq[seq]; ok {
				lh = k
				break
			}
		}
	}
	if lh == "" {
		return fleetcache.PureZstdFrame{}, apperr.New(apperr.CodeNotFound, "frame missing")
	}
	bySeq := b.Frames[lh]
	if bySeq == nil {
		return fleetcache.PureZstdFrame{}, apperr.New(apperr.CodeNotFound, "locator frames missing")
	}
	f, ok := bySeq[seq]
	if !ok {
		return fleetcache.PureZstdFrame{}, apperr.New(apperr.CodeNotFound, "frame seq missing")
	}
	cp := append([]byte(nil), f.Bytes...)
	return fleetcache.PureZstdFrame{Bytes: cp, Size: int64(len(cp)), SHA256: f.SHA256, Seq: seq}, nil
}

func handleFrameExport(
	w http.ResponseWriter,
	r *http.Request,
	cfg Config,
	backend FrameExportBackend,
	authn AssertionAuth,
	admission *fleetcache.StreamAdmission,
	lh string,
	seq int,
) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	// identity only — never gzip pure-zstd wire.
	if ae := r.Header.Get("Accept-Encoding"); ae != "" && !strings.Contains(strings.ToLower(ae), "identity") && ae != "*" {
		// Allow missing Accept-Encoding; reject explicit non-identity compressions that would wrap zstd.
		if strings.Contains(strings.ToLower(ae), "gzip") || strings.Contains(strings.ToLower(ae), "br") {
			http.Error(w, `{"error":"accept_encoding_identity_required"}`, http.StatusNotAcceptable)
			return
		}
	}

	assertHdr := r.Header.Get(CacheAssertionHeader)
	assertion, err := fleetcache.DecodeAssertionHeader(assertHdr)
	if err != nil {
		writeFrameErr(w, http.StatusUnauthorized, fleetcache.FrameExportScopeDenied, "assertion missing or invalid")
		return
	}
	fleetID := ""
	if cfg.Roster != nil {
		fleetID = cfg.Roster.FleetID
	}
	req := fleetcache.FrameExportRequest{LocatorHash: lh, Seq: seq}
	// Optional declared integrity from client query/headers.
	if v := r.Header.Get("X-Fleet-Zstd-Size"); v != "" {
		if n, e := strconv.ParseInt(v, 10, 64); e == nil {
			req.DeclaredZstdSize = n
		}
	}
	if v := r.Header.Get("X-Fleet-Zstd-SHA256"); v != "" {
		req.DeclaredZstdSHA256 = v
	}

	res, err := fleetcache.ServeFrameExport(r.Context(), backend, backend, req, assertion, fleetcache.ServeFrameExportOptions{
		AssertionKey: authn.Key,
		Nonces:       authn.Nonces,
		Now:          time.Now().UTC(),
		FleetID:      fleetID,
		PolicyEpoch:  authn.PolicyEpoch,
		Admission:    admission,
	})
	if err != nil || res.Status != fleetcache.FrameExportOK {
		status := http.StatusForbidden
		switch res.Status {
		case fleetcache.FrameExportNotFound:
			status = http.StatusNotFound
		case fleetcache.FrameExportNotMaterial:
			status = http.StatusConflict
		case fleetcache.FrameExportOversize, fleetcache.FrameExportInvalid:
			status = http.StatusBadRequest
		case fleetcache.FrameExportCorrupt:
			status = http.StatusConflict
		case fleetcache.FrameExportCancelled:
			status = 499
		case fleetcache.FrameExportUnavailable, fleetcache.FrameExportAdmittedOut:
			status = http.StatusServiceUnavailable
		case fleetcache.FrameExportScopeDenied:
			status = http.StatusForbidden
		}
		if res.Status == "" && err != nil {
			if apperr.CodeOf(err) == apperr.CodeAuthorization {
				status = http.StatusForbidden
				res.Status = fleetcache.FrameExportScopeDenied
			} else {
				status = http.StatusServiceUnavailable
				res.Status = fleetcache.FrameExportUnavailable
			}
		}
		writeFrameErr(w, status, res.Status, res.Residual)
		return
	}

	w.Header().Set("Content-Type", fleetcache.ContentTypePureZstd)
	w.Header().Set("Content-Length", strconv.FormatInt(res.Size, 10))
	w.Header().Set("Accept-Encoding", "identity")
	w.Header().Set("X-Fleet-Cache-Status", string(res.Status))
	w.Header().Set("X-Fleet-Zstd-Size", strconv.FormatInt(res.Size, 10))
	w.Header().Set("X-Fleet-Zstd-SHA256", res.SHA256)
	w.Header().Set("X-Fleet-Frame-Seq", strconv.Itoa(res.Seq))
	w.Header().Set("X-Fleet-Locator-Hash", lh)
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusOK)
	// Stream one frame only — no multi-frame / whole-log buffer.
	_, _ = w.Write(res.Bytes)
}

func writeFrameErr(w http.ResponseWriter, httpStatus int, st fleetcache.FrameExportStatus, residual string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error":    string(st),
		"status":   string(st),
		"residual": residual,
	})
}

// FramePath builds GET path for one frame.
func FramePath(locatorHash string, seq int) string {
	return CachePathPrefix + "/objects/" + strings.ToLower(strings.TrimSpace(locatorHash)) + "/frames/" + strconv.Itoa(seq)
}
