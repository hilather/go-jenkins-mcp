package fleetmcp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/fleetcache"
)

// FrameExportClient performs owner-directed one-frame pure-zstd transfers (FLC-022).
// Contacts only the provided owner set — never full-roster broadcast.
type FrameExportClient struct {
	Client    *http.Client
	MeshToken string
	Timeout   time.Duration
	// Mode empty/off/shadow skips peer I/O.
	Mode fleetcache.Mode
	// AssertionKey issues OpFrame assertions per attempt.
	AssertionKey       []byte
	RequestingMemberID string
	SubjectKeyHash     string
	PolicyEpoch        int64
}

// PeerFrameResult is one owner's frame export outcome (secret-free residuals).
type PeerFrameResult struct {
	MemberID  string
	OK        bool
	Result    *fleetcache.FrameExportResult
	ErrorCode string
	Residual  string
}

// FrameExportOwnersResult aggregates owner-directed frame fetches.
type FrameExportOwnersResult struct {
	Status                    fleetcache.FrameExportStatus
	Result                    *fleetcache.FrameExportResult
	OwnersTried               []string
	PeerResults               []PeerFrameResult
	OriginFallbackRecommended bool
	Residual                  string
}

// FetchFrameOwners queries each owner in order until a verified pure-zstd frame or exhaustion.
func (c *FrameExportClient) FetchFrameOwners(
	ctx context.Context,
	fleetID string,
	req fleetcache.FrameExportRequest,
	owners []fleetcache.OwnerContact,
	originFallback bool,
) (FrameExportOwnersResult, error) {
	out := FrameExportOwnersResult{OriginFallbackRecommended: originFallback}
	if c == nil {
		out.Status = fleetcache.FrameExportModeOff
		out.Residual = "frame client nil; origin fallback recommended"
		out.OriginFallbackRecommended = true
		return out, nil
	}
	mode := c.Mode
	if mode == "" {
		mode = fleetcache.ModeOff
	}
	if mode == fleetcache.ModeOff || mode == fleetcache.ModeShadow {
		out.Status = fleetcache.FrameExportModeOff
		out.Residual = "fleet-cache mode off or shadow; peer frame export skipped"
		out.OriginFallbackRecommended = originFallback || mode == fleetcache.ModeOff
		return out, nil
	}
	req.LocatorHash = strings.ToLower(strings.TrimSpace(req.LocatorHash))
	if err := fleetcache.ValidateFrameExportRequest(req); err != nil {
		out.Status = fleetcache.FrameExportInvalid
		return out, err
	}
	if strings.TrimSpace(c.MeshToken) == "" || len(c.AssertionKey) < 16 {
		out.Status = fleetcache.FrameExportUnavailable
		out.Residual = "frame client not configured"
		out.OriginFallbackRecommended = true
		return out, apperr.New(apperr.CodePolicyDenial, "frame export requires mesh token and assertion key")
	}
	if strings.TrimSpace(c.RequestingMemberID) == "" {
		out.Status = fleetcache.FrameExportInvalid
		return out, apperr.New(apperr.CodeInvalidArgument, "requesting member id required")
	}
	to := c.Timeout
	if to <= 0 {
		to = DefaultPeerTimeout
	}
	client := c.Client
	if client == nil {
		client = &http.Client{Timeout: to}
	}

	for _, o := range owners {
		out.OwnersTried = append(out.OwnersTried, o.MemberID)
		pr := PeerFrameResult{MemberID: o.MemberID}
		if strings.TrimSpace(o.PeerURL) == "" {
			pr.OK = false
			pr.ErrorCode = "no_url"
			pr.Residual = "owner peer_url missing"
			out.PeerResults = append(out.PeerResults, pr)
			continue
		}
		now := time.Now().UTC()
		a, err := fleetcache.IssueAssertion(c.AssertionKey, fleetcache.AssertionClaims{
			FleetID:            fleetID,
			RequestingMemberID: c.RequestingMemberID,
			LocatorHash:        req.LocatorHash,
			Operation:          fleetcache.OpFrame,
			SubjectKeyHash:     c.SubjectKeyHash,
			PolicyEpoch:        c.PolicyEpoch,
			IssuedAt:           now,
			ExpiresAt:          now.Add(fleetcache.DefaultAssertionTTL),
		})
		if err != nil {
			pr.OK = false
			pr.ErrorCode = "assertion"
			pr.Residual = "issue assertion failed"
			out.PeerResults = append(out.PeerResults, pr)
			continue
		}
		enc, err := fleetcache.EncodeAssertionHeader(a)
		if err != nil {
			pr.OK = false
			pr.ErrorCode = "assertion"
			pr.Residual = "encode assertion failed"
			out.PeerResults = append(out.PeerResults, pr)
			continue
		}
		base := strings.TrimRight(strings.TrimSpace(o.PeerURL), "/")
		u := base + FramePath(req.LocatorHash, req.Seq)
		reqCtx, cancel := context.WithTimeout(ctx, to)
		httpReq, err := http.NewRequestWithContext(reqCtx, http.MethodGet, u, nil)
		if err != nil {
			cancel()
			pr.OK = false
			pr.ErrorCode = "request"
			pr.Residual = "build request failed"
			out.PeerResults = append(out.PeerResults, pr)
			continue
		}
		httpReq.Header.Set(MeshTokenHeader, c.MeshToken)
		httpReq.Header.Set(CacheAssertionHeader, enc)
		httpReq.Header.Set("Accept", fleetcache.ContentTypePureZstd)
		httpReq.Header.Set("Accept-Encoding", "identity")
		if req.DeclaredZstdSize > 0 {
			httpReq.Header.Set("X-Fleet-Zstd-Size", strconv.FormatInt(req.DeclaredZstdSize, 10))
		}
		if req.DeclaredZstdSHA256 != "" {
			httpReq.Header.Set("X-Fleet-Zstd-SHA256", req.DeclaredZstdSHA256)
		}
		res, err := client.Do(httpReq)
		if err != nil {
			cancel()
			pr.OK = false
			if reqCtx.Err() != nil {
				pr.ErrorCode = "timeout"
				pr.Residual = "peer timeout"
			} else {
				pr.ErrorCode = "peer_error"
				pr.Residual = "peer unreachable"
			}
			out.PeerResults = append(out.PeerResults, pr)
			continue
		}

		if res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusForbidden {
			_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 4<<10))
			_ = res.Body.Close()
			cancel()
			pr.OK = false
			pr.ErrorCode = "auth_failed"
			pr.Residual = "peer auth or scope denied"
			out.PeerResults = append(out.PeerResults, pr)
			continue
		}
		if res.StatusCode == http.StatusNotFound {
			_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 4<<10))
			_ = res.Body.Close()
			cancel()
			pr.OK = true
			pr.Result = &fleetcache.FrameExportResult{Status: fleetcache.FrameExportNotFound}
			out.PeerResults = append(out.PeerResults, pr)
			continue
		}
		if res.StatusCode == http.StatusConflict {
			body, _ := io.ReadAll(io.LimitReader(res.Body, 4<<10))
			_ = res.Body.Close()
			cancel()
			var errBody struct {
				Status string `json:"status"`
			}
			_ = json.Unmarshal(body, &errBody)
			st := fleetcache.FrameExportStatus(errBody.Status)
			if st == "" {
				st = fleetcache.FrameExportNotMaterial
			}
			pr.OK = true
			pr.Result = &fleetcache.FrameExportResult{Status: st}
			out.PeerResults = append(out.PeerResults, pr)
			continue
		}
		if res.StatusCode < 200 || res.StatusCode >= 300 {
			_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 4<<10))
			_ = res.Body.Close()
			cancel()
			pr.OK = false
			pr.ErrorCode = "http_error"
			pr.Residual = "peer HTTP error"
			out.PeerResults = append(out.PeerResults, pr)
			continue
		}

		// Integrity: Content-Length must not silently override client-declared size.
		// Prefer req.Declared* (manifest) over peer-supplied headers; peer may lie.
		var contentLen int64
		if cl := res.Header.Get("Content-Length"); cl != "" {
			if n, e := strconv.ParseInt(cl, 10, 64); e == nil && n > 0 {
				contentLen = n
			}
		}
		if req.DeclaredZstdSize > 0 && contentLen > 0 && contentLen != req.DeclaredZstdSize {
			_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, fleetcache.MaxZstdFrameBytes+1))
			_ = res.Body.Close()
			cancel()
			pr.OK = false
			pr.ErrorCode = "size_mismatch"
			pr.Residual = "content-length disagrees with declared zstd size"
			out.PeerResults = append(out.PeerResults, pr)
			continue
		}
		// Read bound: declared size wins; else Content-Length; else hard cap.
		readSize := req.DeclaredZstdSize
		if readSize <= 0 {
			readSize = contentLen
		}

		var raw []byte
		var rerr error
		if readSize > 0 {
			if readSize > fleetcache.MaxZstdFrameBytes {
				_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 1<<10))
				_ = res.Body.Close()
				cancel()
				pr.OK = false
				pr.ErrorCode = "oversize"
				pr.Residual = "declared/content-length exceeds max"
				out.PeerResults = append(out.PeerResults, pr)
				continue
			}
			// Exact size with early EOF / extra-byte fail closed.
			limited := io.LimitReader(res.Body, readSize+1)
			raw, rerr = fleetcache.ReadExactFrameBody(limited, readSize)
			_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 1<<10))
			_ = res.Body.Close()
			cancel()
			if rerr != nil {
				pr.OK = false
				if apperr.CodeOf(rerr) == apperr.CodeUpstreamProtocol {
					pr.ErrorCode = "protocol"
				} else {
					pr.ErrorCode = "read"
				}
				pr.Residual = "frame body integrity failed"
				out.PeerResults = append(out.PeerResults, pr)
				continue
			}
		} else {
			// Unknown length: hard cap + reject oversize.
			lr := io.LimitReader(res.Body, fleetcache.MaxZstdFrameBytes+1)
			raw, rerr = io.ReadAll(lr)
			_ = res.Body.Close()
			cancel()
			if rerr != nil {
				pr.OK = false
				pr.ErrorCode = "read"
				pr.Residual = "body read failed"
				out.PeerResults = append(out.PeerResults, pr)
				continue
			}
			if int64(len(raw)) > fleetcache.MaxZstdFrameBytes {
				pr.OK = false
				pr.ErrorCode = "oversize"
				pr.Residual = "frame exceeds max"
				out.PeerResults = append(out.PeerResults, pr)
				continue
			}
		}

		// Fail closed: body must match client-declared size/hash when set (manifest).
		// Also reject peer response headers that disagree with declared or body.
		bodySHA := fleetcacheSHA(raw)
		if req.DeclaredZstdSize > 0 {
			if err := fleetcache.VerifyPureZstdFrame(raw, req.DeclaredZstdSize, req.DeclaredZstdSHA256); err != nil {
				pr.OK = false
				pr.ErrorCode = "corrupt"
				pr.Residual = "body disagrees with declared size/hash"
				out.PeerResults = append(out.PeerResults, pr)
				continue
			}
		} else if req.DeclaredZstdSHA256 != "" {
			if err := fleetcache.VerifyPureZstdFrame(raw, int64(len(raw)), req.DeclaredZstdSHA256); err != nil {
				pr.OK = false
				pr.ErrorCode = "corrupt"
				pr.Residual = "body disagrees with declared hash"
				out.PeerResults = append(out.PeerResults, pr)
				continue
			}
		} else {
			// No client declaration: still bound size; optional header verify if present.
			hdrSHA := res.Header.Get("X-Fleet-Zstd-SHA256")
			if err := fleetcache.VerifyPureZstdFrame(raw, int64(len(raw)), hdrSHA); err != nil {
				pr.OK = false
				pr.ErrorCode = "corrupt"
				pr.Residual = "frame verify failed"
				out.PeerResults = append(out.PeerResults, pr)
				continue
			}
		}
		// Peer-supplied hash header must not contradict declared or body.
		if hdrSHA := res.Header.Get("X-Fleet-Zstd-SHA256"); hdrSHA != "" {
			if !strings.EqualFold(hdrSHA, bodySHA) {
				pr.OK = false
				pr.ErrorCode = "corrupt"
				pr.Residual = "response hash header disagrees with body"
				out.PeerResults = append(out.PeerResults, pr)
				continue
			}
			if req.DeclaredZstdSHA256 != "" && !strings.EqualFold(hdrSHA, req.DeclaredZstdSHA256) {
				pr.OK = false
				pr.ErrorCode = "corrupt"
				pr.Residual = "response hash header disagrees with declared hash"
				out.PeerResults = append(out.PeerResults, pr)
				continue
			}
		}
		if hdrSz := res.Header.Get("X-Fleet-Zstd-Size"); hdrSz != "" {
			if n, e := strconv.ParseInt(hdrSz, 10, 64); e == nil && n > 0 {
				if n != int64(len(raw)) {
					pr.OK = false
					pr.ErrorCode = "corrupt"
					pr.Residual = "response size header disagrees with body"
					out.PeerResults = append(out.PeerResults, pr)
					continue
				}
				if req.DeclaredZstdSize > 0 && n != req.DeclaredZstdSize {
					pr.OK = false
					pr.ErrorCode = "size_mismatch"
					pr.Residual = "response size header disagrees with declared size"
					out.PeerResults = append(out.PeerResults, pr)
					continue
				}
			}
		}

		fr := fleetcache.FrameExportResult{
			Bytes:  raw,
			Size:   int64(len(raw)),
			SHA256: bodySHA,
			Seq:    req.Seq,
			Status: fleetcache.FrameExportOK,
		}
		pr.OK = true
		pr.Result = &fr
		out.PeerResults = append(out.PeerResults, pr)
		cp := fr
		out.Status = fleetcache.FrameExportOK
		out.Result = &cp
		out.OriginFallbackRecommended = false
		return out, nil
	}

	var anyFail bool
	for _, p := range out.PeerResults {
		if !p.OK {
			anyFail = true
		}
	}
	if anyFail {
		out.Status = fleetcache.FrameExportUnavailable
		out.Residual = "owner frame export incomplete; origin fallback recommended"
		out.OriginFallbackRecommended = true
		return out, nil
	}
	out.Status = fleetcache.FrameExportNotFound
	out.Residual = "no owner frame hit"
	out.OriginFallbackRecommended = originFallback
	return out, nil
}

func fleetcacheSHA(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
