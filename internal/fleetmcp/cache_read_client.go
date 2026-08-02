package fleetmcp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/fleetcache"
)

// DecodedReadClient performs owner-directed bounded decoded reads (FLC-031).
// Contacts only the provided owner set — never full-roster broadcast.
type DecodedReadClient struct {
	Client    *http.Client
	MeshToken string
	Timeout   time.Duration
	// Mode is fleet-cache mode. Empty/off/shadow skip peer I/O.
	Mode fleetcache.Mode
	// AssertionKey issues OpRead assertions per attempt (HMAC material; never log).
	AssertionKey []byte
	// RequestingMemberID is stamped into assertions.
	RequestingMemberID string
	// SubjectKeyHash optional opaque subject hash for claims.
	SubjectKeyHash string
	PolicyEpoch    int64
}

// PeerDecodedReadResult is one owner's decoded-read outcome (secret-free residuals).
type PeerDecodedReadResult struct {
	MemberID  string
	OK        bool
	Result    *fleetcache.DecodedReadResult
	ErrorCode string
	Residual  string
}

// DecodedReadOwnersResult aggregates owner-directed decoded reads.
type DecodedReadOwnersResult struct {
	Status                    fleetcache.DecodedReadStatus
	Result                    *fleetcache.DecodedReadResult
	OwnersTried               []string
	PeerResults               []PeerDecodedReadResult
	OriginFallbackRecommended bool
	Residual                  string
}

// ReadOwners queries each owner in order until a verified decoded hit or exhaustion.
// assertionMaxDecoded is stamped into each assertion (0 → request/default ceiling).
func (c *DecodedReadClient) ReadOwners(
	ctx context.Context,
	fleetID string,
	req fleetcache.DecodedReadRequest,
	owners []fleetcache.OwnerContact,
	originFallback bool,
) (DecodedReadOwnersResult, error) {
	out := DecodedReadOwnersResult{OriginFallbackRecommended: originFallback}
	if c == nil {
		out.Status = fleetcache.DecodedReadModeOff
		out.Residual = "decoded read client nil; origin fallback recommended"
		out.OriginFallbackRecommended = true
		return out, nil
	}
	mode := c.Mode
	if mode == "" {
		mode = fleetcache.ModeOff
	}
	if mode == fleetcache.ModeOff || mode == fleetcache.ModeShadow {
		out.Status = fleetcache.DecodedReadModeOff
		out.Residual = "fleet-cache mode off or shadow; peer decoded read skipped"
		out.OriginFallbackRecommended = originFallback || mode == fleetcache.ModeOff
		return out, nil
	}
	req.LocatorHash = strings.ToLower(strings.TrimSpace(req.LocatorHash))
	if err := fleetcache.ValidateDecodedReadRequest(req); err != nil {
		out.Status = fleetcache.DecodedReadInvalid
		return out, err
	}
	if strings.TrimSpace(c.MeshToken) == "" || len(c.AssertionKey) < 16 {
		out.Status = fleetcache.DecodedReadUnavailable
		out.Residual = "decoded read client not configured"
		out.OriginFallbackRecommended = true
		return out, apperr.New(apperr.CodePolicyDenial, "decoded read requires mesh token and assertion key")
	}
	if strings.TrimSpace(c.RequestingMemberID) == "" {
		out.Status = fleetcache.DecodedReadInvalid
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

	claimMax := req.MaxDecodedBytes
	if claimMax <= 0 {
		claimMax = fleetcache.DefaultDecodedReadCeiling
	}
	// Known-size forms: claim must cover the request.
	switch req.Kind {
	case fleetcache.ReadKindByteRange:
		if req.Length > claimMax {
			claimMax = req.Length
		}
	case fleetcache.ReadKindTailBytes:
		if req.TailN > claimMax {
			claimMax = req.TailN
		}
	}
	if claimMax > fleetcache.AbsoluteDecodedReadCeiling {
		claimMax = fleetcache.AbsoluteDecodedReadCeiling
	}

	for _, o := range owners {
		out.OwnersTried = append(out.OwnersTried, o.MemberID)
		pr := PeerDecodedReadResult{MemberID: o.MemberID}
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
			Operation:          fleetcache.OpRead,
			MaxDecodedBytes:    claimMax,
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
		body, _ := json.Marshal(decodedReadJSON{
			Kind:            req.Kind,
			Start:           req.Start,
			Length:          req.Length,
			StartLine:       req.StartLine,
			LineCount:       req.LineCount,
			TailN:           req.TailN,
			MaxDecodedBytes: req.MaxDecodedBytes,
		})
		base := strings.TrimRight(strings.TrimSpace(o.PeerURL), "/")
		u := base + DecodedReadPath(req.LocatorHash)
		reqCtx, cancel := context.WithTimeout(ctx, to)
		httpReq, err := http.NewRequestWithContext(reqCtx, http.MethodPost, u, bytes.NewReader(body))
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
		httpReq.Header.Set("Content-Type", "application/json")
		httpReq.Header.Set("Accept", "application/json")
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
		raw, _ := io.ReadAll(io.LimitReader(res.Body, fleetcache.AbsoluteDecodedReadCeiling+8<<10))
		_ = res.Body.Close()
		cancel()
		if res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusForbidden {
			pr.OK = false
			pr.ErrorCode = "auth_failed"
			pr.Residual = "peer auth or scope denied"
			// Try parse residual status.
			var errBody struct {
				Status string `json:"status"`
			}
			_ = json.Unmarshal(raw, &errBody)
			if errBody.Status == string(fleetcache.DecodedReadScopeDenied) {
				pr.ErrorCode = "scope_denied"
			}
			out.PeerResults = append(out.PeerResults, pr)
			continue
		}
		if res.StatusCode == http.StatusNotFound {
			pr.OK = true
			pr.Result = &fleetcache.DecodedReadResult{Status: fleetcache.DecodedReadNotFound}
			out.PeerResults = append(out.PeerResults, pr)
			continue
		}
		if res.StatusCode == http.StatusConflict {
			pr.OK = true
			pr.Result = &fleetcache.DecodedReadResult{Status: fleetcache.DecodedReadNotMaterialized, Residual: "not_materialized"}
			out.PeerResults = append(out.PeerResults, pr)
			continue
		}
		if res.StatusCode < 200 || res.StatusCode >= 300 {
			pr.OK = false
			pr.ErrorCode = "http_error"
			pr.Residual = "peer HTTP error"
			out.PeerResults = append(out.PeerResults, pr)
			continue
		}
		var wrap decodedReadResponseJSON
		if err := json.Unmarshal(raw, &wrap); err != nil {
			pr.OK = false
			pr.ErrorCode = "protocol"
			pr.Residual = "invalid peer JSON"
			out.PeerResults = append(out.PeerResults, pr)
			continue
		}
		data, err := base64.StdEncoding.DecodeString(wrap.DataB64)
		if err != nil {
			pr.OK = false
			pr.ErrorCode = "protocol"
			pr.Residual = "invalid data_b64"
			out.PeerResults = append(out.PeerResults, pr)
			continue
		}
		if int64(len(data)) > fleetcache.AbsoluteDecodedReadCeiling {
			pr.OK = false
			pr.ErrorCode = "over_ceiling"
			pr.Residual = "peer body exceeds absolute ceiling"
			out.PeerResults = append(out.PeerResults, pr)
			continue
		}
		dr := fleetcache.DecodedReadResult{
			Data:              data,
			RawStart:          wrap.RawStart,
			RawEnd:            wrap.RawEnd,
			LineStart:         wrap.LineStart,
			LineEnd:           wrap.LineEnd,
			RequestedBytes:    wrap.DecodedBytes,
			DecompressedBytes: wrap.DecompressedBytes,
			FramesOpened:      wrap.FramesOpened,
			Sealed:            wrap.Sealed,
			Status:            fleetcache.DecodedReadOK,
		}
		pr.OK = true
		pr.Result = &dr
		out.PeerResults = append(out.PeerResults, pr)
		// First successful body wins.
		cp := dr
		out.Status = fleetcache.DecodedReadOK
		out.Result = &cp
		out.Residual = ""
		out.OriginFallbackRecommended = false
		return out, nil
	}

	// No body hit.
	var anyFail bool
	for _, p := range out.PeerResults {
		if !p.OK {
			anyFail = true
			continue
		}
		if p.Result != nil && p.Result.Status == fleetcache.DecodedReadNotMaterialized {
			out.Status = fleetcache.DecodedReadNotMaterialized
			out.Residual = "not_materialized"
			out.OriginFallbackRecommended = true
			return out, nil
		}
	}
	if anyFail {
		out.Status = fleetcache.DecodedReadUnavailable
		out.Residual = "owner decoded read incomplete; origin fallback recommended"
		out.OriginFallbackRecommended = true
		return out, nil
	}
	out.Status = fleetcache.DecodedReadNotFound
	out.Residual = "no owner decoded hit"
	out.OriginFallbackRecommended = originFallback
	return out, nil
}
