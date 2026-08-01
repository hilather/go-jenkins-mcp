package jenkins

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// WhoAmI is the sanitized Jenkins identity response from /whoAmI/api/json.
// It contains no credential material.
//
// ID is the stable principal: Jenkins WhoAmI exposes the login as JSON field
// "name" (not "id"); older fixtures may still emit "id". WhoAmI maps both.
type WhoAmI struct {
	ID            string `json:"id"`
	FullName      string `json:"fullName"`
	Anonymous     bool   `json:"anonymous"`
	Authenticated bool   `json:"authenticated"`
}

// whoAmIWire is the raw controller JSON (field names vary by version / docs).
type whoAmIWire struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	FullName      string `json:"fullName"`
	Anonymous     bool   `json:"anonymous"`
	Authenticated bool   `json:"authenticated"`
}

// maxWhoAmIBody caps identity JSON so a misbehaving controller cannot inflate memory.
const maxWhoAmIBody = 64 << 10 // 64 KiB

// WhoAmIPath is the approved Jenkins identity endpoint (AUTH-004).
const WhoAmIPath = "/whoAmI/api/json"

// WhoAmI calls Jenkins /whoAmI/api/json with the client's credentials.
// On HTTP errors the returned error message never includes the API token.
func (opts *Client) WhoAmI(ctx context.Context) (WhoAmI, error) {
	if opts == nil {
		return WhoAmI{}, fmt.Errorf("jenkins client is nil")
	}
	client := opts.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := opts.CallJenkins(ctx, client, http.MethodGet, WhoAmIPath, nil, nil)
	if err != nil {
		// Transport errors may echo URLs; strip any accidental userinfo and never
		// surface Basic auth material (token is only in the request header).
		return WhoAmI{}, fmt.Errorf("whoAmI request failed: %w", sanitizeWhoAmIErr(err))
	}
	defer resp.Body.Close()

	body, err := readLimited(resp.Body, maxWhoAmIBody)
	if err != nil {
		return WhoAmI{}, fmt.Errorf("failed to read whoAmI response")
	}

	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return WhoAmI{}, fmt.Errorf("whoAmI rejected credentials (HTTP %d)", resp.StatusCode)
	case resp.StatusCode == http.StatusNotFound:
		return WhoAmI{}, fmt.Errorf("whoAmI endpoint not found (HTTP 404)")
	case resp.StatusCode != http.StatusOK:
		// Do not dump body into the error (may contain unexpected content).
		return WhoAmI{}, fmt.Errorf("whoAmI returned HTTP %d", resp.StatusCode)
	}

	var wire whoAmIWire
	if err := json.Unmarshal(body, &wire); err != nil {
		return WhoAmI{}, fmt.Errorf("whoAmI response is not valid JSON")
	}
	// Prefer explicit "id"; real Jenkins LTS WhoAmI uses "name" for the login.
	id := strings.TrimSpace(wire.ID)
	if id == "" {
		id = strings.TrimSpace(wire.Name)
	}
	return WhoAmI{
		ID:            id,
		FullName:      strings.TrimSpace(wire.FullName),
		Anonymous:     wire.Anonymous,
		Authenticated: wire.Authenticated,
	}, nil
}

// sanitizeWhoAmIErr avoids propagating huge or credential-like transport strings.
// Structured apperr values (AuthProvider refresh fail, mutation guard denials)
// are preserved so callers can fail closed with stable codes.
func sanitizeWhoAmIErr(err error) error {
	if err == nil {
		return nil
	}
	var ae *apperr.Error
	if errors.As(err, &ae) && ae != nil {
		// Already secret-scrubbed by construction; do not re-wrap into a bare
		// "transport error" (would drop CodeAuthentication from mid-serve refresh).
		return ae
	}
	msg := err.Error()
	// Collapse to a short, non-secret class message when the raw error is long.
	if len(msg) > 200 {
		return fmt.Errorf("transport error")
	}
	if strings.Contains(strings.ToLower(msg), "token") ||
		strings.Contains(msg, "Authorization") {
		return fmt.Errorf("transport error")
	}
	return err
}
