package jenkins

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// ErrCrossOrigin is returned when a request would send credentials to an
// unapproved origin (NET-001).
var ErrCrossOrigin = errors.New("cross-origin jenkins request refused")

// ErrInvalidBaseURL is returned when the configured Jenkins base URL cannot be
// normalized into a pinned origin.
var ErrInvalidBaseURL = errors.New("invalid jenkins base url")

// NormalizeBaseURL parses and normalizes a Jenkins base URL for origin pinning.
//
// Rules (NET-001):
//   - scheme must be http or https
//   - host is required
//   - userinfo is rejected (credentials belong in the secret store / client fields)
//   - fragment and query are stripped
//   - path is cleaned; trailing slash removed (path-prefix reverse proxies kept)
//   - default ports are left explicit if present in input host
func NormalizeBaseURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("%w: empty", ErrInvalidBaseURL)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidBaseURL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("%w: unsupported scheme %q", ErrInvalidBaseURL, u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("%w: missing host", ErrInvalidBaseURL)
	}
	if u.User != nil {
		return nil, fmt.Errorf("%w: userinfo not allowed", ErrInvalidBaseURL)
	}
	// Reject opaque / protocol-relative misuse after parse.
	if u.Opaque != "" {
		return nil, fmt.Errorf("%w: opaque URL not allowed", ErrInvalidBaseURL)
	}

	u.Fragment = ""
	u.RawFragment = ""
	u.RawQuery = ""
	u.ForceQuery = false

	// Clean path while preserving a reverse-proxy prefix (e.g. /jenkins).
	p := u.Path
	if p == "" {
		p = "/"
	}
	// path.Clean collapses ".." — apply on a rooted path then re-trim.
	p = cleanURLPath(p)
	if p == "/" {
		u.Path = ""
	} else {
		u.Path = strings.TrimRight(p, "/")
	}
	u.RawPath = ""
	u.OmitHost = false
	return u, nil
}

// cleanURLPath returns a cleaned absolute path without a trailing slash
// (except for root "/"). Rejects backslash-style separators that some agents
// might smuggle.
func cleanURLPath(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	// Manual clean: collapse //, resolve . and .. without importing path
	// (path.Clean is fine for URL paths that are already slash-separated).
	segs := strings.Split(p, "/")
	out := make([]string, 0, len(segs))
	for _, s := range segs {
		switch s {
		case "", ".":
			continue
		case "..":
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
		default:
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return "/"
	}
	return "/" + strings.Join(out, "/")
}

// SameOrigin reports whether target is the same scheme/host/port as base and
// under the approved base path prefix (reverse-proxy path).
func SameOrigin(base, target *url.URL) bool {
	if base == nil || target == nil {
		return false
	}
	if !strings.EqualFold(base.Scheme, target.Scheme) {
		return false
	}
	if !strings.EqualFold(base.Host, target.Host) {
		return false
	}
	return pathUnderBase(base.Path, target.Path)
}

// pathUnderBase reports whether targetPath is basePath or a sub-path of it.
// Empty/root base path accepts any path on the host.
func pathUnderBase(basePath, targetPath string) bool {
	bp := strings.TrimRight(basePath, "/")
	if bp == "" {
		return true
	}
	tp := targetPath
	if tp == "" {
		tp = "/"
	}
	if tp == bp {
		return true
	}
	return strings.HasPrefix(tp, bp+"/")
}

// resolveRequestURL builds the full request URL for an API path.
//
// Relative paths (including those starting with "/") are joined to the
// normalized base, preserving any path prefix. Absolute http(s) URLs are
// accepted only when they match the pinned origin (scheme, host, port, path
// prefix). Other schemes and cross-origin absolute URLs are rejected.
func (opts *Client) resolveRequestURL(apiPath string) (string, error) {
	base, err := opts.normalizedBase()
	if err != nil {
		return "", err
	}
	apiPath = strings.TrimSpace(apiPath)
	if apiPath == "" {
		return base.String(), nil
	}

	// Absolute URL?
	if strings.HasPrefix(apiPath, "http://") || strings.HasPrefix(apiPath, "https://") ||
		strings.HasPrefix(apiPath, "//") {
		if strings.HasPrefix(apiPath, "//") {
			return "", fmt.Errorf("%w: protocol-relative URL not allowed", ErrCrossOrigin)
		}
		target, err := url.Parse(apiPath)
		if err != nil {
			return "", fmt.Errorf("invalid absolute URL: %w", err)
		}
		if target.User != nil {
			return "", fmt.Errorf("%w: userinfo in request URL", ErrCrossOrigin)
		}
		if target.Fragment != "" || target.RawFragment != "" {
			target.Fragment = ""
			target.RawFragment = ""
		}
		if !SameOrigin(base, target) {
			return "", fmt.Errorf("%w: %s does not match pinned origin", ErrCrossOrigin, target.Host)
		}
		return target.String(), nil
	}

	// Relative (or root-absolute path): join with base path prefix.
	rel, err := url.Parse(apiPath)
	if err != nil {
		return "", fmt.Errorf("invalid api path: %w", err)
	}
	if rel.IsAbs() || rel.Host != "" {
		return "", fmt.Errorf("%w: non-http absolute or host-bearing path", ErrCrossOrigin)
	}
	if rel.Scheme != "" {
		return "", fmt.Errorf("%w: unsupported scheme in path", ErrCrossOrigin)
	}

	joined := *base
	basePath := strings.TrimRight(base.Path, "/")
	relPath := rel.Path
	if relPath == "" {
		// query-only relative?
		if rel.RawQuery != "" {
			joined.RawQuery = rel.RawQuery
			return joined.String(), nil
		}
		return base.String(), nil
	}
	if !strings.HasPrefix(relPath, "/") {
		relPath = "/" + relPath
	}
	// Keep path as concatenation; clean the path portion only.
	joined.Path = cleanURLPath(basePath + relPath)
	if joined.Path == "/" {
		// API paths are never just "/"; keep explicit root if that is what we got.
		joined.Path = "/"
	}
	joined.RawQuery = rel.RawQuery
	joined.Fragment = ""
	return joined.String(), nil
}

func (opts *Client) normalizedBase() (*url.URL, error) {
	if opts == nil {
		return nil, fmt.Errorf("%w: nil client", ErrInvalidBaseURL)
	}
	return NormalizeBaseURL(opts.URL)
}

// withPinnedRedirect returns a shallow copy of client with a CheckRedirect
// policy that refuses cross-origin redirects and strips URL userinfo.
// Credentials (Basic auth header) are never re-applied by this helper on a
// cross-origin hop because the hop is rejected outright.
func (opts *Client) withPinnedRedirect(client *http.Client) *http.Client {
	if client == nil {
		client = http.DefaultClient
	}
	base, err := opts.normalizedBase()
	if err != nil {
		// Leave redirect behavior default; CallJenkins will fail on resolve.
		return client
	}
	clone := *client
	clone.CheckRedirect = pinnedCheckRedirect(base, client.CheckRedirect)
	return &clone
}

func pinnedCheckRedirect(base *url.URL, prev func(*http.Request, []*http.Request) error) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		// Strip any userinfo that a Location might have injected.
		if req.URL != nil {
			req.URL.User = nil
		}
		if req.URL == nil || !SameOrigin(base, req.URL) {
			host := ""
			if req.URL != nil {
				host = req.URL.Host
			}
			return fmt.Errorf("%w: redirect to %q", ErrCrossOrigin, host)
		}
		// Drop Authorization on redirect if a previous policy would; we keep
		// same-origin Basic auth because Jenkins often redirects / to /login
		// or trailing-slash variants on the same origin.
		if prev != nil {
			return prev(req, via)
		}
		return nil
	}
}
