package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// FallthroughProbeResult is the evaluation of one invalid-bearer response.
type FallthroughProbeResult struct {
	// Denied is true when the response fails closed (401/403).
	Denied bool
	// FallthroughDetected is true when status is success and identity indicates
	// session/Basic/anonymous success despite invalid bearer.
	FallthroughDetected bool
	// StatusCode is the HTTP status observed.
	StatusCode int
	// Reason is a short non-secret explanation.
	Reason string
}

// FallthroughBodyClass classifies the response body for offline fallthrough
// evaluation (no secret material; labels only).
type FallthroughBodyClass string

const (
	// BodyClassUnknown — unparsed or non-JSON body without login/error markers.
	BodyClassUnknown FallthroughBodyClass = "unknown"
	// BodyClassEmpty — zero-length or whitespace-only body.
	BodyClassEmpty FallthroughBodyClass = "empty"
	// BodyClassWhoAmIAuthenticated — whoAmI-shaped JSON with authenticated=true.
	BodyClassWhoAmIAuthenticated FallthroughBodyClass = "whoami_authenticated"
	// BodyClassWhoAmIAnonymous — whoAmI-shaped JSON with anonymous=true.
	BodyClassWhoAmIAnonymous FallthroughBodyClass = "whoami_anonymous"
	// BodyClassErrorJSON — OAuth/error JSON (e.g. invalid_token) without success principal.
	BodyClassErrorJSON FallthroughBodyClass = "error_json"
	// BodyClassHTMLLogin — HTML login / form page (session realm leak signal when paired with 2xx).
	BodyClassHTMLLogin FallthroughBodyClass = "html_login"
	// BodyClassHTMLError — HTML error page (Stapler/404/500) without login form markers.
	// Paired with 2xx still counts as fallthrough (must have been 401/403).
	BodyClassHTMLError FallthroughBodyClass = "html_error"
)

// FallthroughProbeInput is the pure-function input for fallthrough classification
// from a probe that sent Authorization: Bearer <invalid>.
type FallthroughProbeInput struct {
	// StatusCode is the HTTP status observed.
	StatusCode int
	// WWWAuthenticate is the raw WWW-Authenticate header value (may be empty).
	WWWAuthenticate string
	// BodyClass is a coarse body classification (see FallthroughBodyClass).
	BodyClass FallthroughBodyClass
	// WhoAmIAuthenticated / WhoAmIAnonymous are optional explicit whoAmI flags
	// (when body was parsed as whoAmI). Prefer BodyClass when set.
	WhoAmIAuthenticated bool
	WhoAmIAnonymous     bool
}

// EvaluateInvalidBearerResponse applies FallthroughMustDeny to a Jenkins-like
// response observed after a request that carried Authorization: Bearer <invalid>.
//
// Contract:
//   - HTTP 401 or 403 → denied (pass)
//   - HTTP 200 with authenticated principal or anonymous success → fallthrough (fail)
//   - Other 2xx with body indicating whoAmI success → fallthrough (fail)
//   - Network/5xx are inconclusive (not treated as pass for qualification)
//
// Prefer ClassifyFallthroughProbe when WWW-Authenticate / body class are available.
func EvaluateInvalidBearerResponse(statusCode int, whoAmIAuthenticated, whoAmIAnonymous bool) FallthroughProbeResult {
	return ClassifyFallthroughProbe(FallthroughProbeInput{
		StatusCode:          statusCode,
		WhoAmIAuthenticated: whoAmIAuthenticated,
		WhoAmIAnonymous:     whoAmIAnonymous,
		BodyClass:           bodyClassFromWhoAmIFlags(whoAmIAuthenticated, whoAmIAnonymous),
	})
}

func bodyClassFromWhoAmIFlags(authenticated, anonymous bool) FallthroughBodyClass {
	switch {
	case authenticated:
		return BodyClassWhoAmIAuthenticated
	case anonymous:
		return BodyClassWhoAmIAnonymous
	default:
		return BodyClassUnknown
	}
}

// ClassifyFallthroughProbe is the pure FallthroughMustDeny evaluator:
// given status + optional WWW-Authenticate + body class, classify pass/fail.
//
// Pass (Denied): 401/403 (optionally with Bearer WWW-Authenticate challenge).
// Fail (FallthroughDetected): any 2xx success for a request that carried invalid bearer.
// Inconclusive: 5xx, 3xx, 404 without clear success, transport-only (status 0).
func ClassifyFallthroughProbe(in FallthroughProbeInput) FallthroughProbeResult {
	res := FallthroughProbeResult{StatusCode: in.StatusCode}
	if !FallthroughMustDeny {
		// Defensive: constant is always true; keep evaluators honest if it changes.
		res.Reason = "FallthroughMustDeny is false (misconfigured contract)"
		return res
	}

	// Resolve body class from flags when caller only set whoAmI bits.
	bc := in.BodyClass
	if bc == "" {
		bc = bodyClassFromWhoAmIFlags(in.WhoAmIAuthenticated, in.WhoAmIAnonymous)
	}
	authN := in.WhoAmIAuthenticated || bc == BodyClassWhoAmIAuthenticated
	anon := in.WhoAmIAnonymous || bc == BodyClassWhoAmIAnonymous
	www := strings.TrimSpace(in.WWWAuthenticate)
	bearerChallenge := wwwAuthenticateIsBearerChallenge(www)

	switch {
	case in.StatusCode == http.StatusUnauthorized || in.StatusCode == http.StatusForbidden:
		res.Denied = true
		if bearerChallenge {
			res.Reason = "resource server denied invalid bearer (Bearer WWW-Authenticate)"
		} else if www != "" {
			res.Reason = "resource server denied invalid bearer (non-Bearer WWW-Authenticate present)"
		} else {
			res.Reason = "resource server denied invalid bearer"
		}
		return res

	case in.StatusCode >= 200 && in.StatusCode < 300:
		res.FallthroughDetected = true
		switch {
		case authN:
			// Fail closed: invalid-bearer must never authenticate a principal.
			res.Reason = "invalid bearer succeeded as authenticated principal (session/Basic fallthrough)"
		case anon:
			res.Reason = "invalid bearer succeeded as anonymous (anon fallthrough)"
		case bc == BodyClassHTMLLogin:
			res.Reason = "invalid bearer returned HTML login page with success status (realm fallthrough)"
		case bc == BodyClassHTMLError:
			res.Reason = "invalid bearer returned HTML error page with success status (must be 401/403)"
		case bc == BodyClassErrorJSON:
			// 2xx with error JSON is still a contract fail (should have been 401).
			res.Reason = "invalid bearer returned success status with error JSON body (must be 401/403)"
		case bc == BodyClassEmpty:
			res.Reason = "invalid bearer returned success status with empty body (possible fallthrough)"
		default:
			res.Reason = "invalid bearer returned success status (possible fallthrough)"
		}
		return res

	case in.StatusCode == 0:
		res.Reason = "inconclusive: no HTTP status (transport failure)"
		return res

	default:
		res.Reason = fmt.Sprintf("inconclusive HTTP %d (not a pass for fallthrough qualification)", in.StatusCode)
		return res
	}
}

// wwwAuthenticateIsBearerChallenge reports RFC 6750-style Bearer challenges.
// Comparison is case-insensitive on the auth-scheme token.
func wwwAuthenticateIsBearerChallenge(www string) bool {
	www = strings.TrimSpace(www)
	if www == "" {
		return false
	}
	// Multiple challenges may be comma-separated; check each scheme start.
	// Simple scan: any challenge token that is "Bearer" (optionally with params).
	for _, part := range splitAuthChallenges(www) {
		scheme, _, _ := strings.Cut(strings.TrimSpace(part), " ")
		if strings.EqualFold(scheme, "Bearer") {
			return true
		}
	}
	return false
}

// splitAuthChallenges splits WWW-Authenticate on commas that separate challenges.
// Parameter commas inside quoted strings are not fully parsed; good enough for
// offline fixture classification (Bearer realm="…", error="invalid_token").
func splitAuthChallenges(www string) []string {
	// Most servers emit a single Bearer challenge; keep simple split for multi.
	if !strings.Contains(www, ",") {
		return []string{www}
	}
	// If it looks like one Bearer challenge with params, do not split on param commas.
	trimmed := strings.TrimSpace(www)
	if strings.HasPrefix(strings.ToLower(trimmed), "bearer ") || strings.EqualFold(trimmed, "Bearer") {
		return []string{www}
	}
	return strings.Split(www, ",")
}

// ClassifyResponseBodyClass maps a bounded body sample to FallthroughBodyClass
// without retaining the body (offline fixture helper for probes/tests).
func ClassifyResponseBodyClass(body []byte) FallthroughBodyClass {
	if len(body) == 0 {
		return BodyClassEmpty
	}
	trim := strings.TrimSpace(string(body))
	if trim == "" {
		return BodyClassEmpty
	}
	lower := strings.ToLower(trim)
	// HTML login / form markers take precedence over generic HTML error.
	if strings.Contains(lower, "name=\"j_password\"") || strings.Contains(lower, "name='j_password'") ||
		strings.Contains(lower, "type=\"password\"") || strings.Contains(lower, "type='password'") ||
		strings.Contains(lower, "/j_spring_security_check") || strings.Contains(lower, "login form") {
		return BodyClassHTMLLogin
	}
	// HTML document without login form: Stapler/404/500-style error pages.
	if strings.HasPrefix(lower, "<!doctype html") || strings.HasPrefix(lower, "<html") {
		if htmlLooksLikeErrorPage(lower) {
			return BodyClassHTMLError
		}
		// Generic HTML without clear error markers still treated as login/realm
		// surface for fallthrough (historical html_login class).
		return BodyClassHTMLLogin
	}
	// Non-document HTML fragments with error markers.
	if strings.Contains(lower, "<h1>") && (strings.Contains(lower, "error") ||
		strings.Contains(lower, "not found") || strings.Contains(lower, "forbidden") ||
		strings.Contains(lower, "unauthorized")) {
		return BodyClassHTMLError
	}
	// JSON paths.
	if strings.HasPrefix(trim, "{") {
		var who struct {
			Authenticated bool   `json:"authenticated"`
			Anonymous     bool   `json:"anonymous"`
			Error         string `json:"error"`
			ErrorCode     string `json:"errorCode"`
		}
		if err := json.Unmarshal(body, &who); err == nil {
			if who.Error != "" || who.ErrorCode != "" {
				return BodyClassErrorJSON
			}
			if who.Authenticated {
				return BodyClassWhoAmIAuthenticated
			}
			if who.Anonymous {
				return BodyClassWhoAmIAnonymous
			}
		}
		// Generic error-shaped JSON without whoAmI flags.
		if strings.Contains(lower, "\"error\"") || strings.Contains(lower, "invalid_token") {
			return BodyClassErrorJSON
		}
	}
	return BodyClassUnknown
}

// htmlLooksLikeErrorPage detects common Jenkins/Stapler/proxy HTML error pages.
func htmlLooksLikeErrorPage(lowerHTML string) bool {
	markers := []string{
		"status code",
		"http status",
		"oops!",
		"something went wrong",
		"internal server error",
		"not found",
		"access denied",
		"forbidden",
		"unauthorized",
		"error 404",
		"error 500",
		"error 403",
		"error 401",
		"stack trace",
		"exception:",
		"javax.servlet",
		"org.kohsuke",
		"stapler",
	}
	for _, m := range markers {
		if strings.Contains(lowerHTML, m) {
			return true
		}
	}
	// <title>…Error…</title> or <h1/h2> with error-ish words.
	if strings.Contains(lowerHTML, "<title>") {
		// Cheap scan: title containing error/not found.
		if i := strings.Index(lowerHTML, "<title>"); i >= 0 {
			rest := lowerHTML[i:]
			if j := strings.Index(rest, "</title>"); j > 0 {
				title := rest[:j]
				if strings.Contains(title, "error") || strings.Contains(title, "not found") ||
					strings.Contains(title, "forbidden") || strings.Contains(title, "unauthorized") {
					return true
				}
			}
		}
	}
	return false
}

// FallthroughFixture is one pure offline classifier row (status + headers + body
// class → expected Denied / FallthroughDetected). Used by tests and probe-rs
// offline matrix output. No secrets.
type FallthroughFixture struct {
	// ID is a stable fixture key for docs/tests.
	ID string
	// Input is the pure classifier input.
	Input FallthroughProbeInput
	// WantDenied is the expected Denied flag.
	WantDenied bool
	// WantFallthrough is the expected FallthroughDetected flag.
	WantFallthrough bool
	// Summary is a short non-secret description for operator matrix output.
	Summary string
}

// OfflineFallthroughFixtures returns the expanded Wave 33 classifier matrix
// (empty body, HTML error/login, WWW-Authenticate Bearer, authenticated fail-closed).
// Contract: invalid-bearer success as authenticated → FallthroughDetected (fail closed).
func OfflineFallthroughFixtures() []FallthroughFixture {
	return []FallthroughFixture{
		{
			ID: "401_empty_bearer_www",
			Input: FallthroughProbeInput{
				StatusCode:      http.StatusUnauthorized,
				WWWAuthenticate: `Bearer realm="Jenkins", error="invalid_token"`,
				BodyClass:       BodyClassEmpty,
			},
			WantDenied: true,
			Summary:    "401 + empty body + Bearer WWW-Authenticate → deny (pass)",
		},
		{
			ID: "401_empty_no_www",
			Input: FallthroughProbeInput{
				StatusCode: http.StatusUnauthorized,
				BodyClass:  BodyClassEmpty,
			},
			WantDenied: true,
			Summary:    "401 + empty body → deny (pass)",
		},
		{
			ID: "401_error_json_bearer_www",
			Input: FallthroughProbeInput{
				StatusCode:      http.StatusUnauthorized,
				WWWAuthenticate: `Bearer realm="Jenkins", error="invalid_token", error_description="validation failed"`,
				BodyClass:       BodyClassErrorJSON,
			},
			WantDenied: true,
			Summary:    "401 + error JSON + Bearer challenge → deny (pass)",
		},
		{
			ID: "401_html_error",
			Input: FallthroughProbeInput{
				StatusCode:      http.StatusUnauthorized,
				WWWAuthenticate: `Bearer realm="Jenkins"`,
				BodyClass:       BodyClassHTMLError,
			},
			WantDenied: true,
			Summary:    "401 + HTML error page + Bearer WWW-Authenticate → deny (pass)",
		},
		{
			ID: "403_html_error",
			Input: FallthroughProbeInput{
				StatusCode: http.StatusForbidden,
				BodyClass:  BodyClassHTMLError,
			},
			WantDenied: true,
			Summary:    "403 + HTML error page → deny (pass)",
		},
		{
			ID: "401_basic_www_still_deny",
			Input: FallthroughProbeInput{
				StatusCode:      http.StatusUnauthorized,
				WWWAuthenticate: `Basic realm="Jenkins"`,
				BodyClass:       BodyClassEmpty,
			},
			WantDenied: true,
			Summary:    "401 + Basic WWW-Authenticate still deny (pass; scheme noted)",
		},
		{
			ID: "200_whoami_authenticated_fail_closed",
			Input: FallthroughProbeInput{
				StatusCode:          http.StatusOK,
				BodyClass:           BodyClassWhoAmIAuthenticated,
				WhoAmIAuthenticated: true,
			},
			WantFallthrough: true,
			Summary:         "200 authenticated principal → fallthrough FAIL (must deny invalid bearer)",
		},
		{
			ID: "200_whoami_anonymous",
			Input: FallthroughProbeInput{
				StatusCode: http.StatusOK,
				BodyClass:  BodyClassWhoAmIAnonymous,
			},
			WantFallthrough: true,
			Summary:         "200 anonymous whoAmI → fallthrough FAIL",
		},
		{
			ID: "200_empty_body",
			Input: FallthroughProbeInput{
				StatusCode: http.StatusOK,
				BodyClass:  BodyClassEmpty,
			},
			WantFallthrough: true,
			Summary:         "200 + empty body → fallthrough FAIL",
		},
		{
			ID: "204_empty",
			Input: FallthroughProbeInput{
				StatusCode: http.StatusNoContent,
				BodyClass:  BodyClassEmpty,
			},
			WantFallthrough: true,
			Summary:         "204 No Content → fallthrough FAIL",
		},
		{
			ID: "200_html_login",
			Input: FallthroughProbeInput{
				StatusCode: http.StatusOK,
				BodyClass:  BodyClassHTMLLogin,
			},
			WantFallthrough: true,
			Summary:         "200 + HTML login form → realm fallthrough FAIL",
		},
		{
			ID: "200_html_error",
			Input: FallthroughProbeInput{
				StatusCode: http.StatusOK,
				BodyClass:  BodyClassHTMLError,
			},
			WantFallthrough: true,
			Summary:         "200 + HTML error page → fallthrough FAIL (must be 401/403)",
		},
		{
			ID: "200_error_json",
			Input: FallthroughProbeInput{
				StatusCode: http.StatusOK,
				BodyClass:  BodyClassErrorJSON,
			},
			WantFallthrough: true,
			Summary:         "200 + error JSON → fallthrough FAIL",
		},
		{
			ID: "502_inconclusive",
			Input: FallthroughProbeInput{
				StatusCode: http.StatusBadGateway,
				BodyClass:  BodyClassEmpty,
			},
			Summary: "502 → inconclusive (not a pass)",
		},
		{
			ID: "0_transport",
			Input: FallthroughProbeInput{
				StatusCode: 0,
			},
			Summary: "status 0 transport → inconclusive",
		},
	}
}

// FormatFallthroughClassifierMatrix renders the offline fixture matrix for
// oauth probe-rs --offline / doctor notes (secret-free).
func FormatFallthroughClassifierMatrix() string {
	var b strings.Builder
	b.WriteString("fallthrough classifier matrix (offline fixtures; Done* for classifier only):\n")
	for _, f := range OfflineFallthroughFixtures() {
		eval := ClassifyFallthroughProbe(f.Input)
		outcome := "inconclusive"
		switch {
		case eval.Denied:
			outcome = "DENIED(pass)"
		case eval.FallthroughDetected:
			outcome = "FALLTHROUGH(fail)"
		}
		b.WriteString(fmt.Sprintf("  - %-36s → %s  %s\n", f.ID, outcome, f.Summary))
	}
	b.WriteString("  note: live jwt-auth-filter lab still required for production pin\n")
	return b.String()
}
