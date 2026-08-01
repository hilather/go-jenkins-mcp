package diagnostics

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/auth"
	"github.com/simonfxr/go-jenkins-mcp/internal/config"
	"github.com/simonfxr/go-jenkins-mcp/internal/policy"
	"github.com/simonfxr/go-jenkins-mcp/internal/profile"
	"github.com/simonfxr/go-jenkins-mcp/internal/redact"
	"github.com/simonfxr/go-jenkins-mcp/internal/telemetry"
)

// Support bundle (OPS-001 / Wave 23 expand): privacy-scrubbed local diagnostics only.
// Explicitly excludes tokens, keyring material, full logs, artifact bodies,
// cookies, and Authorization headers.

// Bundle category names (stable, listed before creation).
const (
	BundleCatManifest            = "manifest"
	BundleCatVersion             = "version"
	BundleCatProfile             = "profile_effective_no_secrets"
	BundleCatDoctor              = "doctor_report"
	BundleCatCacheStatus         = "cache_status"
	BundleCatCapabilities        = "capability_summary"
	BundleCatMetrics             = "metrics_snapshot"
	BundleCatErrorSigs           = "recent_error_signatures"
	BundleCatRuntime             = "runtime_goos_goarch"
	BundleCatSecuritySelfCheck   = "security_self_check"
	BundleCatReleaseEvidenceLite = "release_evidence_lite"
	BundleCatRSQualification     = "rs_qualification_summary"
)

// BundleExcludedCategories documents what is never included (operator-facing).
var BundleExcludedCategories = []string{
	"tokens_or_api_keys",
	"keyring_material",
	"cache_encryption_keys",
	"full_build_logs",
	"artifact_bodies",
	"cookies",
	"authorization_headers",
	"private_keys",
	"raw_http_transcripts",
	"raw_log_samples",
}

// DefaultBundleCategories is the include set for offline-safe members (Wave 23).
func DefaultBundleCategories() []string {
	return []string{
		BundleCatManifest,
		BundleCatVersion,
		BundleCatProfile,
		BundleCatDoctor,
		BundleCatCacheStatus,
		BundleCatCapabilities,
		BundleCatMetrics,
		BundleCatErrorSigs,
		BundleCatRuntime,
		BundleCatSecuritySelfCheck,
		BundleCatReleaseEvidenceLite,
		BundleCatRSQualification,
	}
}

// SupportBundleOptions configures a safe support bundle (OPS-001 residual).
type SupportBundleOptions struct {
	// Profile is required (non-secret connection profile).
	Profile *profile.Profile
	// Paths optional XDG paths; resolved when nil.
	Paths *config.Paths
	// Doctor report to embed (already sanitized). When nil, RunDoctor is invoked offline.
	DoctorReport *Report
	// DoctorOpts used when DoctorReport is nil (network skipped for bundle by default).
	DoctorOpts DoctorOptions
	// Cache status optional precomputed; when nil, RunCacheStatus is used.
	Cache *CacheStatus
	// CapabilitySummary is an optional already-safe capability JSON map (no secrets).
	CapabilitySummary map[string]any
	// ErrorSignatures are recent cached error signature hashes/messages (non-secret).
	// When empty and LogSample is set, signatures may be derived via ExtractCandidates.
	// When still empty, a residual note is written (no full logs).
	ErrorSignatures []ErrorSignatureEntry
	// LogSample is an optional size-capped log snippet used only to derive error
	// signature hashes (DIAG-001 ExtractCandidates). Never written raw into the zip.
	LogSample string
	// Metrics optional snapshot.
	Metrics *telemetry.Metrics
	// Version / Commit / BuildTime are binary metadata (diagnostics-local; no cmd import).
	Version   string
	Commit    string
	BuildTime string
	// PolicyResult optional preloaded policy for security self-check; when nil, LoadFromEnviron.
	PolicyResult *policy.LoadResult
	// SelfCheckReport optional precomputed security self-check; when nil and enabled, RunSecuritySelfCheck.
	SelfCheckReport *SelfCheckReport
	// RSQualification optional precomputed offline RS summary; when nil and enabled, built from Profile.
	RSQualification *auth.OfflineRSQualificationSummary
	// IncludeSecuritySelfCheck enables security_self_check.json. nil ⇒ true (offline-safe default).
	IncludeSecuritySelfCheck *bool
	// IncludeReleaseEvidenceLite enables release_evidence_lite.json. nil ⇒ true.
	IncludeReleaseEvidenceLite *bool
	// IncludeRSQualification enables rs_qualification_summary.json. nil ⇒ true.
	IncludeRSQualification *bool
	// OutputDir overrides the default cache dir for the zip. Empty ⇒ XDG cache/support-bundles.
	OutputDir string
	// Now optional clock.
	Now func() time.Time
	// PreviewOnly when true does not write a zip; only returns the plan.
	PreviewOnly bool
}

// ErrorSignatureEntry is a privacy-safe recent error signature row (DIAG-001 style).
type ErrorSignatureEntry struct {
	Signature string `json:"signature"`
	Pattern   string `json:"pattern,omitempty"`
	Count     int    `json:"count,omitempty"`
	// Message is redacted and truncated.
	Message string `json:"message,omitempty"`
}

// SupportBundlePlan is the preview / manifest of what a bundle will contain.
type SupportBundlePlan struct {
	Included []string `json:"included"`
	Excluded []string `json:"excluded"`
	// OutputPath is where the zip will be (or was) written.
	OutputPath string `json:"outputPath,omitempty"`
	// PreviewOnly is true when no archive was written.
	PreviewOnly bool `json:"previewOnly,omitempty"`
}

// SupportBundleResult is the outcome of CreateSupportBundle.
type SupportBundleResult struct {
	Plan       SupportBundlePlan `json:"plan"`
	Path       string            `json:"path,omitempty"`
	Bytes      int64             `json:"bytes,omitempty"`
	CreatedAt  time.Time         `json:"createdAt"`
	Categories []string          `json:"categories"`
}

// maxBundleErrorSigs bounds signature rows.
const maxBundleErrorSigs = 50

// maxBundleFileBytes soft-caps individual JSON members (defense in depth).
const maxBundleFileBytes = 1 << 20 // 1 MiB per member

// maxBundleLogSampleBytes caps LogSample before ExtractCandidates (never zip raw).
const maxBundleLogSampleBytes = 64 << 10 // 64 KiB

// releaseEvidenceLiteSchema is the diagnostics-local lite snapshot id (not cmd/release-evidence).
const releaseEvidenceLiteSchema = "jenkins-mcp.support-bundle.release-evidence-lite.v1"

// CreateSupportBundle writes a privacy-scrubbed zip under the user cache dir (OPS-001).
// Always lists included/excluded categories. Never embeds keyring tokens or full logs.
func CreateSupportBundle(ctx context.Context, opts SupportBundleOptions) (SupportBundleResult, error) {
	if opts.Profile == nil {
		return SupportBundleResult{}, apperr.New(apperr.CodeInvalidArgument, "profile is required")
	}
	now := time.Now().UTC()
	if opts.Now != nil {
		now = opts.Now().UTC()
	}

	included := buildIncludedCategories(opts)
	plan := SupportBundlePlan{
		Included:    append([]string(nil), included...),
		Excluded:    append([]string(nil), BundleExcludedCategories...),
		PreviewOnly: opts.PreviewOnly,
	}

	outDir, err := resolveBundleDir(opts)
	if err != nil {
		return SupportBundleResult{}, err
	}
	fname := fmt.Sprintf("support-bundle-%s-%s.zip",
		sanitizePathToken(string(opts.Profile.ID)),
		now.Format("20060102T150405Z"))
	outPath := filepath.Join(outDir, fname)
	plan.OutputPath = outPath

	if opts.PreviewOnly {
		return SupportBundleResult{
			Plan:       plan,
			CreatedAt:  now,
			Categories: included,
		}, nil
	}

	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return SupportBundleResult{}, apperr.New(apperr.CodeInternal, "failed to create support bundle directory")
	}

	// Build members in memory (bounded), then zip.
	members := map[string][]byte{}

	// manifest.json
	manifest := map[string]any{
		"schemaVersion": 1,
		"createdAt":     now.Format(time.RFC3339),
		"profileId":     string(opts.Profile.ID),
		"included":      included,
		"excluded":      BundleExcludedCategories,
		"redaction":     "secrets_scrubbed; no keyring values; no full logs; no artifact bodies; no raw log samples",
		"note":          "Support bundle OPS-001 (Wave 23 expand). Safe offline diagnostics only.",
	}
	members["manifest.json"] = mustJSON(manifest)

	// version.json
	members["version.json"] = mustJSON(map[string]any{
		"version":   nonEmpty(opts.Version, "dev"),
		"commit":    nonEmpty(opts.Commit, "unknown"),
		"buildTime": nonEmpty(opts.BuildTime, "unknown"),
	})

	// runtime.json
	members["runtime.json"] = mustJSON(map[string]any{
		"goos":   runtime.GOOS,
		"goarch": runtime.GOARCH,
		"go":     runtime.Version(),
		"numCPU": runtime.NumCPU(),
	})

	// profile_effective.json — non-secret fields only
	members["profile_effective.json"] = mustJSON(safeProfileMap(opts.Profile))

	// doctor.json
	docRep := opts.DoctorReport
	if docRep == nil {
		dopts := opts.DoctorOpts
		dopts.Profile = opts.Profile
		if dopts.Paths == nil {
			dopts.Paths = opts.Paths
		}
		// Bundle doctor defaults to offline (no whoAmI) unless caller set otherwise.
		if !dopts.SkipNetwork && opts.DoctorReport == nil && opts.DoctorOpts.HTTPClient == nil {
			dopts.SkipNetwork = true
		}
		dopts.Version = firstNonEmpty(dopts.Version, opts.Version)
		dopts.Commit = firstNonEmpty(dopts.Commit, opts.Commit)
		dopts.BuildTime = firstNonEmpty(dopts.BuildTime, opts.BuildTime)
		rep, derr := RunDoctor(ctx, dopts)
		if derr != nil {
			members["doctor.json"] = mustJSON(map[string]any{
				"error": redact.Secrets(apperr.ModelMessage(derr)),
			})
		} else {
			for i := range rep.Checks {
				rep.Checks[i] = SanitizeCheck(rep.Checks[i])
			}
			rep.Overall = OverallStatus(rep.Checks)
			docRep = &rep
		}
	}
	if docRep != nil {
		for i := range docRep.Checks {
			docRep.Checks[i] = SanitizeCheck(docRep.Checks[i])
		}
		members["doctor.json"] = mustJSON(docRep)
	}

	// cache_status.json
	var cache *CacheStatus
	if opts.Cache != nil {
		cache = opts.Cache
	} else {
		st, cerr := RunCacheStatus(ctx, CacheStatusOptions{
			Profile: opts.Profile,
			Paths:   opts.Paths,
			Metrics: opts.Metrics,
		})
		if cerr != nil {
			members["cache_status.json"] = mustJSON(map[string]any{
				"error": redact.Secrets(apperr.ModelMessage(cerr)),
			})
		} else {
			cache = &st
		}
	}
	if cache != nil {
		members["cache_status.json"] = mustJSON(cache)
	}

	// capability_summary.json
	if opts.CapabilitySummary != nil {
		members["capability_summary.json"] = mustJSON(scrubMap(opts.CapabilitySummary))
	} else {
		members["capability_summary.json"] = mustJSON(map[string]any{
			"note": "capability summary not provided (serve-time cache not available to CLI)",
		})
	}

	// metrics.json
	metrics := opts.Metrics
	if metrics == nil {
		if g := telemetry.Global(); g != nil {
			metrics = g.Metrics
		}
	}
	if metrics != nil {
		snap := metrics.Snapshot()
		members["metrics.json"] = mustJSON(snap)
	} else {
		members["metrics.json"] = mustJSON(map[string]any{
			"note": "no in-process metrics registry",
		})
	}

	// error_signatures.json (hashes only; optional ExtractCandidates from LogSample)
	members["error_signatures.json"] = mustJSON(buildErrorSignaturesMember(opts))

	// Wave 23 optional offline members (enabled by default).
	if bundleFlagEnabled(opts.IncludeSecuritySelfCheck, true) {
		members["security_self_check.json"] = mustJSON(buildSecuritySelfCheckMember(ctx, opts, now))
	}
	if bundleFlagEnabled(opts.IncludeReleaseEvidenceLite, true) {
		members["release_evidence_lite.json"] = mustJSON(buildReleaseEvidenceLiteMember(opts, now))
	}
	if bundleFlagEnabled(opts.IncludeRSQualification, true) {
		members["rs_qualification_summary.json"] = mustJSON(buildRSQualificationMember(opts))
	}

	// Cap individual members.
	for k, v := range members {
		if len(v) > maxBundleFileBytes {
			members[k] = mustJSON(map[string]any{
				"truncated": true,
				"note":      "member exceeded " + fmt.Sprintf("%d", maxBundleFileBytes) + " bytes",
			})
		}
		// Final secret canary scrub on raw JSON text.
		members[k] = []byte(redact.Secrets(string(v)))
	}

	// Write zip with 0600 file mode.
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range members {
		w, zerr := zw.Create(name)
		if zerr != nil {
			_ = zw.Close()
			return SupportBundleResult{}, apperr.New(apperr.CodeInternal, "failed to create zip entry")
		}
		if _, zerr = w.Write(body); zerr != nil {
			_ = zw.Close()
			return SupportBundleResult{}, apperr.New(apperr.CodeInternal, "failed to write zip entry")
		}
	}
	// README for operators
	readme := []byte(supportBundleREADME(included))
	if rw, zerr := zw.Create("README.txt"); zerr == nil {
		_, _ = rw.Write([]byte(redact.Secrets(string(readme))))
	}
	if err := zw.Close(); err != nil {
		return SupportBundleResult{}, apperr.New(apperr.CodeInternal, "failed to finalize support bundle zip")
	}

	// Atomic-ish write: temp then rename.
	tmp := outPath + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0o600); err != nil {
		return SupportBundleResult{}, apperr.New(apperr.CodeInternal, "failed to write support bundle")
	}
	if err := os.Rename(tmp, outPath); err != nil {
		_ = os.Remove(tmp)
		return SupportBundleResult{}, apperr.New(apperr.CodeInternal, "failed to finalize support bundle path")
	}

	return SupportBundleResult{
		Plan:       plan,
		Path:       outPath,
		Bytes:      int64(buf.Len()),
		CreatedAt:  now,
		Categories: included,
	}, nil
}

// buildIncludedCategories applies enable flags to the default offline-safe set.
func buildIncludedCategories(opts SupportBundleOptions) []string {
	base := DefaultBundleCategories()
	out := make([]string, 0, len(base))
	for _, c := range base {
		switch c {
		case BundleCatSecuritySelfCheck:
			if !bundleFlagEnabled(opts.IncludeSecuritySelfCheck, true) {
				continue
			}
		case BundleCatReleaseEvidenceLite:
			if !bundleFlagEnabled(opts.IncludeReleaseEvidenceLite, true) {
				continue
			}
		case BundleCatRSQualification:
			if !bundleFlagEnabled(opts.IncludeRSQualification, true) {
				continue
			}
		}
		out = append(out, c)
	}
	return out
}

// bundleFlagEnabled treats nil as defaultOn (offline-safe sections default on).
func bundleFlagEnabled(flag *bool, defaultOn bool) bool {
	if flag == nil {
		return defaultOn
	}
	return *flag
}

func buildErrorSignaturesMember(opts SupportBundleOptions) map[string]any {
	sigs := opts.ErrorSignatures
	source := "caller"
	if len(sigs) == 0 && strings.TrimSpace(opts.LogSample) != "" {
		// Derive signature hashes only. Never zip LogSample text or finding messages
		// (log lines may carry secrets that pattern redaction misses).
		sample := opts.LogSample
		if len(sample) > maxBundleLogSampleBytes {
			sample = sample[:maxBundleLogSampleBytes]
		}
		ext := ExtractCandidates(sample, Options{
			MaxFindings: maxBundleErrorSigs,
		})
		sigs = make([]ErrorSignatureEntry, 0, len(ext.Findings))
		for _, f := range ext.Findings {
			sigs = append(sigs, ErrorSignatureEntry{
				Signature: f.Signature,
				Pattern:   f.Pattern,
				Count:     f.Count,
				// Message omitted on purpose for sample-derived rows.
			})
		}
		source = "log_sample_extract"
	}
	if len(sigs) > maxBundleErrorSigs {
		sigs = sigs[:maxBundleErrorSigs]
	}
	safeSigs := make([]ErrorSignatureEntry, 0, len(sigs))
	for _, s := range sigs {
		safeSigs = append(safeSigs, ErrorSignatureEntry{
			Signature: redact.Secrets(s.Signature),
			Pattern:   redact.Secrets(s.Pattern),
			Count:     s.Count,
			Message:   truncateBundle(redact.Secrets(s.Message), 256),
		})
	}
	out := map[string]any{
		"signatures": safeSigs,
		"source":     source,
		"note":       "recent error signature hashes only; no full logs; no raw log samples",
	}
	if len(safeSigs) == 0 {
		out["residual"] = "no error signatures provided; pass ErrorSignatures or a size-capped LogSample for ExtractCandidates"
	}
	return out
}

func buildSecuritySelfCheckMember(ctx context.Context, opts SupportBundleOptions, now time.Time) map[string]any {
	if opts.SelfCheckReport != nil {
		// Re-scrub messages; never assume caller sanitized fully.
		rep := *opts.SelfCheckReport
		for i := range rep.Items {
			rep.Items[i].Message = redact.SanitizeForModel(rep.Items[i].Message)
			if rep.Items[i].Details != nil {
				rep.Items[i].Details = scrubMap(rep.Items[i].Details)
			}
		}
		return map[string]any{
			"overall":                     rep.Overall,
			"version":                     rep.Version,
			"commit":                      rep.Commit,
			"profile_id":                  rep.ProfileID,
			"items":                       rep.Items,
			"residuals":                   rep.Residuals,
			"independent_review_required": rep.IndependentReviewRequired,
			"generated_at":                rep.GeneratedAt,
			"source":                      "caller",
		}
	}
	rep, err := RunSecuritySelfCheck(ctx, SelfCheckOptions{
		Profile:      opts.Profile,
		Paths:        opts.Paths,
		PolicyResult: opts.PolicyResult,
		Version:      opts.Version,
		Commit:       opts.Commit,
		Now: func() time.Time {
			return now
		},
		// Category plan canary is cheap and useful inside the bundle report.
		SkipSupportBundleCanary: false,
	})
	if err != nil {
		return map[string]any{
			"residual": true,
			"note":     "security self-check unavailable: " + redact.Secrets(apperr.ModelMessage(err)),
		}
	}
	// Drop full item dump of details that might be large; keep items (already secret-free).
	for i := range rep.Items {
		if rep.Items[i].Details != nil {
			rep.Items[i].Details = scrubMap(rep.Items[i].Details)
		}
	}
	return map[string]any{
		"overall":                     rep.Overall,
		"version":                     rep.Version,
		"commit":                      rep.Commit,
		"profile_id":                  rep.ProfileID,
		"items":                       rep.Items,
		"residuals":                   rep.Residuals,
		"independent_review_required": rep.IndependentReviewRequired,
		"generated_at":                rep.GeneratedAt,
		"source":                      "offline_run",
	}
}

func buildReleaseEvidenceLiteMember(opts SupportBundleOptions, now time.Time) map[string]any {
	// Diagnostics-local snapshot only (version/runtime). Avoids cmd/ release-evidence cycle.
	return map[string]any{
		"schema":       releaseEvidenceLiteSchema,
		"offline":      true,
		"generated_at": now.Format(time.RFC3339),
		"profile_id":   string(opts.Profile.ID),
		"version": map[string]any{
			"version":   nonEmpty(opts.Version, "dev"),
			"commit":    nonEmpty(opts.Commit, "unknown"),
			"buildTime": nonEmpty(opts.BuildTime, "unknown"),
		},
		"runtime": map[string]any{
			"goos":   runtime.GOOS,
			"goarch": runtime.GOARCH,
			"go":     runtime.Version(),
			"numCPU": runtime.NumCPU(),
		},
		"residual": []string{
			"lite snapshot only — not full REL-002 release-evidence gates",
			"see docs/release/gates.md and jenkins-mcp release-evidence --offline for full offline pack",
		},
		"note": "version/runtime only; no tokens, no live Jenkins, no keyring",
	}
}

func buildRSQualificationMember(opts SupportBundleOptions) map[string]any {
	if opts.RSQualification != nil {
		sum := *opts.RSQualification
		return map[string]any{
			"fallthrough_must_deny":   sum.FallthroughMustDeny,
			"jwks_outage_behavior":    sum.JWKSOutageBehavior,
			"jwks_outage_acceptable":  sum.JWKSOutageAcceptable,
			"required_route_count":    sum.RequiredRouteCount,
			"outside_api_glob_count":  sum.OutsideAPIGlobCount,
			"inventory_ok":            sum.InventoryOK,
			"threats_contract_tested": sum.ThreatsContractTested,
			"threats_residual_lab":    sum.ThreatsResidualLab,
			"offline_automated":       sum.OfflineAutomated,
			"live_lab_residuals":      sum.LiveLabResiduals,
			"doc":                     sum.Doc,
			"source":                  "caller",
			"note":                    "offline RS matrix only; live jwt-auth-filter lab residual",
		}
	}
	method := ""
	if opts.Profile != nil {
		method = string(opts.Profile.AuthMethod)
	}
	sum := auth.BuildOfflineRSQualificationSummary(method)
	return map[string]any{
		"auth_method":             method,
		"fallthrough_must_deny":   sum.FallthroughMustDeny,
		"jwks_outage_behavior":    sum.JWKSOutageBehavior,
		"jwks_outage_acceptable":  sum.JWKSOutageAcceptable,
		"required_route_count":    sum.RequiredRouteCount,
		"outside_api_glob_count":  sum.OutsideAPIGlobCount,
		"inventory_ok":            sum.InventoryOK,
		"threats_contract_tested": sum.ThreatsContractTested,
		"threats_residual_lab":    sum.ThreatsResidualLab,
		"offline_automated":       sum.OfflineAutomated,
		"live_lab_residuals":      sum.LiveLabResiduals,
		"doc":                     sum.Doc,
		"source":                  "offline_build",
		"note":                    "offline RS matrix only; live jwt-auth-filter lab residual",
	}
}

func resolveBundleDir(opts SupportBundleOptions) (string, error) {
	if strings.TrimSpace(opts.OutputDir) != "" {
		return opts.OutputDir, nil
	}
	paths, err := resolvePaths(opts.Paths)
	if err != nil {
		return "", apperr.New(apperr.CodeInternal, "failed to resolve XDG paths for support bundle")
	}
	// Per-user cache: $XDG_CACHE_HOME/jenkins-mcp/support-bundles/<profileId>/
	return filepath.Join(paths.CacheDir, "support-bundles", sanitizePathToken(string(opts.Profile.ID))), nil
}

func safeProfileMap(p *profile.Profile) map[string]any {
	if p == nil {
		return map[string]any{}
	}
	m := map[string]any{
		"configVersion": p.ConfigVersion,
		"id":            string(p.ID),
		"displayName":   p.DisplayName,
		"jenkinsURL":    p.JenkinsURL,
		"authMethod":    string(p.AuthMethod),
		"username":      p.Username,
		// Never include anything secret-like. Paths only for TLS.
		"caBundlePath_base":   filepath.Base(p.CABundlePath),
		"proxyURL_configured": p.ProxyURL != "",
		"noProxy_count":       len(p.NoProxy),
		"clientCert_base":     filepath.Base(p.ClientCertFile),
		"clientKey_base":      filepath.Base(p.ClientKeyFile),
		"dataDir_base":        filepath.Base(p.DataDir),
		"verifiedPrincipalId": p.VerifiedPrincipalID,
		// Explicit absences:
		"has_token_field": false,
		"has_password":    false,
	}
	if p.ReadOnly != nil {
		m["readOnly"] = *p.ReadOnly
	}
	// Drop empty path bases that would show ".".
	for _, k := range []string{"caBundlePath_base", "clientCert_base", "clientKey_base", "dataDir_base"} {
		if v, ok := m[k].(string); ok && (v == "." || v == "") {
			delete(m, k)
		}
	}
	return scrubMap(m)
}

func scrubMap(in map[string]any) map[string]any {
	if in == nil {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		lk := strings.ToLower(k)
		if looksSecretKey(lk) {
			continue
		}
		switch t := v.(type) {
		case string:
			out[k] = redact.Secrets(t)
		case map[string]any:
			out[k] = scrubMap(t)
		default:
			out[k] = v
		}
	}
	return out
}

func mustJSON(v any) []byte {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return []byte(`{"error":"marshal_failed"}`)
	}
	return b
}

func sanitizePathToken(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "default"
	}
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	out := b.String()
	if out == "" || out == "." || out == ".." {
		return "default"
	}
	return out
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

func truncateBundle(s string, n int) string {
	if n <= 0 || len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func supportBundleREADME(included []string) string {
	if len(included) == 0 {
		included = DefaultBundleCategories()
	}
	var b strings.Builder
	b.WriteString("jenkins-mcp support bundle (OPS-001 / Wave 23)\n")
	b.WriteString("==============================================\n\n")
	b.WriteString("This archive contains privacy-scrubbed local diagnostics only.\n\n")
	b.WriteString("Included categories:\n")
	for _, c := range included {
		b.WriteString("  - ")
		b.WriteString(c)
		b.WriteByte('\n')
	}
	b.WriteString("\nExplicitly excluded:\n")
	for _, c := range BundleExcludedCategories {
		b.WriteString("  - ")
		b.WriteString(c)
		b.WriteByte('\n')
	}
	b.WriteString("\nRedaction: secret-like keys dropped; token/password patterns scrubbed.\n")
	b.WriteString("Do not place API tokens into this tree. Path is under XDG cache.\n")
	b.WriteString("security_self_check / release_evidence_lite / rs_qualification_summary are offline-safe only.\n")
	return b.String()
}

// ReadBundleFile is a test helper to extract one zip member (bounded).
func ReadBundleFile(zipPath, name string) ([]byte, error) {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	for _, f := range r.File {
		if f.Name != name {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		defer rc.Close()
		return io.ReadAll(io.LimitReader(rc, maxBundleFileBytes+1))
	}
	return nil, fmt.Errorf("member %q not found", name)
}
