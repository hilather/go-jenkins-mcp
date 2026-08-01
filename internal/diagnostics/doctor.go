package diagnostics

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/auth"
	"github.com/simonfxr/go-jenkins-mcp/internal/config"
	"github.com/simonfxr/go-jenkins-mcp/internal/jenkins"
	"github.com/simonfxr/go-jenkins-mcp/internal/keyring"
	"github.com/simonfxr/go-jenkins-mcp/internal/policy"
	"github.com/simonfxr/go-jenkins-mcp/internal/profile"
	"github.com/simonfxr/go-jenkins-mcp/internal/store"
	"github.com/simonfxr/go-jenkins-mcp/internal/telemetry"
	"github.com/simonfxr/go-jenkins-mcp/internal/update"
)

// DefaultDoctorNetworkTimeout bounds identity verify during doctor (OPS-001).
const DefaultDoctorNetworkTimeout = 5 * time.Second

// DoctorOptions configures a doctor run. Secrets must never appear in options
// fields that are logged; Session is used only for network identity checks.
type DoctorOptions struct {
	// Profile is the loaded connection profile (required).
	Profile *profile.Profile
	// Paths are XDG locations (optional; resolved when nil).
	Paths *config.Paths
	// Keyring for credential presence checks (value never read into report).
	Keyring *keyring.Store
	// Version metadata for the binary check.
	Version   string
	Commit    string
	BuildTime string
	// SkipNetwork skips whoAmI (offline / --offline).
	SkipNetwork bool
	// NetworkTimeout bounds identity verify (0 → DefaultDoctorNetworkTimeout).
	NetworkTimeout time.Duration
	// HTTPClient optional override for identity verify (tests); when nil, built
	// from profile TLS/proxy settings.
	HTTPClient *http.Client
	// Metrics optional in-process snapshot source.
	Metrics *telemetry.Metrics
	// Circuit optional NET-003 circuit state source (e.g. *jenkins.Client).
	// When nil (CLI offline doctor without a live client), the check is skipped.
	// Offline-capable: no network; only reports in-process breaker snapshot.
	Circuit CircuitStateProvider
	// PolicyResult optional preloaded overlay result; when nil, LoadFromEnviron is used.
	PolicyResult *policy.LoadResult
	// ProfileReadOnly / Flag / Env for effective RO sources (optional).
	FlagReadOnly   bool
	EnvReadOnly    bool
	AllowMutations bool
	// Gate optional live ReadOnlyGate (serve path). When set, read_only and
	// mutations checks use this gate so DynamicForce hot-apply is visible
	// without reconstructing Inputs. Flag/Env/AllowMutations still apply when
	// Gate is nil (CLI doctor / offline bundle).
	Gate *policy.ReadOnlyGate
	// Now is optional clock for tests.
	Now func() time.Time
}

// CircuitStateProvider reports the NET-003 circuit breaker snapshot for doctor
// (OBS Wave 27). *jenkins.Client implements this.
type CircuitStateProvider interface {
	CircuitState() jenkins.CircuitState
}

// RunDoctor executes OPS-001 checks and returns a secret-free Report.
func RunDoctor(ctx context.Context, opts DoctorOptions) (Report, error) {
	if opts.Profile == nil {
		return Report{}, apperr.New(apperr.CodeInvalidArgument, "profile is required")
	}
	p := opts.Profile
	rep := Report{
		ProfileID: string(p.ID),
		Version:   opts.Version,
		Commit:    opts.Commit,
	}

	// binary/version
	verMsg := opts.Version
	if verMsg == "" {
		verMsg = "dev"
	}
	rep.Checks = append(rep.Checks, SanitizeCheck(Check{
		Name:    "binary",
		Status:  StatusOK,
		Message: fmt.Sprintf("jenkins-mcp %s", verMsg),
		Details: map[string]any{
			"commit":    nonEmpty(opts.Commit, "unknown"),
			"buildTime": nonEmpty(opts.BuildTime, "unknown"),
		},
	}))

	// profile exists + URL normalize
	rep.Checks = append(rep.Checks, checkProfile(p))

	// keyring credential present (not value)
	rep.Checks = append(rep.Checks, checkKeyring(ctx, opts, p))

	// TLS/CA path exists if configured
	rep.Checks = append(rep.Checks, checkTLSPaths(p)...)

	// data dir permissions
	paths, err := resolvePaths(opts.Paths)
	if err != nil {
		rep.Checks = append(rep.Checks, SanitizeCheck(Check{
			Name:    "data_dir",
			Status:  StatusFail,
			Message: "failed to resolve XDG paths",
		}))
	} else {
		dataDir, derr := resolveDataDir(p, paths)
		rep.Checks = append(rep.Checks, checkDataDir(dataDir, derr))
		// store open + schema version
		if derr == nil {
			rep.Checks = append(rep.Checks, checkStore(ctx, dataDir))
			// ARC-008: optional sample pack verify when archives/ has data.
			rep.Checks = append(rep.Checks, checkCacheSampleVerify(ctx, p, paths))
		} else {
			rep.Checks = append(rep.Checks, SanitizeCheck(Check{
				Name:    "store",
				Status:  StatusSkip,
				Message: "store check skipped (data dir unavailable)",
			}))
			rep.Checks = append(rep.Checks, SanitizeCheck(Check{
				Name:    "cache_verify_sample",
				Status:  StatusSkip,
				Message: "sample verify skipped (data dir unavailable)",
			}))
		}
	}

	// policy overlay load status
	rep.Checks = append(rep.Checks, checkPolicy(opts))

	// read-only effective sources
	rep.Checks = append(rep.Checks, checkReadOnly(opts, p))

	// Wave 32: mutation registration vs executable (allow-mutations under force RO).
	rep.Checks = append(rep.Checks, checkMutations(opts, p))

	// identity verify (whoAmI) if network allowed
	rep.Checks = append(rep.Checks, checkIdentity(ctx, opts, p))

	// OAUTH-009: jwt-auth-filter / RS capability note (offline matrix + optional online)
	rep.Checks = append(rep.Checks, checkRSAuth(ctx, opts, p))

	// JAS-001: offline structural note when OIDC issuer host matches Jenkins host
	rep.Checks = append(rep.Checks, checkJenkinsNotAS(p))

	// metrics snapshot summary if available
	rep.Checks = append(rep.Checks, checkMetrics(opts))

	// NET-003 / OBS Wave 27: circuit state when a client is available (no network).
	rep.Checks = append(rep.Checks, checkCircuit(opts))

	// HOST-008 / multi-user residual: secret-free gateway env posture (offline).
	rep.Checks = append(rep.Checks, checkGatewayStatus())

	// UPD-001 Wave 35: LKG on-disk re-verify when a record exists (offline).
	rep.Checks = append(rep.Checks, checkUpdateLKG(opts.Paths))

	for i := range rep.Checks {
		rep.Checks[i] = SanitizeCheck(rep.Checks[i])
	}
	rep.Overall = OverallStatus(rep.Checks)
	return rep, nil
}

// checkUpdateLKG reports LKG on-disk integrity (Wave 35 / UPD-001).
// Skip when no LKG; warn when LKG is present but the staged artifact is missing
// or sha256 mismatches when the path is resolvable; ok on match.
// Corrupt LKG is warn (operator must repair) — secret-free messaging only.
func checkUpdateLKG(paths *config.Paths) Check {
	const name = "update_lkg"
	vres, err := update.VerifyLKG(update.VerifyLKGOptions{Paths: paths})
	if err != nil {
		return SanitizeCheck(Check{
			Name:    name,
			Status:  StatusWarn,
			Message: "update LKG unreadable or corrupt: " + apperr.ModelMessage(err),
			Details: map[string]any{
				"lkg_present": true,
				"residual":    "remove or repair last_known_good.json; re-run update download",
			},
		})
	}
	if vres == nil || !vres.LKGPresent {
		return SanitizeCheck(Check{
			Name:    name,
			Status:  StatusSkip,
			Message: "no update LKG record (skip; optional after verified download)",
		})
	}
	if vres.OK {
		return SanitizeCheck(Check{
			Name:    name,
			Status:  StatusOK,
			Message: fmt.Sprintf("LKG on-disk artifact matches sha256 (version=%s)", vres.Version),
			Details: map[string]any{
				"version":        vres.Version,
				"channel":        vres.Channel,
				"path_basename":  vres.PathBasename,
				"sha_match":      true,
				"artifact_found": true,
			},
		})
	}
	// LKG present but artifact missing / unresolvable / hash mismatch → warn.
	// Soft for doctor (download may use a custom outdir); CLI verify-lkg fails closed.
	details := map[string]any{
		"version":        vres.Version,
		"channel":        vres.Channel,
		"path_basename":  vres.PathBasename,
		"sha_match":      vres.SHAMatch,
		"artifact_found": vres.ArtifactFound,
	}
	if vres.ExpectedSHA256 != "" {
		details["expected_sha256"] = vres.ExpectedSHA256
	}
	if vres.ActualSHA256 != "" {
		details["actual_sha256"] = vres.ActualSHA256
	}
	msg := vres.Reason
	if msg == "" {
		msg = "LKG present but on-disk re-verify did not pass"
	}
	return SanitizeCheck(Check{
		Name:    name,
		Status:  StatusWarn,
		Message: msg,
		Details: details,
	})
}

func resolvePaths(p *config.Paths) (config.Paths, error) {
	if p != nil {
		return *p, nil
	}
	return config.Resolve()
}

func resolveDataDir(p *profile.Profile, paths config.Paths) (string, error) {
	id := string(p.ID)
	if p.DataDir != "" {
		return store.EnsureProfileDataDir(p.DataDir, id)
	}
	return store.EnsureProfileDataDir(paths.ProfileDataDir(id), id)
}

func checkProfile(p *profile.Profile) Check {
	if err := p.Validate(); err != nil {
		return SanitizeCheck(Check{
			Name:    "profile",
			Status:  StatusFail,
			Message: apperr.ModelMessage(err),
		})
	}
	u, err := jenkins.NormalizeBaseURL(p.JenkinsURL)
	if err != nil {
		return SanitizeCheck(Check{
			Name:    "profile",
			Status:  StatusFail,
			Message: "jenkins URL failed normalize",
			Details: map[string]any{"error": err.Error()},
		})
	}
	return SanitizeCheck(Check{
		Name:    "profile",
		Status:  StatusOK,
		Message: "profile valid",
		Details: map[string]any{
			"id":         string(p.ID),
			"jenkinsURL": u.String(),
			"authMethod": string(p.AuthMethod),
			"username":   p.Username,
		},
	})
}

func checkKeyring(ctx context.Context, opts DoctorOptions, p *profile.Profile) Check {
	if opts.Keyring == nil {
		return SanitizeCheck(Check{
			Name:    "keyring",
			Status:  StatusWarn,
			Message: "keyring not configured for doctor",
		})
	}
	if strings.TrimSpace(p.Username) == "" {
		return SanitizeCheck(Check{
			Name:    "keyring",
			Status:  StatusFail,
			Message: "profile has no username; run jenkins-mcp login --profile",
		})
	}
	prov := auth.NewAPITokenProvider(opts.Keyring)
	st, err := prov.Status(ctx, auth.ProfileFrom(p))
	if err != nil {
		return SanitizeCheck(Check{
			Name:    "keyring",
			Status:  StatusFail,
			Message: "keyring status failed",
			Details: map[string]any{"error": apperr.ModelMessage(err)},
		})
	}
	if !st.HasCredential {
		return SanitizeCheck(Check{
			Name:    "keyring",
			Status:  StatusFail,
			Message: "no credential in keyring for this profile",
			Details: map[string]any{
				"has_credential": false,
				"username":       st.User,
			},
		})
	}
	return SanitizeCheck(Check{
		Name:    "keyring",
		Status:  StatusOK,
		Message: "credential present in keyring (value not retrieved for report)",
		Details: map[string]any{
			"has_credential": true,
			"username":       st.User,
			"method":         string(st.Method),
		},
	})
}

func checkTLSPaths(p *profile.Profile) []Check {
	var out []Check
	checkPath := func(name, path string, requiredPair bool) {
		path = strings.TrimSpace(path)
		if path == "" {
			if requiredPair {
				return
			}
			out = append(out, SanitizeCheck(Check{
				Name:    name,
				Status:  StatusSkip,
				Message: name + " not configured",
			}))
			return
		}
		fi, err := os.Stat(path)
		if err != nil {
			out = append(out, SanitizeCheck(Check{
				Name:    name,
				Status:  StatusFail,
				Message: name + " path not readable",
				Details: map[string]any{"path_base": filepath.Base(path)},
			}))
			return
		}
		if fi.IsDir() {
			out = append(out, SanitizeCheck(Check{
				Name:    name,
				Status:  StatusFail,
				Message: name + " path is a directory",
				Details: map[string]any{"path_base": filepath.Base(path)},
			}))
			return
		}
		out = append(out, SanitizeCheck(Check{
			Name:    name,
			Status:  StatusOK,
			Message: name + " path exists",
			Details: map[string]any{"path_base": filepath.Base(path)},
		}))
	}
	if strings.TrimSpace(p.CABundlePath) == "" {
		out = append(out, SanitizeCheck(Check{
			Name:    "tls_ca_bundle",
			Status:  StatusSkip,
			Message: "caBundlePath not configured (system trust store)",
		}))
	} else {
		checkPath("tls_ca_bundle", p.CABundlePath, false)
	}
	// mTLS: paths only — never read private key contents into the report.
	if p.ClientCertFile != "" || p.ClientKeyFile != "" {
		checkPath("tls_client_cert", p.ClientCertFile, false)
		checkPath("tls_client_key_path", p.ClientKeyFile, false)
		// Confirm key file is not world-readable when present (mode only).
		if p.ClientKeyFile != "" {
			if fi, err := os.Stat(p.ClientKeyFile); err == nil {
				perm := fi.Mode().Perm()
				if perm&0o077 != 0 {
					out = append(out, SanitizeCheck(Check{
						Name:    "tls_client_key_mode",
						Status:  StatusWarn,
						Message: fmt.Sprintf("client key file mode %04o is group/other-accessible", perm),
					}))
				}
			}
		}
	}
	if p.ProxyURL != "" {
		out = append(out, SanitizeCheck(Check{
			Name:    "proxy",
			Status:  StatusOK,
			Message: "proxyURL configured",
			Details: map[string]any{"proxyURL": p.ProxyURL},
		}))
	}
	return out
}

func checkDataDir(dataDir string, resolveErr error) Check {
	if resolveErr != nil {
		return SanitizeCheck(Check{
			Name:    "data_dir",
			Status:  StatusFail,
			Message: "data directory unavailable",
			Details: map[string]any{"error": apperr.ModelMessage(resolveErr)},
		})
	}
	if err := store.ValidateDir(dataDir); err != nil {
		return SanitizeCheck(Check{
			Name:    "data_dir",
			Status:  StatusFail,
			Message: "data directory permissions check failed",
			Details: map[string]any{
				"path_base": filepath.Base(dataDir),
				"error":     apperr.ModelMessage(err),
			},
		})
	}
	fi, err := os.Stat(dataDir)
	mode := ""
	if err == nil {
		mode = fmt.Sprintf("%04o", fi.Mode().Perm())
	}
	return SanitizeCheck(Check{
		Name:    "data_dir",
		Status:  StatusOK,
		Message: "data directory permissions ok",
		Details: map[string]any{
			"path_base": filepath.Base(dataDir),
			"mode":      mode,
		},
	})
}

func checkStore(ctx context.Context, dataDir string) Check {
	meta, err := store.Open(dataDir)
	if err != nil {
		return SanitizeCheck(Check{
			Name:    "store",
			Status:  StatusFail,
			Message: "failed to open L1 store",
			Details: map[string]any{"error": apperr.ModelMessage(err)},
		})
	}
	defer func() { _ = meta.Close() }()
	st, err := meta.Stats(ctx)
	if err != nil {
		return SanitizeCheck(Check{
			Name:    "store",
			Status:  StatusFail,
			Message: "store stats failed",
			Details: map[string]any{"error": apperr.ModelMessage(err)},
		})
	}
	status := StatusOK
	msg := fmt.Sprintf("store open schema=%d expected=%d", st.SchemaVersion, store.CurrentSchemaVersion)
	if st.SchemaVersion != store.CurrentSchemaVersion {
		status = StatusWarn
		msg = fmt.Sprintf("store schema version %d differs from expected %d", st.SchemaVersion, store.CurrentSchemaVersion)
	}
	return SanitizeCheck(Check{
		Name:    "store",
		Status:  status,
		Message: msg,
		Details: map[string]any{
			"schemaVersion":   st.SchemaVersion,
			"expectedSchema":  store.CurrentSchemaVersion,
			"generations":     st.Generations,
			"chunks":          st.Chunks,
			"l1PhysicalBytes": st.L1PhysicalBytes,
			"l1LogicalBytes":  st.L1LogicalBytes,
		},
	})
}

// checkCacheSampleVerify runs a small ARC-008 sample verify when packs exist.
func checkCacheSampleVerify(ctx context.Context, p *profile.Profile, paths config.Paths) Check {
	dataDir, err := resolveDataDir(p, paths)
	if err != nil {
		return SanitizeCheck(Check{
			Name:    "cache_verify_sample",
			Status:  StatusSkip,
			Message: "sample verify skipped (data dir unavailable)",
		})
	}
	arch := filepath.Join(dataDir, store.ArchivesDirName)
	packs, err := store.ListArchivePacks(arch)
	if err != nil {
		return SanitizeCheck(Check{
			Name:    "cache_verify_sample",
			Status:  StatusWarn,
			Message: "failed to list packs for sample verify",
			Details: map[string]any{"error": apperr.ModelMessage(err)},
		})
	}
	if len(packs) == 0 {
		return SanitizeCheck(Check{
			Name:    "cache_verify_sample",
			Status:  StatusSkip,
			Message: "no L2 packs to sample-verify",
		})
	}
	// Bound sample verify time so doctor stays snappy.
	vctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	vrep, verr := RunCacheVerify(vctx, CacheVerifyOptions{
		Profile: p,
		Paths:   &paths,
		Full:    false,
		Sample:  1,
	})
	if verr != nil && !vrep.Cancelled {
		return SanitizeCheck(Check{
			Name:    "cache_verify_sample",
			Status:  StatusWarn,
			Message: "sample verify error",
			Details: map[string]any{"error": apperr.ModelMessage(verr)},
		})
	}
	status := StatusOK
	msg := fmt.Sprintf("sample verify ok packs_checked=%d pack_ok=%d", vrep.PacksChecked, vrep.PackOK)
	if vrep.PackFail > 0 {
		status = StatusWarn
		msg = fmt.Sprintf("sample verify found failures pack_fail=%d", vrep.PackFail)
	}
	if vrep.Cancelled {
		status = StatusWarn
		msg = "sample verify cancelled or timed out"
	}
	return SanitizeCheck(Check{
		Name:    "cache_verify_sample",
		Status:  status,
		Message: msg,
		Details: map[string]any{
			"packsTotal":   vrep.PacksTotal,
			"packsChecked": vrep.PacksChecked,
			"packOk":       vrep.PackOK,
			"packFail":     vrep.PackFail,
			"issueCounts":  vrep.IssueCounts,
		},
	})
}

func checkPolicy(opts DoctorOptions) Check {
	var res policy.LoadResult
	var err error
	if opts.PolicyResult != nil {
		res = *opts.PolicyResult
	} else {
		res, err = policy.LoadFromEnviron()
		if err != nil {
			return SanitizeCheck(Check{
				Name:    "policy",
				Status:  StatusFail,
				Message: "policy overlay load failed (fail closed)",
				Details: map[string]any{"error": apperr.ModelMessage(err)},
			})
		}
	}
	if !res.Present {
		return SanitizeCheck(Check{
			Name:    "policy",
			Status:  StatusOK,
			Message: "no enterprise policy overlay (pilot default)",
			Details: res.StatusMap(),
		})
	}
	return SanitizeCheck(Check{
		Name:    "policy",
		Status:  StatusOK,
		Message: "enterprise policy overlay loaded",
		Details: res.StatusMap(),
	})
}

// doctorGate returns the live Gate when provided, else builds one from
// DoctorOptions Inputs (same sources as serve / POL-001).
func doctorGate(opts DoctorOptions, p *profile.Profile) *policy.ReadOnlyGate {
	if opts.Gate != nil {
		return opts.Gate
	}
	var profileRO *bool
	if p != nil {
		v := p.EffectiveReadOnly()
		// Only contribute when field is set on the document.
		if p.ReadOnly != nil {
			profileRO = &v
		}
	}
	force := policy.AsEnterpriseForce(nil)
	if opts.PolicyResult != nil && opts.PolicyResult.Overlay != nil {
		force = policy.AsEnterpriseForce(opts.PolicyResult.Overlay)
	} else {
		if res, err := policy.LoadFromEnviron(); err == nil {
			force = policy.AsEnterpriseForce(res.Overlay)
		}
	}
	envRO := opts.EnvReadOnly
	if !opts.FlagReadOnly && !opts.EnvReadOnly {
		// Reflect process env when CLI did not pass explicit flags.
		envRO = policy.EnvReadOnlyFromEnviron()
	}
	return policy.NewReadOnlyGate(policy.Inputs{
		FlagReadOnly:    opts.FlagReadOnly,
		EnvReadOnly:     envRO,
		ProfileReadOnly: profileRO,
		Force:           force,
		AllowMutations:  opts.AllowMutations,
	})
}

func checkReadOnly(opts DoctorOptions, p *profile.Profile) Check {
	gate := doctorGate(opts, p)
	st := gate.State()
	return SanitizeCheck(Check{
		Name:    "read_only",
		Status:  StatusOK,
		Message: fmt.Sprintf("effective read-only=%v", st.Effective),
		Details: map[string]any{
			"read_only": st.Effective,
			"sources":   st.Sources,
		},
	})
}

// checkMutations reports Wave 30/32 registration vs executable posture.
// Secret-free: bools + optional catalog count only (never tool param schemas).
//
// Status:
//   - ok   — mutations executable (full write) or registered posture is consistent
//     without the registered-but-not-executable intermediate
//   - warn — registered under force/RO + allow-mutations but not executable until RO clears
//   - skip — pilot default RO (no allow-mutations; mutations not registered)
func checkMutations(opts DoctorOptions, p *profile.Profile) Check {
	gate := doctorGate(opts, p)
	st := gate.State()
	readOnlyEffective := st.Effective
	allowOptIn := gate.AllowMutationsOptIn()
	shouldRegister := gate.ShouldRegisterMutations()
	// mutations_executable mirrors AllowMutationRegistration (!Effective).
	executable := gate.AllowMutationRegistration()

	details := map[string]any{
		"read_only_effective":       readOnlyEffective,
		"allow_mutations_opt_in":    allowOptIn,
		"mutations_should_register": shouldRegister,
		"mutations_executable":      executable,
		"sources":                   st.Sources,
		// Catalog size only (non-secret tool names); not a live registry dump.
		"mutation_tool_catalog_count": len(policy.MutationToolNames()),
	}

	switch {
	case shouldRegister && !executable:
		// Wave 30 intermediate: tools registered under force/RO so force clear
		// re-lists without restart; DenyMutation still blocks until RO clears.
		return SanitizeCheck(Check{
			Name:   "mutations",
			Status: StatusWarn,
			Message: "mutations registered (allow-mutations) but not executable while effective " +
				"read-only is on (e.g. enterprise force_read_only); clear force/RO to enable writes",
			Details: details,
		})
	case executable:
		return SanitizeCheck(Check{
			Name:    "mutations",
			Status:  StatusOK,
			Message: "mutations registered and executable (allow-mutations; no stronger read-only source)",
			Details: details,
		})
	default:
		// Pilot default RO or explicit RO without allow-mutations: omit at register.
		return SanitizeCheck(Check{
			Name:   "mutations",
			Status: StatusSkip,
			Message: "mutations not registered (pilot default read-only or no --allow-mutations); " +
				"opt-in with --allow-mutations only when writes are intentional",
			Details: details,
		})
	}
}

func checkIdentity(ctx context.Context, opts DoctorOptions, p *profile.Profile) Check {
	if opts.SkipNetwork {
		return SanitizeCheck(Check{
			Name:    "identity",
			Status:  StatusSkip,
			Message: "network checks skipped (--offline)",
		})
	}
	if opts.Keyring == nil {
		return SanitizeCheck(Check{
			Name:    "identity",
			Status:  StatusSkip,
			Message: "identity verify skipped (no keyring)",
		})
	}
	prov := auth.NewAPITokenProvider(opts.Keyring)
	sess, err := prov.Authenticate(ctx, auth.ProfileFrom(p))
	if err != nil {
		return SanitizeCheck(Check{
			Name:    "identity",
			Status:  StatusFail,
			Message: "cannot authenticate for identity verify",
			Details: map[string]any{"error": apperr.ModelMessage(err)},
		})
	}
	// Ensure secret never lingers in report paths: use only for HTTP then drop.
	timeout := opts.NetworkTimeout
	if timeout <= 0 {
		timeout = DefaultDoctorNetworkTimeout
	}
	nctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var apiClient *http.Client
	if opts.HTTPClient != nil {
		apiClient = opts.HTTPClient
	} else {
		hc, err := jenkins.NewHTTPClients(transportFromProfile(p))
		if err != nil {
			sess.Secret = ""
			return SanitizeCheck(Check{
				Name:    "identity",
				Status:  StatusFail,
				Message: "TLS/proxy configuration invalid for identity verify",
				Details: map[string]any{"error": apperr.ModelMessage(err)},
			})
		}
		apiClient = hc.API
	}
	principal, err := auth.VerifyIdentityHTTP(nctx, auth.ProfileFrom(p), sess, apiClient)
	sess.Secret = "" // scrub
	if err != nil {
		msg := apperr.ModelMessage(err)
		if tlsMsg := jenkins.FormatTLSError(err); tlsMsg != "" {
			msg = tlsMsg
		}
		status := StatusFail
		if apperr.CodeOf(err) == apperr.CodeTimeout || apperr.CodeOf(err) == apperr.CodeCancelled {
			status = StatusWarn
		}
		return SanitizeCheck(Check{
			Name:    "identity",
			Status:  status,
			Message: "identity verify failed",
			Details: map[string]any{
				"error": msg,
				"code":  string(apperr.CodeOf(err)),
			},
		})
	}
	return SanitizeCheck(Check{
		Name:    "identity",
		Status:  StatusOK,
		Message: "identity verified via whoAmI",
		Details: map[string]any{
			"principal_id":   principal.ID,
			"principal_name": principal.FullName,
		},
	})
}

// checkRSAuth reports OAUTH-009 resource-server qualification notes.
// Offline: capability matrix + residual checklist. Online (oidc_bearer with
// keyring tokens): best-effort bearer whoAmI + invalid-bearer sample.
// Never claims live jwt-auth-filter lab complete without residual wording.
func checkRSAuth(ctx context.Context, opts DoctorOptions, p *profile.Profile) Check {
	method := ""
	if p != nil {
		method = string(p.AuthMethod)
	}
	rep := auth.BuildOfflineRSProbe(method)
	sum := auth.BuildOfflineRSQualificationSummary(method)
	details := map[string]any{
		"fallthrough_must_deny":   rep.FallthroughMustDeny,
		"jwks_outage":             rep.JWKSOutageBehavior,
		"jwks_outage_acceptable":  rep.JWKSOutageAcceptable,
		"required_routes":         rep.RequiredRouteCount,
		"outside_api_glob":        rep.OutsideAPIGlobCount,
		"inventory_ok":            rep.InventoryOK,
		"threats_contract_tested": rep.ThreatsContractTested,
		"threats_residual_lab":    rep.ThreatsResidualLab,
		"offline_automated":       rep.OfflineAutomated,
		"live_lab_residuals":      sum.LiveLabResiduals,
		"path_level":              rep.PathLevel,
		"plugin_role":             string(rep.PluginRole),
		"doc":                     sum.Doc,
	}
	status := StatusOK
	msg := fmt.Sprintf("RS qualification matrix: %d routes, fallthrough_must_deny=%v, inventory_ok=%v (live lab residual)",
		rep.RequiredRouteCount, rep.FallthroughMustDeny, rep.InventoryOK)

	if !rep.InventoryOK || !rep.JWKSOutageAcceptable || !rep.FallthroughMustDeny {
		status = StatusFail
		msg = "RS offline qualification contracts broken (inventory/JWKS/fallthrough)"
		details["inventory_issue_count"] = rep.InventoryIssueCount
	}

	// Always surface oic-auth-only guidance when profile is not oidc_bearer with RS intent.
	if method == string(profile.AuthMethodAPIToken) || method == "" {
		details["note"] = "api_token pilot path; qualify jwt-auth-filter before enabling oidc_bearer"
	}
	if method == string(profile.AuthMethodOIDC) {
		if status != StatusFail {
			status = StatusWarn
			msg = "oidc_bearer requires qualified jwt-auth-filter (or proxy); live lab residual"
		}
		details["warning"] = auth.WarnOnlyOICAuthWithoutRS
		details["residuals"] = rep.Residuals
	}

	// Online optional: bearer whoAmI when OIDC tokens present and network allowed.
	if !opts.SkipNetwork && method == string(profile.AuthMethodOIDC) && opts.Keyring != nil && p != nil {
		oidc := auth.NewOIDCProvider(opts.Keyring, opts.HTTPClient)
		sess, err := oidc.Authenticate(ctx, auth.ProfileFrom(p))
		if err == nil && strings.TrimSpace(sess.Secret) != "" {
			timeout := opts.NetworkTimeout
			if timeout <= 0 {
				timeout = DefaultDoctorNetworkTimeout
			}
			nctx, cancel := context.WithTimeout(ctx, timeout)
			apiClient := opts.HTTPClient
			if apiClient == nil {
				if hc, herr := jenkins.NewHTTPClients(transportFromProfile(p)); herr == nil {
					apiClient = hc.API
				}
			}
			if apiClient != nil {
				jc := &jenkins.Client{
					URL:        p.JenkinsURL,
					Token:      sess.Secret,
					AuthScheme: jenkins.AuthSchemeBearer,
					Client:     apiClient,
				}
				if who, werr := ProbeBearerWhoAmI(nctx, jc); werr == nil {
					details["bearer_whoami"] = "ok"
					details["principal_id"] = who.ID
					// Fallthrough sample on whoAmI only (bounded).
					if fr, ferr := ProbeInvalidBearerFallthrough(nctx, RSProbeOptions{
						Client: &jenkins.Client{URL: p.JenkinsURL, Client: apiClient},
						HTTP:   apiClient,
						Paths:  []string{jenkins.WhoAmIPath},
					}); ferr == nil {
						details["invalid_bearer_denied"] = fr.AllDenied
						if !fr.AllDenied {
							status = StatusWarn
							msg = "oidc_bearer online: invalid bearer did not fail closed on whoAmI (possible RS fallthrough)"
							details["fallthrough"] = fr.Fallthrough
						} else if status == StatusWarn {
							// Keep warn for residual lab but note online samples OK.
							msg = "oidc_bearer: bearer whoAmI ok + invalid bearer denied; live plugin version pin residual"
						}
					}
				} else {
					details["bearer_whoami"] = "failed"
					details["bearer_whoami_error"] = apperr.ModelMessage(werr)
					status = StatusWarn
					msg = "oidc_bearer: bearer whoAmI failed (login/RS/token issue)"
				}
			}
			cancel()
			sess.Secret = ""
		} else {
			details["bearer_whoami"] = "skipped_no_token"
		}
	}

	return SanitizeCheck(Check{
		Name:    "rs_auth",
		Status:  status,
		Message: msg,
		Details: details,
	})
}

// checkJenkinsNotAS is an offline structural check (JAS-001 / ADR 0003):
// oidc.issuer must not share the Jenkins controller host. Stock Jenkins is
// never the OAuth authorization server (default no-go).
func checkJenkinsNotAS(p *profile.Profile) Check {
	if p == nil {
		return SanitizeCheck(Check{
			Name:    "jenkins_as_as",
			Status:  StatusSkip,
			Message: "no profile",
		})
	}
	if p.AuthMethod != profile.AuthMethodOIDC {
		return SanitizeCheck(Check{
			Name:    "jenkins_as_as",
			Status:  StatusSkip,
			Message: "not oidc_bearer; Jenkins-as-AS check N/A",
			Details: map[string]any{"authMethod": string(p.AuthMethod)},
		})
	}
	if p.OIDC == nil || strings.TrimSpace(p.OIDC.Issuer) == "" {
		return SanitizeCheck(Check{
			Name:    "jenkins_as_as",
			Status:  StatusFail,
			Message: "oidc_bearer profile missing issuer (cannot prove AS is not Jenkins)",
		})
	}
	if err := auth.RejectJenkinsAsAuthorizationServer(p.JenkinsURL, p.OIDC.Issuer); err != nil {
		return SanitizeCheck(Check{
			Name:    "jenkins_as_as",
			Status:  StatusFail,
			Message: "oidc.issuer host matches Jenkins controller — stock Jenkins must never be the OAuth authorization server (ADR 0003 / docs/auth/jas-no-go.md)",
			Details: map[string]any{
				"authMethod": string(p.AuthMethod),
				// Non-secret hosts only; never tokens.
				"hint": "point oidc.issuer at Entra or another approved external IdP",
			},
		})
	}
	return SanitizeCheck(Check{
		Name:    "jenkins_as_as",
		Status:  StatusOK,
		Message: "oidc.issuer is not co-hosted with Jenkins (AS ≠ controller)",
		Details: map[string]any{"authMethod": string(p.AuthMethod)},
	})
}

func checkMetrics(opts DoctorOptions) Check {
	if opts.Metrics == nil {
		if g := telemetry.Global(); g != nil && g.Metrics != nil {
			opts.Metrics = g.Metrics
		}
	}
	if opts.Metrics == nil {
		return SanitizeCheck(Check{
			Name:    "metrics",
			Status:  StatusSkip,
			Message: "no in-process metrics registry (serve not running)",
		})
	}
	snap := opts.Metrics.Snapshot()
	return SanitizeCheck(Check{
		Name:    "metrics",
		Status:  StatusOK,
		Message: "metrics snapshot available",
		Details: map[string]any{
			"counters": snap.Counters,
			"gauges":   snap.Gauges,
		},
	})
}

// checkCircuit reports NET-003 circuit breaker state without network I/O.
// Skips when no client/provider is wired (typical CLI offline doctor).
func checkCircuit(opts DoctorOptions) Check {
	if opts.Circuit == nil {
		return SanitizeCheck(Check{
			Name:    "circuit_breaker",
			Status:  StatusSkip,
			Message: "no jenkins client (circuit state unavailable)",
		})
	}
	st := opts.Circuit.CircuitState()
	details := map[string]any{
		"state":               st.State,
		"consecutiveFailures": st.ConsecutiveFailures,
		"failureThreshold":    st.FailureThreshold,
	}
	if !st.OpenUntil.IsZero() {
		details["openUntil"] = st.OpenUntil.UTC().Format(time.RFC3339)
	}
	switch st.State {
	case "open":
		return SanitizeCheck(Check{
			Name:    "circuit_breaker",
			Status:  StatusWarn,
			Message: "circuit open (upstream 5xx/transport failures)",
			Details: details,
		})
	case "half-open":
		return SanitizeCheck(Check{
			Name:    "circuit_breaker",
			Status:  StatusWarn,
			Message: "circuit half-open (probe in progress)",
			Details: details,
		})
	default:
		return SanitizeCheck(Check{
			Name:    "circuit_breaker",
			Status:  StatusOK,
			Message: "circuit closed",
			Details: details,
		})
	}
}

func transportFromProfile(p *profile.Profile) jenkins.TransportConfig {
	cfg := jenkins.DefaultTransportConfig()
	if p == nil {
		return cfg
	}
	if p.CABundlePath != "" {
		cfg.CABundlePath = p.CABundlePath
	}
	if p.ProxyURL != "" {
		cfg.ProxyURL = p.ProxyURL
	}
	if len(p.NoProxy) > 0 {
		cfg.NoProxy = append([]string(nil), p.NoProxy...)
	}
	if p.ClientCertFile != "" {
		cfg.ClientCertFile = p.ClientCertFile
	}
	if p.ClientKeyFile != "" {
		cfg.ClientKeyFile = p.ClientKeyFile
	}
	return cfg
}

func nonEmpty(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}
