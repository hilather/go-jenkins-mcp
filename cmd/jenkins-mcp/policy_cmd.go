package main

import (
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/config"
	"github.com/simonfxr/go-jenkins-mcp/internal/policy"
)

// EnvPolicySignDev gates the dev-only `policy sign` subcommand (MGR-001).
// Never enable in production packaging. Private keys must not be committed.
const EnvPolicySignDev = "JENKINS_MCP_POLICY_SIGN_DEV"

// runPolicy dispatches `jenkins-mcp policy <verify|show-effective|sign>`.
func runPolicy(args []string) error {
	if len(args) < 1 {
		return apperr.New(apperr.CodeInvalidArgument,
			"policy subcommand required: verify|show-effective|sign")
	}
	switch args[0] {
	case "verify":
		return runPolicyVerify(args[1:])
	case "show-effective":
		return runPolicyShowEffective(args[1:])
	case "sign", "sign-multi":
		// sign-multi is an alias for multi-key UX; both share runPolicySign.
		return runPolicySign(args[1:])
	case "-h", "--help", "help":
		fmt.Fprint(os.Stdout, policyUsage())
		return nil
	default:
		return apperr.New(apperr.CodeInvalidArgument,
			"unknown policy subcommand (verify|show-effective|sign)")
	}
}

func policyUsage() string {
	return `jenkins-mcp policy — enterprise policy bundle tools (MGR-001)

Usage:
  jenkins-mcp policy verify --file PATH [--keys PATH] [--json]
  jenkins-mcp policy show-effective --profile ID [--json]
  jenkins-mcp policy sign --file OVERLAY.json --key PRIVATE.pem --key-id ID --out BUNDLE.json
      [--bundle-seq N] [--not-after RFC3339] [--min-version N]
  jenkins-mcp policy sign --file OVERLAY.json --key a.pem --key-id a --key b.pem --key-id b --out BUNDLE.json
  jenkins-mcp policy sign --file OVERLAY.json --keys-dir DIR --out BUNDLE.json
  jenkins-mcp policy sign-multi  # alias of multi-key policy sign

verify:
  Cryptographically verifies a plain overlay or signed overlay.bundle.json.
  --keys points at a trusted public key file or directory (or env
  JENKINS_MCP_POLICY_TRUSTED_KEYS / XDG policy/trusted_keys/).
  Multi-sig threshold: JENKINS_MCP_POLICY_MIN_SIGNATURES (default 1; set 2 for dual-control).

show-effective:
  Prints force_read_only, deny_tools, max_result_bytes, max_tools_per_minute,
  max_tools_burst, signature_state, and
  effective read-only sources for a profile. Secret-free.

sign (DEV ONLY):
  Requires JENKINS_MCP_POLICY_SIGN_DEV=1. Signs an overlay with local Ed25519
  private key(s). Repeatable --key/--key-id pairs are matched by occurrence
  order; --keys-dir loads <key_id>.pem files (id from basename). One key uses
  the single-sig path; two or more populate signatures[] (multi-sig lite).
  Never commit private keys; not a production CA / HSM/KMS substitute.
`
}

func runPolicyVerify(args []string) error {
	fs := flag.NewFlagSet("policy verify", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	file := fs.String("file", "", "Policy overlay or signed bundle path (required)")
	keys := fs.String("keys", "", "Trusted public keys file or directory")
	asJSON := fs.Bool("json", false, "Emit machine-readable JSON")
	// Default: do not mutate last-good (verify is offline inspection).
	// --check-downgrade enables last-good read+write like serve.
	checkDowngrade := fs.Bool("check-downgrade", false, "Apply last-good anti-rollback checks (and update cache on success)")
	if err := fs.Parse(args); err != nil {
		return apperr.New(apperr.CodeInvalidArgument, err.Error())
	}
	if strings.TrimSpace(*file) == "" {
		return apperr.New(apperr.CodeInvalidArgument, "--file is required")
	}

	paths, err := config.Resolve()
	if err != nil {
		return err
	}
	opts := policy.LoadOptions{
		Path:         *file,
		Paths:        &paths,
		SkipLastGood: !*checkDowngrade,
	}
	if k := strings.TrimSpace(*keys); k != "" {
		set, err := policy.LoadTrustedKeys(k)
		if err != nil {
			return err
		}
		opts.TrustedKeys = set
	}
	// Build verifier: prefer injected keys, else environ.
	v, err := policy.DefaultVerifierFromEnviron(opts)
	if err != nil {
		return err
	}
	// If keys were explicitly provided but DefaultVerifier fell through to Nop
	// because TrustedKeys was only set on opts — DefaultVerifierFromEnviron
	// already honors opts.TrustedKeys.
	opts.Verifier = v

	// When --keys provided and set non-empty, force Ed25519 require-signed.
	if opts.TrustedKeys.Len() > 0 {
		if _, ok := v.(policy.Ed25519SignatureVerifier); !ok {
			// Should not happen; reconstruct.
			opts.Verifier = policy.BundleVerifier(opts.TrustedKeys, nil, true)
		}
	}

	res, err := policy.LoadOverlay(opts)
	report := map[string]any{
		"schema":           "jenkins-mcp.policy.verify.v1",
		"ok":               err == nil,
		"policy_path_base": filepath.Base(*file),
	}
	if err != nil {
		report["error"] = apperr.ModelMessage(err)
		if *asJSON {
			return writeJSON(report)
		}
		fmt.Fprintf(os.Stderr, "policy verify: FAIL: %s\n", apperr.ModelMessage(err))
		return err
	}
	for k, v := range res.StatusMap() {
		report[k] = v
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}
	fmt.Printf("policy verify: OK signature_state=%s", res.SignatureState)
	if res.BundleSeq > 0 {
		fmt.Printf(" bundle_seq=%d key_id=%s", res.BundleSeq, res.KeyID)
	}
	fmt.Println()
	if res.Overlay != nil {
		fmt.Printf("  force_read_only=%v mode=%s deny_tools=%d deny_job_prefixes=%d deny_node_names=%d deny_view_names=%d deny_artifact_paths=%d deny_branch_names=%d\n",
			res.Overlay.ForceReadOnly, res.Overlay.NormalizeMode(),
			len(res.Overlay.DenyTools), len(res.Overlay.DenyJobPrefixes),
			len(res.Overlay.DenyNodeNames), len(res.Overlay.DenyViewNames),
			len(res.Overlay.DenyArtifactPaths), len(res.Overlay.DenyBranchNames))
	}
	return nil
}

func runPolicyShowEffective(args []string) error {
	fs := flag.NewFlagSet("policy show-effective", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	profileID := fs.String("profile", "", "Connection profile id (required)")
	asJSON := fs.Bool("json", false, "Emit machine-readable JSON")
	readOnly := fs.Bool("read-only", false, "Simulate --read-only flag")
	allowMut := fs.Bool("allow-mutations", false, "Simulate --allow-mutations (must not defeat enterprise force)")
	if err := fs.Parse(args); err != nil {
		return apperr.New(apperr.CodeInvalidArgument, err.Error())
	}
	if strings.TrimSpace(*profileID) == "" {
		return apperr.New(apperr.CodeInvalidArgument, "--profile is required")
	}

	// Load profile for profile.read_only (non-secret).
	var profileRO *bool
	st, err := profileStore()
	if err != nil {
		return err
	}
	p, err := st.Load(*profileID)
	if err != nil {
		return err
	}
	v := p.EffectiveReadOnly()
	profileRO = &v

	polRes, err := policy.LoadFromEnviron()
	if err != nil {
		return err
	}
	ro := policy.Inputs{
		FlagReadOnly:    *readOnly,
		EnvReadOnly:     policy.EnvReadOnlyFromEnviron(),
		ProfileReadOnly: profileRO,
		Force:           policy.AsEnterpriseForce(polRes.Overlay),
		AllowMutations:  *allowMut,
	}
	ex := policy.ExplainEffective(*profileID, polRes, ro)
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(ex)
	}
	fmt.Printf("profile=%s policy_present=%v signature_state=%s\n",
		ex.ProfileID, ex.PolicyPresent, ex.SignatureState)
	fmt.Printf("  force_read_only=%v mode=%s\n", ex.ForceReadOnly, ex.Mode)
	if ex.MaxResultBytes != nil {
		fmt.Printf("  max_result_bytes=%d\n", *ex.MaxResultBytes)
	}
	if ex.MaxToolsPerMinute != nil {
		fmt.Printf("  max_tools_per_minute=%d\n", *ex.MaxToolsPerMinute)
	}
	if ex.MaxToolsBurst != nil {
		fmt.Printf("  max_tools_burst=%d\n", *ex.MaxToolsBurst)
	}
	if len(ex.DenyTools) > 0 {
		fmt.Printf("  deny_tools=%s\n", strings.Join(ex.DenyTools, ","))
	}
	if len(ex.DenyJobPrefixes) > 0 {
		fmt.Printf("  deny_job_prefixes=%s\n", strings.Join(ex.DenyJobPrefixes, ","))
	}
	if len(ex.DenyNodeNames) > 0 {
		fmt.Printf("  deny_node_names=%s\n", strings.Join(ex.DenyNodeNames, ","))
	}
	if len(ex.DenyViewNames) > 0 {
		fmt.Printf("  deny_view_names=%s\n", strings.Join(ex.DenyViewNames, ","))
	}
	if len(ex.DenyArtifactPaths) > 0 {
		fmt.Printf("  deny_artifact_paths=%s\n", strings.Join(ex.DenyArtifactPaths, ","))
	}
	if len(ex.DenyBranchNames) > 0 {
		fmt.Printf("  deny_branch_names=%s\n", strings.Join(ex.DenyBranchNames, ","))
	}
	if ex.BundleSeq > 0 {
		fmt.Printf("  bundle_seq=%d key_id=%s\n", ex.BundleSeq, ex.KeyID)
	}
	if roMap, ok := ex.ReadOnly["effective"]; ok {
		fmt.Printf("  read_only.effective=%v sources=%v\n", roMap, ex.ReadOnly["sources"])
	}
	for _, n := range ex.Notes {
		fmt.Printf("  note: %s\n", n)
	}
	return nil
}

func runPolicySign(args []string) error {
	if !policy.ParseEnvReadOnly(os.Getenv(EnvPolicySignDev)) {
		return apperr.New(apperr.CodePolicyDenial,
			"policy sign is dev-only; set JENKINS_MCP_POLICY_SIGN_DEV=1 (never ship private keys)")
	}
	fs := flag.NewFlagSet("policy sign", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	file := fs.String("file", "", "Plain overlay JSON to sign (required)")
	var keyPaths multiString
	var keyIDs multiString
	fs.Var(&keyPaths, "key", "Ed25519 private key PEM path (repeatable; pair with --key-id by order; never commit)")
	fs.Var(&keyIDs, "key-id", "Public key id for the corresponding --key (repeatable; order-paired)")
	keysDir := fs.String("keys-dir", "", "Directory of private key PEMs named <key_id>.pem (alt to --key/--key-id pairs)")
	out := fs.String("out", "", "Output bundle path (required)")
	bundleSeq := fs.Int64("bundle-seq", 1, "Monotonic bundle_seq (>=1)")
	notAfter := fs.String("not-after", "", "Optional RFC3339 expiry")
	minVersion := fs.Int("min-version", policy.CurrentOverlayVersion, "Minimum client overlay schema version")
	issuedAt := fs.String("issued-at", "", "Optional RFC3339 issued_at (default: now UTC)")
	if err := fs.Parse(args); err != nil {
		return apperr.New(apperr.CodeInvalidArgument, err.Error())
	}
	if strings.TrimSpace(*file) == "" || strings.TrimSpace(*out) == "" {
		return apperr.New(apperr.CodeInvalidArgument, "--file and --out are required")
	}

	signers, err := resolvePolicySigners(keyPaths, keyIDs, strings.TrimSpace(*keysDir))
	if err != nil {
		return err
	}
	// Best-effort zeroize private key material after use.
	defer zeroizeSigners(signers)

	raw, err := os.ReadFile(*file)
	if err != nil {
		return apperr.Wrap(apperr.CodeInvalidArgument, "read overlay file", err)
	}
	var ov policy.Overlay
	if err := json.Unmarshal(raw, &ov); err != nil {
		return apperr.Wrap(apperr.CodeInvalidArgument, "overlay JSON invalid", err)
	}
	ov.Signature = ""
	if err := ov.Validate(); err != nil {
		return err
	}

	issued := strings.TrimSpace(*issuedAt)
	if issued == "" {
		issued = time.Now().UTC().Format(time.RFC3339)
	}
	env := &policy.BundleEnvelope{
		SchemaVersion: policy.CurrentBundleSchemaVersion,
		Alg:           policy.AlgEd25519,
		// Top-level key_id is always part of the signed body; first signer wins.
		KeyID:      strings.TrimSpace(signers[0].KeyID),
		IssuedAt:   issued,
		NotAfter:   strings.TrimSpace(*notAfter),
		MinVersion: *minVersion,
		BundleSeq:  *bundleSeq,
		Overlay:    ov,
	}

	if len(signers) == 1 {
		// Backward-compatible single-sig path (top-level signature only).
		if err := policy.SignBundle(env, signers[0].Priv); err != nil {
			return err
		}
	} else {
		// Multi-sig lite: signatures[] populated; top-level signature empty.
		if err := policy.SignBundleMulti(env, signers); err != nil {
			return err
		}
	}

	outBytes, err := policy.MarshalBundle(env)
	if err != nil {
		return err
	}
	// Ensure parent exists when --out has a directory component.
	if dir := filepath.Dir(*out); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return apperr.Wrap(apperr.CodeInternal, "create output dir", err)
		}
	}
	if err := os.WriteFile(*out, outBytes, 0o644); err != nil {
		return apperr.Wrap(apperr.CodeInternal, "write bundle", err)
	}
	if len(signers) == 1 {
		fmt.Printf("signed bundle_seq=%d key_id=%s -> %s\n", env.BundleSeq, env.KeyID, filepath.Base(*out))
	} else {
		ids := make([]string, len(signers))
		for i, s := range signers {
			ids[i] = s.KeyID
		}
		fmt.Printf("signed multi-sig bundle_seq=%d signatures=%d key_ids=%s -> %s\n",
			env.BundleSeq, len(signers), strings.Join(ids, ","), filepath.Base(*out))
	}
	return nil
}

// resolvePolicySigners builds BundleSigner list from either order-paired
// --key/--key-id flags or a --keys-dir of <key_id>.pem files.
// Mutually exclusive modes. Private key bytes are loaded into memory only.
func resolvePolicySigners(keyPaths, keyIDs multiString, keysDir string) ([]policy.BundleSigner, error) {
	hasPairs := len(keyPaths) > 0 || len(keyIDs) > 0
	if keysDir != "" && hasPairs {
		return nil, apperr.New(apperr.CodeInvalidArgument,
			"use either --key/--key-id pairs or --keys-dir, not both")
	}
	if keysDir != "" {
		return loadSignersFromKeysDir(keysDir)
	}
	if len(keyPaths) == 0 || len(keyIDs) == 0 {
		return nil, apperr.New(apperr.CodeInvalidArgument,
			"--key and --key-id are required (repeatable pairs), or provide --keys-dir")
	}
	if len(keyPaths) != len(keyIDs) {
		return nil, apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("--key and --key-id counts must match (got %d keys, %d key-ids; paired by occurrence order)",
				len(keyPaths), len(keyIDs)))
	}
	out := make([]policy.BundleSigner, 0, len(keyPaths))
	seen := make(map[string]struct{}, len(keyPaths))
	for i := range keyPaths {
		id := strings.TrimSpace(keyIDs[i])
		path := strings.TrimSpace(keyPaths[i])
		if id == "" || path == "" {
			return nil, apperr.New(apperr.CodeInvalidArgument,
				fmt.Sprintf("signer[%d]: --key and --key-id must be non-empty", i))
		}
		if _, dup := seen[id]; dup {
			return nil, apperr.New(apperr.CodeInvalidArgument,
				fmt.Sprintf("duplicate --key-id %q", id))
		}
		seen[id] = struct{}{}
		priv, err := loadPrivateKeyFile(path)
		if err != nil {
			return nil, err
		}
		out = append(out, policy.BundleSigner{KeyID: id, Priv: priv})
	}
	return out, nil
}

// loadSignersFromKeysDir loads Ed25519 private PEMs from a directory.
// File basenames (minus .pem/.key) become key_id. Sorted by key_id for stability.
func loadSignersFromKeysDir(dir string) ([]policy.BundleSigner, error) {
	st, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, apperr.New(apperr.CodeInvalidArgument,
				fmt.Sprintf("keys-dir not found: %s", filepath.Base(dir)))
		}
		return nil, apperr.Wrap(apperr.CodeInvalidArgument, "keys-dir unreadable", err)
	}
	if !st.IsDir() {
		return nil, apperr.New(apperr.CodeInvalidArgument, "--keys-dir must be a directory")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeInvalidArgument, "keys-dir unreadable", err)
	}
	type item struct {
		id   string
		path string
	}
	var items []item
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		lower := strings.ToLower(name)
		if strings.HasSuffix(lower, ".md") || strings.HasSuffix(lower, ".txt") ||
			strings.HasSuffix(lower, ".pub") || strings.HasSuffix(lower, ".json") {
			// Skip docs and public-key / trust-store files.
			continue
		}
		id := privateKeyIDFromFilename(name)
		if id == "" {
			continue
		}
		items = append(items, item{id: id, path: filepath.Join(dir, name)})
	}
	if len(items) == 0 {
		return nil, apperr.New(apperr.CodeInvalidArgument,
			"--keys-dir has no private key PEM files (expected <key_id>.pem)")
	}
	sort.Slice(items, func(i, j int) bool { return items[i].id < items[j].id })
	out := make([]policy.BundleSigner, 0, len(items))
	seen := make(map[string]struct{}, len(items))
	for _, it := range items {
		if _, dup := seen[it.id]; dup {
			return nil, apperr.New(apperr.CodeInvalidArgument,
				fmt.Sprintf("duplicate key_id %q in keys-dir", it.id))
		}
		seen[it.id] = struct{}{}
		priv, err := loadPrivateKeyFile(it.path)
		if err != nil {
			return nil, err
		}
		out = append(out, policy.BundleSigner{KeyID: it.id, Priv: priv})
	}
	return out, nil
}

func privateKeyIDFromFilename(name string) string {
	base := filepath.Base(name)
	for _, ext := range []string{".pem", ".key"} {
		if strings.HasSuffix(strings.ToLower(base), ext) {
			base = base[:len(base)-len(ext)]
			break
		}
	}
	return strings.TrimSpace(base)
}

func loadPrivateKeyFile(path string) (ed25519.PrivateKey, error) {
	privRaw, err := os.ReadFile(path)
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeInvalidArgument,
			fmt.Sprintf("read private key %s", filepath.Base(path)), err)
	}
	priv, err := policy.ParsePrivateKeyBytes(privRaw)
	// Zeroize best-effort (Go GC still owns copies; clear our buffer).
	for i := range privRaw {
		privRaw[i] = 0
	}
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeInvalidArgument,
			fmt.Sprintf("private key %s invalid", filepath.Base(path)), err)
	}
	return priv, nil
}

func zeroizeSigners(signers []policy.BundleSigner) {
	for i := range signers {
		for j := range signers[i].Priv {
			signers[i].Priv[j] = 0
		}
	}
}

func writeJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
