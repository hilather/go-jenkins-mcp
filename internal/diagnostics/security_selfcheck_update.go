package diagnostics

import (
	"path/filepath"
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/update"
)

// checkUpdateLKGResidual is Wave 47 Track C / UPD-001 residual honesty:
// proves offline that LKG is documented as last verified download metadata
// only (not an installed binary), install/rollback is operator-owned, and
// VerifyLKG fails closed when no LKG record is present — without network,
// private keys, or real release artifacts.
//
// Pure offline: imports update package residual constant + VerifyLKG with a
// guaranteed-absent path. Bool details only (secret-free).
func checkUpdateLKGResidual() SelfCheckItem {
	const (
		name    = "update_lkg_residual"
		control = "UPD-001"
	)
	fail := func(msg string) SelfCheckItem {
		return SelfCheckItem{
			Name:    name,
			Status:  SelfCheckFail,
			Message: msg,
			Control: control,
		}
	}

	// --- Residual honesty constant exported and non-empty ---
	note := strings.TrimSpace(update.LKGResidualNote())
	if note == "" {
		return fail("LKGResidualNote / ResidualLKGIntegrity must be non-empty")
	}
	if note != strings.TrimSpace(update.ResidualLKGIntegrity) {
		return fail("LKGResidualNote must match ResidualLKGIntegrity")
	}
	lower := strings.ToLower(note)
	// Honesty phrases: not an installed binary + metadata + operator-owned.
	if !strings.Contains(lower, "not an installed binary") {
		return fail("ResidualLKGIntegrity must include \"not an installed binary\"")
	}
	if !strings.Contains(lower, "metadata") {
		return fail("ResidualLKGIntegrity must mention metadata")
	}
	if !strings.Contains(lower, "operator-owned") && !strings.Contains(lower, "operator owned") {
		return fail("ResidualLKGIntegrity must state install/rollback is operator-owned")
	}

	// --- VerifyLKG with absent path: fail closed, residual populated, secret-free ---
	// Guaranteed-missing path under a synthetic root (no ambient env / XDG).
	absent := filepath.Join(string(filepath.Separator), "jenkins-mcp-selfcheck-absent", "last_known_good.json")
	vres, err := update.VerifyLKG(update.VerifyLKGOptions{LKGPath: absent})
	if err != nil {
		return fail("VerifyLKG on absent path must not error (missing LKG is result not error)")
	}
	if vres == nil {
		return fail("VerifyLKG must return non-nil result")
	}
	if vres.OK {
		return fail("VerifyLKG must fail closed (OK=false) when LKG is absent")
	}
	if vres.LKGPresent {
		return fail("VerifyLKG LKGPresent must be false when record is absent")
	}
	if strings.TrimSpace(vres.Residual) == "" {
		return fail("VerifyLKG Residual must be populated (LKG residual honesty)")
	}
	if !strings.EqualFold(strings.TrimSpace(vres.Residual), note) {
		return fail("VerifyLKG Residual must equal ResidualLKGIntegrity")
	}
	// Reason is secret-free (no private keys, PEM, tokens, URLs with credentials).
	reason := vres.Reason
	if reason == "" {
		return fail("VerifyLKG Reason must explain absent LKG (fail closed)")
	}
	if leak := residualSecretLeak(reason); leak != "" {
		return fail("VerifyLKG Reason must be secret-free: " + leak)
	}
	if leak := residualSecretLeak(note); leak != "" {
		return fail("ResidualLKGIntegrity must be secret-free: " + leak)
	}

	// Residual honesty: auto-install not implemented; install/rollback operator-owned.
	return SelfCheckItem{
		Name:    name,
		Status:  SelfCheckOK,
		Message: "LKG residual honesty offline; LKG is last verified download metadata only — not auto-install",
		Control: control,
		Details: map[string]any{
			"lkg_is_metadata_only":            true,
			"install_rollback_operator_owned": true,
			"residual_auto_install":           false,
			"verify_lkg_absent_fail_closed":   true,
			"residual_note_nonempty":          true,
		},
	}
}

// residualSecretLeak returns a short label when s looks like secret material.
func residualSecretLeak(s string) string {
	u := strings.ToUpper(s)
	switch {
	case strings.Contains(u, "BEGIN PRIVATE"):
		return "pem_private"
	case strings.Contains(u, "BEGIN PUBLIC"):
		return "pem_public"
	case strings.Contains(s, "Bearer "):
		return "bearer"
	case strings.Contains(s, "password="):
		return "password"
	default:
		return ""
	}
}
