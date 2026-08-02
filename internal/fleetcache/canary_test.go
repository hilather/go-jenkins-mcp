package fleetcache_test

import (
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/fleetcache"
)

// FLC-072: shadow/read/full canary criteria + fail-closed transitions + preconditions.
// Residual honesty: live multi-host canary is residual (CanaryHonestyResidual).

func TestCanaryCriteriaFor_ShadowReadFullNonEmpty(t *testing.T) {
	t.Parallel()
	for _, stage := range []fleetcache.CanaryStage{
		fleetcache.CanaryStageShadow,
		fleetcache.CanaryStageRead,
		fleetcache.CanaryStageFull,
	} {
		c, err := fleetcache.CriteriaFor(stage)
		if err != nil {
			t.Fatalf("CriteriaFor(%s): %v", stage, err)
		}
		if c.Stage != stage {
			t.Fatalf("stage %q want %q", c.Stage, stage)
		}
		if len(c.Entry) == 0 || len(c.Exit) == 0 || len(c.Rollback) == 0 {
			t.Fatalf("%s: entry/exit/rollback must be non-empty: %+v", stage, c)
		}
		// Rollback always documents set mode off + no data migration (restore local-only).
		hasMigration, hasOff := false, false
		for _, r := range c.Rollback {
			if strings.Contains(r, "no_data_migration") {
				hasMigration = true
			}
			if strings.Contains(r, "set_mode_off") {
				hasOff = true
			}
		}
		if !hasMigration || !hasOff {
			t.Fatalf("%s rollback must include set_mode_off + no_data_migration: %v", stage, c.Rollback)
		}
		for _, list := range [][]string{c.Entry, c.Exit, c.Rollback} {
			for _, code := range list {
				if strings.TrimSpace(code) == "" {
					t.Fatalf("%s empty criteria code", stage)
				}
				assertSecretFree(t, "criteria:"+string(stage), code)
			}
		}
	}
}

func TestCanaryCriteriaFor_OffAndUnknown(t *testing.T) {
	t.Parallel()
	c, err := fleetcache.CriteriaFor(fleetcache.CanaryStageOff)
	if err != nil {
		t.Fatal(err)
	}
	if c.Stage != fleetcache.CanaryStageOff || len(c.Entry) == 0 {
		t.Fatalf("off criteria: %+v", c)
	}
	_, err = fleetcache.CriteriaFor(fleetcache.CanaryStage("explode"))
	if err == nil {
		t.Fatal("unknown stage must fail closed")
	}
	assertSecretFree(t, "criteria_err", err.Error())
}

func TestValidateTransition_AdjacentAndDenied(t *testing.T) {
	t.Parallel()
	// off→shadow OK
	tr := fleetcache.ValidateTransition(fleetcache.CanaryStageOff, fleetcache.CanaryStageShadow)
	if !tr.Allowed || tr.Residual != fleetcache.ResidualTransitionAllowed {
		t.Fatalf("off→shadow: %+v", tr)
	}
	// shadow→read OK
	tr = fleetcache.ValidateTransition(fleetcache.CanaryStageShadow, fleetcache.CanaryStageRead)
	if !tr.Allowed {
		t.Fatalf("shadow→read: %+v", tr)
	}
	// read→full OK
	tr = fleetcache.ValidateTransition(fleetcache.CanaryStageRead, fleetcache.CanaryStageFull)
	if !tr.Allowed {
		t.Fatalf("read→full: %+v", tr)
	}
	// full→read (step down) OK
	tr = fleetcache.ValidateTransition(fleetcache.CanaryStageFull, fleetcache.CanaryStageRead)
	if !tr.Allowed {
		t.Fatalf("full→read: %+v", tr)
	}
	// off→full DENIED (no silent full enable)
	tr = fleetcache.ValidateTransition(fleetcache.CanaryStageOff, fleetcache.CanaryStageFull)
	if tr.Allowed || tr.Residual != fleetcache.ResidualTransitionAdjacentOnly {
		t.Fatalf("off→full must deny adjacent_only: %+v", tr)
	}
	// off→read DENIED
	tr = fleetcache.ValidateTransition(fleetcache.CanaryStageOff, fleetcache.CanaryStageRead)
	if tr.Allowed {
		t.Fatalf("off→read must deny: %+v", tr)
	}
	// shadow→full DENIED
	tr = fleetcache.ValidateTransition(fleetcache.CanaryStageShadow, fleetcache.CanaryStageFull)
	if tr.Allowed {
		t.Fatalf("shadow→full must deny: %+v", tr)
	}
	// read→off rollback OK
	tr = fleetcache.ValidateTransition(fleetcache.CanaryStageRead, fleetcache.CanaryStageOff)
	if !tr.Allowed || tr.Residual != fleetcache.ResidualRollbackNoMigration {
		t.Fatalf("read→off rollback: %+v", tr)
	}
	// same stage noop
	tr = fleetcache.ValidateTransition(fleetcache.CanaryStageShadow, fleetcache.CanaryStageShadow)
	if !tr.Allowed || tr.Residual != fleetcache.ResidualTransitionNoopSame {
		t.Fatalf("noop: %+v", tr)
	}
	// unknown denied
	tr = fleetcache.ValidateTransition(fleetcache.CanaryStage("x"), fleetcache.CanaryStageOff)
	if tr.Allowed || tr.Residual != fleetcache.ResidualTransitionUnknownStage {
		t.Fatalf("unknown from: %+v", tr)
	}
	assertSecretFree(t, "transition", tr.Residual,
		fleetcache.ResidualTransitionAdjacentOnly,
		fleetcache.ResidualRollbackNoMigration,
	)
}

func TestRollbackToOff_AlwaysAllowedNoMigration(t *testing.T) {
	t.Parallel()
	for _, from := range fleetcache.KnownCanaryStages() {
		tr := fleetcache.RollbackToOff(from)
		if !tr.Allowed || tr.To != fleetcache.CanaryStageOff {
			t.Fatalf("RollbackToOff(%s): %+v", from, tr)
		}
		if tr.Residual != fleetcache.ResidualRollbackNoMigration {
			t.Fatalf("residual want rollback_no_migration got %q", tr.Residual)
		}
		// Residual claims no migration explicitly.
		if !strings.Contains(tr.Residual, "no_migration") {
			t.Fatalf("residual must claim no migration: %q", tr.Residual)
		}
		assertSecretFree(t, "rollback", tr.Residual, string(tr.From), string(tr.To))
	}
	// From full / read still rolls back cleanly.
	tr := fleetcache.RollbackToOff(fleetcache.CanaryStageFull)
	if !tr.Allowed || tr.From != fleetcache.CanaryStageFull {
		t.Fatalf("%+v", tr)
	}
}

func TestApplyCanaryMode_MapsCorrectly(t *testing.T) {
	t.Parallel()
	cases := []struct {
		stage fleetcache.CanaryStage
		mode  fleetcache.Mode
	}{
		{fleetcache.CanaryStageOff, fleetcache.ModeOff},
		{fleetcache.CanaryStageShadow, fleetcache.ModeShadow},
		{fleetcache.CanaryStageRead, fleetcache.ModeRead},
		{fleetcache.CanaryStageFull, fleetcache.ModeFull},
	}
	for _, tc := range cases {
		m, err := fleetcache.ApplyCanaryMode(tc.stage)
		if err != nil {
			t.Fatalf("%s: %v", tc.stage, err)
		}
		if m != tc.mode {
			t.Fatalf("%s → %q want %q", tc.stage, m, tc.mode)
		}
	}
	_, err := fleetcache.ApplyCanaryMode(fleetcache.CanaryStage("bogus"))
	if err == nil {
		t.Fatal("bogus stage must error")
	}
	assertSecretFree(t, "apply_err", err.Error())
	// Empty stage maps to ModeOff (product default / ResolveConfig parity).
	m, err := fleetcache.ApplyCanaryMode("")
	if err != nil || m != fleetcache.ModeOff {
		t.Fatalf("empty → ModeOff: mode=%q err=%v", m, err)
	}
}

func TestCheckCanaryPreconditions_FailClosed(t *testing.T) {
	t.Parallel()
	// full without handlers → fail closed
	ok, res := fleetcache.CheckCanaryPreconditions(fleetcache.CanaryPrecondition{
		HandlersLive:   false,
		OriginFallback: true,
		ModeRequested:  fleetcache.ModeFull,
	})
	if ok || res != fleetcache.ResidualPrecondHandlersNotLive {
		t.Fatalf("full no handlers: ok=%v residual=%q", ok, res)
	}
	// read without origin fallback → fail closed
	ok, res = fleetcache.CheckCanaryPreconditions(fleetcache.CanaryPrecondition{
		HandlersLive:   true,
		OriginFallback: false,
		ModeRequested:  fleetcache.ModeRead,
	})
	if ok || res != fleetcache.ResidualPrecondOriginFallbackRequired {
		t.Fatalf("read no origin: ok=%v residual=%q", ok, res)
	}
	// read with both OK
	ok, res = fleetcache.CheckCanaryPreconditions(fleetcache.CanaryPrecondition{
		HandlersLive:   true,
		OriginFallback: true,
		ModeRequested:  fleetcache.ModeRead,
	})
	if !ok || res != fleetcache.ResidualPrecondOK {
		t.Fatalf("read ok: ok=%v residual=%q", ok, res)
	}
	// full with both OK
	ok, res = fleetcache.CheckCanaryPreconditions(fleetcache.CanaryPrecondition{
		HandlersLive:   true,
		OriginFallback: true,
		ModeRequested:  fleetcache.ModeFull,
	})
	if !ok {
		t.Fatalf("full ok residual=%q", res)
	}
	// shadow does not require peer I/O
	ok, res = fleetcache.CheckCanaryPreconditions(fleetcache.CanaryPrecondition{
		HandlersLive:   false,
		OriginFallback: false,
		ModeRequested:  fleetcache.ModeShadow,
	})
	if !ok || res != fleetcache.ResidualPrecondShadowNoPeerIO {
		t.Fatalf("shadow: ok=%v residual=%q", ok, res)
	}
	// mode off always OK
	ok, res = fleetcache.CheckCanaryPreconditions(fleetcache.CanaryPrecondition{
		ModeRequested: fleetcache.ModeOff,
	})
	if !ok || res != fleetcache.ResidualPrecondModeOff {
		t.Fatalf("off: ok=%v residual=%q", ok, res)
	}
	// unknown mode fail closed
	ok, res = fleetcache.CheckCanaryPreconditions(fleetcache.CanaryPrecondition{
		HandlersLive:   true,
		OriginFallback: true,
		ModeRequested:  fleetcache.Mode("explode"),
	})
	if ok || res != fleetcache.ResidualPrecondUnknownMode {
		t.Fatalf("unknown: ok=%v residual=%q", ok, res)
	}
	assertSecretFree(t, "precond",
		fleetcache.ResidualPrecondHandlersNotLive,
		fleetcache.ResidualPrecondOriginFallbackRequired,
		fleetcache.ResidualPrecondOK,
		fleetcache.ResidualPrecondShadowNoPeerIO,
		res,
	)
}

func TestCanary_NoSilentFullEnable(t *testing.T) {
	t.Parallel()
	// Combined gate: promotion off→full denied AND preconditions without handlers fail.
	tr := fleetcache.ValidateTransition(fleetcache.CanaryStageOff, fleetcache.CanaryStageFull)
	if tr.Allowed {
		t.Fatal("must not allow off→full")
	}
	ok, _ := fleetcache.CheckCanaryPreconditions(fleetcache.CanaryPrecondition{
		HandlersLive:   false,
		OriginFallback: false,
		ModeRequested:  fleetcache.ModeFull,
	})
	if ok {
		t.Fatal("must not enable full without preconditions")
	}
}

func TestCanary_HonestyResidual_LiveMultiHost(t *testing.T) {
	t.Parallel()
	r := fleetcache.CanaryHonestyResidual
	if !strings.Contains(r, "FLC-072") {
		t.Fatalf("missing FLC-072: %q", r)
	}
	if !strings.Contains(r, "live multi-host") && !strings.Contains(r, "live_multi_host") {
		t.Fatalf("must document live multi-host residual: %q", r)
	}
	if !strings.Contains(strings.ToLower(r), "offline") {
		t.Fatalf("must claim offline library Done*: %q", r)
	}
	if !strings.Contains(r, "default off") && !strings.Contains(r, "mode default off") {
		t.Fatalf("must keep mode default off honesty: %q", r)
	}
	assertSecretFree(t, "honesty", r)
}

func TestCanary_SecretFreeAllResidualsAndCriteria(t *testing.T) {
	t.Parallel()
	// Plant-style canary: known secret shapes must never appear in library strings.
	residuals := []string{
		fleetcache.ResidualRollbackNoMigration,
		fleetcache.ResidualTransitionAdjacentOnly,
		fleetcache.ResidualTransitionUnknownStage,
		fleetcache.ResidualTransitionNoopSame,
		fleetcache.ResidualTransitionAllowed,
		fleetcache.ResidualPrecondOK,
		fleetcache.ResidualPrecondHandlersNotLive,
		fleetcache.ResidualPrecondOriginFallbackRequired,
		fleetcache.ResidualPrecondModeOff,
		fleetcache.ResidualPrecondShadowNoPeerIO,
		fleetcache.ResidualPrecondUnknownMode,
		fleetcache.ResidualCanaryUnknownStage,
		fleetcache.CanaryHonestyResidual,
	}
	assertSecretFree(t, "residuals", residuals...)

	for _, stage := range fleetcache.KnownCanaryStages() {
		c, err := fleetcache.CriteriaFor(stage)
		if err != nil {
			t.Fatal(err)
		}
		for _, list := range [][]string{c.Entry, c.Exit, c.Rollback} {
			assertSecretFree(t, "stage:"+string(stage), list...)
		}
	}

	// Transition residuals across matrix.
	for _, from := range fleetcache.KnownCanaryStages() {
		for _, to := range fleetcache.KnownCanaryStages() {
			tr := fleetcache.ValidateTransition(from, to)
			assertSecretFree(t, "tr", tr.Residual, string(tr.From), string(tr.To))
		}
		rb := fleetcache.RollbackToOff(from)
		assertSecretFree(t, "rb", rb.Residual)
	}
}

func TestParseCanaryStage(t *testing.T) {
	t.Parallel()
	s, err := fleetcache.ParseCanaryStage("  READ ")
	if err != nil || s != fleetcache.CanaryStageRead {
		t.Fatalf("got %q err=%v", s, err)
	}
	s, err = fleetcache.ParseCanaryStage("")
	if err != nil || s != fleetcache.CanaryStageOff {
		t.Fatalf("empty → off: got %q err=%v", s, err)
	}
	_, err = fleetcache.ParseCanaryStage("full-blast")
	if err == nil {
		t.Fatal("want error")
	}
	assertSecretFree(t, "parse_err", err.Error())
}
