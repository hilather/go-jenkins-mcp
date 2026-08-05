package cachecontrol

import (
	"encoding/json"
	"testing"
	"time"
)

func TestResolve_AbsentConfig_CompatibilityDefaults(t *testing.T) {
	reg := DefaultRegistry()
	eff, err := Resolve(ResolveInputs{Registry: reg})
	if err != nil {
		t.Fatal(err)
	}
	if !eff.Global.Enabled {
		t.Fatal("global enabled")
	}
	if eff.Global.AllowRawDump {
		t.Fatal("raw dump must default false")
	}
	if !eff.Global.RuntimeOverridesEnabled {
		t.Fatal("runtime overrides enabled by default")
	}
	// All available types read_write except ratarmount
	for _, id := range AllTypeIDs() {
		tc, ok := eff.TypeConfig(id)
		if !ok {
			t.Fatalf("missing type %s", id)
		}
		if id == TypeRatarmountIndex {
			if tc.Mode != ModeOff {
				t.Fatalf("ratarmount mode %s", tc.Mode)
			}
			continue
		}
		if tc.Mode != ModeReadWrite {
			t.Fatalf("%s mode=%s want read_write (absent-config compatibility)", id, tc.Mode)
		}
		if tc.FleetShare {
			t.Fatalf("%s fleetShare should default false", id)
		}
		// Mode decisions match pre-feature open-cache behavior
		if !ShouldLookup(true, tc.Mode) || !ShouldFill(true, tc.Mode) {
			t.Fatalf("%s should allow lookup and fill by default", id)
		}
	}
	// Provenance for mode is built_in
	fs, ok := eff.SourceDetails["types.artifact_blob.mode"]
	if !ok || fs.Source != SourceBuiltIn {
		t.Fatalf("mode source %+v", fs)
	}
}

func TestResolve_EmergencyForceOff(t *testing.T) {
	eff, err := Resolve(ResolveInputs{
		Registry: DefaultRegistry(),
		Startup: StartupConstraints{
			ForceOff: []TypeID{TypeArtifactBlob, TypeStageLog},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if eff.TypeMode(TypeArtifactBlob) != ModeOff {
		t.Fatal("force off artifact_blob")
	}
	if eff.TypeMode(TypeStageLog) != ModeOff {
		t.Fatal("force off stage_log")
	}
	if eff.TypeMode(TypeConsoleLog) != ModeReadWrite {
		t.Fatal("console_log unchanged")
	}
	fs := eff.SourceDetails["types.artifact_blob.mode"]
	if fs.Source != SourceEmergencyForceOff {
		t.Fatalf("source %s", fs.Source)
	}
}

func TestResolve_RuntimeOverride_Mode(t *testing.T) {
	ro := ModeReadOnly
	eff, err := Resolve(ResolveInputs{
		Registry: DefaultRegistry(),
		Overrides: &RuntimeOverrides{
			Revision: 7,
			Types: map[TypeID]TypeConfig{
				TypeTestReport: {Mode: &ro},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if eff.Revision != 7 {
		t.Fatalf("revision %d", eff.Revision)
	}
	if eff.TypeMode(TypeTestReport) != ModeReadOnly {
		t.Fatal("override not applied")
	}
	fs := eff.SourceDetails["types.test_report.mode"]
	if fs.Source != SourceRuntimeOverride {
		t.Fatalf("source %s", fs.Source)
	}
	// Disable does not purge — config has no wipe flag; mode off keeps data by contract
	off := ModeOff
	eff2, err := Resolve(ResolveInputs{
		Registry: DefaultRegistry(),
		Overrides: &RuntimeOverrides{
			Revision: 8,
			Types:    map[TypeID]TypeConfig{TypeTestReport: {Mode: &off}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if ShouldLookup(true, eff2.TypeMode(TypeTestReport)) || ShouldFill(true, eff2.TypeMode(TypeTestReport)) {
		t.Fatal("off must bypass")
	}
}

func TestResolve_ProfileAndServerPrecedence(t *testing.T) {
	srvMode := ModeWriteOnly
	profMode := ModeReadOnly
	server := &DeclarativeConfig{
		Version: 1,
		Cache: DeclarativeCache{
			Types: map[string]TypeConfig{
				string(TypePipelineStages): {Mode: &srvMode},
			},
		},
	}
	profile := &DeclarativeConfig{
		Version: 1,
		Cache: DeclarativeCache{
			Types: map[string]TypeConfig{
				string(TypePipelineStages): {Mode: &profMode},
			},
		},
	}
	eff, err := Resolve(ResolveInputs{Server: server, Profile: profile, Registry: DefaultRegistry()})
	if err != nil {
		t.Fatal(err)
	}
	// profile > server
	if eff.TypeMode(TypePipelineStages) != ModeReadOnly {
		t.Fatalf("got %s", eff.TypeMode(TypePipelineStages))
	}
	if eff.SourceDetails["types.pipeline_stages.mode"].Source != SourceProfileConfig {
		t.Fatalf("source %+v", eff.SourceDetails["types.pipeline_stages.mode"])
	}
}

func TestResolve_StartupBlocksRawDump(t *testing.T) {
	trueV := true
	doc := &DeclarativeConfig{
		Version: 1,
		Cache: DeclarativeCache{
			Global: GlobalConfig{
				Dump: &DumpGlobalConfig{AllowRaw: &trueV},
			},
		},
	}
	eff, err := Resolve(ResolveInputs{
		Profile:  doc,
		Registry: DefaultRegistry(),
		Startup:  StartupConstraints{AllowRawDump: false},
	})
	if err != nil {
		t.Fatal(err)
	}
	if eff.Global.AllowRawDump {
		t.Fatal("startup must block raw dump")
	}
}

func TestResolve_DisableRuntimeMutations(t *testing.T) {
	eff, err := Resolve(ResolveInputs{
		Registry: DefaultRegistry(),
		Startup:  StartupConstraints{DisableRuntimeMutations: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if eff.Global.RuntimeOverridesEnabled {
		t.Fatal("runtime mutations should be disabled")
	}
}

func TestValidate_UnknownType(t *testing.T) {
	m := ModeOff
	doc := &DeclarativeConfig{
		Version: 1,
		Cache: DeclarativeCache{
			Types: map[string]TypeConfig{"not_a_real_type": {Mode: &m}},
		},
	}
	if err := ValidateDeclarative(doc); err == nil {
		t.Fatal("expected unknown type")
	}
}

func TestValidate_QuotaInvariant(t *testing.T) {
	soft := int64(10)
	hard := int64(5)
	doc := &DeclarativeConfig{
		Version: 1,
		Cache: DeclarativeCache{
			Types: map[string]TypeConfig{
				string(TypeConsoleLog): {Quota: &QuotaConfig{SoftBytes: &soft, HardBytes: &hard}},
			},
		},
	}
	if err := ValidateDeclarative(doc); err == nil {
		t.Fatal("expected soft>hard rejection")
	}
}

func TestParseDeclarativeJSON_EmptyIsNil(t *testing.T) {
	doc, err := ParseDeclarativeJSON(nil)
	if err != nil || doc != nil {
		t.Fatalf("got %+v %v", doc, err)
	}
	doc, err = ParseDeclarativeJSON([]byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if doc.Version != 1 {
		t.Fatalf("version %d", doc.Version)
	}
}

func TestParseDeclarativeJSON_RoundTripDefaults(t *testing.T) {
	raw, err := json.Marshal(BuiltInDefaults())
	if err != nil {
		t.Fatal(err)
	}
	doc, err := ParseDeclarativeJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateDeclarative(doc); err != nil {
		t.Fatal(err)
	}
	// Resolve with only profile=built-in encoding still yields read_write
	eff, err := Resolve(ResolveInputs{Profile: doc, Registry: DefaultRegistry()})
	if err != nil {
		t.Fatal(err)
	}
	if eff.TypeMode(TypeArtifactCatalog) != ModeReadWrite {
		t.Fatal(eff.TypeMode(TypeArtifactCatalog))
	}
}

func TestTerminalTTL_ZeroMeansNoExpiry(t *testing.T) {
	// Compatibility: terminalTTL 0 is valid and means no time expiry.
	zero := DurationJSON{D: 0}
	doc := &DeclarativeConfig{
		Version: 1,
		Cache: DeclarativeCache{
			Types: map[string]TypeConfig{
				string(TypeConsoleLog): {
					Freshness: &FreshnessConfig{TerminalTTL: &zero},
				},
			},
		},
	}
	eff, err := Resolve(ResolveInputs{Profile: doc, Registry: DefaultRegistry()})
	if err != nil {
		t.Fatal(err)
	}
	tc, _ := eff.TypeConfig(TypeConsoleLog)
	if tc.TerminalTTL != 0 {
		t.Fatalf("terminalTTL=%v", tc.TerminalTTL)
	}
	// Explicit non-zero still works
	hour := DurationJSON{D: time.Hour}
	doc.Cache.Types[string(TypeConsoleLog)] = TypeConfig{
		Freshness: &FreshnessConfig{TerminalTTL: &hour},
	}
	eff, err = Resolve(ResolveInputs{Profile: doc, Registry: DefaultRegistry()})
	if err != nil {
		t.Fatal(err)
	}
	tc, _ = eff.TypeConfig(TypeConsoleLog)
	if tc.TerminalTTL != time.Hour {
		t.Fatal(tc.TerminalTTL)
	}
}

func TestModeForResourceKind(t *testing.T) {
	eff, err := Resolve(ResolveInputs{Registry: DefaultRegistry()})
	if err != nil {
		t.Fatal(err)
	}
	if ModeForResourceKind(eff, "artifact_blob") != ModeReadWrite {
		t.Fatal("artifact_blob")
	}
	if ModeForResourceKind(eff, "unknown_kind") != ModeOff {
		t.Fatal("unknown fail closed")
	}
}
