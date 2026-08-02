package fleetcache_test

import (
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/fleetcache"
)

func TestAdmitObjectClass_ConsoleLogAllowed(t *testing.T) {
	t.Parallel()
	res := fleetcache.AdmitObjectClass(fleetcache.ObjectKindConsoleLog, 1024)
	if !res.Allowed || res.Residual != fleetcache.ObjectClassResidualAllowed {
		t.Fatalf("%+v", res)
	}
	if res.MaxObjectRawBytes <= 0 {
		t.Fatal("expected size limit")
	}
	if res.ApprovalToken == "" {
		t.Fatal("expected approval token")
	}
	assertSecretFree(t, "admit", res.Residual, res.ApprovalToken, res.Kind)
}

func TestAdmitObjectClass_UnknownDenied(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"artifact", "binary_blob", "junit_report", "s3_object", ""} {
		res := fleetcache.AdmitObjectClass(kind, 1)
		if res.Allowed {
			t.Fatalf("%q should be denied", kind)
		}
		if res.Residual != fleetcache.ObjectClassResidualUnknownDenied && kind != "" {
			t.Fatalf("%q residual %q", kind, res.Residual)
		}
		if err := fleetcache.RequireObjectClass(kind, 1); err == nil {
			t.Fatalf("%q Require should fail", kind)
		} else if apperr.CodeOf(err) != apperr.CodePolicyDenial && apperr.CodeOf(err) != apperr.CodeInvalidArgument {
			// empty kind may be invalid or policy
			if kind != "" && apperr.CodeOf(err) != apperr.CodePolicyDenial {
				t.Fatalf("code %s", apperr.CodeOf(err))
			}
		}
	}
}

func TestAdmitObjectClass_DisabledAndSizeLimit(t *testing.T) {
	t.Parallel()
	reg := fleetcache.DefaultObjectClassRegistry()
	p := reg[fleetcache.ObjectKindConsoleLog]
	p.Enabled = false
	reg[fleetcache.ObjectKindConsoleLog] = p
	a := fleetcache.NewObjectClassAdmission(reg)
	res := a.AdmitObjectClass(fleetcache.ObjectKindConsoleLog, 1)
	if res.Allowed || res.Residual != fleetcache.ObjectClassResidualDisabled {
		t.Fatalf("%+v", res)
	}

	reg2 := fleetcache.DefaultObjectClassRegistry()
	a2 := fleetcache.NewObjectClassAdmission(reg2)
	res2 := a2.AdmitObjectClass(fleetcache.ObjectKindConsoleLog, fleetcache.DefaultMaxObjectRawBytesConsoleLog+1)
	if res2.Allowed || res2.Residual != fleetcache.ObjectClassResidualExceedsSizeLimit {
		t.Fatalf("%+v", res2)
	}
	if err := fleetcache.RequireObjectClass(fleetcache.ObjectKindConsoleLog, fleetcache.DefaultMaxObjectRawBytesConsoleLog+1); err == nil {
		t.Fatal("expected quota denial")
	} else if apperr.CodeOf(err) != apperr.CodeQuota {
		t.Fatalf("code %s", apperr.CodeOf(err))
	}
}

func TestLocator_UnknownObjectKindFailClosed(t *testing.T) {
	t.Parallel()
	// Bypass NewConsoleLogLocator by constructing raw Locator.
	loc := fleetcache.Locator{
		FleetID: "f", CachePool: "p", ControllerID: "c",
		ObjectKind: "artifact", JobFullNameNormalized: "job/demo", BuildNumber: 1,
		LocatorSchemaVersion: fleetcache.LocatorSchemaVersion,
	}
	if _, err := loc.Hash(); err == nil {
		t.Fatal("artifact class must not hash as valid peer locator")
	}
	// Valid console_log still works.
	ok, err := fleetcache.NewConsoleLogLocator("f", "p", "c", "job/demo", 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ok.Hash(); err != nil {
		t.Fatal(err)
	}
}

func TestObjectClassStatusResidual_Observable(t *testing.T) {
	t.Parallel()
	s := fleetcache.ObjectClassStatusResidual()
	if !strings.Contains(s, "console_log") || !strings.Contains(s, "unknown_default_deny") {
		t.Fatalf("%q", s)
	}
	assertSecretFree(t, "status", s)
	kinds := fleetcache.DefaultObjectClassAdmission.ApprovedObjectKinds()
	if len(kinds) != 1 || kinds[0] != fleetcache.ObjectKindConsoleLog {
		t.Fatalf("%v", kinds)
	}
}

func TestNilAdmission_FailClosed(t *testing.T) {
	t.Parallel()
	var a *fleetcache.ObjectClassAdmission
	res := a.AdmitObjectClass(fleetcache.ObjectKindConsoleLog, 1)
	if res.Allowed {
		t.Fatal("nil admission must fail closed")
	}
}
