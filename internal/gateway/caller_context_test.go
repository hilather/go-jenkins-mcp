package gateway_test

import (
	"context"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/contracts"
	"github.com/hilather/go-jenkins-mcp/internal/gateway"
)

func TestContextWithCaller_RoundTrip(t *testing.T) {
	t.Parallel()
	want := gateway.Caller{
		Subject:    "alice-sub",
		Tenant:     "t1",
		WorkloadID: "w1",
		ProfileID:  contracts.ProfileID("corp"),
	}
	ctx := gateway.ContextWithCaller(context.Background(), want)
	got, ok := gateway.CallerFromContext(ctx)
	if !ok {
		t.Fatal("expected caller")
	}
	if got.Subject != want.Subject || got.Tenant != want.Tenant ||
		got.WorkloadID != want.WorkloadID || got.ProfileID != want.ProfileID {
		t.Fatalf("got %+v want %+v", got, want)
	}
	// Unset context.
	if _, ok := gateway.CallerFromContext(context.Background()); ok {
		t.Fatal("background must not have caller")
	}
	if _, ok := gateway.CallerFromContext(nil); ok {
		t.Fatal("nil ctx")
	}
	// Nil parent becomes Background.
	ctx2 := gateway.ContextWithCaller(nil, want)
	if _, ok := gateway.CallerFromContext(ctx2); !ok {
		t.Fatal("nil parent")
	}
}

func TestCallerFromHTTPInbound_AndMergeDefaults(t *testing.T) {
	t.Parallel()
	in := gateway.HTTPInbound{
		ExternalSubject: "bob-sub",
		Tenant:          "tenant-b",
		// Workload empty — filled from defaults
		Verified: true,
	}
	c := gateway.CallerFromHTTPInbound(in, contracts.ProfileID("corp"))
	if c.Subject != "bob-sub" || string(c.ProfileID) != "corp" || c.Tenant != "tenant-b" {
		t.Fatalf("%+v", c)
	}
	if c.WorkloadID != "" {
		t.Fatalf("workload should be empty before merge: %+v", c)
	}
	if !c.Valid() {
		// Profile + subject present → Valid.
		t.Fatalf("expected valid: %+v", c)
	}
	defaults := gateway.Caller{
		Subject:    "process-default-must-not-replace",
		Tenant:     "tenant-default",
		WorkloadID: "wl-default",
		ProfileID:  contracts.ProfileID("corp"),
	}
	merged := gateway.MergeCallerDefaults(c, defaults)
	if merged.Subject != "bob-sub" {
		t.Fatalf("subject must stay HTTP: %q", merged.Subject)
	}
	if merged.Tenant != "tenant-b" {
		t.Fatalf("tenant from HTTP: %q", merged.Tenant)
	}
	if merged.WorkloadID != "wl-default" {
		t.Fatalf("workload from defaults: %q", merged.WorkloadID)
	}
	// Empty inbound subject stays empty (invalid) after merge — Subject not filled.
	empty := gateway.CallerFromHTTPInbound(gateway.HTTPInbound{}, "corp")
	mergedEmpty := gateway.MergeCallerDefaults(empty, defaults)
	if mergedEmpty.Subject != "" {
		t.Fatalf("must not elevate empty subject from defaults: %+v", mergedEmpty)
	}
	if mergedEmpty.Valid() {
		t.Fatal("empty subject must remain invalid")
	}
}

func TestMultiUserEnabled(t *testing.T) {
	t.Parallel()
	cases := []struct {
		v    string
		want bool
	}{
		{"", false},
		{"0", false},
		{"false", false},
		{"no", false},
		{"1", true},
		{"true", true},
		{"YES", true},
		{"on", true},
		{"  true  ", true},
	}
	for _, tc := range cases {
		got := gateway.MultiUserEnabled(func(string) string { return tc.v })
		if got != tc.want {
			t.Fatalf("v=%q got %v want %v", tc.v, got, tc.want)
		}
	}
	// getenv nil uses os.Getenv — just ensure no panic.
	_ = gateway.MultiUserEnabled(nil)
}

// Canary: Caller context helpers never embed secret-looking material in StatusMap.
func TestCallerContext_NoSecretFields(t *testing.T) {
	t.Parallel()
	c := gateway.Caller{Subject: "s", ProfileID: "p", Tenant: "t"}
	blob := strings.Join([]string{
		c.Subject, c.Tenant, c.WorkloadID, string(c.ProfileID),
	}, " ")
	for _, bad := range []string{"token", "password", "Authorization", "Bearer"} {
		if strings.Contains(strings.ToLower(blob), strings.ToLower(bad)) {
			// Subjects may accidentally contain words — only check StatusMap keys.
			_ = bad
		}
	}
	sm := c.StatusMap()
	for k := range sm {
		if strings.Contains(strings.ToLower(k), "token") ||
			strings.Contains(strings.ToLower(k), "secret") {
			t.Fatalf("status map key looks secret: %q", k)
		}
	}
}
