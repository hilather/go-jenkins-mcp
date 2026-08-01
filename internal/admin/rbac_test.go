package admin_test

import (
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/admin"
)

func TestParseRole(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in      string
		want    admin.Role
		wantErr bool
	}{
		{"", admin.RoleViewer, false},
		{"viewer", admin.RoleViewer, false},
		{"VIEWER", admin.RoleViewer, false},
		{" operator ", admin.RoleOperator, false},
		{"policy_admin", admin.RolePolicyAdmin, false},
		{"admin", "", true},
		{"root", "", true},
		{"policy-admin", "", true},
		{"superuser", "", true},
	}
	for _, tc := range cases {
		got, err := admin.ParseRole(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParseRole(%q) want error, got %q", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseRole(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseRole(%q)=%q want %q", tc.in, got, tc.want)
		}
	}
}

func TestRoleCan_Matrix(t *testing.T) {
	t.Parallel()
	// viewer: read only
	if !admin.RoleViewer.Can(admin.PermRead) {
		t.Fatal("viewer must have PermRead")
	}
	if admin.RoleViewer.Can(admin.PermPolicyWrite) {
		t.Fatal("viewer must not have PermPolicyWrite")
	}
	if admin.RoleViewer.Can(admin.PermCacheDestructive) {
		t.Fatal("viewer must not have PermCacheDestructive")
	}
	if admin.RoleViewer.Can(admin.PermGatewayOps) {
		t.Fatal("viewer must not have PermGatewayOps")
	}

	// operator: day-2 cache destructive + gateway_ops; not policy write
	if !admin.RoleOperator.Can(admin.PermRead) {
		t.Fatal("operator must have PermRead")
	}
	if !admin.RoleOperator.Can(admin.PermCacheDestructive) {
		t.Fatal("operator must have PermCacheDestructive")
	}
	if !admin.RoleOperator.Can(admin.PermGatewayOps) {
		t.Fatal("operator must have PermGatewayOps")
	}
	if admin.RoleOperator.Can(admin.PermPolicyWrite) {
		t.Fatal("operator must not have PermPolicyWrite")
	}

	// policy_admin: policy write + gateway_ops; not cache destructive
	if !admin.RolePolicyAdmin.Can(admin.PermRead) {
		t.Fatal("policy_admin must have PermRead")
	}
	if !admin.RolePolicyAdmin.Can(admin.PermPolicyWrite) {
		t.Fatal("policy_admin must have PermPolicyWrite")
	}
	if !admin.RolePolicyAdmin.Can(admin.PermGatewayOps) {
		t.Fatal("policy_admin must have PermGatewayOps")
	}
	if admin.RolePolicyAdmin.Can(admin.PermCacheDestructive) {
		t.Fatal("policy_admin must not have PermCacheDestructive")
	}

	// Unknown / empty role: fail closed (no grants)
	if admin.Role("root").Can(admin.PermRead) {
		t.Fatal("unknown role must not have PermRead")
	}
	if admin.Role("root").Can(admin.PermPolicyWrite) {
		t.Fatal("unknown role must not have PermPolicyWrite")
	}
	if admin.Role("").Can(admin.PermRead) {
		t.Fatal("empty role must not have PermRead (middleware must attach role)")
	}
}

func TestCanWidenForceReadOnly_AlwaysFalse(t *testing.T) {
	t.Parallel()
	// policy_admin can hold policy write permission but still cannot widen
	// enterprise force_read_only — pure helper always false.
	for _, r := range []admin.Role{
		admin.RoleViewer,
		admin.RoleOperator,
		admin.RolePolicyAdmin,
		admin.Role("root"),
		"",
	} {
		if admin.CanWidenForceReadOnly(r) {
			t.Fatalf("CanWidenForceReadOnly(%q) must be false", r)
		}
	}
}

func TestRolePermissions(t *testing.T) {
	t.Parallel()
	viewer := admin.RoleViewer.PermissionStrings()
	if len(viewer) != 1 || viewer[0] != "read" {
		t.Fatalf("viewer perms=%v", viewer)
	}
	op := admin.RoleOperator.PermissionStrings()
	if len(op) != 3 || op[0] != "read" || op[1] != "cache_destructive" || op[2] != "gateway_ops" {
		t.Fatalf("operator perms=%v", op)
	}
	pa := admin.RolePolicyAdmin.PermissionStrings()
	if len(pa) != 3 || pa[0] != "read" || pa[1] != "policy_write" || pa[2] != "gateway_ops" {
		t.Fatalf("policy_admin perms=%v", pa)
	}
}
