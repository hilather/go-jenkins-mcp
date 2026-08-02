package keyring_test

import (
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/keyring"
)

func TestMemoryStoreRoundTrip(t *testing.T) {
	t.Parallel()
	mem := keyring.NewMemory()
	st := keyring.NewStore(mem)
	ref := keyring.CredentialRef{
		ProfileID: "corp",
		Origin:    "https://jenkins.example.com",
		Method:    "api_token",
		Account:   "alice",
	}
	const token = "s3cret-api-token-value-never-log"
	if err := st.SetAPIToken(ref, token); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetAPIToken(ref)
	if err != nil {
		t.Fatal(err)
	}
	if got != token {
		t.Fatalf("token mismatch")
	}
	// Replace
	if err := st.SetAPIToken(ref, "replacement-token"); err != nil {
		t.Fatal(err)
	}
	got, err = st.GetAPIToken(ref)
	if err != nil || got != "replacement-token" {
		t.Fatalf("replace: %q %v", got, err)
	}
	if err := st.DeleteAPIToken(ref); err != nil {
		t.Fatal(err)
	}
	_, err = st.GetAPIToken(ref)
	if err == nil {
		t.Fatal("expected missing after delete")
	}
	if apperr.CodeOf(err) != apperr.CodeAuthentication {
		t.Fatalf("code: %v", apperr.CodeOf(err))
	}
	// Delete missing is OK
	if err := st.DeleteAPIToken(ref); err != nil {
		t.Fatal(err)
	}
}

func TestAccountKeyNamespace(t *testing.T) {
	t.Parallel()
	k := keyring.AccountKey(keyring.CredentialRef{
		ProfileID: "corp",
		Origin:    "https://Jenkins.Example.com/path",
		Method:    "api_token",
		Account:   "alice",
	})
	if !strings.Contains(k, "profile=corp") || !strings.Contains(k, "account=alice") {
		t.Fatalf("key: %s", k)
	}
	if strings.Contains(k, "/path") {
		t.Fatalf("origin should drop path: %s", k)
	}
	// Different profiles isolate
	k2 := keyring.AccountKey(keyring.CredentialRef{
		ProfileID: "other",
		Origin:    "https://jenkins.example.com",
		Method:    "api_token",
		Account:   "alice",
	})
	if k == k2 {
		t.Fatal("profile must isolate keyring namespace")
	}
}

func TestCacheKeyRoundTripAndIsolation(t *testing.T) {
	t.Parallel()
	mem := keyring.NewMemory()
	st := keyring.NewStore(mem)
	// Test vector — not a production secret.
	mat := make([]byte, 32)
	for i := range mat {
		mat[i] = byte(i ^ 0x5a)
	}
	if err := st.SetCacheKey("corp", 1, mat); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetCacheKey("corp", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 32 {
		t.Fatalf("len %d", len(got))
	}
	for i := range mat {
		if got[i] != mat[i] {
			t.Fatal("material mismatch")
		}
	}
	// Different profile isolated.
	_, err = st.GetCacheKey("other", 1)
	if err == nil {
		t.Fatal("expected missing for other profile")
	}
	ok, err := st.HasCacheKey("corp", 1)
	if err != nil || !ok {
		t.Fatalf("HasCacheKey: %v %v", ok, err)
	}
	ok, err = st.HasCacheKey("corp", 2)
	if err != nil || ok {
		t.Fatalf("HasCacheKey v2: %v %v", ok, err)
	}
	// Account key never embeds material.
	ak := keyring.CacheKeyAccountKey("corp", 1)
	if strings.Contains(ak, string(mat)) || strings.Contains(ak, "5a") {
		t.Fatalf("account key leaked material: %s", ak)
	}
	if err := st.DeleteCacheKey("corp", 1); err != nil {
		t.Fatal(err)
	}
	_, err = st.GetCacheKey("corp", 1)
	if err == nil {
		t.Fatal("expected missing after delete")
	}
}

func TestCacheKeyErrorsNeverContainMaterial(t *testing.T) {
	t.Parallel()
	mem := keyring.NewMemory()
	st := keyring.NewStore(mem)
	mat := make([]byte, 32)
	for i := range mat {
		mat[i] = byte(0xab)
	}
	const canary = "CACHE_KEY_CANARY_must_never_appear"
	// Plant API token canary in same backend to ensure errors stay generic.
	_ = st.SetAPIToken(keyring.CredentialRef{
		ProfileID: "corp",
		Origin:    "https://jenkins.example.com",
		Method:    "api_token",
		Account:   "alice",
	}, canary)
	_ = st.SetCacheKey("corp", 1, mat)
	_, err := st.GetCacheKey("corp", 99)
	if err == nil {
		t.Fatal("expected missing")
	}
	if strings.Contains(err.Error(), canary) || strings.Contains(err.Error(), "«") {
		t.Fatalf("secret leaked: %v", err)
	}
	// Encode form of material must not appear.
	encHint := "q6urq6ur" // prefix of base64(0xab…)
	if strings.Contains(err.Error(), encHint) {
		t.Fatalf("key material encoding leaked: %v", err)
	}
}

func TestErrorsNeverContainSecret(t *testing.T) {
	t.Parallel()
	mem := keyring.NewMemory()
	st := keyring.NewStore(mem)
	const token = "CANARY_SECRET_TOKEN_xyz_12345"
	ref := keyring.CredentialRef{
		ProfileID: "corp",
		Origin:    "https://jenkins.example.com",
		Method:    "api_token",
		Account:   "alice",
	}
	_ = st.SetAPIToken(ref, token)
	// Force not-found error path
	_, err := st.GetAPIToken(keyring.CredentialRef{
		ProfileID: "corp",
		Origin:    "https://jenkins.example.com",
		Method:    "api_token",
		Account:   "bob",
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), token) {
		t.Fatalf("secret leaked in error: %v", err)
	}
	// Invalid ref
	err = st.SetAPIToken(keyring.CredentialRef{}, token)
	if err == nil || strings.Contains(err.Error(), token) {
		t.Fatalf("invalid ref err: %v", err)
	}
}

func TestValidateRef(t *testing.T) {
	t.Parallel()
	st := keyring.NewStore(keyring.NewMemory())
	err := st.SetAPIToken(keyring.CredentialRef{
		ProfileID: "corp",
		Origin:    "https://j.example",
		Method:    "api_token",
		// Account missing
	}, "tok")
	if err == nil {
		t.Fatal("expected validation error")
	}
	if apperr.CodeOf(err) != apperr.CodeInvalidArgument {
		t.Fatalf("code %v", apperr.CodeOf(err))
	}
}

func TestOIDCTokensRoundTripAndIsolation(t *testing.T) {
	t.Parallel()
	mem := keyring.NewMemory()
	st := keyring.NewStore(mem)
	const blob = `{"v":1,"access_token":"OIDC_BLOB_CANARY_xyz","refresh_token":"r"}`
	if err := st.SetOIDCTokens("corp", blob); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetOIDCTokens("corp")
	if err != nil {
		t.Fatal(err)
	}
	if got != blob {
		t.Fatalf("mismatch")
	}
	// Distinct from api_token namespace.
	ref := keyring.CredentialRef{
		ProfileID: "corp",
		Origin:    "https://jenkins.example.com",
		Method:    "api_token",
		Account:   "alice",
	}
	if err := st.SetAPIToken(ref, "api-token-value"); err != nil {
		t.Fatal(err)
	}
	// Different profile isolated.
	_, err = st.GetOIDCTokens("other")
	if err == nil {
		t.Fatal("expected missing for other profile")
	}
	ok, err := st.HasOIDCTokens("corp")
	if err != nil || !ok {
		t.Fatalf("HasOIDCTokens: %v %v", ok, err)
	}
	ak := keyring.OIDCTokensAccountKey("corp")
	if !strings.Contains(ak, keyring.MethodOIDCTokens) || strings.Contains(ak, "OIDC_BLOB_CANARY") {
		t.Fatalf("account key: %s", ak)
	}
	if err := st.DeleteOIDCTokens("corp"); err != nil {
		t.Fatal(err)
	}
	_, err = st.GetOIDCTokens("corp")
	if err == nil {
		t.Fatal("expected missing after delete")
	}
	// api_token still present after oidc delete.
	tok, err := st.GetAPIToken(ref)
	if err != nil || tok != "api-token-value" {
		t.Fatalf("api token disturbed: %q %v", tok, err)
	}
}

func TestOIDCTokensErrorsNeverContainSecret(t *testing.T) {
	t.Parallel()
	st := keyring.NewStore(keyring.NewMemory())
	const canary = "OIDC_CANARY_SECRET_must_not_leak"
	_ = st.SetOIDCTokens("corp", canary)
	_, err := st.GetOIDCTokens("other")
	if err == nil {
		t.Fatal("expected missing")
	}
	if strings.Contains(err.Error(), canary) {
		t.Fatalf("secret leaked: %v", err)
	}
}

// unavailableBackend always returns ErrUnavailable (headless fail-closed).
type unavailableBackend struct{}

func (unavailableBackend) Set(_, _, _ string) error { return keyring.ErrUnavailable }
func (unavailableBackend) Get(_, _ string) (string, error) {
	return "", keyring.ErrUnavailable
}
func (unavailableBackend) Delete(_, _ string) error { return keyring.ErrUnavailable }

func TestUnavailableFailClosed(t *testing.T) {
	t.Parallel()
	st := keyring.NewStore(unavailableBackend{})
	err := st.SetAPIToken(keyring.CredentialRef{
		ProfileID: "corp",
		Origin:    "https://jenkins.example.com",
		Method:    "api_token",
		Account:   "alice",
	}, "tok")
	if err == nil {
		t.Fatal("expected unavailable error")
	}
	msg := err.Error()
	if strings.Contains(msg, "tok") {
		t.Fatalf("secret in error: %s", msg)
	}
	if !strings.Contains(strings.ToLower(msg), "secret service") {
		t.Fatalf("should diagnose secret service: %s", msg)
	}
	if apperr.CodeOf(err) != apperr.CodeAuthentication {
		t.Fatalf("code %v", apperr.CodeOf(err))
	}
}
