package gateway_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/contracts"
	"github.com/simonfxr/go-jenkins-mcp/internal/gateway"
)

const consentStoreCanary = "access_token_must_never_appear_consent_store_xyz"

func consentInfo(sess string) gateway.ConsentInfo {
	return gateway.ConsentInfo{
		AuthorizationURL: "https://login.microsoftonline.com/t/oauth2/v2.0/authorize?state=" + sess,
		SessionID:        sess,
		Provider:         "agentcore",
	}
}

func TestMemoryConsentSessionStore_PutGetListDelete(t *testing.T) {
	t.Parallel()
	s := gateway.NewMemoryConsentSessionStore(time.Hour, "")
	info := consentInfo("sess-mem-1")
	if err := s.Put(gateway.ConsentSessionRecord{
		Info:       info,
		SubjectKey: "tenant|alice|corp",
	}); err != nil {
		t.Fatal(err)
	}
	got, ok := s.Get("sess-mem-1")
	if !ok || got.Info.SessionID != "sess-mem-1" {
		t.Fatalf("Get: ok=%v got=%+v", ok, got)
	}
	if got.Info.AuthorizationURL != info.AuthorizationURL {
		t.Fatalf("url: %q", got.Info.AuthorizationURL)
	}
	bySub, ok := s.GetBySubjectKey("tenant|alice|corp")
	if !ok || bySub.SessionID() != "sess-mem-1" {
		t.Fatalf("GetBySubjectKey: %+v", bySub)
	}
	list := s.List()
	if len(list) != 1 {
		t.Fatalf("List: %d", len(list))
	}
	s.Delete("sess-mem-1")
	if _, ok := s.Get("sess-mem-1"); ok {
		t.Fatal("expected delete")
	}
	if len(s.List()) != 0 {
		t.Fatal("list not empty after delete")
	}
}

func TestMemoryConsentSessionStore_TTLExpiry(t *testing.T) {
	t.Parallel()
	s := gateway.NewMemoryConsentSessionStore(time.Hour, "")
	// Inject short-lived record via ExpiresAt.
	now := time.Now()
	if err := s.Put(gateway.ConsentSessionRecord{
		Info:      consentInfo("sess-ttl-1"),
		StoredAt:  now.Add(-2 * time.Hour),
		ExpiresAt: now.Add(-time.Minute), // already expired
	}); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Get("sess-ttl-1"); ok {
		t.Fatal("expired Get must miss")
	}
	if len(s.List()) != 0 {
		t.Fatal("expired List must be empty")
	}

	// Fresh entry with TTL from store.
	s2 := gateway.NewMemoryConsentSessionStore(50*time.Millisecond, "")
	if err := s2.Put(gateway.ConsentSessionRecord{Info: consentInfo("sess-ttl-2")}); err != nil {
		t.Fatal(err)
	}
	if _, ok := s2.Get("sess-ttl-2"); !ok {
		t.Fatal("want hit before TTL")
	}
	time.Sleep(80 * time.Millisecond)
	if _, ok := s2.Get("sess-ttl-2"); ok {
		t.Fatal("want miss after TTL")
	}
}

// OAUTH-010: PurgeExpired returns deleted count; keeps live metadata; secret-free.
func TestMemoryConsentSessionStore_PurgeExpired(t *testing.T) {
	t.Parallel()
	s := gateway.NewMemoryConsentSessionStore(time.Hour, "")
	now := time.Now()
	if err := s.Put(gateway.ConsentSessionRecord{
		Info:      consentInfo("sess-live-1"),
		StoredAt:  now,
		ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	// Put of an already-expired record: subsequent Put would purge it, so seed
	// via Put then inject a second expired without an intervening purge by
	// using Put only once for expired and calling PurgeExpired explicitly.
	if err := s.Put(gateway.ConsentSessionRecord{
		Info:      consentInfo("sess-exp-1"),
		StoredAt:  now.Add(-2 * time.Hour),
		ExpiresAt: now.Add(-time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	// EntryCount includes expired until purge (Put does not purge the record
	// it just inserted).
	if n := s.EntryCount(); n != 2 {
		t.Fatalf("EntryCount before purge: %d want 2 (live+expired)", n)
	}
	deleted := s.PurgeExpired()
	if deleted != 1 {
		t.Fatalf("PurgeExpired deleted=%d want 1", deleted)
	}
	if deleted2 := s.PurgeExpired(); deleted2 != 0 {
		t.Fatalf("second PurgeExpired: %d", deleted2)
	}
	if s.EntryCount() != 1 {
		t.Fatalf("remaining EntryCount: %d", s.EntryCount())
	}
	if _, ok := s.Get("sess-live-1"); !ok {
		t.Fatal("live session must remain")
	}
	if _, ok := s.Get("sess-exp-1"); ok {
		t.Fatal("expired must be gone")
	}
	// Surfaces secret-free after purge.
	blob := s.String() + " " + fmt.Sprint(s.StatusMap())
	for _, bad := range []string{consentStoreCanary, "access_token=", "refresh_token=", "client_secret="} {
		if strings.Contains(blob, bad) {
			t.Fatalf("surface contained %q", bad)
		}
	}
}

func TestMemoryConsentSessionStore_DeleteSessionAndClear(t *testing.T) {
	t.Parallel()
	s := gateway.NewMemoryConsentSessionStore(time.Hour, "")
	if err := s.Put(gateway.ConsentSessionRecord{Info: consentInfo("sess-del-1")}); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(gateway.ConsentSessionRecord{Info: consentInfo("sess-del-2")}); err != nil {
		t.Fatal(err)
	}
	if !s.DeleteSession("sess-del-1") {
		t.Fatal("want DeleteSession true")
	}
	if s.DeleteSession("sess-del-1") {
		t.Fatal("second DeleteSession must be false")
	}
	if s.DeleteSession("") {
		t.Fatal("empty id must be false")
	}
	if s.EntryCount() != 1 {
		t.Fatalf("count: %d", s.EntryCount())
	}
	s.Clear()
	if s.EntryCount() != 0 || len(s.List()) != 0 {
		t.Fatal("Clear must empty store")
	}
}

func TestMemoryConsentSessionStore_PurgeExpired_FileBacked(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "consent_sessions.json")
	s, err := gateway.NewFileBackedConsentSessionStore(time.Hour, path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := s.Put(gateway.ConsentSessionRecord{
		Info:      consentInfo("sess-file-live"),
		ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(gateway.ConsentSessionRecord{
		Info:      consentInfo("sess-file-exp"),
		StoredAt:  now.Add(-time.Hour),
		ExpiresAt: now.Add(-time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	if n := s.PurgeExpired(); n != 1 {
		t.Fatalf("purge: %d", n)
	}
	// Reload: only live remains.
	s2, err := gateway.NewFileBackedConsentSessionStore(time.Hour, path)
	if err != nil {
		t.Fatal(err)
	}
	if len(s2.List()) != 1 || s2.List()[0].SessionID() != "sess-file-live" {
		t.Fatalf("reload list: %+v", s2.List())
	}
}

func TestMemoryConsentSessionStore_NoTokenCanaries(t *testing.T) {
	t.Parallel()
	s := gateway.NewMemoryConsentSessionStore(time.Hour, "")
	info := consentInfo("sess-canary-1")
	if err := s.Put(gateway.ConsentSessionRecord{
		Info:       info,
		SubjectKey: "tenant|bob|corp",
	}); err != nil {
		t.Fatal(err)
	}
	// Surfaces must never include canary token material.
	blob := s.String() + " " + fmt.Sprint(s.StatusMap())
	rec, _ := s.Get("sess-canary-1")
	blob += " " + rec.String() + " " + fmt.Sprint(rec.StatusMap())
	raw, err := json.Marshal(s.StatusMap())
	if err != nil {
		t.Fatal(err)
	}
	blob += " " + string(raw)
	for _, bad := range []string{
		consentStoreCanary,
		"access_token=",
		"refresh_token=",
		"client_secret=",
		"Authorization: Bearer",
	} {
		if strings.Contains(blob, bad) {
			t.Fatalf("surface contained %q: %s", bad, blob)
		}
	}
	// StatusMap must not embed full authorization_url (query/state).
	sm := rec.StatusMap()
	if _, ok := sm["authorization_url"]; ok {
		t.Fatal("StatusMap must not embed full authorization_url")
	}
	if sm["has_authorization_url"] != true {
		t.Fatalf("StatusMap: %+v", sm)
	}
	// Reject Put of token-shaped session id.
	err = s.Put(gateway.ConsentSessionRecord{
		Info: gateway.ConsentInfo{
			AuthorizationURL: "https://login.example/authorize",
			SessionID:        "access_token=" + consentStoreCanary,
		},
	})
	if err == nil {
		t.Fatal("want reject token-shaped session id")
	}
}

func TestMemoryConsentSessionStore_FileRoundTripMetadataOnly(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "consent_sessions.json")
	s1, err := gateway.NewFileBackedConsentSessionStore(time.Hour, path)
	if err != nil {
		t.Fatal(err)
	}
	info := consentInfo("sess-file-1")
	if err := s1.Put(gateway.ConsentSessionRecord{
		Info:       info,
		SubjectKey: "tenant|carol|corp",
	}); err != nil {
		t.Fatal(err)
	}
	// File must exist with 0600-ish perms and metadata-only keys.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	low := strings.ToLower(body)
	for _, bad := range []string{
		`"access_token"`,
		`"refresh_token"`,
		`"client_secret"`,
		consentStoreCanary,
	} {
		if strings.Contains(low, strings.ToLower(bad)) || strings.Contains(body, bad) {
			t.Fatalf("file contained forbidden %q:\n%s", bad, body)
		}
	}
	if !strings.Contains(body, "sess-file-1") || !strings.Contains(body, "authorization_url") {
		t.Fatalf("file missing metadata: %s", body)
	}
	// Reload into a fresh store (crash recovery of metadata only).
	s2, err := gateway.NewFileBackedConsentSessionStore(time.Hour, path)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := s2.Get("sess-file-1")
	if !ok {
		t.Fatal("reload Get miss")
	}
	if got.Info.AuthorizationURL != info.AuthorizationURL || got.Info.SessionID != info.SessionID {
		t.Fatalf("reload mismatch: %+v", got)
	}
	if got.SubjectKey != "tenant|carol|corp" {
		t.Fatalf("subject: %q", got.SubjectKey)
	}
	// Surfaces after reload still secret-free.
	blob := s2.String() + " " + fmt.Sprint(s2.StatusMap()) + " " + got.String()
	for _, bad := range []string{consentStoreCanary, "access_token=", "refresh_token="} {
		if strings.Contains(blob, bad) {
			t.Fatalf("reload surface %q", bad)
		}
	}
}

func TestMemoryConsentSessionStore_FileRejectsTokenFields(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "poison.json")
	// Plant a file that pretends to store tokens (must fail closed).
	poison := `{"version":1,"entries":{"x":{"authorization_url":"https://a/","session_id":"s1","access_token":"sekrit"}}}`
	if err := os.WriteFile(path, []byte(poison), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := gateway.NewFileBackedConsentSessionStore(time.Hour, path)
	if err == nil {
		t.Fatal("want fail closed on token fields in file")
	}
}

func TestRememberConsentRequired_AndObtainWire(t *testing.T) {
	t.Parallel()
	store := gateway.NewMemoryConsentSessionStore(time.Hour, "")
	// Direct helper.
	gateway.RememberConsentRequired(store, "tenant|dave|corp", consentInfo("sess-remember-1"))
	if _, ok := store.Get("sess-remember-1"); !ok {
		t.Fatal("Remember miss")
	}

	// Obtain wire: ConsentRequired → store.
	p, err := gateway.NewAgentCoreProvider(gateway.AgentCoreConfig{
		AuthorizationServerBaseURL: "https://login.microsoftonline.com/t",
		Audience:                   "api://jenkins-api",
		ClientID:                   "public-client",
		Mode:                       gateway.ModeAuthorizationCode,
		JenkinsBaseURL:             "https://jenkins.example.invalid",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	p.Live = true
	p.ConsentStore = store
	p.Fetcher = gateway.FuncTokenFetcher(func(ctx context.Context, caller gateway.Caller, cfg gateway.AgentCoreConfig) (gateway.Credential, error) {
		return gateway.Credential{}, gateway.NewConsentRequired(consentInfo("sess-obtain-wire-1"))
	})
	caller := gateway.Caller{
		Subject:   "dave",
		Tenant:    "tenant",
		ProfileID: contracts.ProfileID("corp"),
	}
	_, err = p.Obtain(context.Background(), caller)
	if err == nil {
		t.Fatal("expected ConsentRequired")
	}
	cr, ok := gateway.AsConsentRequired(err)
	if !ok || cr == nil {
		t.Fatalf("want ConsentRequired: %v", err)
	}
	got, ok := store.Get("sess-obtain-wire-1")
	if !ok {
		t.Fatal("Obtain did not remember consent metadata")
	}
	if got.SubjectKey != gateway.SubjectKey(caller) {
		t.Fatalf("subject key: got %q want %q", got.SubjectKey, gateway.SubjectKey(caller))
	}
	// No token canaries on error or store surfaces.
	blob := err.Error() + " " + store.String() + " " + fmt.Sprint(got.StatusMap())
	for _, bad := range []string{consentStoreCanary, "access_token=", "refresh_token="} {
		if strings.Contains(blob, bad) {
			t.Fatalf("canary %q", bad)
		}
	}
}

func TestConsentSessionPathFromEnviron(t *testing.T) {
	t.Parallel()
	env := map[string]string{
		"XDG_DATA_HOME": "/tmp/xdg-data-consent-test",
	}
	getenv := func(k string) string { return env[k] }
	p := gateway.ConsentSessionPathFromEnviron(getenv)
	if !strings.HasSuffix(p, filepath.FromSlash(gateway.DefaultConsentSessionRelPath)) {
		t.Fatalf("path: %q", p)
	}
	env[gateway.EnvConsentSessionStorePath] = "/custom/consent.json"
	if gateway.ConsentSessionPathFromEnviron(getenv) != "/custom/consent.json" {
		t.Fatal("env override")
	}
}

func TestOpenConsentSessionStoreForCLI_MissingFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "missing.json")
	getenv := func(k string) string {
		if k == gateway.EnvConsentSessionStorePath {
			return path
		}
		return ""
	}
	s, err := gateway.OpenConsentSessionStoreForCLI(getenv)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.List()) != 0 {
		t.Fatal("want empty list for missing file")
	}
}

func TestOpenConsentSessionStoreForCLI_ListsMetadata(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "consent_sessions.json")
	s, err := gateway.NewFileBackedConsentSessionStore(time.Hour, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(gateway.ConsentSessionRecord{
		Info:       consentInfo("sess-cli-1"),
		SubjectKey: "t|u|p",
	}); err != nil {
		t.Fatal(err)
	}
	getenv := func(k string) string {
		if k == gateway.EnvConsentSessionStorePath {
			return path
		}
		return ""
	}
	opened, err := gateway.OpenConsentSessionStoreForCLI(getenv)
	if err != nil {
		t.Fatal(err)
	}
	list := opened.List()
	if len(list) != 1 || list[0].SessionID() != "sess-cli-1" {
		t.Fatalf("list: %+v", list)
	}
	// CLI residual rows use StatusMap (no full token fields).
	row := list[0].StatusMap()
	raw, _ := json.Marshal(row)
	if strings.Contains(string(raw), consentStoreCanary) {
		t.Fatal("canary in CLI row")
	}
	if _, ok := row["authorization_url"]; ok {
		t.Fatal("CLI StatusMap must not dump full authorization_url")
	}
}

func TestOpenConsentSessionStoreForPurge_MissingAndPathOverride(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing-purge.json")
	s, err := gateway.OpenConsentSessionStoreForPurge(missing, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	if s.EntryCount() != 0 {
		t.Fatal("missing file → empty")
	}
	// Mutations bind path (file appears after Put).
	if err := s.Put(gateway.ConsentSessionRecord{Info: consentInfo("sess-purge-open-1")}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(missing); err != nil {
		t.Fatalf("expected file after put: %v", err)
	}
	// Env path used when override empty.
	envPath := filepath.Join(dir, "env-consent.json")
	s2, err := gateway.NewFileBackedConsentSessionStore(time.Hour, envPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := s2.Put(gateway.ConsentSessionRecord{Info: consentInfo("sess-env-1")}); err != nil {
		t.Fatal(err)
	}
	getenv := func(k string) string {
		if k == gateway.EnvConsentSessionStorePath {
			return envPath
		}
		return ""
	}
	opened, err := gateway.OpenConsentSessionStoreForPurge("", getenv)
	if err != nil {
		t.Fatal(err)
	}
	if len(opened.List()) != 1 || opened.List()[0].SessionID() != "sess-env-1" {
		t.Fatalf("env open: %+v", opened.List())
	}
}
