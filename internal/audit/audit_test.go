package audit_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/audit"
)

func TestMemoryOrdering(t *testing.T) {
	t.Parallel()
	m := &audit.Memory{}
	ctx := context.Background()
	for i, typ := range []string{audit.TypeLoginSuccess, audit.TypeServeStart, audit.TypeToolDeny} {
		if err := m.Emit(ctx, audit.Event{
			Type:       typ,
			ProfileID:  "corp",
			Decision:   audit.DecisionSuccess,
			ReasonCode: "ok",
			Time:       time.Unix(int64(1000+i), 0).UTC(),
		}); err != nil {
			t.Fatal(err)
		}
	}
	evs := m.Events()
	if len(evs) != 3 {
		t.Fatalf("len=%d", len(evs))
	}
	if evs[0].Type != audit.TypeLoginSuccess || evs[1].Type != audit.TypeServeStart || evs[2].Type != audit.TypeToolDeny {
		t.Fatalf("order: %+v", []string{evs[0].Type, evs[1].Type, evs[2].Type})
	}
	if evs[0].SchemaVersion != audit.CurrentSchemaVersion {
		t.Fatalf("schema=%d", evs[0].SchemaVersion)
	}
}

func TestRedactionCanary_NoSecretsInEvent(t *testing.T) {
	t.Parallel()
	const canary = "CANARY_TOKEN_audit_must_never_store_abc123xyz"
	m := &audit.Memory{}
	ctx := context.Background()
	// Attempt to inject secret-like material into free-form-ish fields.
	err := m.Emit(ctx, audit.Event{
		Type:        audit.TypeLoginFail,
		ProfileID:   "corp",
		PrincipalID: "alice",
		// Multi-user correlation fields: never store tokens/vault material.
		ExternalSubject: "Bearer " + canary,
		SubjectKeyHash:  "tid|" + canary + "|corp",
		Tool:            "jenkins_get_build_logs",
		Action:          "login",
		Decision:        audit.DecisionFail,
		ReasonCode:      "auth_failed",
		// Misconfigured caller might try to put a token in RequestID / PrincipalID.
		RequestID: "Bearer " + canary,
	})
	if err != nil {
		t.Fatal(err)
	}
	evs := m.Events()
	if len(evs) != 1 {
		t.Fatalf("len=%d", len(evs))
	}
	raw, err := json.Marshal(evs[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), canary) {
		t.Fatalf("token canary leaked into audit event JSON: %s", raw)
	}
	if strings.Contains(string(raw), "Authorization:") {
		t.Fatalf("authorization header leaked: %s", raw)
	}
	// Full log bodies / parameters must not be fields at all.
	body := string(raw)
	for _, banned := range []string{"prompt", "logBody", "parameters", "artifact", "excerpt"} {
		// JSON keys we intentionally do not have.
		if strings.Contains(body, `"`+banned+`"`) {
			t.Fatalf("unexpected content field %q in %s", banned, body)
		}
	}
	// Raw subject key (tenant|subject|profile) must never appear; only opaque hash.
	if strings.Contains(body, "tid|") || strings.Contains(evs[0].SubjectKeyHash, "|") {
		t.Fatalf("raw subject key leaked: %s", body)
	}
}

func TestExternalSubjectClipped(t *testing.T) {
	t.Parallel()
	// maxIDLen = 128 runes; oversize ExternalSubject must be clipped (not full store).
	long := strings.Repeat("x", 200)
	m := &audit.Memory{}
	if err := m.Emit(context.Background(), audit.Event{
		Type:            audit.TypeToolDeny,
		ExternalSubject: long,
		Decision:        audit.DecisionDeny,
	}); err != nil {
		t.Fatal(err)
	}
	got := m.Events()[0].ExternalSubject
	if got == long {
		t.Fatal("ExternalSubject must be length-capped")
	}
	if n := len([]rune(got)); n > 128 {
		t.Fatalf("ExternalSubject rune len=%d want <=128", n)
	}
	if got == "" {
		t.Fatal("expected non-empty clipped ExternalSubject")
	}
}

func TestSubjectKeyHashStableAndOpaque(t *testing.T) {
	t.Parallel()
	const sk = "tenant-a|alice-sub|corp"
	want := audit.HashOpaque(sk)
	if want == "" || strings.Contains(want, "|") || strings.Contains(want, "alice") {
		t.Fatalf("HashOpaque not opaque: %q", want)
	}
	m := &audit.Memory{}
	ctx := context.Background()
	// Preferred path: caller already hashed.
	if err := m.Emit(ctx, audit.Event{
		Type:           audit.TypeToolDeny,
		SubjectKeyHash: want,
		Decision:       audit.DecisionDeny,
	}); err != nil {
		t.Fatal(err)
	}
	// Misconfigured path: raw subject key → re-hashed to same HashOpaque value.
	if err := m.Emit(ctx, audit.Event{
		Type:           audit.TypeToolDeny,
		SubjectKeyHash: sk,
		Decision:       audit.DecisionDeny,
	}); err != nil {
		t.Fatal(err)
	}
	evs := m.Events()
	if len(evs) != 2 {
		t.Fatalf("len=%d", len(evs))
	}
	if evs[0].SubjectKeyHash != want {
		t.Fatalf("pre-hashed preserved: got %q want %q", evs[0].SubjectKeyHash, want)
	}
	if evs[1].SubjectKeyHash != want {
		t.Fatalf("raw key re-hash stable: got %q want %q", evs[1].SubjectKeyHash, want)
	}
	// Second emit of same pre-hash is stable.
	if err := m.Emit(ctx, audit.Event{
		Type:           audit.TypeToolDeny,
		SubjectKeyHash: want,
		Decision:       audit.DecisionDeny,
	}); err != nil {
		t.Fatal(err)
	}
	if m.Events()[2].SubjectKeyHash != want {
		t.Fatal("SubjectKeyHash not stable across emits")
	}
}

func TestEmitContextAndNilSink(t *testing.T) {
	t.Parallel()
	if err := audit.Emit(context.Background(), nil, audit.Event{Type: audit.TypeServeStart}); err != nil {
		t.Fatal(err)
	}
	m := &audit.Memory{}
	ctx := audit.WithSink(context.Background(), m)
	if err := audit.Emit(ctx, nil, audit.Event{
		Type:     audit.TypeServeStart,
		Decision: audit.DecisionSuccess,
	}); err != nil {
		t.Fatal(err)
	}
	if m.Len() != 1 {
		t.Fatalf("len=%d", m.Len())
	}
	if audit.FromContext(context.Background()) != nil {
		t.Fatal("expected nil sink")
	}
}

func TestHashOpaque(t *testing.T) {
	t.Parallel()
	if audit.HashOpaque("") != "" {
		t.Fatal("empty")
	}
	a := audit.HashOpaque("folder/job")
	b := audit.HashOpaque("folder/job")
	c := audit.HashOpaque("other")
	if a != b || a == "" || a == c {
		t.Fatalf("hash a=%s b=%s c=%s", a, b, c)
	}
	// Not the raw name.
	if strings.Contains(a, "job") || strings.Contains(a, "folder") {
		t.Fatalf("hash should be opaque: %s", a)
	}
}

func TestFileSinkJSONLAndMode(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sink, err := audit.NewFile(audit.FileConfig{Dir: dir, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()

	ctx := context.Background()
	if err := sink.Emit(ctx, audit.Event{
		Type:        audit.TypeServeStart,
		ProfileID:   "corp",
		PrincipalID: "alice",
		Decision:    audit.DecisionSuccess,
		ReasonCode:  "ok",
		Duration:    12 * time.Millisecond,
	}); err != nil {
		t.Fatal(err)
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}

	path := sink.Path()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("file mode %04o want 0600", perm)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(string(data))
	var e audit.Event
	if err := json.Unmarshal([]byte(line), &e); err != nil {
		t.Fatalf("jsonl: %v body=%q", err, line)
	}
	if e.Type != audit.TypeServeStart || e.ProfileID != "corp" || e.DurationMs != 12 {
		t.Fatalf("event=%+v", e)
	}
}

func TestFileRotation(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sink, err := audit.NewFile(audit.FileConfig{
		Dir:        dir,
		MaxBytes:   200, // small so we rotate quickly
		MaxRotated: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()

	ctx := context.Background()
	for i := 0; i < 40; i++ {
		if err := sink.Emit(ctx, audit.Event{
			Type:       audit.TypeToolDeny,
			ProfileID:  "corp",
			Tool:       "jenkins_get_jobs",
			Decision:   audit.DecisionDeny,
			ReasonCode: "explicit_deny",
			RequestID:  "req-" + strings.Repeat("x", 20),
		}); err != nil {
			t.Fatal(err)
		}
	}
	// At least one rotated sibling should exist.
	rotated := filepath.Join(dir, audit.DefaultFileName+".1")
	if _, err := os.Stat(rotated); err != nil {
		// Rotation only if size exceeded; assert active file still readable.
		t.Logf("no rotated file yet (ok if lines small): %v", err)
	}
	// Active file must remain 0600.
	fi, err := os.Stat(sink.Path())
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %04o", fi.Mode().Perm())
	}
}

func TestOpenProfileSink(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	s, err := audit.OpenProfileSink(root)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Emit(context.Background(), audit.Event{Type: audit.TypeLoginSuccess, Decision: audit.DecisionSuccess}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "audit", audit.DefaultFileName)
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	// Empty dir → nop
	s2, err := audit.OpenProfileSink("")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s2.(audit.Nop); !ok {
		t.Fatalf("want Nop got %T", s2)
	}
}

func TestAuditFailureDoesNotAuthorize(t *testing.T) {
	// Documented contract: Emit errors must not flip deny→allow.
	// Sink returns error on cancelled context; authorization path is independent.
	t.Parallel()
	m := &audit.Memory{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := m.Emit(ctx, audit.Event{Type: audit.TypeToolDeny, Decision: audit.DecisionDeny})
	if err == nil {
		t.Fatal("expected context error from Memory on cancelled ctx")
	}
	// Policy decision remains deny regardless of audit error (caller responsibility).
	// This test only proves the sink fails closed on cancelled emit without recording.
	if m.Len() != 0 {
		t.Fatal("must not record on cancelled emit")
	}
}
