package fleet_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/config"
	"github.com/hilather/go-jenkins-mcp/internal/telemetry"
	"github.com/hilather/go-jenkins-mcp/internal/telemetry/fleet"
)

func testPaths(t *testing.T) config.Paths {
	t.Helper()
	root := t.TempDir()
	return config.Paths{
		ConfigDir: filepath.Join(root, "config"),
		DataDir:   filepath.Join(root, "data"),
		CacheDir:  filepath.Join(root, "cache"),
	}
}

// tlsTestClient returns an HTTP client that trusts the httptest TLS server
// and still allows Exporter to inject CheckRedirect refuse.
func tlsTestClient(srv *httptest.Server) *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // test only
		},
	}
}

func TestDisabledByDefault(t *testing.T) {
	// Cannot combine t.Parallel with t.Setenv.
	t.Setenv(fleet.EnvTelemetry, "")
	t.Setenv(fleet.EnvTelemetryURL, "")
	if fleet.EnabledFromEnv() {
		t.Fatal("expected disabled when env unset")
	}
	// Explicit Enabled=false also yields nil collector.
	off := false
	c, err := fleet.NewCollector(fleet.CollectorConfig{
		Paths:   testPaths(t),
		Metrics: telemetry.NewMetrics(),
		Enabled: &off,
	})
	if err != nil {
		t.Fatal(err)
	}
	if c != nil {
		t.Fatal("collector must be nil when disabled")
	}
}

func TestEnabledViaEnv(t *testing.T) {
	t.Setenv(fleet.EnvTelemetry, "1")
	fleet.ResetInstallIDCache()
	paths := testPaths(t)
	on := true
	c, err := fleet.NewCollector(fleet.CollectorConfig{
		Paths:    paths,
		Metrics:  telemetry.NewMetrics(),
		Enabled:  &on,
		Version:  "test-1.0",
		ReadOnly: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if c == nil {
		t.Fatal("expected collector when enabled")
	}
	c.SnapshotOnce()
	if c.Queue() == nil || c.Queue().Depth() != 1 {
		t.Fatalf("queue depth=%d", c.Queue().Depth())
	}
	ev := c.LastEvent()
	if ev == nil || ev.SchemaVersion != fleet.SchemaVersion {
		t.Fatalf("last event: %+v", ev)
	}
	if ev.Version != "test-1.0" {
		t.Fatalf("version=%q", ev.Version)
	}
	if !ev.ReadOnly {
		t.Fatal("expected read_only=true on snapshot")
	}
}

func TestForceOffOverridesEnv(t *testing.T) {
	t.Parallel()
	if fleet.EffectiveEnabled(true) {
		t.Fatal("force-off must win")
	}
	on := true
	c, err := fleet.NewCollector(fleet.CollectorConfig{
		Paths:    testPaths(t),
		Enabled:  &on,
		ForceOff: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if c != nil {
		t.Fatal("force-off must yield nil collector")
	}
}

// Regression: overlay fleet_telemetry_force_off true disables even when env would enable.
func TestOverlayForceOffWinsOverEnvEnable(t *testing.T) {
	t.Setenv(fleet.EnvTelemetry, "1")
	if !fleet.EnabledFromEnv() {
		t.Fatal("env should enable")
	}
	// Overlay pin true → EffectiveEnabled false (env cannot re-enable).
	if fleet.EffectiveEnabled(true) {
		t.Fatal("force-off must win over JENKINS_MCP_TELEMETRY=1")
	}
	// Overlay pin false → env wins.
	if !fleet.EffectiveEnabled(false) {
		t.Fatal("force-off false must leave env enable intact")
	}
	on := true
	c, err := fleet.NewCollector(fleet.CollectorConfig{
		Paths:    testPaths(t),
		Enabled:  &on,
		ForceOff: true, // same as overlay.FleetTelemetryForceOff
	})
	if err != nil {
		t.Fatal(err)
	}
	if c != nil {
		t.Fatal("ForceOff true must yield nil even when Enabled=true")
	}
}

// Regression: SetForceOff mid-session suppresses snapshots; clear re-enables.
func TestSetForceOffHotApply(t *testing.T) {
	t.Parallel()
	on := true
	c, err := fleet.NewCollector(fleet.CollectorConfig{
		Paths:    testPaths(t),
		Enabled:  &on,
		ForceOff: false,
		Metrics:  telemetry.NewMetrics(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if c == nil {
		t.Fatal("expected collector")
	}
	if !c.Enabled() || c.ForceOff() {
		t.Fatal("initial state")
	}
	c.SnapshotOnce()
	if c.LastEvent() == nil {
		t.Fatal("expected snapshot before force-off")
	}
	c.SetForceOff(true)
	if c.Enabled() || !c.ForceOff() {
		t.Fatal("force-off should disable")
	}
	// Clear lastSnap observation: SnapshotOnce must no-op (no new event written).
	// We only assert no panic and Enabled false.
	c.SnapshotOnce()
	c.SetForceOff(false)
	if !c.Enabled() || c.ForceOff() {
		t.Fatal("clear force-off should re-enable live collector")
	}
	c.SnapshotOnce()
	if c.LastEvent() == nil {
		t.Fatal("expected snapshot after clear")
	}
}

func TestInstallationIDStableAndRandom(t *testing.T) {
	fleet.ResetInstallIDCache()
	paths := testPaths(t)
	id1, err := fleet.LoadOrCreateInstallationID(paths)
	if err != nil {
		t.Fatal(err)
	}
	id2, err := fleet.LoadOrCreateInstallationID(paths)
	if err != nil {
		t.Fatal(err)
	}
	if id1 != id2 {
		t.Fatalf("not stable: %s vs %s", id1, id2)
	}
	if len(id1) != 36 || strings.Count(id1, "-") != 4 {
		t.Fatalf("bad uuid form: %q", id1)
	}
	// Not hostname-derived: file exists and is random hex-ish.
	b, err := os.ReadFile(fleet.InstallIDPath(paths))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), id1) {
		t.Fatal("file missing id")
	}
}

func TestQueueBoundDropsOldest(t *testing.T) {
	t.Parallel()
	q, err := fleet.NewQueue(fleet.QueueConfig{MaxEvents: 3, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		ev := fleet.BuildEvent(fleet.BuildOptions{
			InstallationID: "00000000-0000-4000-8000-000000000001",
			Version:        "v",
			Counters:       map[string]int64{telemetry.MetricToolCalls: int64(i)},
			Now:            time.Unix(int64(1000+i), 0).UTC(),
		})
		if !q.Enqueue(ev) {
			t.Fatalf("enqueue %d failed", i)
		}
	}
	if q.Depth() != 3 {
		t.Fatalf("depth=%d want 3", q.Depth())
	}
	if q.Dropped() != 2 {
		t.Fatalf("dropped=%d want 2", q.Dropped())
	}
	all := q.PeekAll()
	if all[0].Counters[telemetry.MetricToolCalls] != 2 {
		t.Fatalf("oldest remaining should be counter 2, got %+v", all[0].Counters)
	}
}

func TestQueueByteBound(t *testing.T) {
	t.Parallel()
	// Tiny byte budget forces drops even with high MaxEvents.
	q, err := fleet.NewQueue(fleet.QueueConfig{MaxEvents: 100, MaxBytes: 200})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		ev := fleet.BuildEvent(fleet.BuildOptions{
			InstallationID: "00000000-0000-4000-8000-000000000002",
			Version:        "v",
			Counters: map[string]int64{
				telemetry.MetricToolCalls:     int64(i),
				telemetry.MetricPolicyDenials: int64(i),
				telemetry.MetricCacheHits:     int64(i),
			},
		})
		q.Enqueue(ev)
	}
	if q.Bytes() > 200 {
		t.Fatalf("bytes=%d exceed max", q.Bytes())
	}
	if q.Dropped() < 1 {
		t.Fatal("expected drops under byte bound")
	}
}

// TestCanaryNoSecretsInExportedJSON plants sample secrets in metrics labels and
// event fields and asserts queue/export JSON never contains them (MGR-002).
func TestCanaryNoSecretsInExportedJSON(t *testing.T) {
	t.Parallel()
	const (
		apiToken     = "super-secret-api-token-MGR002-canary"
		authHeader   = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.canary-jwt"
		jobLog       = "BUILD LOG: password=hunter2 stage=deploy"
		jobParams    = `{"PASSWORD":"p@ss","BRANCH":"main","TOKEN":"job-param-token"}`
		refreshToken = "oauth-refresh-token-MGR002-canary-xyz"
		jenkins      = "https://user:tokensecret@jenkins.example.corp/job/secret-job"
	)
	m := telemetry.NewMetrics()
	m.Inc(telemetry.MetricToolCalls, 3)
	m.Inc(telemetry.MetricPolicyDenials, 1)
	m.Inc(telemetry.MetricCacheHits, 2)
	// Plant canary secrets as high-cardinality counter labels — must be dropped.
	m.Inc("token:"+apiToken, 1)
	m.Inc("Authorization:"+authHeader, 1)
	m.Inc("log:"+jobLog, 1)
	m.Inc("params:"+jobParams, 1)
	m.Inc("refresh:"+refreshToken, 1)
	m.Inc("url:"+jenkins, 1)
	m.Inc(fleet.ErrorCodeMetricPrefix+string(apperr.CodeTimeout), 2)
	m.Inc(fleet.ErrorCodeMetricPrefix+"not_a_real_code", 9)
	m.Inc(fleet.ErrorCodeMetricPrefix+string(apperr.CodePolicyDenial), 1)

	ev := fleet.BuildEvent(fleet.BuildOptions{
		InstallationID: "00000000-0000-4000-8000-000000000003",
		ProfileID:      "corp-prod",
		Version:        "1.2.3",
		AuthMethod:     "api_token",
		ReadOnly:       true,
		Counters:       m.Snapshot().Counters,
		// Explicit free-text attempts must not appear:
		ErrorCodes: map[string]int64{
			string(apperr.CodeAuthentication): 1,
			"free text leak " + apiToken:      5,
			"Authorization: " + authHeader:    3,
			refreshToken:                      2,
		},
	})
	raw, err := fleet.MarshalEvent(ev)
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	canaries := []string{
		apiToken, authHeader, jobLog, jobParams, refreshToken,
		"tokensecret", "hunter2", "user:tokensecret", "secret-job",
		"p@ss", "job-param-token", "Bearer eyJ",
	}
	for _, canary := range canaries {
		if strings.Contains(s, canary) {
			t.Fatalf("canary %q leaked in export JSON: %s", canary, s)
		}
	}
	if err := fleet.ValidateExportJSON(raw); err != nil {
		t.Fatal(err)
	}
	// Only allowlisted counters.
	if _, ok := ev.Counters["token:"+apiToken]; ok {
		t.Fatal("secret-labeled counter exported")
	}
	if _, ok := ev.Counters["Authorization:"+authHeader]; ok {
		t.Fatal("Authorization counter exported")
	}
	if _, ok := ev.Counters["params:"+jobParams]; ok {
		t.Fatal("job params counter exported")
	}
	if _, ok := ev.Counters["refresh:"+refreshToken]; ok {
		t.Fatal("refresh token counter exported")
	}
	if ev.Counters[telemetry.MetricToolCalls] != 3 {
		t.Fatalf("tool_calls=%d", ev.Counters[telemetry.MetricToolCalls])
	}
	// Error codes: stable only.
	if ev.ErrorCodes[string(apperr.CodeTimeout)] != 2 {
		t.Fatalf("timeout code: %+v", ev.ErrorCodes)
	}
	if ev.ErrorCodes[string(apperr.CodePolicyDenial)] != 1 {
		t.Fatalf("policy_denial code: %+v", ev.ErrorCodes)
	}
	if _, ok := ev.ErrorCodes["not_a_real_code"]; ok {
		t.Fatal("invalid error code exported")
	}
	if _, ok := ev.ErrorCodes["free text leak "+apiToken]; ok {
		t.Fatal("free-text error code key exported")
	}
	// Profile id is hashed, not raw.
	if strings.Contains(s, "corp-prod") {
		t.Fatal("raw profile id must not appear")
	}
	if ev.ProfileIDHash == "" || len(ev.ProfileIDHash) != 64 {
		t.Fatalf("profile hash: %q", ev.ProfileIDHash)
	}
	if ev.AuthMethod != fleet.AuthMethodAPIToken {
		t.Fatalf("auth_method=%q", ev.AuthMethod)
	}
	if !ev.ReadOnly {
		t.Fatal("read_only expected true")
	}

	// Queue path: planted secrets in raw Event fields must be stripped on enqueue.
	q, err := fleet.NewQueue(fleet.QueueConfig{MaxEvents: 4, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	smuggled := fleet.Event{
		SchemaVersion:  fleet.SchemaVersion,
		EventType:      fleet.EventTypeHealthSnapshot,
		InstallationID: "00000000-0000-4000-8000-000000000099",
		Version:        "smuggle-test",
		OS:             "linux",
		Arch:           "amd64",
		AuthMethod:     "custom-auth-with-" + apiToken, // free-form collapses to unknown
		ReadOnly:       true,
		Counters: map[string]int64{
			telemetry.MetricToolCalls:     1,
			"Authorization:" + authHeader: 9,
			"log:" + jobLog:               1,
			"params:" + jobParams:         1,
			"refresh:" + refreshToken:     1,
		},
		ErrorCodes: map[string]int64{
			string(apperr.CodeTimeout): 1,
			"Bearer " + apiToken:       4,
		},
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		// ProfileIDHash smuggle free text must be dropped (not hex).
		ProfileIDHash: "not-a-hash-" + refreshToken,
	}
	if !q.Enqueue(smuggled) {
		t.Fatal("enqueue sanitized event should succeed")
	}
	queued := q.PeekAll()
	if len(queued) != 1 {
		t.Fatalf("depth=%d", len(queued))
	}
	qraw, err := fleet.MarshalEvent(queued[0])
	if err != nil {
		t.Fatal(err)
	}
	qs := string(qraw)
	for _, canary := range []string{apiToken, authHeader, jobLog, jobParams, refreshToken, "Bearer "} {
		if strings.Contains(qs, canary) {
			t.Fatalf("canary %q leaked in queue JSON: %s", canary, qs)
		}
	}
	if _, ok := queued[0].Counters["Authorization:"+authHeader]; ok {
		t.Fatal("authorization counter survived enqueue sanitize")
	}
	if queued[0].ProfileIDHash != "" {
		t.Fatalf("smuggled profile hash retained: %q", queued[0].ProfileIDHash)
	}
	if queued[0].AuthMethod != fleet.AuthMethodUnknown {
		t.Fatalf("auth method with embedded secret must collapse to unknown, got %q", queued[0].AuthMethod)
	}
}

func TestRejectOversizeStringFields(t *testing.T) {
	t.Parallel()
	huge := strings.Repeat("A", fleet.MaxVersionLen+50)
	ev := fleet.BuildEvent(fleet.BuildOptions{
		InstallationID: "00000000-0000-4000-8000-0000000000bb",
		Version:        huge,
		AuthMethod:     "api_token",
	})
	if utf8.RuneCountInString(ev.Version) > fleet.MaxVersionLen {
		t.Fatalf("version not clamped: len=%d", utf8.RuneCountInString(ev.Version))
	}
	raw, err := fleet.MarshalEvent(ev)
	if err != nil {
		t.Fatal(err)
	}
	if err := fleet.ValidateExportJSON(raw); err != nil {
		t.Fatal(err)
	}
	// ValidateExportJSON must reject already-marshaled oversize if someone bypasses sanitize.
	bad := []byte(`{"schema_version":1,"event_type":"health_snapshot","installation_id":"00000000-0000-4000-8000-0000000000cc","version":"` + huge + `","os":"linux","arch":"amd64","auth_method":"api_token","read_only":false,"counters":{},"ts":"2026-01-01T00:00:00Z"}`)
	if err := fleet.ValidateExportJSON(bad); err == nil {
		t.Fatal("expected oversize rejection")
	}
	// Unknown top-level field rejected.
	unknown := []byte(`{"schema_version":1,"event_type":"health_snapshot","installation_id":"00000000-0000-4000-8000-0000000000cd","version":"v","os":"linux","arch":"amd64","auth_method":"api_token","read_only":false,"counters":{},"ts":"2026-01-01T00:00:00Z","job_parameters":{"PASSWORD":"x"}}`)
	if err := fleet.ValidateExportJSON(unknown); err == nil {
		t.Fatal("expected unknown field rejection")
	}
}

func TestExporterHTTPSOnlyRejectsHTTP(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("http server must not be reached")
		w.WriteHeader(200)
	}))
	t.Cleanup(srv.Close)

	exp := fleet.NewExporter(fleet.ExporterConfig{URL: srv.URL, Client: srv.Client()})
	ev := fleet.BuildEvent(fleet.BuildOptions{
		InstallationID: "00000000-0000-4000-8000-0000000000dd",
		Version:        "v",
		Counters:       map[string]int64{telemetry.MetricToolCalls: 1},
	})
	err := exp.Post(context.Background(), []fleet.Event{ev})
	if err == nil {
		t.Fatal("expected https-only rejection for http URL")
	}
	if !strings.Contains(err.Error(), "https") {
		t.Fatalf("err=%v", err)
	}
	if exp.LastError() != "invalid_url" {
		t.Fatalf("lastErr=%q", exp.LastError())
	}
}

func TestExporterRejectsUserinfoURL(t *testing.T) {
	t.Parallel()
	err := fleet.ValidateExportURL("https://user:secret@telemetry.example/v1")
	if err == nil {
		t.Fatal("expected userinfo rejection")
	}
	exp := fleet.NewExporter(fleet.ExporterConfig{URL: "https://user:secret@telemetry.example/v1"})
	err = exp.Post(context.Background(), []fleet.Event{fleet.BuildEvent(fleet.BuildOptions{
		InstallationID: "00000000-0000-4000-8000-0000000000de",
		Version:        "v",
	})})
	if err == nil {
		t.Fatal("expected post rejection")
	}
}

func TestExporterNetworkFailDoesNotPanicAndBacksOff(t *testing.T) {
	t.Parallel()
	// TLS server that always fails.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)

	exp := fleet.NewExporter(fleet.ExporterConfig{
		URL:        srv.URL,
		Client:     tlsTestClient(srv),
		MinBackoff: 10 * time.Millisecond,
		MaxBackoff: 50 * time.Millisecond,
	})
	q, err := fleet.NewQueue(fleet.QueueConfig{MaxEvents: 10, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	ev := fleet.BuildEvent(fleet.BuildOptions{
		InstallationID: "00000000-0000-4000-8000-000000000004",
		Version:        "v",
		Counters:       map[string]int64{telemetry.MetricToolCalls: 1},
	})
	q.Enqueue(ev)
	ctx := context.Background()
	n, err := exp.DrainAndExport(ctx, q, 8)
	if err == nil {
		t.Fatal("expected export error")
	}
	if n != 0 {
		t.Fatalf("exported=%d", n)
	}
	// Failed batch re-queued.
	if q.Depth() != 1 {
		t.Fatalf("depth after fail=%d", q.Depth())
	}
	if exp.CurrentBackoff() < 10*time.Millisecond {
		t.Fatalf("backoff too small: %v", exp.CurrentBackoff())
	}
	_, _, failures := exp.Stats()
	if failures < 1 {
		t.Fatal("expected failure stat")
	}
}

func TestExporterSuccessDrainsQueueTLS(t *testing.T) {
	t.Parallel()
	const canaryRefresh = "oauth-refresh-must-not-appear-in-body"
	var got atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// No Authorization header on export requests.
		if r.Header.Get("Authorization") != "" {
			t.Error("Authorization must not be set on fleet export")
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if strings.Contains(string(body), "Authorization") {
			t.Error("Authorization must not appear in body")
		}
		if strings.Contains(string(body), canaryRefresh) {
			t.Error("refresh token canary in body")
		}
		var env fleet.ExportEnvelope
		if err := json.Unmarshal(body, &env); err != nil {
			t.Errorf("body: %v", err)
			http.Error(w, "bad", 400)
			return
		}
		got.Add(int64(len(env.Events)))
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	exp := fleet.NewExporter(fleet.ExporterConfig{URL: srv.URL, Client: tlsTestClient(srv)})
	q, _ := fleet.NewQueue(fleet.QueueConfig{MaxEvents: 10})
	for i := 0; i < 3; i++ {
		q.Enqueue(fleet.BuildEvent(fleet.BuildOptions{
			InstallationID: "00000000-0000-4000-8000-000000000005",
			Version:        "v",
			Counters: map[string]int64{
				telemetry.MetricToolCalls:  int64(i + 1),
				"refresh:" + canaryRefresh: 1,
			},
		}))
	}
	n, err := exp.DrainAndExport(context.Background(), q, 16)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 || q.Depth() != 0 || got.Load() != 3 {
		t.Fatalf("n=%d depth=%d got=%d", n, q.Depth(), got.Load())
	}
}

func TestExporterNoRedirects(t *testing.T) {
	t.Parallel()
	var hops atomic.Int32
	final := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hops.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(final.Close)

	redir := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hops.Add(1)
		http.Redirect(w, r, final.URL+"/v1/events", http.StatusFound)
	}))
	t.Cleanup(redir.Close)

	exp := fleet.NewExporter(fleet.ExporterConfig{
		URL:    redir.URL + "/v1/events",
		Client: tlsTestClient(redir),
	})
	ev := fleet.BuildEvent(fleet.BuildOptions{
		InstallationID: "00000000-0000-4000-8000-0000000000ee",
		Version:        "v",
		Counters:       map[string]int64{telemetry.MetricToolCalls: 1},
	})
	err := exp.Post(context.Background(), []fleet.Event{ev})
	// 302 is non-2xx → fail closed; must not follow to final.
	if err == nil {
		t.Fatal("expected fail on redirect status")
	}
	if hops.Load() != 1 {
		t.Fatalf("followed redirect: hops=%d", hops.Load())
	}
}

func TestCollectorNetworkFailDoesNotErrorServePath(t *testing.T) {
	// Bad TLS URL — collector Start must not panic or block.
	var hits atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Error(w, "down", 500)
	}))
	t.Cleanup(srv.Close)

	paths := testPaths(t)
	fleet.ResetInstallIDCache()
	m := telemetry.NewMetrics()
	m.Inc(telemetry.MetricToolCalls, 1)
	on := true
	q, err := fleet.NewQueue(fleet.QueueConfig{Dir: fleet.TelemetryDir(paths), MaxEvents: 8})
	if err != nil {
		t.Fatal(err)
	}
	c, err := fleet.NewCollector(fleet.CollectorConfig{
		Paths:    paths,
		Metrics:  m,
		Enabled:  &on,
		Queue:    q,
		Exporter: fleet.NewExporter(fleet.ExporterConfig{URL: srv.URL, Client: tlsTestClient(srv), MinBackoff: time.Millisecond, MaxBackoff: 5 * time.Millisecond}),
		Interval: 50 * time.Millisecond,
		Version:  "serve-test",
		ReadOnly: true,
	})
	if err != nil || c == nil {
		t.Fatalf("collector: %v %#v", err, c)
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.Start(ctx)
	// Simulate serve continuing while export fails.
	time.Sleep(80 * time.Millisecond)
	cancel()
	// Serve path: SnapshotOnce still works after failures.
	c.SnapshotOnce()
	if c.LastEvent() == nil {
		t.Fatal("expected last event after network fail")
	}
	// No assertion on hits — export ticker is 30s; Drain not required for this test.
	// Point is: Start + SnapshotOnce never returned error / never panicked.
	_ = hits.Load()
}

func TestLastSnapshotPersisted(t *testing.T) {
	paths := testPaths(t)
	q, err := fleet.NewQueue(fleet.QueueConfig{Dir: fleet.TelemetryDir(paths)})
	if err != nil {
		t.Fatal(err)
	}
	ev := fleet.BuildEvent(fleet.BuildOptions{
		InstallationID: "00000000-0000-4000-8000-000000000006",
		Version:        "persist",
		Counters:       map[string]int64{telemetry.MetricCacheHits: 7},
	})
	q.Enqueue(ev)
	got, err := fleet.LastSnapshotFromPaths(paths)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != "persist" || got.Counters[telemetry.MetricCacheHits] != 7 {
		t.Fatalf("%+v", got)
	}
}

func TestSafeURLHostStripsUserinfo(t *testing.T) {
	t.Parallel()
	h := fleet.SafeURLHost("https://user:secret@telemetry.example.com:8443/v1/events")
	if h != "telemetry.example.com:8443" {
		t.Fatalf("host=%q", h)
	}
	if strings.Contains(h, "secret") || strings.Contains(h, "user") {
		t.Fatal("userinfo leaked")
	}
}

func TestNormalizeAuthMethod(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"api_token":          fleet.AuthMethodAPIToken,
		"oidc_bearer":        fleet.AuthMethodOIDCBearer,
		"weird-custom-value": fleet.AuthMethodUnknown,
		"":                   fleet.AuthMethodUnknown,
	}
	for in, want := range cases {
		if got := fleet.NormalizeAuthMethod(in); got != want {
			t.Fatalf("%q → %q want %q", in, got, want)
		}
	}
}

func TestBuildStatusCategoriesAndLocalQueueResidual(t *testing.T) {
	t.Parallel()
	st := fleet.BuildStatus(nil, "id", false, false, "")
	if st.Enabled {
		t.Fatal("disabled")
	}
	if len(st.CategoriesExported) == 0 || len(st.CategoriesForbidden) == 0 {
		t.Fatal("categories required for operator inspection")
	}
	foundTokens, foundLogs, foundRefresh, foundParams := false, false, false, false
	for _, f := range st.CategoriesForbidden {
		switch f {
		case "tokens", "api_tokens":
			foundTokens = true
		case "logs", "job_log_text":
			foundLogs = true
		case "oauth_refresh_tokens":
			foundRefresh = true
		case "raw_job_parameters":
			foundParams = true
		}
	}
	if !foundTokens || !foundLogs || !foundRefresh || !foundParams {
		t.Fatalf("forbidden categories incomplete: %+v", st.CategoriesForbidden)
	}
	// Enabled without export URL → local queue residual note.
	st2 := fleet.BuildStatus(nil, "id", true, false, "")
	if !strings.Contains(st2.Residual, "local queue only") {
		t.Fatalf("expected local-queue residual, got %q", st2.Residual)
	}
	if !strings.Contains(st2.Residual, "privacy review") {
		t.Fatalf("expected production review residual, got %q", st2.Residual)
	}
	if !strings.Contains(st2.Residual, "fleet_telemetry_force_off") {
		t.Fatalf("expected overlay force-off residual honesty, got %q", st2.Residual)
	}
	// With export URL configured, local-queue-only note should be absent.
	st3 := fleet.BuildStatus(nil, "id", true, true, "telemetry.example")
	if strings.Contains(st3.Residual, "local queue only") {
		t.Fatalf("unexpected local-queue residual when URL set: %q", st3.Residual)
	}
	// Allowed field list exposed for operators/docs.
	fields := fleet.SortedAllowedJSONFields()
	wantFields := map[string]bool{
		"version": true, "os": true, "arch": true, "auth_method": true,
		"read_only": true, "error_codes": true, "schema_version": true,
	}
	for f := range wantFields {
		found := false
		for _, got := range fields {
			if got == f {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("allowed field %q missing from %v", f, fields)
		}
	}
}
