package policy_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/jenkins"
	"github.com/simonfxr/go-jenkins-mcp/internal/policy"
)

func TestCheckToolAccess_RODeniesMutation(t *testing.T) {
	t.Parallel()
	gate := policy.NewDefaultReadOnlyGate()
	err := policy.CheckToolAccess(context.Background(), gate, nil, fixtureAdmin, policy.ToolStartJob, policy.EffectMutate)
	if err == nil || apperr.CodeOf(err) != apperr.CodePolicyDenial {
		t.Fatalf("err=%v", err)
	}
}

func TestCheckToolAccess_PolicyDeniesRead(t *testing.T) {
	t.Parallel()
	gate := policy.NewReadOnlyGate(policy.Inputs{AllowMutations: true})
	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode: policy.ModePilot,
		DenyTools: map[string]struct{}{
			"jenkins_get_build_logs": {},
		},
	})
	err := policy.CheckToolAccess(context.Background(), gate, ev, fixtureAdmin, "jenkins_get_build_logs", policy.EffectRead)
	if err == nil || apperr.CodeOf(err) != apperr.CodePolicyDenial {
		t.Fatalf("err=%v", err)
	}
	// Other reads ok.
	if err := policy.CheckToolAccess(context.Background(), gate, ev, fixtureAdmin, "jenkins_get_jobs", policy.EffectRead); err != nil {
		t.Fatal(err)
	}
}

func TestCheckToolAccess_EmptySubjectWithPolicy(t *testing.T) {
	t.Parallel()
	gate := policy.NewDefaultReadOnlyGate()
	ev := policy.NewDenyOnlyEvaluator(policy.Document{Mode: policy.ModePilot})
	err := policy.CheckToolAccess(context.Background(), gate, ev, policy.Subject{}, "jenkins_get_jobs", policy.EffectRead)
	if err == nil || apperr.CodeOf(err) != apperr.CodePolicyDenial {
		t.Fatalf("empty subject must deny when policy present: %v", err)
	}
}

func TestCheckToolAccess_Cancelled(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := policy.CheckToolAccess(ctx, policy.NewDefaultReadOnlyGate(), nil, fixtureAdmin, "jenkins_get_jobs", policy.EffectRead)
	if err == nil || apperr.CodeOf(err) != apperr.CodeCancelled {
		t.Fatalf("err=%v", err)
	}
}

func TestReadOnlyMutationGuard_BlocksMutateAllowsReadAuth(t *testing.T) {
	t.Parallel()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	gate := policy.NewDefaultReadOnlyGate()
	c := jenkins.NewClient(srv.URL, "u", "t").WithMutationGuard(policy.NewReadOnlyMutationGuard(gate))

	// Mutation blocked, no network.
	_, err := c.CallJenkins(context.Background(), c.Client, http.MethodPost, "/job/x/buildWithParameters", nil, nil)
	if err == nil || apperr.CodeOf(err) != apperr.CodePolicyDenial {
		t.Fatalf("mutate under RO: %v", err)
	}
	// Unclassified POST blocked.
	_, err = c.CallJenkins(context.Background(), c.Client, http.MethodPost, "/scriptText", nil, nil)
	if err == nil || apperr.CodeOf(err) != apperr.CodePolicyDenial {
		t.Fatalf("unclassified under RO: %v", err)
	}
	if hits.Load() != 0 {
		t.Fatal("no network on denied writes")
	}

	// GET ok.
	resp, err := c.CallJenkins(context.Background(), c.Client, http.MethodGet, "/api/json", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	// Crumb (auth) ok under RO.
	resp, err = c.CallJenkins(context.Background(), c.Client, http.MethodGet, "/crumbIssuer/api/json", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if hits.Load() != 2 {
		t.Fatalf("hits=%d", hits.Load())
	}
}

func TestReadOnlyMutationGuard_AllowsMutateWhenNotRO(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	gate := policy.NewReadOnlyGate(policy.Inputs{AllowMutations: true})
	c := jenkins.NewClient(srv.URL, "u", "t").WithMutationGuard(policy.NewReadOnlyMutationGuard(gate))
	resp, err := c.CallJenkins(context.Background(), c.Client, http.MethodPost, "/job/x/build", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}

func TestCheckStoreRead(t *testing.T) {
	t.Parallel()
	// Nil evaluator: allow (stub no-op).
	if err := policy.CheckStoreRead(context.Background(), nil, fixtureAdmin, "job/a"); err != nil {
		t.Fatal(err)
	}
	// Explicit deny of store_cached_read.
	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode: policy.ModePilot,
		DenyTools: map[string]struct{}{
			policy.StoreReadAction: {},
		},
	})
	err := policy.CheckStoreRead(context.Background(), ev, fixtureAdmin, "secret-job")
	if err == nil || apperr.CodeOf(err) != apperr.CodePolicyDenial {
		t.Fatalf("store deny: %v", err)
	}
	// Empty subject with evaluator fails closed.
	err = policy.CheckStoreRead(context.Background(), policy.NewDenyOnlyEvaluator(policy.Document{Mode: policy.ModePilot}), policy.Subject{}, "j")
	if err == nil {
		t.Fatal("empty subject")
	}
	// Job prefix deny on store resource.
	ev2 := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:            policy.ModePilot,
		DenyJobPrefixes: []string{"secret"},
	})
	err = policy.CheckStoreRead(context.Background(), ev2, fixtureAdmin, "secret/child")
	if err == nil || apperr.CodeOf(err) != apperr.CodePolicyDenial {
		t.Fatalf("job prefix store: %v", err)
	}
	// Regression: strict mode must not treat store_cached_read as unknown_tool.
	evStrict := policy.NewDenyOnlyEvaluator(policy.Document{Mode: policy.ModeStrict})
	if err := policy.CheckStoreRead(context.Background(), evStrict, fixtureAdmin, "public/job"); err != nil {
		t.Fatalf("strict store read of allowed job: %v", err)
	}
}

func TestEvaluateWithContext(t *testing.T) {
	t.Parallel()
	ev := policy.NewDenyOnlyEvaluator(policy.Document{Mode: policy.ModePilot})
	d, err := policy.EvaluateWithContext(context.Background(), ev, fixtureAdmin, policy.Action{ToolName: "jenkins_get_jobs", Class: policy.EffectRead}, policy.Target{})
	if err != nil || !d.Allowed() {
		t.Fatalf("%+v err=%v", d, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = policy.EvaluateWithContext(ctx, ev, fixtureAdmin, policy.Action{ToolName: "jenkins_get_jobs"}, policy.Target{})
	if err == nil {
		t.Fatal("cancelled")
	}
}

func TestMeasureEvaluateOverhead(t *testing.T) {
	t.Parallel()
	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode: policy.ModePilot,
		DenyTools: map[string]struct{}{
			"jenkins_get_build_logs": {},
		},
	})
	avg := policy.MeasureEvaluate(ev, fixtureAdmin, policy.Action{ToolName: "jenkins_get_jobs", Class: policy.EffectRead}, policy.Target{}, 200)
	// Loose bound: pure in-memory deny-only eval should be well under 1ms avg.
	if avg > time.Millisecond {
		t.Fatalf("policy eval avg %v exceeds 1ms budget (POL-004 overhead)", avg)
	}
}

func TestClassifyReexport(t *testing.T) {
	t.Parallel()
	if policy.ClassifyJenkinsRequest("GET", "/api/json") != jenkins.RequestRead {
		t.Fatal("reexport")
	}
	if !policy.RequiresMutationPermission(jenkins.RequestMutate) {
		t.Fatal("reexport mutate")
	}
}

func TestUnclassifiedToolStrict(t *testing.T) {
	t.Parallel()
	// Newly introduced tools denied until classified (strict mode).
	if policy.IsExplicitlyClassified("jenkins_evil_new_tool") {
		t.Fatal("unknown must not be classified")
	}
	ev := policy.NewDenyOnlyEvaluator(policy.Document{Mode: policy.ModeStrict})
	d := ev.Evaluate(fixtureAdmin, policy.Action{ToolName: "jenkins_evil_new_tool", Class: policy.EffectRead}, policy.Target{})
	if !d.Denied() || d.ReasonCode != policy.ReasonUnknownTool {
		t.Fatalf("%+v", d)
	}
}

func TestDenialNoSecrets(t *testing.T) {
	t.Parallel()
	gate := policy.NewDefaultReadOnlyGate()
	g := policy.NewReadOnlyMutationGuard(gate)
	err := g.CheckRequest(context.Background(), jenkins.RequestMutate, "POST", "/job/x/build?token=supersecret")
	if err == nil {
		t.Fatal("want deny")
	}
	s := err.Error()
	if strings.Contains(s, "supersecret") || strings.Contains(s, "token=") {
		t.Fatalf("denial leaked query/secret: %q", s)
	}
}
