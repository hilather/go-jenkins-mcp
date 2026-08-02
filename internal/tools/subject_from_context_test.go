package tools_test

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/jenkins"
	"github.com/hilather/go-jenkins-mcp/internal/policy"
	"github.com/hilather/go-jenkins-mcp/internal/tools"
)

// perUserDenyEval denies a tool only for a specific JenkinsUserID.
// Used to prove multi-user policy.Subject rebind without per-subject deny_tools
// document support (deny_tools is process-wide).
type perUserDenyEval struct {
	deniedUser string
	deniedTool string
}

func (e *perUserDenyEval) Evaluate(subject policy.Subject, action policy.Action, target policy.Target) policy.Decision {
	// Mirror DenyOnlyEvaluator subject checks (empty/anonymous/no profile).
	if !subject.Valid() {
		return policy.Decision{
			Effect:      policy.EffectDeny,
			ReasonCode:  policy.ReasonSubjectInvalid,
			Explanation: "subject invalid",
		}
	}
	tool := strings.TrimSpace(action.ToolName)
	if tool == e.deniedTool && subject.JenkinsUserID == e.deniedUser {
		return policy.Decision{
			Effect:      policy.EffectDeny,
			ReasonCode:  policy.ReasonExplicitDeny,
			MatchedRule: "deny_for_user:" + e.deniedUser,
			Explanation: "tool denied for subject",
		}
	}
	return policy.Decision{Effect: policy.EffectAllow}
}

// subjectSlot holds the multi-user subject for tests that cannot rely on MCP
// SDK propagating custom context values through InMemory transports.
// SubjectFromContext still never reads tool args — only this trusted slot.
type subjectSlot struct {
	v atomic.Value // policy.Subject; missing = no context subject
}

func (s *subjectSlot) set(subj policy.Subject) {
	s.v.Store(subj)
}

func (s *subjectSlot) clear() {
	s.v = atomic.Value{}
}

func (s *subjectSlot) fromContext(ctx context.Context) (policy.Subject, bool) {
	_ = ctx // production adapter uses gateway.PolicySubjectFromContext(ctx)
	v := s.v.Load()
	if v == nil {
		return policy.Subject{}, false
	}
	subj, ok := v.(policy.Subject)
	return subj, ok
}

// Regression: multi-user policy.Subject rebind — Alice denied, Bob allowed
// under the same process RegisterOptions.Subject (process default).
func TestSubjectFromContext_AliceDeniedBobAllowed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const toolName = "test_mu_policy_tool"
	processDefault := policy.NewSubject("corp", "process-user", true)
	alice := policy.NewSubject("corp", "alice", true).WithExternal("alice-sub")
	bob := policy.NewSubject("corp", "bob", true).WithExternal("bob-sub")

	slot := &subjectSlot{}
	ev := &perUserDenyEval{deniedUser: "alice", deniedTool: toolName}

	var ran atomic.Int32
	server := mcp.NewServer(&mcp.Implementation{Name: "mu-policy", Version: "test"}, nil)
	opts := &tools.RegisterOptions{
		Gate:    policy.NewDefaultReadOnlyGate(),
		Policy:  ev,
		Subject: processDefault, // process default never alice/bob
		SubjectFromContext: func(c context.Context) (policy.Subject, bool) {
			return slot.fromContext(c)
		},
	}
	tools.ForceRegisterReadToolForTest(server, opts, &mcp.Tool{
		Name:        toolName,
		Description: "multi-user policy rebind test",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args emptyArgs) (*mcp.CallToolResult, gateOut, error) {
		ran.Add(1)
		return structuredGateOK()
	})

	cs := connectToolClient(t, ctx, server)

	// Alice in context → denied.
	slot.set(alice)
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: toolName, Arguments: map[string]any{}})
	if err != nil {
		t.Fatalf("alice transport: %v", err)
	}
	if res == nil || !res.IsError {
		t.Fatalf("alice must be policy-denied, got %#v", res)
	}
	text := toolErrorText(res)
	if !strings.Contains(strings.ToLower(text), "denied") &&
		!strings.Contains(text, string(apperr.CodePolicyDenial)) {
		t.Fatalf("alice denial text: %q", text)
	}
	if ran.Load() != 0 {
		t.Fatal("handler must not run for alice")
	}

	// Bob in context → allowed (same process Subject).
	slot.set(bob)
	res2, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: toolName, Arguments: map[string]any{}})
	if err != nil {
		t.Fatalf("bob transport: %v", err)
	}
	if res2 != nil && res2.IsError {
		t.Fatalf("bob must be allowed: %s", toolErrorText(res2))
	}
	if ran.Load() != 1 {
		t.Fatalf("handler must run for bob: ran=%d", ran.Load())
	}
}

// spoofIdentityArgs accepts identity-like keys that RejectIdentityToolArgs
// forbids in gateway paths. Schema must include them so CallTool validation
// does not reject the request before policy runs.
type spoofIdentityArgs struct {
	AsUser      string `json:"as_user,omitempty"`
	Subject     string `json:"subject,omitempty"`
	JenkinsUser string `json:"jenkins_user,omitempty"`
	Tenant      string `json:"tenant,omitempty"`
}

// Regression: tool args (as_user / subject / jenkins_user) cannot override
// the trusted context subject. Alice stays denied even when args claim bob.
func TestSubjectFromContext_ToolArgsCannotOverride(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const toolName = "test_mu_no_spoof"
	processDefault := policy.NewSubject("corp", "process-user", true)
	alice := policy.NewSubject("corp", "alice", true).WithExternal("alice-sub")

	slot := &subjectSlot{}
	slot.set(alice)
	ev := &perUserDenyEval{deniedUser: "alice", deniedTool: toolName}

	server := mcp.NewServer(&mcp.Implementation{Name: "mu-spoof", Version: "test"}, nil)
	tools.ForceRegisterReadToolForTest(server, &tools.RegisterOptions{
		Gate:    policy.NewDefaultReadOnlyGate(),
		Policy:  ev,
		Subject: processDefault,
		SubjectFromContext: func(c context.Context) (policy.Subject, bool) {
			return slot.fromContext(c)
		},
	}, &mcp.Tool{Name: toolName, Description: "spoof test"},
		func(ctx context.Context, req *mcp.CallToolRequest, args spoofIdentityArgs) (*mcp.CallToolResult, gateOut, error) {
			// Even if args claim bob, effectiveSubject must remain alice.
			if args.AsUser != "" || args.JenkinsUser != "" {
				// Handler only runs if policy allowed — which must not happen for alice.
				t.Fatalf("handler must not run; spoof args present as_user=%q jenkins_user=%q",
					args.AsUser, args.JenkinsUser)
			}
			t.Fatal("handler must not run when alice denied")
			return structuredGateOK()
		})

	cs := connectToolClient(t, ctx, server)
	// Identity keys in tool args must not rebind subject (GWY-002).
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: toolName,
		Arguments: map[string]any{
			"as_user":      "bob",
			"subject":      "bob-sub",
			"jenkins_user": "bob",
			"tenant":       "evil-tenant",
		},
	})
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	if res == nil || !res.IsError {
		t.Fatalf("want policy deny despite spoof args, got %#v", res)
	}
}

// Multi-user off (no SubjectFromContext): process Subject is used unchanged.
func TestSubjectFromContext_MultiUserOff_ProcessSubject(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const toolName = "test_mu_off"
	// Process subject is alice → denied by per-user eval.
	processAlice := policy.NewSubject("corp", "alice", true)
	ev := &perUserDenyEval{deniedUser: "alice", deniedTool: toolName}

	server := mcp.NewServer(&mcp.Implementation{Name: "mu-off", Version: "test"}, nil)
	tools.ForceRegisterReadToolForTest(server, &tools.RegisterOptions{
		Gate:    policy.NewDefaultReadOnlyGate(),
		Policy:  ev,
		Subject: processAlice,
		// SubjectFromContext nil = multi-user off
	}, &mcp.Tool{Name: toolName, Description: "multi-user off"},
		func(ctx context.Context, req *mcp.CallToolRequest, args emptyArgs) (*mcp.CallToolResult, gateOut, error) {
			t.Fatal("process alice must be denied without SubjectFromContext")
			return structuredGateOK()
		})

	cs := connectToolClient(t, ctx, server)
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: toolName, Arguments: map[string]any{}})
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	if res == nil || !res.IsError {
		t.Fatalf("process subject alice must be denied: %#v", res)
	}

	// Process bob allowed without context rebind.
	server2 := mcp.NewServer(&mcp.Implementation{Name: "mu-off-bob", Version: "test"}, nil)
	var ran bool
	tools.ForceRegisterReadToolForTest(server2, &tools.RegisterOptions{
		Gate:    policy.NewDefaultReadOnlyGate(),
		Policy:  ev,
		Subject: policy.NewSubject("corp", "bob", true),
	}, &mcp.Tool{Name: toolName, Description: "multi-user off bob"},
		func(ctx context.Context, req *mcp.CallToolRequest, args emptyArgs) (*mcp.CallToolResult, gateOut, error) {
			ran = true
			return structuredGateOK()
		})
	cs2 := connectToolClient(t, ctx, server2)
	res2, err := cs2.CallTool(ctx, &mcp.CallToolParams{Name: toolName, Arguments: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	if res2 != nil && res2.IsError {
		t.Fatalf("process bob must be allowed: %s", toolErrorText(res2))
	}
	if !ran {
		t.Fatal("handler did not run for process bob")
	}
}

// ListTools discovery also uses effectiveSubject (middleware ctx).
func TestSubjectFromContext_ListToolsFilter(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const denied = "jenkins_get_build_logs"
	processDefault := policy.NewSubject("corp", "process-user", true)
	alice := policy.NewSubject("corp", "alice", true)
	bob := policy.NewSubject("corp", "bob", true)

	slot := &subjectSlot{}
	// Process-wide deny_tools for denied tool would hide for everyone; use
	// per-user eval so Alice cannot discover while Bob can.
	ev := &perUserDenyEval{deniedUser: "alice", deniedTool: denied}

	server := mcp.NewServer(&mcp.Implementation{Name: "mu-list", Version: "test"}, nil)
	tools.Register(server, &jenkins.Client{}, &tools.RegisterOptions{
		Gate:    policy.NewDefaultReadOnlyGate(),
		Policy:  ev,
		Subject: processDefault,
		SubjectFromContext: func(c context.Context) (policy.Subject, bool) {
			return slot.fromContext(c)
		},
	})
	cs := connectListToolsSession(t, ctx, server)

	// No context subject → process default (process-user) → tool listed.
	slot.clear()
	got := listNamesFromSession(t, ctx, cs)
	if _, ok := got[denied]; !ok {
		t.Fatalf("process default must see %q", denied)
	}

	// Alice → omitted.
	slot.set(alice)
	gotA := listNamesFromSession(t, ctx, cs)
	if _, ok := gotA[denied]; ok {
		t.Fatalf("alice must not discover %q", denied)
	}
	if _, ok := gotA["jenkins_get_jobs"]; !ok {
		t.Fatal("alice must still see unrelated tools")
	}

	// Bob → listed again.
	slot.set(bob)
	gotB := listNamesFromSession(t, ctx, cs)
	if _, ok := gotB[denied]; !ok {
		t.Fatalf("bob must discover %q", denied)
	}
}

// Invalid context subject fails closed (does not elevate to process default).
func TestSubjectFromContext_InvalidDoesNotElevate(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const toolName = "test_mu_invalid"
	// Process default is valid bob — would allow if elevated.
	processBob := policy.NewSubject("corp", "bob", true)
	// Partial multi-user identity: external only, no Jenkins principal.
	invalidAlice := policy.Subject{
		ProfileID:       "corp",
		ExternalSubject: "alice-sub",
		Verified:        false,
	}

	slot := &subjectSlot{}
	slot.set(invalidAlice)
	// Allow everyone who is Valid; invalid subjects denied by check.
	ev := policy.NewDenyOnlyEvaluator(policy.Document{Mode: policy.ModePilot})

	server := mcp.NewServer(&mcp.Implementation{Name: "mu-inv", Version: "test"}, nil)
	tools.ForceRegisterReadToolForTest(server, &tools.RegisterOptions{
		Gate:    policy.NewDefaultReadOnlyGate(),
		Policy:  ev,
		Subject: processBob,
		SubjectFromContext: func(c context.Context) (policy.Subject, bool) {
			return slot.fromContext(c)
		},
	}, &mcp.Tool{Name: toolName, Description: "invalid subject"},
		func(ctx context.Context, req *mcp.CallToolRequest, args emptyArgs) (*mcp.CallToolResult, gateOut, error) {
			t.Fatal("invalid context subject must not elevate to process bob")
			return structuredGateOK()
		})

	cs := connectToolClient(t, ctx, server)
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: toolName, Arguments: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	if res == nil || !res.IsError {
		t.Fatalf("invalid subject must deny, got %#v", res)
	}
}
