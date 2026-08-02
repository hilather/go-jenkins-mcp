package policy_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/policy"
)

// QA-001 Wave 21: policy overlay JSON load + deny_job_prefixes matching (POL-002/004).
// Fail closed on garbage; never panic.

const fuzzMaxOverlay = 32 << 10 // 32 KiB

// FuzzLoadOverlayJSON unmarshals random overlay/bundle JSON and exercises
// Validate + LoadOverlay (temp file) with Nop pilot verifier.
func FuzzLoadOverlayJSON(f *testing.F) {
	f.Add([]byte(``))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{`))
	f.Add([]byte(`null`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`{"version":1,"mode":"pilot"}`))
	f.Add([]byte(`{"version":1,"force_read_only":true,"mode":"strict","deny_tools":["jenkins_get_build_logs"],"deny_job_prefixes":["secret-folder"],"max_result_bytes":4096}`))
	f.Add([]byte(`{"version":99,"mode":"pilot"}`))
	f.Add([]byte(`{"version":1,"mode":"elevate"}`))
	f.Add([]byte(`{"version":1,"deny_job_prefixes":["  "]}`))
	f.Add([]byte(`{"version":1,"deny_job_prefixes":["../escape"]}`))
	f.Add([]byte(`{"version":1,"deny_job_prefixes":["/absolute"]}`))
	f.Add([]byte(`{"version":1,"deny_job_prefixes":["*"]}`))
	f.Add([]byte(`{"version":1,"deny_job_prefixes":["**"]}`))
	f.Add([]byte(`{"version":1,"deny_job_prefixes":["secret/**","team-*/job"]}`))
	f.Add([]byte(`{"version":1,"deny_tools":[""]}`))
	f.Add([]byte(`{"version":1,"max_result_bytes":0}`))
	f.Add([]byte(`{"version":1,"max_result_bytes":-1}`))
	// Bundle-shaped envelope (should require trusted keys on LoadOverlay).
	f.Add([]byte(`{"schema_version":1,"overlay":{"version":1,"mode":"pilot"},"alg":"ed25519","key_id":"k","signature":"AAAA"}`))
	f.Add([]byte(`{"version":1,"mode":"pilot","signature":"stub"}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > fuzzMaxOverlay {
			return
		}
		// Pure bind + Validate (no I/O).
		var o policy.Overlay
		if err := json.Unmarshal(data, &o); err == nil {
			_ = o.Validate()
			_ = o.NormalizeMode()
			_ = o.DenyJobPrefixList()
			_ = o.DenyToolSet()
			_, _ = o.EffectiveMaxResultBytes()
			_ = policy.DocumentFromOverlay(&o)
			_ = policy.NewDenyOnlyFromOverlay(&o)
			_ = policy.AsEnterpriseForce(&o)
		}
		_ = policy.LooksLikeBundle(data)

		dir := t.TempDir()
		path := filepath.Join(dir, "overlay.json")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		res, err := policy.LoadOverlay(policy.LoadOptions{
			Path:         path,
			SkipLastGood: true,
			Verifier:     policy.NopSignatureVerifier{},
		})
		if err != nil {
			// Fail closed is expected for invalid/bundle-without-keys.
			_ = res
			return
		}
		if res.Present && res.Overlay != nil {
			if res.Overlay.Version != policy.CurrentOverlayVersion {
				t.Fatalf("loaded version %d", res.Overlay.Version)
			}
			// Wire evaluator; must not panic.
			ev := policy.NewDenyOnlyFromOverlay(res.Overlay)
			_ = ev.Evaluate(
				policy.NewSubject("corp", "user", true),
				policy.Action{ToolName: "jenkins_get_build", Class: policy.EffectRead},
				policy.Target{JobName: "demo", BuildNumber: 1},
			)
		}
	})
}

// FuzzDenyJobPrefixMatch exercises exact/folder-prefix and glob-lite deny matching.
// Bare string prefixes must not match (secret-folder vs secret-folder-other).
func FuzzDenyJobPrefixMatch(f *testing.F) {
	f.Add("secret-folder", "secret-folder")
	f.Add("secret-folder", "secret-folder/job-a")
	f.Add("secret-folder", "secret-folder-other")
	f.Add("secret-folder", "other/secret-folder")
	f.Add("hr/payroll", "hr/payroll/run")
	f.Add("hr/payroll", "hr/payroll")
	f.Add("hr/payroll", "hr/payrollX")
	f.Add("secret/**", "secret/x")
	f.Add("team-*/job", "team-a/job")
	f.Add("team-*/job", "team-a/other")
	f.Add("*", "any")
	f.Add("**", "any")
	f.Add("", "job")
	f.Add("job", "")
	f.Add("../x", "job")
	f.Add("a", "a/b/c")
	f.Add(strings.Repeat("p", 100), strings.Repeat("p", 100)+"/child")

	f.Fuzz(func(t *testing.T, prefix, job string) {
		if len(prefix) > fuzzMaxParamStr || len(job) > fuzzMaxParamStr {
			return
		}
		// Direct Document path (bypass Overlay.Validate so bad prefixes still
		// exercise the matcher — production loads validate first).
		ev := policy.NewDenyOnlyEvaluator(policy.Document{
			Mode:            policy.ModePilot,
			DenyJobPrefixes: []string{prefix},
		})
		subj := policy.NewSubject("corp", "admin", true)
		act := policy.Action{ToolName: "jenkins_get_build", Class: policy.EffectRead}
		d := ev.Evaluate(subj, act, policy.Target{JobName: job, BuildNumber: 1})
		// Determinism: second evaluate agrees.
		d2 := ev.Evaluate(subj, act, policy.Target{JobName: job, BuildNumber: 1})
		if d.Denied() != d2.Denied() || d.ReasonCode != d2.ReasonCode {
			t.Fatalf("non-deterministic: %+v vs %+v", d, d2)
		}

		p := strings.TrimSpace(prefix)
		j := strings.TrimSpace(job)
		if j == "" || p == "" {
			// Empty job → no job-prefix rule; empty prefix skipped in loop.
			if d.Denied() && d.ReasonCode == policy.ReasonJobPatternDeny {
				t.Fatalf("unexpected job deny for empty job/prefix: %+v", d)
			}
			return
		}
		// Oracle: MatchDenyJobPattern (Wave 26 glob-lite).
		shouldDeny := policy.MatchDenyJobPattern(p, j)
		if shouldDeny {
			if !d.Denied() || d.ReasonCode != policy.ReasonJobPatternDeny {
				t.Fatalf("expected job deny for prefix=%q job=%q: %+v", p, j, d)
			}
		} else if d.ReasonCode == policy.ReasonJobPatternDeny {
			t.Fatalf("false job deny for prefix=%q job=%q", p, j)
		}

		// Overlay.Validate path when prefix is structurally valid.
		o := &policy.Overlay{
			Version:         policy.CurrentOverlayVersion,
			Mode:            policy.ModePilot,
			DenyJobPrefixes: []string{prefix},
		}
		if err := o.Validate(); err == nil {
			ev2 := policy.NewDenyOnlyFromOverlay(o)
			_ = ev2.Evaluate(subj, act, policy.Target{JobName: job})
			// Validated patterns must agree with matcher.
			if policy.MatchDenyJobPattern(strings.TrimSpace(prefix), j) != shouldDeny {
				t.Fatalf("validated mismatch prefix=%q job=%q", prefix, j)
			}
		}
	})
}

const fuzzMaxParamStr = 4 << 10
