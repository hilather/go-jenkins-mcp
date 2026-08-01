package policy_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/policy"
)

// Wave 26 / POL-002: deny_job_prefixes glob-lite matrix + Wave 29 mid-path **/.
func TestMatchDenyJobPatternMatrix(t *testing.T) {
	t.Parallel()
	cases := []struct {
		pattern string
		job     string
		want    bool
		note    string
	}{
		// Classic exact + folder children
		{"secret-folder", "secret-folder", true, "exact"},
		{"secret-folder", "secret-folder/job-a", true, "child"},
		{"secret-folder", "secret-folder/a/b", true, "deep child"},
		{"secret-folder", "secret-folder-other", false, "sibling bare-prefix must not match"},
		{"secret-folder", "other/secret-folder", false, "suffix not prefix"},
		{"secret-folder", "public/job", false, "unrelated"},
		{"hr/payroll", "hr/payroll", true, "nested exact"},
		{"hr/payroll", "hr/payroll/run", true, "nested child"},
		{"hr/payroll", "hr/payrollX", false, "not path child"},
		{"hr/payroll", "hr/other", false, "sibling folder"},

		// Trailing /** ≡ folder + descendants
		{"secret/**", "secret", true, "/** exact folder"},
		{"secret/**", "secret/job", true, "/** child"},
		{"secret/**", "secret/a/b/c", true, "/** deep"},
		{"secret/**", "secret-other", false, "/** not bare string prefix"},
		{"secret/**", "other/secret", false, "/** not suffix"},
		{"hr/payroll/**", "hr/payroll", true, "nested /** exact"},
		{"hr/payroll/**", "hr/payroll/x", true, "nested /** child"},
		{"hr/payroll/**", "hr/payroll-extra", false, "nested /** sibling name"},

		// Single-segment *
		{"team-*/job", "team-a/job", true, "segment * exact"},
		{"team-*/job", "team-foo/job", true, "segment * multi char"},
		{"team-*/job", "team-/job", true, "* may match empty within segment"},
		{"team-*/job", "team-a/job/nested", true, "glob prefix children"},
		{"team-*/job", "team-a/other", false, "wrong second segment"},
		{"team-*/job", "xteam-a/job", false, "prefix not wildcarded"},
		{"team-*/job", "team-a/jobX", false, "last segment exact"},
		{"*/secret", "prod/secret", true, "leading segment *"},
		{"*/secret", "prod/secret/child", true, "leading * + child"},
		{"*/secret", "prod/public", false, "leading * miss"},
		{"a/*/c", "a/b/c", true, "mid *"},
		{"a/*/c", "a/b/c/d", true, "mid * child"},
		{"a/*/c", "a/b/x", false, "mid * miss"},
		{"a/*/c", "a/c", false, "mid * requires a segment"},

		// * combined with /**
		{"team-*/**", "team-a", true, "glob folder exact"},
		{"team-*/**", "team-a/job", true, "glob folder child"},
		{"team-*/**", "team-a/x/y", true, "glob folder deep"},
		{"team-*/**", "team", false, "incomplete segment"},
		{"team-*/**", "other-a", false, "no match"},

		// Wave 29: mid-path **/ (zero or more segments)
		{"folder/**/job", "folder/job", true, "mid ** zero segments"},
		{"folder/**/job", "folder/a/job", true, "mid ** one segment"},
		{"folder/**/job", "folder/a/b/job", true, "mid ** multi segment"},
		{"folder/**/job", "folder/a/b/job/nested", true, "mid ** + child"},
		{"folder/**/job", "folder/jobX", false, "mid ** last segment exact"},
		{"folder/**/job", "folder/a/other", false, "mid ** wrong tail"},
		{"folder/**/job", "other/job", false, "mid ** wrong head"},
		{"folder/**/job", "folder", false, "mid ** missing required tail"},

		// Leading **/
		{"**/secret", "secret", true, "leading ** zero + exact"},
		{"**/secret", "folder/secret", true, "leading ** one"},
		{"**/secret", "a/b/c/secret", true, "leading ** deep"},
		{"**/secret", "a/b/c/secret/child", true, "leading ** + child"},
		{"**/secret", "secretive", false, "leading ** not bare string"},
		{"**/secret", "folder/secret-other", false, "leading ** segment exact"},
		{"**/secret", "folder/public", false, "leading ** miss"},
		// Wave 29 regression: align with BuildJobPath (collapse // and leading /)
		{"**/secret", "prod//secret", true, "collapse empty segs like BuildJobPath"},
		{"**/secret", "/secret", true, "leading slash collapsed to secret"},
		{"**/secret", "//secret", true, "double leading slash collapsed"},
		{"folder/**/job", "folder//job", true, "mid-path ** with empty segs"},
		{"folder/**/job", "folder///a//job", true, "multiple empty segs collapsed"},
		{"secret", "/secret", true, "classic deny with leading slash"},
		{"folder/job", "folder//job", true, "classic exact with //"},
		{"**/secret", "prod//secretive", false, "collapse still requires exact segment"},

		// Trailing after mid-path
		{"folder/**/job/**", "folder/job", true, "mid+trail strip exact"},
		{"folder/**/job/**", "folder/a/job/x", true, "mid+trail deep child"},
		{"folder/**/job/**", "folder/a/other", false, "mid+trail miss"},

		// Composition: single-segment * with mid **/
		{"team/*/app/**", "team/blue/app", true, "team/*/app exact"},
		{"team/*/app/**", "team/blue/app/deploy", true, "team/*/app child"},
		{"team/*/app/**", "team/blue/other", false, "team/*/app miss"},
		{"team/**/app", "team/app", true, "team/**/app zero"},
		{"team/**/app", "team/x/y/app", true, "team/**/app deep"},
		{"team/**/app", "team/x/y/app/z", true, "team/**/app child"},
		{"team/*/app/**/job", "team/blue/app/job", true, "compose * and mid ** zero"},
		{"team/*/app/**/job", "team/blue/app/x/y/job", true, "compose * and mid ** deep"},
		{"team/*/app/**/job", "team/blue/app/x/y/job/n", true, "compose child"},
		{"team/*/app/**/job", "team/blue/other/job", false, "compose miss app"},
		{"team/*/app/**/job", "team/blue/app", false, "compose missing job tail"},

		// Multiple mid-path **
		{"a/**/b/**/c", "a/b/c", true, "multi ** zeros"},
		{"a/**/b/**/c", "a/x/b/y/c", true, "multi ** fill"},
		{"a/**/b/**/c", "a/x/y/b/z/w/c", true, "multi ** deep"},
		{"a/**/b/**/c", "a/x/b/y/c/child", true, "multi ** child"},
		{"a/**/b/**/c", "a/x/c", false, "multi ** missing b"},
		{"a/**/b/**/c", "a/b/x", false, "multi ** missing c"},

		// Consecutive ** (redundant but valid)
		{"a/**/**/b", "a/b", true, "consecutive ** zero"},
		{"a/**/**/b", "a/x/y/b", true, "consecutive ** fill"},

		// Empty / edge
		{"", "job", false, "empty pattern"},
		{"secret", "", false, "empty job"},
		{"secret-folder", "secret-folder-other/x", false, "sibling path"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.note+"/"+tc.pattern+"→"+tc.job, func(t *testing.T) {
			t.Parallel()
			got := policy.MatchDenyJobPattern(tc.pattern, tc.job)
			if got != tc.want {
				t.Fatalf("MatchDenyJobPattern(%q, %q)=%v want %v (%s)",
					tc.pattern, tc.job, got, tc.want, tc.note)
			}
		})
	}
}

func TestValidateDenyJobPatternRejectsBroadAndUnsafe(t *testing.T) {
	t.Parallel()
	// Valid (Wave 26 + Wave 29 mid-path **/)
	valid := []string{
		"secret-folder",
		"hr/payroll",
		"secret/**",
		"hr/payroll/**",
		"team-*/job",
		"*/secret",
		"a/*/c",
		"team-*/**",
		"*/*", // explicit two-segment; not bare *
		// Wave 29
		"folder/**/job",
		"**/secret",
		"team/**/app",
		"team/*/app/**",
		"folder/**/job/**",
		"a/**/b/**/c",
		"a/**/**/b",
		"**/a/**",
	}
	for _, p := range valid {
		if err := policy.ValidateDenyJobPattern(p); err != nil {
			t.Fatalf("ValidateDenyJobPattern(%q) unexpected: %v", p, err)
		}
	}

	// Invalid / fail closed
	invalid := []struct {
		p    string
		sub  string
		note string
	}{
		{"", "empty", "empty"},
		{"   ", "empty", "whitespace"},
		{"*", "overly broad", "bare *"},
		{"**", "overly broad", "bare **"},
		{"/**", "overly broad", "root /**"},
		{"**/**", "overly broad", "double **/** collapses to bare **"},
		{"/absolute", "absolute", "absolute"},
		{"../escape", "traversal", "dotdot"},
		{"a/../b", "traversal", "mid dotdot"},
		{"secret/", "end with /", "trailing slash"},
		{"a//b", "empty path segment", "double slash"},
		{"foo?", "unsupported", "question"},
		{"foo[", "unclosed", "unclosed class"},
		{"foo[]", "empty character class", "empty class"},
		{"foo[z-a]", "inverted", "inverted range"},
		{`foo\bar`, "unsupported", "backslash"},
		{"a**b", "whole", "embedded **"},
		{"x**/y", "whole", "prefix-embedded **"},
		{"**/", "end with /", "**/ trailing slash only"},
	}
	for _, tc := range invalid {
		err := policy.ValidateDenyJobPattern(tc.p)
		if err == nil {
			t.Fatalf("ValidateDenyJobPattern(%q) want error (%s)", tc.p, tc.note)
		}
		if apperr.CodeOf(err) != apperr.CodeInvalidArgument {
			t.Fatalf("ValidateDenyJobPattern(%q) code=%s (%s)", tc.p, apperr.CodeOf(err), tc.note)
		}
		if tc.sub != "" && !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tc.sub)) &&
			!strings.Contains(strings.ToLower(err.Error()), "overly broad") &&
			!strings.Contains(strings.ToLower(err.Error()), "absolute") &&
			!strings.Contains(strings.ToLower(err.Error()), "traversal") &&
			!strings.Contains(strings.ToLower(err.Error()), "**") &&
			!strings.Contains(strings.ToLower(err.Error()), "empty") &&
			!strings.Contains(strings.ToLower(err.Error()), "unsupported") &&
			!strings.Contains(strings.ToLower(err.Error()), "segment") &&
			!strings.Contains(strings.ToLower(err.Error()), "end with") &&
			!strings.Contains(strings.ToLower(err.Error()), "whole") {
			// Soft check: error is non-empty fail-closed message
			if err.Error() == "" {
				t.Fatalf("empty error for %q", tc.p)
			}
		}
	}

	// */** is valid (any top-level folder matching * + descendants).
	if err := policy.ValidateDenyJobPattern("*/**"); err != nil {
		t.Fatalf("*/** should be valid: %v", err)
	}
}

func TestValidateDenyJobPatternSegmentCap(t *testing.T) {
	t.Parallel()
	// Exactly MaxDenyJobPatternSegments is OK; one more fails.
	segs := make([]string, policy.MaxDenyJobPatternSegments)
	for i := range segs {
		segs[i] = "s"
	}
	ok := strings.Join(segs, "/")
	if err := policy.ValidateDenyJobPattern(ok); err != nil {
		t.Fatalf("max segments should pass: %v", err)
	}
	tooLong := ok + "/x"
	if err := policy.ValidateDenyJobPattern(tooLong); err == nil {
		t.Fatal("over max segments must fail closed")
	}
}

func TestOverlayLoadRejectsBroadDenyJobPrefixes(t *testing.T) {
	t.Parallel()
	for _, body := range []string{
		`{"version":1,"deny_job_prefixes":["*"]}`,
		`{"version":1,"deny_job_prefixes":["**"]}`,
		`{"version":1,"deny_job_prefixes":["/**"]}`,
		`{"version":1,"deny_job_prefixes":["**/**"]}`,
		`{"version":1,"deny_job_prefixes":["../x"]}`,
		`{"version":1,"deny_job_prefixes":["a**b"]}`,
	} {
		path := filepath.Join(t.TempDir(), "overlay.json")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := policy.LoadOverlay(policy.LoadOptions{Path: path})
		if err == nil {
			t.Fatalf("LoadOverlay must fail closed for %s", body)
		}
	}
}

func TestOverlayLoadAcceptsMidPathDenyJobPrefixes(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "overlay.json")
	// Wave 29: a/**/b is now valid (was rejected in Wave 26).
	body := `{
		"version": 1,
		"deny_job_prefixes": ["secret/**", "team-*/job", "folder/**/job", "**/secret", "hr/payroll"]
	}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := policy.LoadOverlay(policy.LoadOptions{Path: path})
	if err != nil {
		t.Fatalf("LoadOverlay: %v", err)
	}
	ev := policy.NewDenyOnlyFromOverlay(res.Overlay)
	subj := policy.NewSubject("corp", "admin", true)
	act := policy.Action{ToolName: "jenkins_get_job", Class: policy.EffectRead}

	denyJobs := []string{
		"secret", "secret/x",
		"team-a/job", "team-z/job/nested",
		"folder/job", "folder/a/b/job", "folder/a/job/nested",
		"secret", "prod/secret", "a/b/c/secret",
		"hr/payroll/run",
	}
	for _, j := range denyJobs {
		d := ev.Evaluate(subj, act, policy.Target{JobName: j})
		if !d.Denied() || d.ReasonCode != policy.ReasonJobPatternDeny {
			t.Fatalf("job %q must deny: %+v", j, d)
		}
	}
	allowJobs := []string{"public", "team-a/other", "hr/other", "secret-other", "folder/other", "other/job"}
	for _, j := range allowJobs {
		d := ev.Evaluate(subj, act, policy.Target{JobName: j})
		if d.ReasonCode == policy.ReasonJobPatternDeny {
			t.Fatalf("job %q must not job-pattern-deny: %+v", j, d)
		}
	}
}

func TestOverlayLoadAcceptsGlobLiteDenyJobPrefixes(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "overlay.json")
	body := `{
		"version": 1,
		"deny_job_prefixes": ["secret/**", "team-*/job", "hr/payroll"]
	}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := policy.LoadOverlay(policy.LoadOptions{Path: path})
	if err != nil {
		t.Fatalf("LoadOverlay: %v", err)
	}
	ev := policy.NewDenyOnlyFromOverlay(res.Overlay)
	subj := policy.NewSubject("corp", "admin", true)
	act := policy.Action{ToolName: "jenkins_get_job", Class: policy.EffectRead}

	denyJobs := []string{"secret", "secret/x", "team-a/job", "team-z/job/nested", "hr/payroll/run"}
	for _, j := range denyJobs {
		d := ev.Evaluate(subj, act, policy.Target{JobName: j})
		if !d.Denied() || d.ReasonCode != policy.ReasonJobPatternDeny {
			t.Fatalf("job %q must deny: %+v", j, d)
		}
	}
	allowJobs := []string{"public", "team-a/other", "hr/other", "secret-other"}
	for _, j := range allowJobs {
		d := ev.Evaluate(subj, act, policy.Target{JobName: j})
		if d.ReasonCode == policy.ReasonJobPatternDeny {
			t.Fatalf("job %q must not job-pattern-deny: %+v", j, d)
		}
	}
}

func TestJobPrefixDenyUsesGlobLite(t *testing.T) {
	t.Parallel()
	// Regression: evaluator path uses MatchDenyJobPattern (not only literal prefix).
	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:            policy.ModePilot,
		DenyJobPrefixes: []string{"team-*/prod", "infra/**", "folder/**/job"},
	})
	subj := policy.NewSubject("corp", "admin", true)
	act := policy.Action{ToolName: "jenkins_get_job"}

	d := ev.Evaluate(subj, act, policy.Target{JobName: "team-blue/prod/deploy"})
	if !d.Denied() || d.ReasonCode != policy.ReasonJobPatternDeny {
		t.Fatalf("glob child: %+v", d)
	}
	d2 := ev.Evaluate(subj, act, policy.Target{JobName: "infra/k8s/cluster"})
	if !d2.Denied() {
		t.Fatalf("/**: %+v", d2)
	}
	d3 := ev.Evaluate(subj, act, policy.Target{JobName: "team-blue/staging"})
	if !d3.Allowed() {
		t.Fatalf("non-match must allow: %+v", d3)
	}
	// Wave 29 mid-path through evaluator
	d4 := ev.Evaluate(subj, act, policy.Target{JobName: "folder/a/b/job"})
	if !d4.Denied() || d4.ReasonCode != policy.ReasonJobPatternDeny {
		t.Fatalf("mid-path **: %+v", d4)
	}
	d5 := ev.Evaluate(subj, act, policy.Target{JobName: "folder/a/other"})
	if !d5.Allowed() {
		t.Fatalf("mid-path non-match must allow: %+v", d5)
	}
}

func TestSegmentStarMultiWildcard(t *testing.T) {
	t.Parallel()
	// Multiple * in one segment
	if !policy.MatchDenyJobPattern("t*m-*", "team-a") {
		t.Fatal("multi-star segment")
	}
	if policy.MatchDenyJobPattern("t*m-*", "tox") {
		t.Fatal("false multi-star")
	}
}

// Regression: mid-path ** must not treat "folder/**/job" as bare string prefix.
func TestMidPathDoubleStarNotStringPrefix(t *testing.T) {
	t.Parallel()
	if policy.MatchDenyJobPattern("folder/**/job", "folderX/job") {
		t.Fatal("must not match across missing slash boundary")
	}
	if policy.MatchDenyJobPattern("**/secret", "mysecret") {
		t.Fatal("**/secret must not match mysecret as string suffix")
	}
}

// Wave 30 / Wave 32: limited brace expansion {a,b,c} + bounded nested braces.
func TestExpandDenyJobBraces(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want []string
		note string
	}{
		{"secret-folder", []string{"secret-folder"}, "no braces"},
		{"team-{blue,green}/app", []string{"team-blue/app", "team-green/app"}, "infix segment"},
		{"{secret,hr}/payroll/**", []string{"secret/payroll/**", "hr/payroll/**"}, "leading brace + /**"},
		{"folder/**/{job-a,job-b}", []string{"folder/**/job-a", "folder/**/job-b"}, "mid-path compose"},
		{"pre-{a,b}-post", []string{"pre-a-post", "pre-b-post"}, "within segment"},
		{"{a,b}/{c,d}", []string{"a/c", "a/d", "b/c", "b/d"}, "cartesian two groups"},
		{"x-{a,b,c}-y", []string{"x-a-y", "x-b-y", "x-c-y"}, "three alts"},
		{"team-{blue,green}-*/app", []string{"team-blue-*/app", "team-green-*/app"}, "brace + segment *"},
		// Wave 32 nested
		{"team-{blue,{green,red}}/app", []string{"team-blue/app", "team-green/app", "team-red/app"}, "nested one-deep"},
		{"{a,{b,c}}-{1,2}", []string{"a-1", "a-2", "b-1", "b-2", "c-1", "c-2"}, "nested cartesian product"},
		{"{a,{b,{c,d}}}", []string{"a", "b", "c", "d"}, "nest depth 3 flatten"},
		{"pre-{x,{y,z}}-post", []string{"pre-x-post", "pre-y-post", "pre-z-post"}, "nested mid-segment"},
		{"folder/**/{job-{a,b},other}", []string{"folder/**/job-a", "folder/**/job-b", "folder/**/other"}, "nested + mid-path **"},
		{"team-{[ab],{c,d}}/app", []string{"team-[ab]/app", "team-c/app", "team-d/app"}, "nested + class alt"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.note, func(t *testing.T) {
			t.Parallel()
			got, err := policy.ExpandDenyJobBraces(tc.in)
			if err != nil {
				t.Fatalf("ExpandDenyJobBraces(%q): %v", tc.in, err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("ExpandDenyJobBraces(%q)=%v want %v", tc.in, got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Fatalf("ExpandDenyJobBraces(%q)[%d]=%q want %q (full %v)", tc.in, i, got[i], tc.want[i], got)
				}
			}
		})
	}
}

func TestMatchDenyJobPatternBraceMatrix(t *testing.T) {
	t.Parallel()
	cases := []struct {
		pattern string
		job     string
		want    bool
		note    string
	}{
		// team-{blue,green}/app
		{"team-{blue,green}/app", "team-blue/app", true, "blue exact"},
		{"team-{blue,green}/app", "team-green/app", true, "green exact"},
		{"team-{blue,green}/app", "team-blue/app/deploy", true, "blue child"},
		{"team-{blue,green}/app", "team-green/app/x/y", true, "green deep child"},
		{"team-{blue,green}/app", "team-red/app", false, "other color"},
		{"team-{blue,green}/app", "team-blue/other", false, "wrong tail"},
		{"team-{blue,green}/app", "team-bluex/app", false, "not bare string"},

		// {secret,hr}/payroll/**
		{"{secret,hr}/payroll/**", "secret/payroll", true, "secret folder"},
		{"{secret,hr}/payroll/**", "secret/payroll/run", true, "secret child"},
		{"{secret,hr}/payroll/**", "hr/payroll/x", true, "hr child"},
		{"{secret,hr}/payroll/**", "secret/other", false, "wrong second"},
		{"{secret,hr}/payroll/**", "public/payroll", false, "other root"},

		// folder/**/{job-a,job-b}
		{"folder/**/{job-a,job-b}", "folder/job-a", true, "zero mid + a"},
		{"folder/**/{job-a,job-b}", "folder/x/y/job-b", true, "deep mid + b"},
		{"folder/**/{job-a,job-b}", "folder/x/job-a/nested", true, "mid + a child"},
		{"folder/**/{job-a,job-b}", "folder/x/job-c", false, "wrong job"},
		{"folder/**/{job-a,job-b}", "other/job-a", false, "wrong head"},

		// cartesian
		{"{a,b}/{c,d}", "a/c", true, "cartesian ac"},
		{"{a,b}/{c,d}", "b/d/child", true, "cartesian bd child"},
		{"{a,b}/{c,d}", "a/x", false, "cartesian miss"},

		// brace + segment *
		{"team-{blue,green}-*/job", "team-blue-1/job", true, "brace+star"},
		{"team-{blue,green}-*/job", "team-green-prod/job/n", true, "brace+star child"},
		{"team-{blue,green}-*/job", "team-red-1/job", false, "brace+star miss color"},

		// Wave 32 nested braces
		{"team-{blue,{green,red}}/app", "team-blue/app", true, "nest blue exact"},
		{"team-{blue,{green,red}}/app", "team-green/app/deploy", true, "nest green child"},
		{"team-{blue,{green,red}}/app", "team-red/app", true, "nest red exact"},
		{"team-{blue,{green,red}}/app", "team-yellow/app", false, "nest miss color"},
		{"{a,{b,c}}-{1,2}", "a-1", true, "nest product a-1"},
		{"{a,{b,c}}-{1,2}", "c-2/child", true, "nest product c-2 child"},
		{"{a,{b,c}}-{1,2}", "a-3", false, "nest product miss"},
		{"folder/**/{job-{a,b},other}", "folder/x/job-a", true, "nest mid ** job-a"},
		{"folder/**/{job-{a,b},other}", "folder/other/y", true, "nest mid ** other child"},
		{"folder/**/{job-{a,b},other}", "folder/x/job-c", false, "nest mid ** miss"},

		// invalid brace must not match (fail closed at match)
		{"team-{blue,green", "team-blue", false, "unclosed no match"},
		{"{a,}", "a", false, "empty alt no match"},
		{"{a,{b,}}", "a", false, "nested empty alt no match"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.note+"/"+tc.pattern+"→"+tc.job, func(t *testing.T) {
			t.Parallel()
			got := policy.MatchDenyJobPattern(tc.pattern, tc.job)
			if got != tc.want {
				t.Fatalf("MatchDenyJobPattern(%q, %q)=%v want %v (%s)",
					tc.pattern, tc.job, got, tc.want, tc.note)
			}
		})
	}
}

func TestValidateDenyJobPatternBraces(t *testing.T) {
	t.Parallel()
	valid := []string{
		"team-{blue,green}/app",
		"{secret,hr}/payroll/**",
		"folder/**/{job-a,job-b}",
		"{a,b}/{c,d}",
		"pre-{x,y}-post",
		"team-{blue,green}-*/job",
		"folder/{a,**}",       // expands to folder/a and folder/** (trailing sugar)
		"{a,b,c,d,e,f,g,h}/x", // max 8 alts
		// Wave 32 nested (≤ MaxDenyJobBraceNestDepth)
		"team-{blue,{green,red}}/app",
		"{a,{b,c}}-{1,2}",
		"{a,{b,{c,d}}}",
		"{a,{b,{c,{d,e}}}}", // depth 4 (max)
		"folder/**/{job-{a,b},other}",
		"team-{[ab],{c,d}}/app",
	}
	for _, p := range valid {
		if err := policy.ValidateDenyJobPattern(p); err != nil {
			t.Fatalf("ValidateDenyJobPattern(%q) unexpected: %v", p, err)
		}
	}

	invalid := []struct {
		p    string
		sub  string
		note string
	}{
		{"{}", "empty brace", "empty group"},
		{"{a,}", "empty brace alternative", "trailing empty alt"},
		{"{,a}", "empty brace alternative", "leading empty alt"},
		{"{a,,b}", "empty brace alternative", "mid empty alt"},
		{"{a}", "at least two", "single alt"},
		{"team-{blue,green", "unclosed", "unclosed open"},
		{"team-blue,green}", "unmatched", "stray close"},
		{"{a,{b,}}", "empty brace alternative", "nested empty alt"},
		{"{a,{b}}", "at least two", "nested single alt"},
		{"{a/b,c}", "path-segment-safe", "slash in alt"},
		{"{a,b/c}", "path-segment-safe", "slash in second alt"},
		{"{a,{b/c,d}}", "path-segment-safe", "slash in nested alt"},
		{"{*,**}", "overly broad", "expands to bare * and **"},
		{"{*}", "at least two", "single * alt"},
		// 9 alternatives > MaxDenyJobBraceAlternatives (8)
		{"{a,b,c,d,e,f,g,h,i}/x", "max alternatives", "too many alts"},
		// cartesian 8*5 = 40 > MaxDenyJobBraceExpanded (32)
		{"{a,b,c,d,e,f,g,h}/{1,2,3,4,5}", "max patterns", "expansion explosion"},
		// nested product explosion: {a,{b,c,d,e}}-{1,2,3,4,5,6,7,8} = 5*8 = 40
		{"{a,{b,c,d,e}}-{1,2,3,4,5,6,7,8}", "max patterns", "nested expansion explosion"},
		// depth 5 > MaxDenyJobBraceNestDepth (4)
		{"{a,{b,{c,{d,{e,f}}}}}", "nesting", "nest depth exceeded"},
		// invalid class still rejected (valid classes are Wave 31)
		{"team-[z-a]/app", "inverted", "inverted class range"},
		{"team-[/]/app", "character class", "slash in class"},
	}
	for _, tc := range invalid {
		err := policy.ValidateDenyJobPattern(tc.p)
		if err == nil {
			t.Fatalf("ValidateDenyJobPattern(%q) want error (%s)", tc.p, tc.note)
		}
		if apperr.CodeOf(err) != apperr.CodeInvalidArgument {
			t.Fatalf("ValidateDenyJobPattern(%q) code=%s (%s)", tc.p, apperr.CodeOf(err), tc.note)
		}
		low := strings.ToLower(err.Error())
		if tc.sub != "" && !strings.Contains(low, strings.ToLower(tc.sub)) &&
			!strings.Contains(low, "overly broad") &&
			!strings.Contains(low, "brace") &&
			!strings.Contains(low, "unsupported") &&
			!strings.Contains(low, "empty") &&
			!strings.Contains(low, "max") &&
			!strings.Contains(low, "nested") &&
			!strings.Contains(low, "nesting") &&
			!strings.Contains(low, "unclosed") &&
			!strings.Contains(low, "unmatched") &&
			!strings.Contains(low, "alternative") &&
			!strings.Contains(low, "segment") {
			if err.Error() == "" {
				t.Fatalf("empty error for %q", tc.p)
			}
		}
	}
}

func TestOverlayLoadBraceDenyJobPrefixes(t *testing.T) {
	t.Parallel()
	// Reject invalid brace at overlay Validate.
	for _, body := range []string{
		`{"version":1,"deny_job_prefixes":["team-{blue,green"]}`,
		`{"version":1,"deny_job_prefixes":["{}"]}`,
		`{"version":1,"deny_job_prefixes":["{a,}"]}`,
		`{"version":1,"deny_job_prefixes":["{a,{b,}}"]}`,
		`{"version":1,"deny_job_prefixes":["{a,{b,{c,{d,{e,f}}}}}"]}`,
		`{"version":1,"deny_job_prefixes":["{a,b,c,d,e,f,g,h,i}"]}`,
	} {
		path := filepath.Join(t.TempDir(), "overlay.json")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := policy.LoadOverlay(policy.LoadOptions{Path: path})
		if err == nil {
			t.Fatalf("LoadOverlay must fail closed for %s", body)
		}
	}

	// Accept valid brace patterns (incl. nested) and deny via evaluator.
	dir := t.TempDir()
	path := filepath.Join(dir, "overlay.json")
	body := `{
		"version": 1,
		"deny_job_prefixes": [
			"team-{blue,green}/app",
			"{secret,hr}/payroll/**",
			"folder/**/{job-a,job-b}",
			"team-{blue,{green,red}}/legacy",
			"{a,{b,c}}-{1,2}"
		]
	}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := policy.LoadOverlay(policy.LoadOptions{Path: path})
	if err != nil {
		t.Fatalf("LoadOverlay: %v", err)
	}
	ev := policy.NewDenyOnlyFromOverlay(res.Overlay)
	subj := policy.NewSubject("corp", "admin", true)
	act := policy.Action{ToolName: "jenkins_get_job", Class: policy.EffectRead}

	denyJobs := []string{
		"team-blue/app", "team-green/app/deploy",
		"secret/payroll", "hr/payroll/run",
		"folder/job-a", "folder/x/y/job-b",
		"team-blue/legacy", "team-green/legacy/x", "team-red/legacy",
		"a-1", "b-2/child", "c-1",
	}
	for _, j := range denyJobs {
		d := ev.Evaluate(subj, act, policy.Target{JobName: j})
		if !d.Denied() || d.ReasonCode != policy.ReasonJobPatternDeny {
			t.Fatalf("job %q must deny: %+v", j, d)
		}
	}
	allowJobs := []string{"team-yellow/app", "public/payroll", "folder/job-c", "team-blue/other", "team-yellow/legacy", "a-3", "d-1"}
	for _, j := range allowJobs {
		d := ev.Evaluate(subj, act, policy.Target{JobName: j})
		if d.ReasonCode == policy.ReasonJobPatternDeny {
			t.Fatalf("job %q must not job-pattern-deny: %+v", j, d)
		}
	}
}

func TestJobPrefixDenyUsesBraceExpansion(t *testing.T) {
	t.Parallel()
	// Regression: evaluator path expands braces via MatchDenyJobPattern.
	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:            policy.ModePilot,
		DenyJobPrefixes: []string{"team-{blue,green}/prod", "infra/{staging,prod}/**"},
	})
	subj := policy.NewSubject("corp", "admin", true)
	act := policy.Action{ToolName: "jenkins_get_job"}

	d := ev.Evaluate(subj, act, policy.Target{JobName: "team-blue/prod/deploy"})
	if !d.Denied() || d.ReasonCode != policy.ReasonJobPatternDeny {
		t.Fatalf("brace child: %+v", d)
	}
	d2 := ev.Evaluate(subj, act, policy.Target{JobName: "infra/staging/k8s"})
	if !d2.Denied() {
		t.Fatalf("brace /**: %+v", d2)
	}
	d3 := ev.Evaluate(subj, act, policy.Target{JobName: "team-red/prod"})
	if !d3.Allowed() {
		t.Fatalf("non-match must allow: %+v", d3)
	}
	d4 := ev.Evaluate(subj, act, policy.Target{JobName: "infra/dev/x"})
	if !d4.Allowed() {
		t.Fatalf("non-matching brace alt must allow: %+v", d4)
	}
}

// Wave 32: nested braces through the deny-only evaluator (e2e path).
func TestJobPrefixDenyUsesNestedBraceExpansion(t *testing.T) {
	t.Parallel()
	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode: policy.ModePilot,
		DenyJobPrefixes: []string{
			"team-{blue,{green,red}}/app",
			"infra/{staging,{prod,dr}}/**",
			"folder/**/{job-{a,b},other}",
		},
	})
	subj := policy.NewSubject("corp", "admin", true)
	act := policy.Action{ToolName: "jenkins_get_job"}

	denyJobs := []string{
		"team-blue/app",
		"team-green/app/deploy",
		"team-red/app",
		"infra/staging/k8s",
		"infra/prod/svc",
		"infra/dr/x/y",
		"folder/job-a",
		"folder/mid/job-b/child",
		"folder/other",
	}
	for _, j := range denyJobs {
		d := ev.Evaluate(subj, act, policy.Target{JobName: j})
		if !d.Denied() || d.ReasonCode != policy.ReasonJobPatternDeny {
			t.Fatalf("nested brace deny %q: %+v", j, d)
		}
	}
	allowJobs := []string{
		"team-yellow/app",
		"team-blue/other",
		"infra/dev/x",
		"folder/job-c",
		"other/job-a",
	}
	for _, j := range allowJobs {
		d := ev.Evaluate(subj, act, policy.Target{JobName: j})
		if d.ReasonCode == policy.ReasonJobPatternDeny {
			t.Fatalf("nested brace must not deny %q: %+v", j, d)
		}
	}
}

func TestNormalizeJobFullName(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want string
		ok   bool
		note string
	}{
		{"prod//secret", "prod/secret", true, "collapse empty segs"},
		{"/secret", "secret", true, "leading slash"},
		{"//secret", "secret", true, "double leading slash"},
		{"secret/", "secret", true, "trailing slash"},
		{"  folder/job  ", "folder/job", true, "trim space"},
		{"folder///a//job", "folder/a/job", true, "multiple empty segs"},
		{"secret", "secret", true, "already clean"},
		{"", "", false, "empty"},
		{"   ", "", false, "whitespace only"},
		{"//", "", false, "only slashes"},
		{"/", "", false, "single slash"},
		{"..", "", false, "dotdot alone"},
		{"../secret", "", false, "leading traversal"},
		{"prod/../secret", "", false, "mid traversal"},
		{"a/..", "", false, "trailing traversal"},
		{"a/../b", "", false, "mid traversal path"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.note+"/"+tc.in, func(t *testing.T) {
			t.Parallel()
			got, ok := policy.NormalizeJobFullName(tc.in)
			if ok != tc.ok || got != tc.want {
				t.Fatalf("NormalizeJobFullName(%q)=(%q,%v) want (%q,%v)",
					tc.in, got, ok, tc.want, tc.ok)
			}
		})
	}
}

// Wave 31: character classes […] for deny_job_prefixes (match-time, not expanded).
func TestMatchDenyJobPatternCharClassMatrix(t *testing.T) {
	t.Parallel()
	cases := []struct {
		pattern string
		job     string
		want    bool
		note    string
	}{
		// Set form [abc]
		{"team-[ab]/job", "team-a/job", true, "set a"},
		{"team-[ab]/job", "team-b/job", true, "set b"},
		{"team-[ab]/job", "team-a/job/nested", true, "set + child"},
		{"team-[ab]/job", "team-c/job", false, "set miss"},
		{"team-[ab]/job", "team-ab/job", false, "class is one char not multi"},
		{"team-[ab]/job", "team-/job", false, "class requires one char"},
		{"team-[ab]/job", "team-aa/job", false, "extra char after class"},

		// Range [a-z] / [0-9]
		{"env-[a-z]", "env-x", true, "alpha range"},
		{"env-[a-z]", "env-A", false, "range case sensitive"},
		{"env-[a-z]", "env-9", false, "alpha not digit"},
		{"build-[0-9]", "build-7", true, "digit range"},
		{"build-[0-9]", "build-a", false, "digit miss"},
		{"build-[0-9]", "build-17", false, "one char only"},
		{"x-[a-c][0-2]", "x-a0", true, "two classes"},
		{"x-[a-c][0-2]", "x-c2", true, "two classes edge"},
		{"x-[a-c][0-2]", "x-d0", false, "first class miss"},
		{"x-[a-c][0-2]", "x-a3", false, "second class miss"},

		// Negation [^…]
		{"p-[^s]*", "p-ublic", true, "neg + star"},
		{"p-[^s]*", "p-secret", false, "neg blocks s"},
		{"p-[^0-9]", "p-a", true, "neg range allow letter"},
		{"p-[^0-9]", "p-5", false, "neg range block digit"},
		{"p-[^0-9]", "p-ab", false, "still one char"},

		// Compose with * in same segment
		{"team-[ab]*", "team-a", true, "class + star empty"},
		{"team-[ab]*", "team-blue", true, "class + star fill"},
		{"team-[ab]*", "team-c", false, "class + star miss head"},
		{"t*[0-9]", "team1", true, "star + class"},
		{"t*[0-9]", "team", false, "star + class needs digit"},
		{"t*[0-9]", "x1", false, "star + class miss prefix"},

		// Compose with mid-path ** and trailing /**
		{"folder/**/job-[ab]", "folder/job-a", true, "mid ** + class"},
		{"folder/**/job-[ab]", "folder/x/y/job-b", true, "mid ** deep + class"},
		{"folder/**/job-[ab]", "folder/x/job-c", false, "mid ** + class miss"},
		{"team-[0-9]/**", "team-1", true, "class folder exact"},
		{"team-[0-9]/**", "team-1/deploy", true, "class folder child"},
		{"team-[0-9]/**", "team-a/deploy", false, "class folder miss"},

		// Compose with braces (expand first, then class match)
		{"team-{[ab],[cd]}/app", "team-a/app", true, "brace+class a"},
		{"team-{[ab],[cd]}/app", "team-d/app", true, "brace+class d"},
		{"team-{[ab],[cd]}/app", "team-d/app/x", true, "brace+class child"},
		{"team-{[ab],[cd]}/app", "team-e/app", false, "brace+class miss"},
		{"{env,stg}-[0-9]", "env-3", true, "brace prefix + class"},
		{"{env,stg}-[0-9]", "stg-9", true, "brace prefix stg"},
		{"{env,stg}-[0-9]", "prod-1", false, "brace prefix miss"},

		// Literal ] as first member (POSIX-style)
		{"x-[]]y", "x-]y", true, "literal close bracket member"},
		{"x-[]]y", "x-ay", false, "literal ] only member"},

		// Invalid class must not match (fail closed at match)
		{"team-[", "team-a", false, "unclosed no match"},
		{"team-[]", "team-", false, "empty class no match"},
		{"team-[z-a]", "team-a", false, "inverted no match"},

		// Bare string prefix still must not match across class boundary
		{"team-[ab]", "team-ab", false, "not multi-char bare"},
		{"team-[ab]", "team-a/extra", true, "exact class segment + child"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.note+"/"+tc.pattern+"→"+tc.job, func(t *testing.T) {
			t.Parallel()
			got := policy.MatchDenyJobPattern(tc.pattern, tc.job)
			if got != tc.want {
				t.Fatalf("MatchDenyJobPattern(%q, %q)=%v want %v (%s)",
					tc.pattern, tc.job, got, tc.want, tc.note)
			}
		})
	}
}

func TestValidateDenyJobPatternCharClasses(t *testing.T) {
	t.Parallel()
	valid := []string{
		"team-[ab]/job",
		"env-[a-z]",
		"build-[0-9]",
		"x-[a-c][0-2]",
		"p-[^s]*",
		"p-[^0-9]",
		"team-[ab]*",
		"folder/**/job-[ab]",
		"team-[0-9]/**",
		"team-{[ab],[cd]}/app",
		"{env,stg}-[0-9]",
		"x-[]]y",
		"pre-[A-Za-z0-9_]-post",
		"*/job-[xy]",
	}
	for _, p := range valid {
		if err := policy.ValidateDenyJobPattern(p); err != nil {
			t.Fatalf("ValidateDenyJobPattern(%q) unexpected: %v", p, err)
		}
	}

	invalid := []struct {
		p    string
		sub  string
		note string
	}{
		{"team-[", "unclosed", "unclosed open"},
		{"team-[ab", "unclosed", "unclosed mid"},
		{"team-[]", "empty character class", "empty []"},
		{"team-[^]", "unclosed", "[^] needs closer after literal ]"},
		{"team-[z-a]", "inverted", "inverted range"},
		{"team-[9-0]", "inverted", "inverted digit range"},
		// Class cannot contain / — path split yields unclosed on first segment.
		{"a[b/c]d", "unclosed", "class spanning slash → unclosed on first seg"},
		{"foo?", "unsupported", "question still unsupported"},
		{`foo\x`, "unsupported", "backslash still unsupported"},
		// Bare * still rejected after any expand path
		{"*", "overly broad", "bare star"},
	}
	for _, tc := range invalid {
		err := policy.ValidateDenyJobPattern(tc.p)
		if err == nil {
			t.Fatalf("ValidateDenyJobPattern(%q) want error (%s)", tc.p, tc.note)
		}
		if apperr.CodeOf(err) != apperr.CodeInvalidArgument {
			t.Fatalf("ValidateDenyJobPattern(%q) code=%s (%s)", tc.p, apperr.CodeOf(err), tc.note)
		}
		low := strings.ToLower(err.Error())
		if tc.sub != "" && !strings.Contains(low, strings.ToLower(tc.sub)) &&
			!strings.Contains(low, "character class") &&
			!strings.Contains(low, "unclosed") &&
			!strings.Contains(low, "empty") &&
			!strings.Contains(low, "inverted") &&
			!strings.Contains(low, "unsupported") &&
			!strings.Contains(low, "overly broad") {
			if err.Error() == "" {
				t.Fatalf("empty error for %q", tc.p)
			}
		}
	}
}

func TestOverlayLoadCharClassDenyJobPrefixes(t *testing.T) {
	t.Parallel()
	// Reject invalid classes at overlay Validate.
	for _, body := range []string{
		`{"version":1,"deny_job_prefixes":["team-["]}`,
		`{"version":1,"deny_job_prefixes":["team-[]"]}`,
		`{"version":1,"deny_job_prefixes":["team-[z-a]"]}`,
		`{"version":1,"deny_job_prefixes":["a[b/c]d"]}`,
	} {
		path := filepath.Join(t.TempDir(), "overlay.json")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := policy.LoadOverlay(policy.LoadOptions{Path: path})
		if err == nil {
			t.Fatalf("LoadOverlay must fail closed for %s", body)
		}
	}

	// Accept valid classes and deny via evaluator.
	dir := t.TempDir()
	path := filepath.Join(dir, "overlay.json")
	body := `{
		"version": 1,
		"deny_job_prefixes": ["team-[ab]/job", "env-[0-9]/**", "folder/**/x-[yz]", "p-[^s]*"]
	}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := policy.LoadOverlay(policy.LoadOptions{Path: path})
	if err != nil {
		t.Fatalf("LoadOverlay: %v", err)
	}
	ev := policy.NewDenyOnlyFromOverlay(res.Overlay)
	subj := policy.NewSubject("corp", "admin", true)
	act := policy.Action{ToolName: "jenkins_get_job", Class: policy.EffectRead}

	denyJobs := []string{
		"team-a/job", "team-b/job/nested",
		"env-3", "env-9/deploy",
		"folder/x-y", "folder/a/b/x-z",
		"p-ublic", "p-rod/x",
	}
	for _, j := range denyJobs {
		d := ev.Evaluate(subj, act, policy.Target{JobName: j})
		if !d.Denied() || d.ReasonCode != policy.ReasonJobPatternDeny {
			t.Fatalf("job %q must deny: %+v", j, d)
		}
	}
	allowJobs := []string{
		"team-c/job", "team-ab/job",
		"env-a/deploy",
		"folder/x-a", "folder/other",
		"p-secret", "public",
	}
	for _, j := range allowJobs {
		d := ev.Evaluate(subj, act, policy.Target{JobName: j})
		if d.ReasonCode == policy.ReasonJobPatternDeny {
			t.Fatalf("job %q must not job-pattern-deny: %+v", j, d)
		}
	}
}

func TestJobPrefixDenyUsesCharClasses(t *testing.T) {
	t.Parallel()
	// Regression: evaluator path uses MatchDenyJobPattern with classes.
	ev := policy.NewDenyOnlyEvaluator(policy.Document{
		Mode:            policy.ModePilot,
		DenyJobPrefixes: []string{"team-[ab]/prod", "infra-[0-9]/**", "team-{[xy],[zw]}/app"},
	})
	subj := policy.NewSubject("corp", "admin", true)
	act := policy.Action{ToolName: "jenkins_get_job"}

	d := ev.Evaluate(subj, act, policy.Target{JobName: "team-a/prod/deploy"})
	if !d.Denied() || d.ReasonCode != policy.ReasonJobPatternDeny {
		t.Fatalf("class child: %+v", d)
	}
	d2 := ev.Evaluate(subj, act, policy.Target{JobName: "infra-2/k8s"})
	if !d2.Denied() {
		t.Fatalf("class /**: %+v", d2)
	}
	d3 := ev.Evaluate(subj, act, policy.Target{JobName: "team-z/app"})
	if !d3.Denied() {
		t.Fatalf("brace+class: %+v", d3)
	}
	d4 := ev.Evaluate(subj, act, policy.Target{JobName: "team-c/prod"})
	if !d4.Allowed() {
		t.Fatalf("non-match must allow: %+v", d4)
	}
	d5 := ev.Evaluate(subj, act, policy.Target{JobName: "infra-a/x"})
	if !d5.Allowed() {
		t.Fatalf("class miss must allow: %+v", d5)
	}
}

// Regression: character class matches exactly one path character, not a multi-char span.
func TestCharClassOneCharNotMulti(t *testing.T) {
	t.Parallel()
	if policy.MatchDenyJobPattern("j-[ab]", "j-ab") {
		t.Fatal("Regression: [ab] must not match multi-char ab")
	}
	if !policy.MatchDenyJobPattern("j-[ab]", "j-a") {
		t.Fatal("Regression: [ab] must match single a")
	}
}
