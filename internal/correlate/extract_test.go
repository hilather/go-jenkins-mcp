package correlate_test

import (
	"strings"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/correlate"
)

func TestExtractJiraKeysFromParams(t *testing.T) {
	t.Parallel()
	res := correlate.ExtractFromParams(map[string]string{
		"JIRA_ISSUE": "PROJ-42",
		"BRANCH":     "feature/ABC-99-fix",
		"API_TOKEN":  "super-secret-token-value",
		"NOTES":      "See PROJ-42 and https://github.com/acme/demo/issues/7",
	}, correlate.ExtractOptions{})
	if res.MaxItems != correlate.DefaultMaxItems {
		t.Fatalf("max=%d", res.MaxItems)
	}
	kinds := map[string]int{}
	ids := map[string]bool{}
	for _, it := range res.Items {
		kinds[it.Kind]++
		ids[it.ID] = true
		if strings.Contains(it.ID, "super-secret") || strings.Contains(it.URL, "super-secret") {
			t.Fatalf("secret leaked: %+v", it)
		}
	}
	if !ids["PROJ-42"] {
		t.Fatalf("missing PROJ-42: %+v", res.Items)
	}
	if !ids["ABC-99"] {
		t.Fatalf("missing ABC-99: %+v", res.Items)
	}
	if !ids["acme/demo#7"] {
		t.Fatalf("missing github issue: %+v", res.Items)
	}
	// Sensitive key never scanned as value source for secrets.
	for _, it := range res.Items {
		if it.SourceKey == "API_TOKEN" {
			t.Fatal("read sensitive key")
		}
	}
}

func TestExtractFromChangeSets(t *testing.T) {
	t.Parallel()
	res := correlate.ExtractFromChangeSets([]correlate.SCMChangeSetInput{
		{
			Kind:     "git",
			RepoURLs: []string{"https://user:pass@github.com/acme/demo.git"},
			Commits: []correlate.SCMCommitInput{
				{
					ID:      "4bf92f3577b34da6a3ce929d0e0e4736a3ce929d",
					Message: "fix: PROJ-7 and https://github.com/acme/demo/pull/3",
				},
			},
		},
	}, correlate.ExtractOptions{})
	var hasSHA, hasJira, hasPR, hasHost bool
	for _, it := range res.Items {
		if strings.Contains(strings.ToLower(it.URL), "pass") || strings.Contains(it.ID, "pass") {
			t.Fatalf("credential in output: %+v", it)
		}
		switch it.Kind {
		case correlate.KindCommitSHA:
			hasSHA = true
		case correlate.KindJiraKey:
			if it.ID == "PROJ-7" {
				hasJira = true
			}
		case correlate.KindGitHubPR:
			hasPR = true
		case correlate.KindSCMHost:
			hasHost = true
			if it.Host != "github.com" {
				t.Fatalf("host=%q", it.Host)
			}
		}
	}
	if !hasSHA || !hasJira || !hasPR || !hasHost {
		t.Fatalf("missing items sha=%v jira=%v pr=%v host=%v items=%+v",
			hasSHA, hasJira, hasPR, hasHost, res.Items)
	}
}

func TestExtractBounds(t *testing.T) {
	t.Parallel()
	params := map[string]string{}
	for i := 0; i < 50; i++ {
		params[string(rune('A'+i%26))+string(rune('A'+(i/26)%26))] = "KEY-" + itoa(i+1)
	}
	// Simpler: many keys in one text.
	text := ""
	for i := 1; i <= 40; i++ {
		text += " KEY-" + itoa(i)
	}
	res := correlate.ExtractFromText(text, correlate.SourceCause, correlate.ExtractOptions{MaxItems: 5})
	if len(res.Items) != 5 {
		t.Fatalf("len=%d want 5", len(res.Items))
	}
	if !res.Truncated {
		t.Fatal("expected truncated")
	}
	if res.MaxItems != 5 {
		t.Fatalf("max=%d", res.MaxItems)
	}
}

func TestHardMaxItems(t *testing.T) {
	t.Parallel()
	text := ""
	for i := 1; i <= 100; i++ {
		text += " ZZ-" + itoa(i)
	}
	res := correlate.ExtractFromText(text, "", correlate.ExtractOptions{MaxItems: 1000})
	if res.MaxItems != correlate.HardMaxItems {
		t.Fatalf("max=%d want hard %d", res.MaxItems, correlate.HardMaxItems)
	}
	if len(res.Items) > correlate.HardMaxItems {
		t.Fatalf("len=%d", len(res.Items))
	}
}

func TestMergeResults(t *testing.T) {
	t.Parallel()
	a := correlate.ExtractFromParams(map[string]string{"JIRA": "AA-1"}, correlate.ExtractOptions{})
	b := correlate.ExtractFromText("BB-2", correlate.SourceCause, correlate.ExtractOptions{})
	m := correlate.MergeResults(correlate.ExtractOptions{MaxItems: 10}, a, b)
	if len(m.Items) < 2 {
		t.Fatalf("items=%+v", m.Items)
	}
}

func TestNormalizeRejectsNonSHA(t *testing.T) {
	t.Parallel()
	res := correlate.ExtractFromChangeSets([]correlate.SCMChangeSetInput{
		{Commits: []correlate.SCMCommitInput{{ID: "not-a-sha"}, {ID: "1234567"}}},
	}, correlate.ExtractOptions{})
	for _, it := range res.Items {
		if it.Kind == correlate.KindCommitSHA {
			t.Fatalf("unexpected sha: %+v", it)
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [16]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
