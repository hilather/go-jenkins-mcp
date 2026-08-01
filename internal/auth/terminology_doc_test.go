package auth_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// AUTH-000: fail closed on affirmative claims that stock Jenkins is a 3LO /
// OAuth authorization server or "Jenkins OAuth provider".
//
// Lines that discuss the prohibition (negation / contingency wording) are
// allowed. Keep patterns narrow to avoid false positives on backlog text such
// as "AgentCore … Jenkins 3LO/OBO" (3LO against Entra for a Jenkins resource).

var affirmativeJenkinsASClaims = []*regexp.Regexp{
	// "Jenkins is a native 3LO provider", "Jenkins acts as an OAuth authorization server", etc.
	regexp.MustCompile(`(?i)Jenkins\s+(is|acts\s+as|serves\s+as)\s+(a\s+|an\s+|the\s+)?(native\s+)?(3LO|three-legged(\s+OAuth)?|OAuth(\s+authorization)?\s+server|OAuth\s+provider)`),
	// Bare product phrase that implies Jenkins hosts OAuth for third parties.
	regexp.MustCompile(`(?i)\bJenkins\s+OAuth\s+provider\b`),
	// "use Jenkins as the OAuth authorization server / 3LO provider"
	regexp.MustCompile(`(?i)\buse\s+Jenkins\s+(as\s+)?(the\s+|an\s+|a\s+)?(native\s+)?(OAuth\s+)?(authorization\s+server|3LO\s+provider|OAuth\s+provider)\b`),
	// Affirmative availability of native Jenkins 3LO.
	regexp.MustCompile(`(?i)\bnative\s+Jenkins\s+3LO\s+(is\s+)?(supported|available|enabled|provided)\b`),
	regexp.MustCompile(`(?i)\bJenkins\s+provides\s+(native\s+)?(3LO|three-legged\s+OAuth)\b`),
}

// Negation / contingency wording on the same or previous line exempts a match
// (markdown hard-wrap often splits "never" from the claim).
var claimNegation = regexp.MustCompile(`(?i)(\bnot\b|\bnever\b|\bno\b|\bwithout\b|\black\b|\bfalse\b|\bdon'?t\b|\bcannot\b|\bmust\s+not\b|\bmust\s+never\b|\bisn'?t\b|\baren'?t\b|\bout\s+of\s+scope\b|\bunavailable\b|\bnot\s+available\b|\bprohibit\b|\bforbid\b|\breject\b|\bwrong\b|\bexclude\b|\blast\s+resort\b|\bonly\s+if\b|\bconditional\b|\bcontingency\b|\bdeferred\b|\bdo\s+not\b|\bdoes\s+not\b|\bdefault\s+no-go\b|\bno-go\b|\bdecision-gated\b|\bgated\b|\bnon-solution\b|\bnot\s+a\b|\bnever\s+label\b|\bnever\s+claim\b|\bfail\s+if\b|\bforbidden\b)`)

var scanExt = map[string]bool{
	".md": true,
	".go": true,
}

// Skip generated/vendor-ish noise and Windows Zone.Identifier sidecars.
func skipPath(rel string) bool {
	base := filepath.Base(rel)
	if strings.HasSuffix(base, ":Zone.Identifier") || strings.Contains(base, "Zone.Identifier") {
		return true
	}
	switch {
	case strings.HasPrefix(rel, "vendor"+string(os.PathSeparator)):
		return true
	case strings.HasPrefix(rel, ".git"+string(os.PathSeparator)):
		return true
	case strings.Contains(rel, string(os.PathSeparator)+"testdata"+string(os.PathSeparator)):
		// Allow fixtures to embed counter-examples without failing the walk.
		return true
	}
	return false
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("go.mod not found at %s: %v", root, err)
	}
	return root
}

func TestTerminologyNoFalseJenkinsASClaims(t *testing.T) {
	t.Parallel()
	root := moduleRoot(t)
	var hits []string

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			name := info.Name()
			if name == ".git" || name == "vendor" || name == "bin" || name == "dist" {
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if skipPath(rel) {
			return nil
		}
		if !scanExt[filepath.Ext(path)] {
			return nil
		}
		// Do not fail the test file for documenting the patterns it detects.
		if strings.HasSuffix(rel, "terminology_doc_test.go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		lines := strings.Split(string(data), "\n")
		for i, line := range lines {
			// Markdown wraps often put "never/not" on the previous line.
			window := line
			if i > 0 {
				window = lines[i-1] + " " + line
			}
			if claimNegation.MatchString(window) {
				continue
			}
			for _, re := range affirmativeJenkinsASClaims {
				if re.MatchString(line) {
					hits = append(hits, rel+":"+strconv.Itoa(i+1)+": "+strings.TrimSpace(line))
					break
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) > 0 {
		t.Fatalf("AUTH-000 terminology: affirmative Jenkins-as-AS/3LO claims (add negation or reword):\n  %s",
			strings.Join(hits, "\n  "))
	}
}

// TestTerminologyDetectorCatchesAffirmativeClaims is a Regression: canary that
// the scanner would catch a false product claim if it appeared without negation.
func TestTerminologyDetectorCatchesAffirmativeClaims(t *testing.T) {
	t.Parallel()
	// Construct strings so this file is not itself a walk hit if skip fails.
	bad := []string{
		"Jenkins " + "is a native 3LO provider for MCP clients.",
		"Configure the " + "Jenkins OAuth provider" + " in Cursor.",
		"We " + "use Jenkins as the OAuth authorization server" + " for agents.",
		"Native " + "Jenkins 3LO is supported" + " in GA.",
		"Jenkins " + "provides native 3LO" + " for third-party apps.",
	}
	for _, line := range bad {
		if claimNegation.MatchString(line) {
			t.Fatalf("canary line unexpectedly negated: %q", line)
		}
		matched := false
		for _, re := range affirmativeJenkinsASClaims {
			if re.MatchString(line) {
				matched = true
				break
			}
		}
		if !matched {
			t.Fatalf("detector missed affirmative claim: %q", line)
		}
	}
	// Negated line must not match as a hit under the walk rule.
	ok := "Jenkins is not a native 3LO provider."
	if !claimNegation.MatchString(ok) {
		t.Fatal("expected negation on ok line")
	}
}
