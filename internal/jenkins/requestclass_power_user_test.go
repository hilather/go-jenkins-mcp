package jenkins_test

import (
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/jenkins"
)

func TestClassifyJenkinsRequest_PowerUserPaths(t *testing.T) {
	cases := []struct {
		method, path string
		want         jenkins.RequestClass
	}{
		{"POST", "/job/foo/1/term", jenkins.RequestMutate},
		{"POST", "/job/foo/1/kill", jenkins.RequestMutate},
		{"POST", "/job/a/job/b/enable", jenkins.RequestMutate},
		{"POST", "/job/a/disable", jenkins.RequestMutate},
		{"POST", "/job/foo/3/toggleLogKeepForever", jenkins.RequestMutate},
		{"POST", "/job/foo/3/submitDescription", jenkins.RequestMutate},
		{"POST", "/job/foo/3/replay/rebuild", jenkins.RequestMutate},
		{"POST", "/job/foo/3/rebuild", jenkins.RequestMutate},
		// Admin surfaces must remain unclassified (fail closed under RO).
		{"POST", "/scriptText", jenkins.RequestUnclassified},
		{"POST", "/job/foo/config.xml", jenkins.RequestUnclassified},
		{"POST", "/pluginManager/installNecessaryPlugins", jenkins.RequestUnclassified},
		{"POST", "/quietDown", jenkins.RequestUnclassified},
	}
	for _, tc := range cases {
		got := jenkins.ClassifyJenkinsRequest(tc.method, tc.path)
		if got != tc.want {
			t.Fatalf("%s %s: got %s want %s", tc.method, tc.path, got, tc.want)
		}
		if jenkins.RequiresMutationPermission(got) != (tc.want != jenkins.RequestRead && tc.want != jenkins.RequestAuth) {
			// mutate + unclassified require permission
			if tc.want == jenkins.RequestMutate || tc.want == jenkins.RequestUnclassified {
				if !jenkins.RequiresMutationPermission(got) {
					t.Fatalf("RequiresMutationPermission false for %s", tc.path)
				}
			}
		}
	}
}
