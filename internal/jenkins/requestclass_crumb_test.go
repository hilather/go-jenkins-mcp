package jenkins_test

import (
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/jenkins"
)

// Regression: a job or folder literally named "crumbIssuer" must not be
// classified as auth traffic. isAuthPath used a bare substring match, so
// POST /job/crumbIssuer/build classified as RequestAuth — and auth traffic
// never requires mutation permission, silently bypassing the POL-004
// read-only/mutation network guard for every write endpoint of such a job.
func TestClassifyJenkinsRequest_JobNamedCrumbIssuerIsNotAuth(t *testing.T) {
	t.Parallel()
	cases := []struct {
		method string
		path   string
		want   jenkins.RequestClass
	}{
		// Real crumb endpoint (root only) stays auth.
		{"GET", "/crumbIssuer/api/json", jenkins.RequestAuth},
		{"GET", "/crumbissuer/api/json", jenkins.RequestAuth},
		{"GET", "/crumbIssuer/api/xml", jenkins.RequestAuth},
		// Job/folder named crumbIssuer: writes are mutations, reads are reads.
		{"POST", "/job/crumbIssuer/build", jenkins.RequestMutate},
		{"POST", "/job/crumbIssuer/buildWithParameters", jenkins.RequestMutate},
		{"POST", "/job/folder/job/crumbIssuer/5/stop", jenkins.RequestMutate},
		{"POST", "/job/crumbIssuer/1/kill", jenkins.RequestMutate},
		{"GET", "/job/crumbIssuer/api/json", jenkins.RequestRead},
		{"GET", "/job/crumbIssuer/1/consoleText", jenkins.RequestRead},
		// Unclassified writes still fail closed.
		{"POST", "/job/crumbIssuer/config.xml", jenkins.RequestUnclassified},
	}
	for _, tc := range cases {
		if got := jenkins.ClassifyJenkinsRequest(tc.method, tc.path); got != tc.want {
			t.Errorf("ClassifyJenkinsRequest(%s, %q) = %s, want %s", tc.method, tc.path, got, tc.want)
		}
	}
}
