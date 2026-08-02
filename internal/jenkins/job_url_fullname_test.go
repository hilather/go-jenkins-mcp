package jenkins_test

import (
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/jenkins"
)

func TestFullNameFromJobURL(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"http://jenkins.example/job/demo/", "demo"},
		{"https://j/ci/job/folder/job/demo/", "folder/demo"},
		{"/job/a/job/b/job/c/", "a/b/c"},
		{"http://j/job/team%20x/job/app/", "team x/app"},
		{"http://j/job/demo/7/", "demo"}, // build number not a job segment after /job/
		{"", ""},
		{"http://j/queue/item/1/", ""},
		{"not-a-url", ""},
	}
	for _, tc := range cases {
		got := jenkins.FullNameFromJobURL(tc.in)
		if got != tc.want {
			t.Fatalf("FullNameFromJobURL(%q)=%q want %q", tc.in, got, tc.want)
		}
	}
}
