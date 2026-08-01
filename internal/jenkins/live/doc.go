//go:build live_jenkins

// Package live holds optional Jenkins LTS integration smoke tests (TST-001).
//
// Build with -tags=live_jenkins and set JENKINS_URL plus ephemeral credentials.
// Default `go test ./...` excludes this package (build constraint).
//
// See testdata/jenkins-compose/ and scripts/jenkins-live-smoke.sh.
package live
