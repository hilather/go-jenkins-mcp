package policy

import "github.com/hilather/go-jenkins-mcp/internal/jenkins"

// Re-export Jenkins request classification for policy-layer callers (POL-004).
// Canonical implementation lives in package jenkins so the client can classify
// without importing policy (FND-004 boundary).

// ClassifyJenkinsRequest marks method+path for enforcement PEPs.
func ClassifyJenkinsRequest(method, path string) jenkins.RequestClass {
	return jenkins.ClassifyJenkinsRequest(method, path)
}

// RequiresMutationPermission reports whether class needs RO/mutation allow.
func RequiresMutationPermission(class jenkins.RequestClass) bool {
	return jenkins.RequiresMutationPermission(class)
}
