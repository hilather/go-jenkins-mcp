// Package resourcecache is the typed non-log resource cache control plane.
//
// It stores immutable artifact blobs, structured Jenkins source objects
// (catalogs, test reports, pipeline stages, SCM changes), and disposable
// derived results (inspection, future ratarmount indexes) separately from the
// progressive console-log frame store in internal/store.
//
// Compatibility: metadata.sqlite / frames / L2 packs / fleet log protocol v1 are
// untouched. New data lives under resources.sqlite and objects/ per profile.
//
// Security: every Get/GetOrFetch requires AccessContext; cache presence never
// grants access. AuthorizationVerifier re-checks job/artifact policy on hits.
// Incomplete/partial objects are never sealed as complete.
package resourcecache
