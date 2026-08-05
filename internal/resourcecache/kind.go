package resourcecache

// ResourceKind identifies a canonical cacheable source kind.
type ResourceKind string

const (
	// KindArtifactBlob is the exact Jenkins artifact body (immutable_blob).
	KindArtifactBlob ResourceKind = "artifact_blob"
	// KindArtifactCatalog is list_artifacts metadata (structured_resource).
	KindArtifactCatalog ResourceKind = "artifact_catalog"
	// KindArtifactText is a bounded text artifact slice (structured; may reference blob).
	KindArtifactText ResourceKind = "artifact_text"
	// KindArtifactInspection is inspect_artifact output (derived_result).
	KindArtifactInspection ResourceKind = "artifact_inspection"
	// KindTestReport is JUnit test report summary + failed cases (structured).
	KindTestReport ResourceKind = "test_report"
	// KindPipelineStages is Pipeline stage graph (structured).
	KindPipelineStages ResourceKind = "pipeline_stages"
	// KindBuildChanges is SCM changeSets for a build (structured).
	KindBuildChanges ResourceKind = "build_changes"
	// KindStageLog is Pipeline stage/node log text (stream_log-like structured text;
	// not progressive console frames).
	KindStageLog ResourceKind = "stage_log"
)

// StorageClass is the physical storage class for a kind.
type StorageClass string

const (
	ClassImmutableBlob     StorageClass = "immutable_blob"
	ClassStructured        StorageClass = "structured_resource"
	ClassDerived           StorageClass = "derived_result"
	ClassStreamLogResidual StorageClass = "stream_log" // stage logs as complete/partial text entries
)

// KindInfo describes class and defaults for a kind.
type KindInfo struct {
	Kind  ResourceKind
	Class StorageClass
	// DefaultShare is subject_private until fleet sharing is proven.
	DefaultShare AuthorizationScope
}

// KnownKinds returns the approved resource kinds for this expansion.
func KnownKinds() []KindInfo {
	return []KindInfo{
		{Kind: KindArtifactBlob, Class: ClassImmutableBlob, DefaultShare: ScopeSubjectPrivate},
		{Kind: KindArtifactCatalog, Class: ClassStructured, DefaultShare: ScopeSubjectPrivate},
		{Kind: KindArtifactText, Class: ClassStructured, DefaultShare: ScopeSubjectPrivate},
		{Kind: KindArtifactInspection, Class: ClassDerived, DefaultShare: ScopeSubjectPrivate},
		{Kind: KindTestReport, Class: ClassStructured, DefaultShare: ScopeSubjectPrivate},
		{Kind: KindPipelineStages, Class: ClassStructured, DefaultShare: ScopeSubjectPrivate},
		{Kind: KindBuildChanges, Class: ClassStructured, DefaultShare: ScopeSubjectPrivate},
		{Kind: KindStageLog, Class: ClassStreamLogResidual, DefaultShare: ScopeSubjectPrivate},
	}
}

// Valid reports whether k is a known resource kind.
func (k ResourceKind) Valid() bool {
	for _, info := range KnownKinds() {
		if info.Kind == k {
			return true
		}
	}
	return false
}

// ClassOf returns the storage class for k, or empty if unknown.
func ClassOf(k ResourceKind) StorageClass {
	for _, info := range KnownKinds() {
		if info.Kind == k {
			return info.Class
		}
	}
	return ""
}

// RequiresArtifactAuth is true when Selector (or ArtifactPath) is a Jenkins
// artifact path that must be re-checked with artifact policy on cache hits.
// Stage-log and other non-artifact kinds must never treat Selector as an
// artifact path (e.g. stage id must not Evaluate jenkins_get_artifact_text).
func RequiresArtifactAuth(k ResourceKind) bool {
	switch k {
	case KindArtifactBlob, KindArtifactText, KindArtifactInspection:
		return true
	default:
		return false
	}
}
