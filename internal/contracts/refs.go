package contracts

import "fmt"

// ProfileID identifies a named Jenkins connection profile.
type ProfileID string

// String returns the profile id, or "" if empty.
func (p ProfileID) String() string { return string(p) }

// Valid reports whether the profile id is non-empty after trim-like checks.
func (p ProfileID) Valid() bool { return string(p) != "" }

// JobRef identifies a job within an optional profile scope.
// FullName is the Jenkins full name (may include folder path separators).
type JobRef struct {
	Profile  ProfileID `json:"profile,omitempty"`
	FullName string    `json:"full_name"`
}

// String returns a stable display form.
func (j JobRef) String() string {
	if j.Profile == "" {
		return j.FullName
	}
	return fmt.Sprintf("%s@%s", j.FullName, j.Profile)
}

// Valid reports whether the job full name is set.
func (j JobRef) Valid() bool { return j.FullName != "" }

// BuildRef identifies a build of a job.
type BuildRef struct {
	Job    JobRef `json:"job"`
	Number int64  `json:"number"`
}

// String returns job#number.
func (b BuildRef) String() string {
	return fmt.Sprintf("%s#%d", b.Job.String(), b.Number)
}

// Valid reports whether job is valid and number is positive.
func (b BuildRef) Valid() bool { return b.Job.Valid() && b.Number > 0 }

// QueueItemRef identifies an item in the Jenkins build queue.
type QueueItemRef struct {
	Profile ProfileID `json:"profile,omitempty"`
	ID      int64     `json:"id"`
}

// String returns a stable display form.
func (q QueueItemRef) String() string {
	if q.Profile == "" {
		return fmt.Sprintf("queue:%d", q.ID)
	}
	return fmt.Sprintf("queue:%d@%s", q.ID, q.Profile)
}

// Valid reports whether the queue id is positive.
func (q QueueItemRef) Valid() bool { return q.ID > 0 }

// LogGenerationRef identifies a progressive-log generation/segment for a build.
// Generation is opaque to callers; the logmirror/store packages own its meaning.
type LogGenerationRef struct {
	Build      BuildRef `json:"build"`
	Generation string   `json:"generation"`
}

// String returns a stable display form.
func (l LogGenerationRef) String() string {
	return fmt.Sprintf("%s/log:%s", l.Build.String(), l.Generation)
}

// Valid reports whether build is valid and generation is non-empty.
func (l LogGenerationRef) Valid() bool { return l.Build.Valid() && l.Generation != "" }

// StageRef identifies a Pipeline stage (or equivalent) within a build.
type StageRef struct {
	Build BuildRef `json:"build"`
	ID    string   `json:"id"`
	Name  string   `json:"name,omitempty"`
}

// String returns a stable display form.
func (s StageRef) String() string {
	if s.Name != "" {
		return fmt.Sprintf("%s/stage:%s(%s)", s.Build.String(), s.ID, s.Name)
	}
	return fmt.Sprintf("%s/stage:%s", s.Build.String(), s.ID)
}

// Valid reports whether build is valid and stage id is non-empty.
func (s StageRef) Valid() bool { return s.Build.Valid() && s.ID != "" }

// TestRef identifies a test result within a build.
type TestRef struct {
	Build     BuildRef `json:"build"`
	Suite     string   `json:"suite,omitempty"`
	ClassName string   `json:"class_name,omitempty"`
	Name      string   `json:"name"`
}

// String returns a stable display form.
func (t TestRef) String() string {
	parts := t.Name
	if t.ClassName != "" {
		parts = t.ClassName + "." + parts
	}
	if t.Suite != "" {
		parts = t.Suite + "/" + parts
	}
	return fmt.Sprintf("%s/test:%s", t.Build.String(), parts)
}

// Valid reports whether build is valid and test name is non-empty.
func (t TestRef) Valid() bool { return t.Build.Valid() && t.Name != "" }

// ArtifactRef identifies a build artifact path.
type ArtifactRef struct {
	Build BuildRef `json:"build"`
	Path  string   `json:"path"`
}

// String returns a stable display form.
func (a ArtifactRef) String() string {
	return fmt.Sprintf("%s/artifact:%s", a.Build.String(), a.Path)
}

// Valid reports whether build is valid and path is non-empty.
func (a ArtifactRef) Valid() bool { return a.Build.Valid() && a.Path != "" }

// NodeRef identifies a Jenkins agent/computer node.
type NodeRef struct {
	Profile ProfileID `json:"profile,omitempty"`
	Name    string    `json:"name"`
}

// String returns a stable display form.
func (n NodeRef) String() string {
	if n.Profile == "" {
		return "node:" + n.Name
	}
	return fmt.Sprintf("node:%s@%s", n.Name, n.Profile)
}

// Valid reports whether the node name is non-empty.
func (n NodeRef) Valid() bool { return n.Name != "" }
