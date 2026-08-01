package jenkins_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/jenkins"
)

func TestRouteMatrix_CoversKnownAPIPathMarkers(t *testing.T) {
	t.Parallel()
	doc := jenkins.KnownRouteMatrix()
	if doc.Version != jenkins.RouteMatrixVersion {
		t.Fatalf("version=%d", doc.Version)
	}
	if len(doc.Routes) == 0 {
		t.Fatal("empty routes")
	}
	for _, marker := range jenkins.KnownAPIPathMarkers() {
		if !jenkins.MatrixCoversMarker(doc, marker) {
			t.Errorf("TST-001: known API path marker %q missing from route matrix — "+
				"add a RouteEntry (and update docs/tst/route-matrix.json)", marker)
		}
	}
}

func TestRouteMatrix_ClassesConsistentWithClassifier(t *testing.T) {
	t.Parallel()
	// Spot-check concrete paths against ClassifyJenkinsRequest.
	cases := []struct {
		method, path string
		want         jenkins.RouteClass
	}{
		{"GET", "/whoAmI/api/json", jenkins.RouteClassRead},
		{"GET", "/crumbIssuer/api/json", jenkins.RouteClassAuth},
		{"POST", "/crumbIssuer/api/json", jenkins.RouteClassAuth},
		{"GET", "/api/json?tree=", jenkins.RouteClassRead},
		{"GET", "/job/demo/7/logText/progressiveText?start=0", jenkins.RouteClassRead},
		{"POST", "/job/demo/buildWithParameters", jenkins.RouteClassMutation},
		{"POST", "/job/demo/7/stop", jenkins.RouteClassMutation},
		{"POST", "/job/demo/7/kill", jenkins.RouteClassMutation},
		{"GET", "/queue/api/json", jenkins.RouteClassRead},
		{"GET", "/computer/api/json", jenkins.RouteClassRead},
		{"GET", "/job/demo/7/artifact/out.txt", jenkins.RouteClassRead},
		{"GET", "/job/demo/7/wfapi/describe", jenkins.RouteClassRead},
	}
	for _, tc := range cases {
		got := jenkins.ClassifyPathPattern(tc.method, tc.path)
		if got != tc.want {
			t.Errorf("%s %s: class=%s want %s", tc.method, tc.path, got, tc.want)
		}
	}

	// Every matrix mutation route must classify at least one sample as mutate.
	doc := jenkins.KnownRouteMatrix()
	for _, r := range doc.Routes {
		if r.Class != jenkins.RouteClassMutation {
			continue
		}
		if len(r.Methods) == 0 {
			t.Errorf("route %s: no methods", r.ID)
		}
		// Build a sample path from first prefix.
		sample := r.PathPattern
		if strings.Contains(sample, "{") {
			sample = strings.ReplaceAll(sample, "{segments}", "demo")
			sample = strings.ReplaceAll(sample, "{n}", "1")
			sample = strings.ReplaceAll(sample, "{id}", "6")
			sample = strings.ReplaceAll(sample, "{path}", "a.txt")
			sample = strings.ReplaceAll(sample, "{class}", "x.Y")
			// Handle alternation in patterns.
			if i := strings.Index(sample, "|"); i >= 0 {
				sample = sample[:i]
			}
			sample = strings.ReplaceAll(sample, "{describe", "describe")
			sample = strings.TrimSuffix(sample, "}")
		}
		method := "POST"
		if len(r.Methods) > 0 {
			method = r.Methods[0]
		}
		// For classifier-only kill/term use concrete paths.
		switch r.ID {
		case "classifier_kill_term":
			sample = "/job/demo/1/kill"
		case "classifier_cancel_item":
			sample = "/queue/cancelItem"
		case "classifier_do_delete":
			sample = "/job/demo/doDelete"
		case "stop_build":
			sample = "/job/demo/1/stop"
		case "build_with_parameters":
			sample = "/job/demo/buildWithParameters"
		}
		got := jenkins.ClassifyPathPattern(method, sample)
		if got != jenkins.RouteClassMutation && got != jenkins.RouteClassAuth {
			// Mutation routes must not classify as plain read.
			if got == jenkins.RouteClassRead {
				t.Errorf("route %s sample %s %s classified as read", r.ID, method, sample)
			}
		}
	}
}

func TestRouteMatrix_GoldenJSON(t *testing.T) {
	t.Parallel()
	got, err := jenkins.RouteMatrixJSON()
	if err != nil {
		t.Fatal(err)
	}
	// Locate docs/tst/route-matrix.json relative to this test file.
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	// internal/jenkins → repo root
	root := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
	goldenPath := filepath.Join(root, "docs", "tst", "route-matrix.json")
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden %s: %v\n--- regenerate with: go test ./internal/jenkins -run TestRouteMatrix_GoldenJSON -update (or copy RouteMatrixJSON output)", goldenPath, err)
	}
	// Compare as JSON values (ignore trailing newline differences).
	var gotV, wantV any
	if err := json.Unmarshal(got, &gotV); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(want, &wantV); err != nil {
		t.Fatalf("golden JSON: %v", err)
	}
	gotNorm, _ := json.Marshal(gotV)
	wantNorm, _ := json.Marshal(wantV)
	if !bytes.Equal(gotNorm, wantNorm) {
		t.Fatalf("docs/tst/route-matrix.json out of date with KnownRouteMatrix()\n"+
			"Update the golden file from internal/jenkins.RouteMatrixJSON().\n"+
			"got len=%d want len=%d", len(got), len(want))
	}
}

func TestRouteMatrix_FixtureInventoryHasCoveredAndResidual(t *testing.T) {
	t.Parallel()
	doc := jenkins.KnownRouteMatrix()
	var covered, residual int
	for _, c := range doc.FixtureInventory {
		switch c.Status {
		case "covered":
			covered++
		case "residual_live", "partial":
			residual++
		default:
			t.Errorf("inventory %s: bad status %q", c.ID, c.Status)
		}
	}
	if covered == 0 {
		t.Fatal("expected covered fixture cells")
	}
	if residual == 0 {
		t.Fatal("expected residual_live/partial cells (honest offline MVP)")
	}
	// Every route with FixtureCovered=true should appear in some covered/partial cell notes or routes list optionally —
	// at minimum count covered routes.
	nFix := 0
	for _, r := range doc.Routes {
		if r.FixtureCovered {
			nFix++
		}
		if r.ID == "" || r.PathPattern == "" || r.Class == "" {
			t.Errorf("incomplete route: %+v", r)
		}
		switch r.Class {
		case jenkins.RouteClassAuth, jenkins.RouteClassRead, jenkins.RouteClassMutation:
		default:
			t.Errorf("route %s: bad class %q", r.ID, r.Class)
		}
	}
	if nFix < 10 {
		t.Fatalf("expected most production routes fixture-covered, got %d", nFix)
	}
}

func TestRouteMatrix_AuthAndMutationPresent(t *testing.T) {
	t.Parallel()
	doc := jenkins.KnownRouteMatrix()
	var hasAuth, hasMut, hasRead bool
	for _, r := range doc.Routes {
		switch r.Class {
		case jenkins.RouteClassAuth:
			hasAuth = true
		case jenkins.RouteClassMutation:
			hasMut = true
		case jenkins.RouteClassRead:
			hasRead = true
		}
	}
	if !hasAuth || !hasMut || !hasRead {
		t.Fatalf("matrix must include auth+read+mutation routes (auth=%v read=%v mut=%v)", hasAuth, hasRead, hasMut)
	}
}
