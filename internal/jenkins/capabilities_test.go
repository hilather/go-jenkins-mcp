package jenkins

import (
	"context"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

func TestCapabilities_PresentViaPluginManager(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	f.setPlugins(pluginPipelineREST, pluginWorkflowAPI, pluginJUnit, pluginWorkflowJob)

	c := f.opts().WithCapabilityTTL(time.Minute)
	set, err := c.Capabilities(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if set.JenkinsVersion != "2.462.3" {
		t.Fatalf("version = %q", set.JenkinsVersion)
	}
	if !set.HasPipelineREST {
		t.Fatal("expected HasPipelineREST")
	}
	if !set.HasJUnit {
		t.Fatal("expected HasJUnit")
	}
	if set.Source != CapabilitySourceLive {
		t.Fatalf("source = %q want live", set.Source)
	}
	if !set.Fresh {
		t.Fatal("expected fresh")
	}
	if set.FetchedAt.IsZero() || set.ExpiresAt.IsZero() {
		t.Fatal("expected timestamps")
	}
	if set.Plugins[pluginJUnit].Version == "" {
		t.Fatalf("plugins map missing junit: %+v", set.Plugins)
	}
}

func TestCapabilities_AbsentPlugins(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	// Empty plugin list (present endpoint, no optional plugins).
	f.setPlugins()

	set, err := f.opts().Capabilities(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if set.HasPipelineREST || set.HasJUnit {
		t.Fatalf("expected no optional caps: %+v", set)
	}
}

func TestCapabilities_DescriptorFallbackWhenPluginManagerDenied(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	f.pluginManagerJSON = "deny"
	f.setDescriptor(descJUnit, 200)
	f.setDescriptor("/descriptorByName/com.cloudbees.workflow.rest.external.RunExt/api/json", 200)

	set, err := f.opts().Capabilities(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !set.HasJUnit {
		t.Fatal("expected JUnit via descriptor")
	}
	if !set.HasPipelineREST {
		t.Fatal("expected Pipeline REST via RunExt descriptor")
	}
}

func TestCapabilities_CacheTTLAndInvalidate(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	f.setPlugins(pluginJUnit)

	c := f.opts().WithCapabilityTTL(time.Hour)
	first, err := c.Capabilities(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if first.Source != CapabilitySourceLive {
		t.Fatalf("first source = %q", first.Source)
	}

	// Second call should hit cache.
	second, err := c.Capabilities(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if second.Source != CapabilitySourceCache {
		t.Fatalf("second source = %q want cache", second.Source)
	}
	if !second.Fresh || !second.HasJUnit {
		t.Fatalf("cached set: %+v", second)
	}

	c.InvalidateCapabilities()
	third, err := c.Capabilities(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if third.Source != CapabilitySourceLive {
		t.Fatalf("after invalidate source = %q", third.Source)
	}
}

func TestCapabilities_RefreshBypassesCache(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	f.setPlugins(pluginJUnit)
	c := f.opts().WithCapabilityTTL(time.Hour)
	if _, err := c.Capabilities(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Drop JUnit from plugins and force refresh.
	f.setPlugins(pluginPipelineREST)
	set, err := c.RefreshCapabilities(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if set.HasJUnit {
		t.Fatal("refresh should see updated plugins")
	}
	if !set.HasPipelineREST {
		t.Fatal("expected pipeline after refresh")
	}
}

func TestCapabilities_VersionChangeNote(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	f.setPlugins(pluginJUnit)
	c := f.opts().WithCapabilityTTL(time.Hour)
	if _, err := c.Capabilities(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.jenkinsVersion = "2.500.1"
	set, err := c.RefreshCapabilities(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if set.JenkinsVersion != "2.500.1" {
		t.Fatalf("version = %q", set.JenkinsVersion)
	}
	found := false
	for _, n := range set.ProbeNotes {
		if n == "jenkins_version_changed" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected version change note, got %v", set.ProbeNotes)
	}
}

func TestGetPipelineStages_CapabilityMissing(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	f.setPlugins() // no pipeline REST

	_, err := f.opts().GetPipelineStages(context.Background(), "demo", 7)
	if err == nil {
		t.Fatal("expected capability_missing")
	}
	if !apperr.IsCode(err, apperr.CodeCapabilityMissing) {
		t.Fatalf("code = %v err = %v", apperr.CodeOf(err), err)
	}
}

func TestGetTestReport_CapabilityMissing(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	f.setPlugins() // no junit

	_, err := f.opts().GetTestReport(context.Background(), "demo", 7, 10)
	if err == nil {
		t.Fatal("expected capability_missing")
	}
	if !apperr.IsCode(err, apperr.CodeCapabilityMissing) {
		t.Fatalf("code = %v err = %v", apperr.CodeOf(err), err)
	}
}
