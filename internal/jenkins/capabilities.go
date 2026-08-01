package jenkins

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// DefaultCapabilityTTL is how long a CapabilitySet is considered fresh (JEN-001).
const DefaultCapabilityTTL = 5 * time.Minute

// maxCapabilityBody caps discovery JSON so plugin lists cannot inflate memory.
const maxCapabilityBody = 1 << 20 // 1 MiB

// Capability source labels (model-visible, non-secret).
const (
	CapabilitySourceLive  = "live"
	CapabilitySourceCache = "cache"
)

// Plugin short names used for feature flags.
const (
	pluginWorkflowAPI   = "workflow-api"
	pluginWorkflowJob   = "workflow-job"
	pluginPipelineREST  = "pipeline-rest-api"
	pluginPipelineStage = "pipeline-stage-view"
	pluginJUnit         = "junit"
)

// Descriptor paths for non-admin capability probes (tree-safe).
const (
	descWorkflowJob = "/descriptorByName/org.jenkinsci.plugins.workflow.job.WorkflowJob/api/json"
	descJUnit       = "/descriptorByName/hudson.tasks.junit.JUnitResultArchiver/api/json"
)

// PluginInfo is an optional plugin signal from capability discovery.
type PluginInfo struct {
	ShortName string `json:"shortName"`
	Version   string `json:"version,omitempty"`
	Active    bool   `json:"active"`
}

// CapabilitySet describes controller features discovered without guessing from
// operational errors (JEN-001). Freshness and Source are always populated.
type CapabilitySet struct {
	JenkinsVersion  string                `json:"jenkinsVersion"`
	HasPipelineREST bool                  `json:"hasPipelineREST"`
	HasJUnit        bool                  `json:"hasJUnit"`
	Plugins         map[string]PluginInfo `json:"plugins,omitempty"`
	FetchedAt       time.Time             `json:"fetchedAt"`
	ExpiresAt       time.Time             `json:"expiresAt"`
	Source          string                `json:"source"` // live | cache
	Fresh           bool                  `json:"fresh"`
	// ProbeNotes are short, safe diagnostics (no secrets, no large payloads).
	ProbeNotes []string `json:"probeNotes,omitempty"`
}

// GetCapabilitiesToolArgs are tool arguments for jenkins_get_capabilities.
type GetCapabilitiesToolArgs struct {
	// Refresh forces a live re-probe, bypassing the TTL cache.
	Refresh bool `json:"refresh,omitempty" jsonschema:"When true, bypass the capability cache and re-probe Jenkins"`
}

// GetCapabilitiesToolResponse is the capability payload returned to the model.
type GetCapabilitiesToolResponse = CapabilitySet

// WithCapabilityTTL sets the capability cache TTL. Zero or negative restores
// DefaultCapabilityTTL. Returns the receiver for chaining.
func (opts *Client) WithCapabilityTTL(ttl time.Duration) *Client {
	if opts == nil {
		return nil
	}
	opts.capMu.Lock()
	defer opts.capMu.Unlock()
	if ttl <= 0 {
		opts.capTTL = 0
	} else {
		opts.capTTL = ttl
	}
	return opts
}

// InvalidateCapabilities drops the cached CapabilitySet (explicit refresh path).
func (opts *Client) InvalidateCapabilities() {
	if opts == nil {
		return
	}
	opts.capMu.Lock()
	defer opts.capMu.Unlock()
	opts.capCache = nil
	opts.capCacheUntil = time.Time{}
}

// Capabilities returns the cached CapabilitySet when still within TTL, otherwise
// probes Jenkins (JEN-001). Results include Fresh and Source.
func (opts *Client) Capabilities(ctx context.Context) (CapabilitySet, error) {
	if opts == nil {
		return CapabilitySet{}, fmt.Errorf("jenkins client is nil")
	}
	now := time.Now()
	opts.capMu.Lock()
	if opts.capCache != nil && now.Before(opts.capCacheUntil) {
		cached := *opts.capCache
		opts.capMu.Unlock()
		cached.Source = CapabilitySourceCache
		cached.Fresh = true
		return cached, nil
	}
	opts.capMu.Unlock()
	return opts.RefreshCapabilities(ctx)
}

// RefreshCapabilities always re-probes Jenkins and updates the cache.
// On version change relative to a previous cache entry the cache is replaced.
func (opts *Client) RefreshCapabilities(ctx context.Context) (CapabilitySet, error) {
	if opts == nil {
		return CapabilitySet{}, fmt.Errorf("jenkins client is nil")
	}
	set, err := opts.probeCapabilities(ctx)
	if err != nil {
		return CapabilitySet{}, err
	}
	ttl := opts.capabilityTTL()
	now := time.Now()
	set.FetchedAt = now
	set.ExpiresAt = now.Add(ttl)
	set.Source = CapabilitySourceLive
	set.Fresh = true

	opts.capMu.Lock()
	// Version change invalidates prior assumptions even if TTL remains.
	if opts.capCache != nil && opts.capCache.JenkinsVersion != "" &&
		set.JenkinsVersion != "" && opts.capCache.JenkinsVersion != set.JenkinsVersion {
		// Explicit note for operators/tests; cache is replaced below.
		set.ProbeNotes = append(set.ProbeNotes, "jenkins_version_changed")
	}
	cp := set
	opts.capCache = &cp
	opts.capCacheUntil = set.ExpiresAt
	opts.capMu.Unlock()
	return set, nil
}

func (opts *Client) capabilityTTL() time.Duration {
	opts.capMu.Lock()
	defer opts.capMu.Unlock()
	if opts.capTTL > 0 {
		return opts.capTTL
	}
	return DefaultCapabilityTTL
}

// probeCapabilities performs bounded, non-admin discovery.
//
// Strategy:
//  1. GET /api/json?tree= (minimal) — X-Jenkins version header
//  2. Optional tree-safe pluginManager listing (may 403 for non-admin)
//  3. Descriptor probes for WorkflowJob and JUnitResultArchiver
//
// Does not require Overall/Administer; pluginManager absence is degraded.
func (opts *Client) probeCapabilities(ctx context.Context) (CapabilitySet, error) {
	var set CapabilitySet
	var notes []string

	version, err := opts.probeJenkinsVersion(ctx)
	if err != nil {
		return CapabilitySet{}, err
	}
	set.JenkinsVersion = version

	plugins, pluginOK, note := opts.probePluginManager(ctx)
	if note != "" {
		notes = append(notes, note)
	}
	if pluginOK && len(plugins) > 0 {
		set.Plugins = plugins
		set.HasPipelineREST = pluginActive(plugins, pluginPipelineREST) ||
			pluginActive(plugins, pluginPipelineStage) ||
			pluginActive(plugins, pluginWorkflowAPI)
		set.HasJUnit = pluginActive(plugins, pluginJUnit)
		// Workflow job presence strengthens pipeline signal.
		if pluginActive(plugins, pluginWorkflowJob) && !set.HasPipelineREST {
			// workflow-job alone does not guarantee wfapi; leave false unless REST present.
			notes = append(notes, "workflow_job_without_pipeline_rest")
		}
	}

	// Descriptor probes fill gaps when pluginManager is inaccessible or partial.
	if !set.HasPipelineREST {
		if ok, n := opts.probeDescriptorOK(ctx, descWorkflowJob); ok {
			// WorkflowJob present: still need REST API for stage graph.
			// Probe a synthetic non-job REST root used by pipeline-rest-api is
			// not always available; treat workflow-api descriptor absence as
			// missing REST. Secondary: if plugin map said workflow-api, already set.
			notes = append(notes, n)
		}
		// pipeline-rest-api has no stable public descriptor; if pluginManager
		// was denied, try HEAD-like GET on a well-known class from that plugin
		// via descriptorByName for Pipeline REST run support.
		if ok, n := opts.probeDescriptorOK(ctx, "/descriptorByName/com.cloudbees.workflow.rest.external.RunExt/api/json"); ok {
			set.HasPipelineREST = true
			notes = append(notes, n)
		} else if n != "" {
			notes = append(notes, n)
		}
	}
	if !set.HasJUnit {
		if ok, n := opts.probeDescriptorOK(ctx, descJUnit); ok {
			set.HasJUnit = true
			notes = append(notes, n)
		} else if n != "" {
			notes = append(notes, n)
		}
	}

	if len(notes) > 0 {
		set.ProbeNotes = notes
	}
	return set, nil
}

func (opts *Client) probeJenkinsVersion(ctx context.Context) (string, error) {
	// Minimal tree keeps the body tiny; version comes from X-Jenkins.
	// Note: "/api/json?tree=" (empty tree) returns HTTP 500 on modern LTS
	// (Regression: TST-001 live / Jenkins 2.541+). Use a one-field tree.
	resp, err := opts.CallJenkins(ctx, opts.Client, http.MethodGet, "/api/json?tree=nodeName", nil, nil)
	if err != nil {
		return "", fmt.Errorf("capability version probe failed: %w", err)
	}
	defer resp.Body.Close()
	// Drain bounded body so the connection can be reused.
	_, _ = readLimited(resp.Body, maxCapabilityBody)

	if resp.StatusCode == http.StatusUnauthorized {
		return "", fmt.Errorf("capability version probe unauthorized (HTTP 401)")
	}
	if resp.StatusCode == http.StatusForbidden {
		return "", fmt.Errorf("capability version probe forbidden (HTTP 403)")
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("capability version probe returned HTTP %d", resp.StatusCode)
	}
	v := strings.TrimSpace(resp.Header.Get("X-Jenkins"))
	if v == "" {
		// Some reverse proxies strip X-Jenkins; leave empty but succeed.
		return "", nil
	}
	return v, nil
}

func (opts *Client) probePluginManager(ctx context.Context) (map[string]PluginInfo, bool, string) {
	// depth=0 + tree limits fields; does not require listing all config.
	const path = "/pluginManager/api/json?depth=0&tree=plugins[shortName,version,active,enabled]"
	resp, err := opts.CallJenkins(ctx, opts.Client, http.MethodGet, path, nil, nil)
	if err != nil {
		return nil, false, "plugin_manager_unreachable"
	}
	defer resp.Body.Close()
	body, err := readLimited(resp.Body, maxCapabilityBody)
	if err != nil {
		return nil, false, "plugin_manager_read_error"
	}
	switch resp.StatusCode {
	case http.StatusOK:
		// continue
	case http.StatusForbidden, http.StatusUnauthorized:
		return nil, false, "plugin_manager_denied"
	case http.StatusNotFound:
		return nil, false, "plugin_manager_missing"
	default:
		return nil, false, fmt.Sprintf("plugin_manager_http_%d", resp.StatusCode)
	}

	var raw struct {
		Plugins []struct {
			ShortName string `json:"shortName"`
			Version   string `json:"version"`
			Active    bool   `json:"active"`
			Enabled   bool   `json:"enabled"`
		} `json:"plugins"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, false, "plugin_manager_decode_error"
	}
	out := make(map[string]PluginInfo, len(raw.Plugins))
	for _, p := range raw.Plugins {
		name := strings.TrimSpace(p.ShortName)
		if name == "" {
			continue
		}
		// Active for our purposes: installed and active (enabled alone is insufficient).
		active := p.Active
		out[name] = PluginInfo{
			ShortName: name,
			Version:   strings.TrimSpace(p.Version),
			Active:    active,
		}
	}
	return out, true, "plugin_manager_ok"
}

// probeDescriptorOK returns true when the descriptor JSON endpoint responds 200.
// 404 means plugin/class absent; 401/403 is noted but treated as unknown (false).
func (opts *Client) probeDescriptorOK(ctx context.Context, path string) (bool, string) {
	resp, err := opts.CallJenkins(ctx, opts.Client, http.MethodGet, path, nil, nil)
	if err != nil {
		return false, "descriptor_unreachable"
	}
	defer resp.Body.Close()
	_, _ = readLimited(resp.Body, 64<<10)
	switch resp.StatusCode {
	case http.StatusOK:
		return true, "descriptor_present"
	case http.StatusNotFound:
		return false, "descriptor_absent"
	case http.StatusForbidden, http.StatusUnauthorized:
		return false, "descriptor_denied"
	default:
		return false, fmt.Sprintf("descriptor_http_%d", resp.StatusCode)
	}
}

func pluginActive(plugins map[string]PluginInfo, shortName string) bool {
	if plugins == nil {
		return false
	}
	p, ok := plugins[shortName]
	return ok && p.Active
}
