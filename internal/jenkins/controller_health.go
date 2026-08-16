package jenkins

import (
	"context"
	"fmt"
	"time"
)

// GetControllerHealthToolArgs are inputs for jenkins_controller_health (HEALTH-002).
// Refresh forces capability re-probe (same semantics as jenkins_get_capabilities).
type GetControllerHealthToolArgs struct {
	// Refresh bypasses the capability cache and re-probes plugins/version.
	Refresh bool `json:"refresh,omitempty" jsonschema:"When true, bypass capability cache and re-probe Jenkins"`
}

// PluginHealthEntry is a shortlist plugin health row (no full inventory dump).
type PluginHealthEntry struct {
	ShortName string `json:"shortName"`
	Version   string `json:"version,omitempty"`
	Active    bool   `json:"active"`
	// Role is a product feature tag (pipeline, junit, …).
	Role string `json:"role,omitempty"`
}

// ControllerFeatureFlags summarizes product features from capability probes.
type ControllerFeatureFlags struct {
	HasPipelineREST bool `json:"hasPipelineREST"`
	HasJUnit        bool `json:"hasJUnit"`
}

// GetControllerHealthToolResponse is a bounded, secret-free controller health summary (HEALTH-002).
type GetControllerHealthToolResponse struct {
	// JenkinsVersion from X-Jenkins / capability probe.
	JenkinsVersion string `json:"jenkinsVersion,omitempty"`
	// Capabilities is the JEN-001 capability snapshot (reused; may be cached).
	Capabilities CapabilitySet `json:"capabilities"`
	// Features is a compact product-feature view derived from capabilities.
	Features ControllerFeatureFlags `json:"features"`
	// PluginShortlist is active core plugins used for capability probes (bounded).
	PluginShortlist []PluginHealthEntry `json:"pluginShortlist,omitempty"`
	// Queue is a queue pressure summary (depth/stuck/oldest); unauthorized ≠ empty.
	Queue *GetQueuePressureToolResponse `json:"queue,omitempty"`
	// Nodes is executor/online/offline totals when authorized.
	Nodes *NodeTotals `json:"nodes,omitempty"`
	// QuietingDown / Mode from cheap root probe.
	QuietingDown bool   `json:"quietingDown,omitempty"`
	Mode         string `json:"mode,omitempty"`
	// NumExecutors on the controller when reported by root API.
	NumExecutors int `json:"numExecutors,omitempty"`

	// Overall is a coarse local status: ok | warn | degraded.
	Overall string `json:"overall"`
	// Notes are short safe diagnostics (capability gaps, unauthorized paths).
	Notes []string `json:"notes,omitempty"`
	// Freshness is when this summary was assembled (UTC).
	Freshness time.Time `json:"freshness"`
	// EvidenceEndpoints lists API paths consulted.
	EvidenceEndpoints []string `json:"evidenceEndpoints,omitempty"`
	// PartialUnauthorized is true when any secondary endpoint returned 403.
	PartialUnauthorized bool `json:"partialUnauthorized,omitempty"`
}

// Core plugins we surface in the shortlist (capability-related only).
var corePluginShortlist = []struct {
	name string
	role string
}{
	{pluginWorkflowAPI, "pipeline"},
	{pluginWorkflowJob, "pipeline"},
	{pluginPipelineREST, "pipeline"},
	{pluginPipelineStage, "pipeline"},
	{pluginJUnit, "junit"},
}

// GetControllerHealth builds a HEALTH-002 summary: version, capabilities, plugin shortlist,
// queue pressure, offline node counts, and quiet-down mode. No mutations, no secrets.
func (opts *Client) GetControllerHealth(ctx context.Context, args GetControllerHealthToolArgs) (*GetControllerHealthToolResponse, error) {
	if opts == nil {
		return nil, fmt.Errorf("jenkins client is nil")
	}
	now := time.Now().UTC()
	out := &GetControllerHealthToolResponse{
		Freshness:         now,
		Overall:           "ok",
		EvidenceEndpoints: make([]string, 0, 6),
	}

	// 1) Capabilities (JEN-001) — version + plugin/feature flags.
	var caps CapabilitySet
	var err error
	if args.Refresh {
		caps, err = opts.RefreshCapabilities(ctx)
	} else {
		caps, err = opts.Capabilities(ctx)
	}
	out.EvidenceEndpoints = append(out.EvidenceEndpoints,
		"/api/json?tree=",
		"/pluginManager/api/json",
		descWorkflowJob,
		descJUnit,
	)
	if err != nil {
		out.Overall = "degraded"
		out.Notes = append(out.Notes, "capabilities: "+safeErrNote(err))
	} else {
		// Scrub probe notes defensively (local scrub; no internal/redact —
		// FND-004). Scrub into a fresh slice: caps may be a cache-hit shallow
		// copy whose ProbeNotes backing array is shared with the capability
		// cache — in-place writes would mutate the cache and race readers.
		if len(caps.ProbeNotes) > 0 {
			scrubbed := make([]string, len(caps.ProbeNotes))
			for i, n := range caps.ProbeNotes {
				scrubbed[i] = scrubSecretsLike(n)
			}
			caps.ProbeNotes = scrubbed
		}
		out.Capabilities = caps
		out.JenkinsVersion = caps.JenkinsVersion
		out.Features = ControllerFeatureFlags{
			HasPipelineREST: caps.HasPipelineREST,
			HasJUnit:        caps.HasJUnit,
		}
		out.PluginShortlist = buildPluginShortlist(caps)
		if !caps.HasPipelineREST {
			out.Notes = append(out.Notes, "pipeline_rest_unavailable: stage graph tools may return capability_missing")
			if out.Overall == "ok" {
				out.Overall = "warn"
			}
		}
		if !caps.HasJUnit {
			out.Notes = append(out.Notes, "junit_plugin_unavailable: test report tools may return capability_missing")
			if out.Overall == "ok" {
				out.Overall = "warn"
			}
		}
		if caps.JenkinsVersion == "" {
			out.Notes = append(out.Notes, "jenkins_version_unknown: X-Jenkins header missing (proxy strip?)")
		}
	}

	// 2) Queue pressure (HEALTH-001).
	qp, qerr := opts.GetQueuePressure(ctx)
	out.EvidenceEndpoints = append(out.EvidenceEndpoints, "/queue/api/json")
	if qerr != nil {
		out.Notes = append(out.Notes, "queue: "+safeErrNote(qerr))
		if out.Overall == "ok" {
			out.Overall = "warn"
		}
	} else if qp != nil {
		if qp.Unauthorized {
			out.PartialUnauthorized = true
			out.Notes = append(out.Notes, "queue: unauthorized (HTTP 403) — not empty")
			if out.Overall == "ok" {
				out.Overall = "warn"
			}
		} else {
			slim := *qp
			if len(slim.Samples) > 3 {
				slim.Samples = slim.Samples[:3]
			}
			// Sanitize why text in samples.
			for i := range slim.Samples {
				slim.Samples[i].Why = sanitizeNodeText(scrubSecretsLike(slim.Samples[i].Why))
				slim.Samples[i].JobName = sanitizeNodeText(slim.Samples[i].JobName)
			}
			out.Queue = &slim
			if slim.StuckCount > 0 {
				out.Notes = append(out.Notes, fmt.Sprintf("queue_stuck_items=%d", slim.StuckCount))
				if out.Overall == "ok" {
					out.Overall = "warn"
				}
			}
		}
	}

	// 3) Node offline / executor summary (HEALTH-001).
	nodes, nerr := opts.GetNodes(ctx, 0, 1) // page size 1 is enough for Summary (full scan)
	out.EvidenceEndpoints = append(out.EvidenceEndpoints, "/computer/api/json")
	if nerr != nil {
		out.Notes = append(out.Notes, "nodes: "+safeErrNote(nerr))
		if out.Overall == "ok" {
			out.Overall = "warn"
		}
	} else if nodes != nil {
		if nodes.Unauthorized {
			out.PartialUnauthorized = true
			out.Notes = append(out.Notes, "nodes: unauthorized (HTTP 403)")
			if out.Overall == "ok" {
				out.Overall = "warn"
			}
		} else {
			sum := nodes.Summary
			out.Nodes = &sum
			if sum.OfflineNodes > 0 {
				out.Notes = append(out.Notes, fmt.Sprintf("offline_nodes=%d/%d", sum.OfflineNodes, sum.TotalNodes))
				if out.Overall == "ok" {
					out.Overall = "warn"
				}
			}
		}
	}

	// 4) Quiet-down / mode flags.
	mode, merr := opts.GetControllerMode(ctx)
	out.EvidenceEndpoints = append(out.EvidenceEndpoints, "/api/json?tree="+modeAPITree)
	if merr != nil {
		out.Notes = append(out.Notes, "mode: "+safeErrNote(merr))
	} else if mode != nil {
		if mode.Unauthorized {
			out.PartialUnauthorized = true
			out.Notes = append(out.Notes, "mode: unauthorized (HTTP 403)")
		} else {
			out.QuietingDown = mode.QuietingDown
			out.Mode = mode.Mode
			out.NumExecutors = mode.NumExecutors
			if mode.JenkinsVersion != "" && out.JenkinsVersion == "" {
				out.JenkinsVersion = mode.JenkinsVersion
			}
			if mode.QuietingDown {
				out.Notes = append(out.Notes, "controller_quieting_down")
				if out.Overall != "degraded" {
					out.Overall = "warn"
				}
			}
		}
	}

	out.EvidenceEndpoints = uniqueStrings(out.EvidenceEndpoints)
	return out, nil
}

func buildPluginShortlist(caps CapabilitySet) []PluginHealthEntry {
	if len(caps.Plugins) == 0 {
		// Descriptor-only probes: emit synthetic rows for known feature flags.
		var out []PluginHealthEntry
		if caps.HasPipelineREST {
			out = append(out, PluginHealthEntry{ShortName: pluginPipelineREST, Active: true, Role: "pipeline"})
		}
		if caps.HasJUnit {
			out = append(out, PluginHealthEntry{ShortName: pluginJUnit, Active: true, Role: "junit"})
		}
		return out
	}
	out := make([]PluginHealthEntry, 0, len(corePluginShortlist))
	for _, c := range corePluginShortlist {
		p, ok := caps.Plugins[c.name]
		if !ok {
			continue
		}
		out = append(out, PluginHealthEntry{
			ShortName: p.ShortName,
			Version:   p.Version,
			Active:    p.Active,
			Role:      c.role,
		})
	}
	return out
}
