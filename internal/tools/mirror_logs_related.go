package tools

import (
	"context"
	"sort"
	"strconv"
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/jenkins"
)

// normalizeRelatedDiscoveryArgs validates include_related options (fail closed on oversized related_max).
// When include_related is false, related_max/direction are ignored.
func normalizeRelatedDiscoveryArgs(args MirrorLogsToolArgs) (relatedMax int, direction string, err error) {
	if !args.IncludeRelated {
		return 0, "", nil
	}
	relatedMax = args.RelatedMax
	if relatedMax <= 0 {
		relatedMax = DefaultRelatedMax
	}
	if relatedMax > HardRelatedMax {
		return 0, "", invalidArg(
			"related_max exceeds hard maximum of " + strconv.Itoa(HardRelatedMax))
	}
	direction = strings.ToLower(strings.TrimSpace(args.RelatedDirection))
	if direction == "" {
		direction = jenkins.GraphDirectionBoth
	}
	switch direction {
	case jenkins.GraphDirectionBoth, jenkins.GraphDirectionUpstream, jenkins.GraphDirectionDownstream:
	default:
		return 0, "", invalidArg("related_direction must be both, upstream, or downstream")
	}
	return relatedMax, direction, nil
}

// discoverRelatedMirrorRequests expands related builds from the first primary seed
// via GetBuildGraph. Soft-fails on graph errors (notes only; never invents jobs).
// Multi-primary lists only expand from the first seed to bound cost.
func discoverRelatedMirrorRequests(
	ctx context.Context,
	client *jenkins.Client,
	primarySeeds []MultiLogRequest,
	seen map[string]struct{},
	relatedMax int,
	direction string,
) (extra []MultiLogRequest, notes []string) {
	if relatedMax <= 0 {
		return nil, nil
	}
	if len(primarySeeds) == 0 {
		notes = append(notes, "related discovery skipped: no primary logs in this call (collection_id residual-only)")
		return nil, notes
	}
	if client == nil {
		notes = append(notes, "related discovery soft-failed: jenkins client unavailable")
		return nil, notes
	}
	if err := ctx.Err(); err != nil {
		notes = append(notes, "related discovery soft-failed: cancelled")
		return nil, notes
	}

	seed := primarySeeds[0]
	if len(primarySeeds) > 1 {
		notes = append(notes, "related discovery used first primary only to bound cost")
	}

	maxNodes := relatedMax + 1 // room for root + extras
	if maxNodes < 2 {
		maxNodes = 2
	}
	// Keep graph node budget modest vs related_max (never expand unbounded).
	if maxNodes > HardRelatedMax+1 {
		maxNodes = HardRelatedMax + 1
	}

	graph, err := client.GetBuildGraph(ctx, jenkins.GetBuildGraphToolArgs{
		JobName:     seed.Job,
		BuildNumber: int(seed.Build),
		MaxDepth:    relatedGraphMaxDepth,
		MaxNodes:    maxNodes,
		Direction:   direction,
	})
	if err != nil {
		// Soft-fail: primaries still acquire.
		code := string(apperr.CodeOf(err))
		if code == "" {
			code = "error"
		}
		notes = append(notes, "related discovery soft-failed: graph "+code)
		return nil, notes
	}
	if graph == nil || len(graph.Nodes) == 0 {
		notes = append(notes, "related discovery: empty graph")
		return nil, notes
	}

	extra = relatedMirrorRequestsFromGraph(graph.Nodes, seen, relatedMax)
	if graph.Truncated && len(extra) >= relatedMax {
		notes = append(notes, "related discovery truncated by graph or related_max budget")
	}
	if graph.CapabilityNote != "" && len(extra) == 0 {
		notes = append(notes, "related discovery: "+graph.CapabilityNote)
	}
	if len(extra) > 0 {
		notes = append(notes, "related discovery added "+strconv.Itoa(len(extra))+" build(s)")
	}
	return extra, notes
}

// relatedMirrorRequestsFromGraph converts graph nodes to extra MultiLogRequests.
// Skips the root and any (job,build) already in seen. Caps at maxExtra.
// Relation labels: upstream | downstream | related (never invents jobs).
func relatedMirrorRequestsFromGraph(nodes []jenkins.BuildGraphNode, seen map[string]struct{}, maxExtra int) []MultiLogRequest {
	if maxExtra <= 0 || len(nodes) == 0 {
		return nil
	}
	// Deterministic: sort non-root nodes by job then build.
	type cand struct {
		job      string
		build    int64
		relation string
	}
	var cands []cand
	for _, n := range nodes {
		if strings.EqualFold(strings.TrimSpace(n.Role), "root") {
			continue
		}
		job := strings.TrimSpace(n.JobName)
		if job == "" || strings.Contains(job, "://") || n.BuildNumber <= 0 {
			continue
		}
		// Normalize folder separators from Jenkins display forms if any slipped through.
		job = strings.ReplaceAll(job, " » ", "/")
		job = strings.Trim(job, "/")
		key := job + "|" + strconv.Itoa(n.BuildNumber)
		if _, ok := seen[key]; ok {
			continue
		}
		rel := relationFromGraphRole(n.Role)
		cands = append(cands, cand{job: job, build: int64(n.BuildNumber), relation: rel})
	}
	sort.Slice(cands, func(i, j int) bool {
		if cands[i].job != cands[j].job {
			return cands[i].job < cands[j].job
		}
		return cands[i].build < cands[j].build
	})
	// Dedup after normalize.
	outSeen := make(map[string]struct{})
	var out []MultiLogRequest
	for _, c := range cands {
		if len(out) >= maxExtra {
			break
		}
		key := c.job + "|" + strconv.FormatInt(c.build, 10)
		if _, ok := outSeen[key]; ok {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		outSeen[key] = struct{}{}
		out = append(out, MultiLogRequest{Job: c.job, Build: c.build, Relation: c.relation})
	}
	return out
}

func relationFromGraphRole(role string) string {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case RelationUpstream:
		return RelationUpstream
	case RelationDownstream:
		return RelationDownstream
	case "root":
		return RelationPrimary
	default:
		return RelationRelated
	}
}
