package auth

import (
	"fmt"
	"strings"
)

// InventoryIssue is one RequiredMCPRoutes completeness problem.
type InventoryIssue struct {
	// Code is a stable machine key (duplicate_id, missing_field, …).
	Code string
	// RouteID is the affected route when applicable.
	RouteID string
	// Detail is a short non-secret description.
	Detail string
}

// ValidateRequiredMCPRoutesInventory checks offline inventory contracts:
// unique IDs, required fields, progressive_text / outside-api-glob marking.
// Returns nil when the inventory satisfies completeness rules.
func ValidateRequiredMCPRoutesInventory() []InventoryIssue {
	var issues []InventoryIssue
	seen := make(map[string]int, len(RequiredMCPRoutes))
	outsideCount := 0
	for i, r := range RequiredMCPRoutes {
		if r.ID == "" {
			issues = append(issues, InventoryIssue{
				Code:   "missing_id",
				Detail: fmt.Sprintf("route index %d has empty ID", i),
			})
			continue
		}
		if prev, ok := seen[r.ID]; ok {
			issues = append(issues, InventoryIssue{
				Code:    "duplicate_id",
				RouteID: r.ID,
				Detail:  fmt.Sprintf("duplicate route ID %q (indices %d and %d)", r.ID, prev, i),
			})
		} else {
			seen[r.ID] = i
		}
		if strings.TrimSpace(r.PathPattern) == "" {
			issues = append(issues, InventoryIssue{
				Code:    "missing_path_pattern",
				RouteID: r.ID,
				Detail:  "PathPattern is required",
			})
		}
		if strings.TrimSpace(r.ExamplePath) == "" {
			issues = append(issues, InventoryIssue{
				Code:    "missing_example_path",
				RouteID: r.ID,
				Detail:  "ExamplePath is required",
			})
		}
		if r.Category == "" {
			issues = append(issues, InventoryIssue{
				Code:    "missing_category",
				RouteID: r.ID,
				Detail:  "Category is required",
			})
		}
		if r.OutsideAPIGlob {
			outsideCount++
		}
		if r.ID == "progressive_text" {
			if !r.OutsideAPIGlob {
				issues = append(issues, InventoryIssue{
					Code:    "progressive_text_not_outside_api_glob",
					RouteID: r.ID,
					Detail:  "progressive_text must set OutsideAPIGlob=true (outside /**/api/**)",
				})
			}
			if r.Category != RSRouteProgressive {
				issues = append(issues, InventoryIssue{
					Code:    "progressive_text_wrong_category",
					RouteID: r.ID,
					Detail:  "progressive_text Category must be progressive_log",
				})
			}
		}
	}
	if _, ok := seen["progressive_text"]; !ok {
		issues = append(issues, InventoryIssue{
			Code:    "missing_progressive_text",
			RouteID: "progressive_text",
			Detail:  "inventory must include progressive_text (LOG-001)",
		})
	}
	// Outside-api-glob must include progressive + artifact + at least one wfapi.
	needOutside := []string{"progressive_text", "artifact_download", "wfapi_describe"}
	for _, id := range needOutside {
		idx, ok := seen[id]
		if !ok {
			issues = append(issues, InventoryIssue{
				Code:    "missing_outside_route",
				RouteID: id,
				Detail:  "required outside-api-glob route missing from inventory",
			})
			continue
		}
		if !RequiredMCPRoutes[idx].OutsideAPIGlob {
			issues = append(issues, InventoryIssue{
				Code:    "outside_route_unmarked",
				RouteID: id,
				Detail:  "route must set OutsideAPIGlob=true",
			})
		}
	}
	if outsideCount < 3 {
		issues = append(issues, InventoryIssue{
			Code:   "outside_api_glob_count",
			Detail: fmt.Sprintf("need >=3 OutsideAPIGlob routes, got %d", outsideCount),
		})
	}
	return issues
}
