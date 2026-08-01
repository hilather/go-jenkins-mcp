package redact

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// EnvRedactPatternsFile is the optional path to a JSON enterprise redact
// pattern list (SEC-002 Wave 27). Prefer env+file over policy overlay so
// invalid config fails closed at serve start without mixed schema concerns.
//
// Unset or empty → no enterprise patterns (built-ins only).
// Set → file must exist, parse, and compile; any error fails closed.
//
// File format (JSON array):
//
//	[{"name":"corp_id","expr":"\\bCORP-[0-9]{6}\\b"}]
//
// Prefer two capture groups (prefix + secret) so the prefix is retained.
// Reports use category counts only — never log match values or secrets.
const EnvRedactPatternsFile = "JENKINS_MCP_REDACT_PATTERNS_FILE"

// Bounds for enterprise pattern files (fail closed on excess).
const (
	// MaxEnterprisePatternsFileBytes is the max JSON file size read from disk.
	MaxEnterprisePatternsFileBytes = 1 << 20 // 1 MiB
	// MaxEnterprisePatterns is the max compiled patterns accepted from one file.
	MaxEnterprisePatterns = 256
)

// PatternConfig is one name/expression pair from config JSON.
// Name becomes the Report category (value-free). Expr is a Go regexp.
type PatternConfig struct {
	Name string `json:"name"`
	Expr string `json:"expr"`
}

// LoadEnterprisePatternsFile reads path as a JSON array of PatternConfig,
// compiles each expression, and returns NamedPatterns. It does not install
// package state — callers use SetEnterprisePatterns / StaticEnterprise.
//
// Fail closed: missing path, oversized file, invalid JSON, non-array root,
// too many patterns, or any invalid regexp returns an error. Empty array
// yields (nil, nil). Never logs match samples or secret material.
func LoadEnterprisePatternsFile(path string) ([]NamedPattern, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("enterprise redact patterns: empty path")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("enterprise redact patterns: open %s: %w", path, err)
	}
	defer f.Close()

	// Bound read: reject files larger than the cap (and stop early).
	limited := io.LimitReader(f, MaxEnterprisePatternsFileBytes+1)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("enterprise redact patterns: read: %w", err)
	}
	if len(raw) > MaxEnterprisePatternsFileBytes {
		return nil, fmt.Errorf("enterprise redact patterns: file exceeds %d bytes", MaxEnterprisePatternsFileBytes)
	}

	return LoadEnterprisePatternsJSON(raw)
}

// LoadEnterprisePatternsJSON compiles a JSON array of PatternConfig.
// See LoadEnterprisePatternsFile for fail-closed rules.
func LoadEnterprisePatternsJSON(raw []byte) ([]NamedPattern, error) {
	raw = trimJSONBOM(raw)
	if len(strings.TrimSpace(string(raw))) == 0 {
		return nil, fmt.Errorf("enterprise redact patterns: empty file")
	}

	// Require a JSON array root (reject objects / bare values).
	var items []PatternConfig
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, fmt.Errorf("enterprise redact patterns: invalid JSON array: %w", err)
	}
	if len(items) > MaxEnterprisePatterns {
		return nil, fmt.Errorf("enterprise redact patterns: %d patterns exceeds max %d", len(items), MaxEnterprisePatterns)
	}

	pairs := make([]struct{ Name, Expr string }, 0, len(items))
	for i, it := range items {
		name := strings.TrimSpace(it.Name)
		expr := strings.TrimSpace(it.Expr)
		if expr == "" {
			// Skip empty expressions (name-only rows are no-ops).
			continue
		}
		if name == "" {
			name = CategoryEnterprise
		}
		// Reject control characters in category names (stable report keys).
		if strings.ContainsFunc(name, func(r rune) bool {
			return r < 0x20 || r == 0x7f
		}) {
			return nil, fmt.Errorf("enterprise redact patterns: item %d: name contains control characters", i)
		}
		pairs = append(pairs, struct{ Name, Expr string }{Name: name, Expr: expr})
	}

	pats, err := CompileEnterprisePatterns(pairs)
	if err != nil {
		// CompileEnterprisePatterns already names the pattern; wrap for surface.
		return nil, fmt.Errorf("enterprise redact patterns: %w", err)
	}
	return pats, nil
}

// ApplyEnterprisePatternsFromEnviron loads optional enterprise patterns from
// EnvRedactPatternsFile and installs them via SetEnterprisePatterns.
//
//	unset/empty env → clears enterprise patterns, returns (0, nil)
//	valid file      → installs, returns (count, nil)
//	any load error  → does not install a partial list; returns (0, err)
//
// Safe to call at serve start. Does not log expressions, matches, or secrets.
func ApplyEnterprisePatternsFromEnviron() (int, error) {
	path := strings.TrimSpace(os.Getenv(EnvRedactPatternsFile))
	if path == "" {
		SetEnterprisePatterns(nil)
		return 0, nil
	}
	pats, err := LoadEnterprisePatternsFile(path)
	if err != nil {
		// Leave prior state uncleared only on failure so a bad reload does not
		// silently drop patterns mid-process; serve start has no prior state.
		return 0, err
	}
	SetEnterprisePatterns(StaticEnterprise(pats))
	return len(pats), nil
}

// ValidateEnterprisePatternsFile loads and compiles path without installing
// package state. Operators use this via `jenkins-mcp redact validate-patterns`.
// Returns pattern count and category names (never match samples).
func ValidateEnterprisePatternsFile(path string) (count int, names []string, err error) {
	pats, err := LoadEnterprisePatternsFile(path)
	if err != nil {
		return 0, nil, err
	}
	names = make([]string, len(pats))
	for i, p := range pats {
		names[i] = p.Category
	}
	return len(pats), names, nil
}

func trimJSONBOM(b []byte) []byte {
	// UTF-8 BOM occasionally appears in hand-edited fleet files.
	if len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF {
		return b[3:]
	}
	return b
}
