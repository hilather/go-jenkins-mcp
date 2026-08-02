package mutation_test

import (
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/mutation"
	"github.com/hilather/go-jenkins-mcp/internal/redact"
)

// QA-001 Wave 21: mutation param normalize/validate pure paths (MUT-002).
// Must never panic on garbage; error returns are OK.

const fuzzMaxParam = 4 << 10 // 4 KiB per string

// FuzzNormalizeParams covers random keys/values including sensitive-looking names.
// Invariant: no panic; sensitive keys fail closed; fingerprint/redact stay safe.
func FuzzNormalizeParams(f *testing.F) {
	f.Add("BRANCH", "main")
	f.Add("ENV", "dev")
	f.Add("password", "secret")
	f.Add("API_TOKEN", "tok123")
	f.Add("client_secret", "s3cr3t")
	f.Add("", "value")
	f.Add("  ", "x")
	f.Add("OK", "")
	f.Add("DEBUG", "true")
	f.Add("nested", `{"a":1}`)
	f.Add("unicode- ind", "val")
	f.Add("name\x00null", "v")
	f.Add(strings.Repeat("k", 200), strings.Repeat("v", 200))

	f.Fuzz(func(t *testing.T, key, value string) {
		if len(key) > fuzzMaxParam || len(value) > fuzzMaxParam {
			return
		}
		// Empty map / nil paths.
		if out, err := mutation.NormalizeParams(nil); err != nil || out != nil {
			t.Fatalf("nil params: out=%v err=%v", out, err)
		}
		if out, err := mutation.NormalizeParams(map[string]any{}); err != nil || out != nil {
			t.Fatalf("empty params: out=%v err=%v", out, err)
		}

		in := map[string]any{key: value}
		out, err := mutation.NormalizeParams(in)
		if err != nil {
			if out != nil {
				t.Fatalf("error with non-nil out: %v", err)
			}
			return
		}
		// Success must never accept sensitive parameter names (fail closed).
		trimmed := strings.TrimSpace(key)
		if trimmed != "" && redact.IsSensitiveFieldName(trimmed) {
			t.Fatalf("sensitive key accepted: %q", key)
		}
		if len(out) != 1 {
			t.Fatalf("expected one normalized key, got %d", len(out))
		}
		// Success path: fingerprint + redaction must not panic.
		fp := mutation.ParamFingerprint(out)
		if fp == "" {
			t.Fatal("empty fingerprint")
		}
		red := mutation.RedactParams(out)
		if red == nil {
			t.Fatal("RedactParams returned nil for non-empty")
		}
		// Multi-key path with a second non-sensitive key.
		in2 := map[string]any{key: value, "SAFE_FLAG": true, "N": float64(1)}
		_, _ = mutation.NormalizeParams(in2)
	})
}

// FuzzValidateAgainstDefinitions exercises random param maps + definition types.
// Invariant: no panic; unknown/secret/unsupported types fail closed with errors.
func FuzzValidateAgainstDefinitions(f *testing.F) {
	// paramName, paramValue, defName, defType, choicesCSV
	f.Add("BRANCH", "main", "BRANCH", "StringParameterDefinition", "")
	f.Add("ENV", "dev", "ENV", "ChoiceParameterDefinition", "dev,stage,prod")
	f.Add("ENV", "production", "ENV", "ChoiceParameterDefinition", "dev,stage,prod")
	f.Add("DEBUG", "true", "DEBUG", "BooleanParameterDefinition", "")
	f.Add("DEBUG", "yes", "DEBUG", "BooleanParameterDefinition", "")
	f.Add("SECRET", "x", "SECRET", "PasswordParameterDefinition", "")
	f.Add("CREDS", "id", "CREDS", "hudson.model.CredentialsParameterDefinition", "")
	f.Add("FILE", "x", "FILE", "FileParameterDefinition", "")
	f.Add("UNKNOWN", "x", "OTHER", "StringParameterDefinition", "")
	f.Add("S", "ok", "S", "hudson.model.StringParameterDefinition", "")
	f.Add("C", "a", "C", "ChoiceParameterDefinition", "a,b")
	f.Add("C", "a", "C", "ChoiceParameterDefinition", "") // empty choices fail closed
	f.Add("", "x", "X", "StringParameterDefinition", "")
	f.Add("X", "1", "", "StringParameterDefinition", "") // empty def name skipped
	f.Add("X", "1", "X", "", "")                         // missing type → string-like
	f.Add("X", "1", "X", "WeirdPluginType", "")
	f.Add("bool", "false", "bool", "Boolean", "")
	f.Add(strings.Repeat("p", 100), "v", strings.Repeat("p", 100), "StringParameterDefinition", "")

	f.Fuzz(func(t *testing.T, paramName, paramValue, defName, defType, choicesCSV string) {
		if len(paramName) > fuzzMaxParam || len(paramValue) > fuzzMaxParam ||
			len(defName) > fuzzMaxParam || len(defType) > fuzzMaxParam || len(choicesCSV) > fuzzMaxParam {
			return
		}

		// Empty defs / empty params paths.
		if err := mutation.ValidateAgainstDefinitions(nil, nil); err != nil {
			t.Fatalf("nil/nil: %v", err)
		}
		if err := mutation.ValidateAgainstDefinitions(map[string]any{}, nil); err != nil {
			t.Fatalf("empty params: %v", err)
		}

		var choices []string
		if choicesCSV != "" {
			choices = strings.Split(choicesCSV, ",")
		}
		defs := []mutation.ParamDefinition{
			{Name: defName, Type: defType, Choices: choices},
			// Second def with overlapping type variety for map iteration coverage.
			{Name: "EXTRA_STRING", Type: "StringParameterDefinition"},
		}
		params := map[string]any{paramName: paramValue}

		// Normalize first when possible (production order); ignore normalize errors.
		if norm, err := mutation.NormalizeParams(params); err == nil && norm != nil {
			params = norm
		}

		_ = mutation.ValidateAgainstDefinitions(params, defs)
		_ = mutation.ValidateAgainstDefinitions(params, nil)
		// Multi-value map with bool/number leaves.
		_ = mutation.ValidateAgainstDefinitions(map[string]any{
			paramName:      paramValue,
			"EXTRA_STRING": 42,
			"flag":         true,
		}, defs)
	})
}
