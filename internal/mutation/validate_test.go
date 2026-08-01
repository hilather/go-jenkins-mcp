package mutation_test

import (
	"strings"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/mutation"
)

func sampleDefs() []mutation.ParamDefinition {
	return []mutation.ParamDefinition{
		{Name: "BRANCH", Type: "StringParameterDefinition"},
		{Name: "ENV", Type: "ChoiceParameterDefinition", Choices: []string{"dev", "stage", "prod"}},
		{Name: "DEBUG", Type: "BooleanParameterDefinition"},
		{Name: "DEPLOY_KEY", Type: "PasswordParameterDefinition"},
		{Name: "CREDS", Type: "hudson.model.CredentialsParameterDefinition"},
		{Name: "ARTIFACT", Type: "FileParameterDefinition"},
	}
}

func TestValidateAgainstDefinitions_HappyPath(t *testing.T) {
	t.Parallel()
	params, err := mutation.NormalizeParams(map[string]any{
		"BRANCH": "main",
		"ENV":    "dev",
		"DEBUG":  true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := mutation.ValidateAgainstDefinitions(params, sampleDefs()); err != nil {
		t.Fatalf("valid params: %v", err)
	}
}

func TestValidateAgainstDefinitions_UnknownParam(t *testing.T) {
	t.Parallel()
	params, err := mutation.NormalizeParams(map[string]any{"NOPE": "x"})
	if err != nil {
		t.Fatal(err)
	}
	err = mutation.ValidateAgainstDefinitions(params, sampleDefs())
	if err == nil || apperr.CodeOf(err) != apperr.CodeInvalidArgument {
		t.Fatalf("want invalid_argument, got %v", err)
	}
	if !strings.Contains(err.Error(), "NOPE") {
		t.Fatalf("msg: %v", err)
	}
}

func TestValidateAgainstDefinitions_BadChoice(t *testing.T) {
	t.Parallel()
	params, err := mutation.NormalizeParams(map[string]any{"ENV": "production"})
	if err != nil {
		t.Fatal(err)
	}
	err = mutation.ValidateAgainstDefinitions(params, sampleDefs())
	if err == nil || apperr.CodeOf(err) != apperr.CodeInvalidArgument {
		t.Fatalf("want invalid_argument, got %v", err)
	}
	if !strings.Contains(err.Error(), "ENV") {
		t.Fatalf("msg: %v", err)
	}
}

func TestValidateAgainstDefinitions_SecretTypeRejected(t *testing.T) {
	t.Parallel()
	// Name is not sensitive-heuristic; type forces reject.
	params := map[string]any{"DEPLOY_KEY": "super-secret-value"}
	err := mutation.ValidateAgainstDefinitions(params, sampleDefs())
	if err == nil || apperr.CodeOf(err) != apperr.CodeInvalidArgument {
		t.Fatalf("want invalid_argument, got %v", err)
	}
	if strings.Contains(err.Error(), "super-secret-value") {
		t.Fatalf("secret leaked: %v", err)
	}
	// Credentials type via full class path.
	err = mutation.ValidateAgainstDefinitions(map[string]any{"CREDS": "id"}, sampleDefs())
	if err == nil {
		t.Fatal("credentials type must reject")
	}
}

func TestValidateAgainstDefinitions_Boolean(t *testing.T) {
	t.Parallel()
	defs := []mutation.ParamDefinition{{Name: "DEBUG", Type: "BooleanParameterDefinition"}}
	for _, v := range []any{true, false, "true", "FALSE"} {
		if err := mutation.ValidateAgainstDefinitions(map[string]any{"DEBUG": v}, defs); err != nil {
			t.Fatalf("value %#v: %v", v, err)
		}
	}
	err := mutation.ValidateAgainstDefinitions(map[string]any{"DEBUG": "yes"}, defs)
	if err == nil || apperr.CodeOf(err) != apperr.CodeInvalidArgument {
		t.Fatalf("want reject yes, got %v", err)
	}
	err = mutation.ValidateAgainstDefinitions(map[string]any{"DEBUG": 1}, defs)
	if err == nil {
		t.Fatal("numeric boolean must reject")
	}
}

func TestValidateAgainstDefinitions_UnsupportedType(t *testing.T) {
	t.Parallel()
	err := mutation.ValidateAgainstDefinitions(
		map[string]any{"ARTIFACT": "path"},
		sampleDefs(),
	)
	if err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("want unsupported, got %v", err)
	}
}

func TestValidateAgainstDefinitions_EmptyDefsRejectAnyParam(t *testing.T) {
	t.Parallel()
	err := mutation.ValidateAgainstDefinitions(map[string]any{"X": "1"}, nil)
	if err == nil {
		t.Fatal("unknown on non-parameterized job")
	}
	if err := mutation.ValidateAgainstDefinitions(nil, nil); err != nil {
		t.Fatalf("empty ok: %v", err)
	}
	if err := mutation.ValidateAgainstDefinitions(map[string]any{}, sampleDefs()); err != nil {
		t.Fatalf("omitted optional ok: %v", err)
	}
}

func TestValidateAgainstDefinitions_ClassPathTypes(t *testing.T) {
	t.Parallel()
	defs := []mutation.ParamDefinition{
		{Name: "S", Type: "hudson.model.StringParameterDefinition"},
		{Name: "C", Type: "hudson.model.ChoiceParameterDefinition", Choices: []string{"a"}},
	}
	if err := mutation.ValidateAgainstDefinitions(map[string]any{"S": "ok", "C": "a"}, defs); err != nil {
		t.Fatal(err)
	}
}
