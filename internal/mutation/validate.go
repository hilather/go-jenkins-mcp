package mutation

import (
	"fmt"
	"strings"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// ParamDefinition is a job-level Jenkins parameter definition used for
// start_job validation (MUT-002). Independent of the Jenkins client types so
// mutation stays free of HTTP/client imports.
type ParamDefinition struct {
	Name    string
	Type    string   // Jenkins type or short class name (e.g. StringParameterDefinition)
	Choices []string // for ChoiceParameterDefinition
}

// paramKind classifies definition types for validation.
type paramKind int

const (
	paramKindString paramKind = iota
	paramKindChoice
	paramKindBoolean
	paramKindSecret
	paramKindUnsupported
)

// ValidateAgainstDefinitions checks normalized parameters against job parameter
// definitions (MUT-002). Call after NormalizeParams.
//
// Rules:
//   - Unknown parameter names → invalid_argument
//   - Choice values not in choices → invalid_argument
//   - Boolean must be bool or "true"/"false" (case-insensitive string)
//   - Password / Credentials / Secret definition types always rejected on the
//     model path (even when the name is not sensitive by heuristic)
//   - Unsupported definition types (File, Run, …) rejected when supplied
//
// Residual: Jenkins does not reliably expose a "required" flag on all definition
// types; missing optional params are allowed so Jenkins can apply defaults.
// Sensitive-name heuristic in NormalizeParams remains an additional defense.
func ValidateAgainstDefinitions(params map[string]any, defs []ParamDefinition) error {
	defByName := make(map[string]ParamDefinition, len(defs))
	for _, d := range defs {
		name := strings.TrimSpace(d.Name)
		if name == "" {
			continue
		}
		// First definition wins if Jenkins ever duplicates names.
		if _, exists := defByName[name]; !exists {
			defByName[name] = ParamDefinition{
				Name:    name,
				Type:    d.Type,
				Choices: d.Choices,
			}
		}
	}

	for name, value := range params {
		def, ok := defByName[name]
		if !ok {
			return apperr.New(apperr.CodeInvalidArgument,
				fmt.Sprintf("parameter %q is not defined on this job", name))
		}
		kind := classifyParamType(def.Type)
		switch kind {
		case paramKindSecret:
			return apperr.New(apperr.CodeInvalidArgument,
				fmt.Sprintf("parameter %q has secret/password type %q and cannot be supplied via the model mutation path",
					name, shortType(def.Type)))
		case paramKindUnsupported:
			return apperr.New(apperr.CodeInvalidArgument,
				fmt.Sprintf("parameter %q has unsupported type %q and cannot be supplied via the model mutation path",
					name, shortType(def.Type)))
		case paramKindChoice:
			if err := validateChoiceValue(name, value, def.Choices); err != nil {
				return err
			}
		case paramKindBoolean:
			if err := validateBooleanValue(name, value); err != nil {
				return err
			}
		case paramKindString:
			if err := validateStringLikeValue(name, value); err != nil {
				return err
			}
		}
	}
	return nil
}

func classifyParamType(typ string) paramKind {
	s := strings.ToLower(shortType(typ))
	if s == "" {
		// Missing type: treat as free-form string (Jenkins free-style defaults).
		return paramKindString
	}
	switch {
	case strings.Contains(s, "password"),
		strings.Contains(s, "passwd"),
		strings.Contains(s, "credentials"),
		strings.Contains(s, "secret"):
		return paramKindSecret
	case strings.Contains(s, "choice"):
		return paramKindChoice
	case strings.Contains(s, "boolean"), strings.Contains(s, "bool"):
		return paramKindBoolean
	case strings.Contains(s, "string"),
		strings.Contains(s, "text"),
		strings.Contains(s, "pt_single"), // Active Choices free-text variants residual
		s == "pt_string":
		return paramKindString
	case strings.Contains(s, "file"),
		strings.Contains(s, "runparameter"),
		strings.Contains(s, "run_parameter"),
		strings.Contains(s, "gitparameter"),
		strings.Contains(s, "git_parameter"),
		strings.Contains(s, "nodeparameter"),
		strings.Contains(s, "labelparameter"):
		return paramKindUnsupported
	default:
		// Unknown plugin types: fail closed when supplied.
		return paramKindUnsupported
	}
}

func shortType(typ string) string {
	t := strings.TrimSpace(typ)
	if i := strings.LastIndex(t, "."); i >= 0 && i+1 < len(t) {
		return t[i+1:]
	}
	return t
}

func validateChoiceValue(name string, value any, choices []string) error {
	s := strings.TrimSpace(fmt.Sprint(value))
	if len(choices) == 0 {
		// Definition present but choices empty/unavailable — fail closed.
		return apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("parameter %q is a choice parameter but no allowed choices are available from Jenkins", name))
	}
	for _, c := range choices {
		if s == c {
			return nil
		}
	}
	return apperr.New(apperr.CodeInvalidArgument,
		fmt.Sprintf("parameter %q value %q is not one of the allowed choices", name, s))
}

func validateBooleanValue(name string, value any) error {
	switch v := value.(type) {
	case bool:
		return nil
	case string:
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "true", "false":
			return nil
		default:
			return apperr.New(apperr.CodeInvalidArgument,
				fmt.Sprintf("parameter %q must be a boolean (true/false), got %q", name, v))
		}
	default:
		return apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("parameter %q must be a boolean (true/false)", name))
	}
}

func validateStringLikeValue(name string, value any) error {
	switch value.(type) {
	case nil, string, bool, float64, float32, int, int32, int64, uint, uint32, uint64:
		return nil
	default:
		// NormalizeParams usually stringifies unknowns; still reject maps/slices.
		return apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("parameter %q must be a scalar value", name))
	}
}
