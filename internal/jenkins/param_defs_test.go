package jenkins

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// Fixture JSON covering String / Choice / Boolean / Password definition types (MUT-002).
const paramDefsJobJSON = `{
  "name": "param-demo",
  "url": "http://jenkins/job/param-demo/",
  "color": "blue",
  "buildable": true,
  "description": "parameterized",
  "lastBuild": null,
  "builds": [],
  "property": [
    {
      "_class": "hudson.model.ParametersDefinitionProperty",
      "parameterDefinitions": [
        {
          "_class": "hudson.model.StringParameterDefinition",
          "name": "BRANCH",
          "type": "StringParameterDefinition",
          "description": "Git branch",
          "defaultParameterValue": { "value": "main" }
        },
        {
          "_class": "hudson.model.ChoiceParameterDefinition",
          "name": "ENV",
          "type": "ChoiceParameterDefinition",
          "choices": ["dev", "stage", "prod"],
          "defaultParameterValue": { "value": "dev" }
        },
        {
          "_class": "hudson.model.BooleanParameterDefinition",
          "name": "DEBUG",
          "type": "BooleanParameterDefinition",
          "defaultParameterValue": { "value": false }
        },
        {
          "_class": "hudson.model.PasswordParameterDefinition",
          "name": "DEPLOY_KEY",
          "type": "PasswordParameterDefinition",
          "defaultParameterValue": { "value": "raw-password-default" }
        },
        {
          "name": "FROM_CLASS_ONLY",
          "_class": "hudson.model.StringParameterDefinition",
          "defaultParameterValue": { "value": "x" }
        },
        {
          "name": "CHOICE_NL",
          "type": "ChoiceParameterDefinition",
          "choices": "alpha\nbeta\ngamma"
        }
      ]
    }
  ]
}`

func TestGetJenkinsJob_ParameterDefinitions(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	f.jobJSON["job/param-demo"] = paramDefsJobJSON

	job, err := f.opts().GetJenkinsJob(context.Background(), "param-demo", 0)
	if err != nil {
		t.Fatal(err)
	}
	if job.Name != "param-demo" {
		t.Fatalf("name: %s", job.Name)
	}
	byName := map[string]BuildParameter{}
	for _, p := range job.Parameters {
		byName[p.Name] = p
	}
	if len(byName) < 5 {
		t.Fatalf("defs: %+v", job.Parameters)
	}
	if byName["BRANCH"].Type != "StringParameterDefinition" || byName["BRANCH"].DefaultValue != "main" {
		t.Fatalf("BRANCH: %+v", byName["BRANCH"])
	}
	if got := byName["ENV"].Choices; len(got) != 3 || got[0] != "dev" {
		t.Fatalf("ENV choices: %v", got)
	}
	if byName["DEBUG"].Type != "BooleanParameterDefinition" {
		t.Fatalf("DEBUG: %+v", byName["DEBUG"])
	}
	// Password default must be scrubbed.
	if byName["DEPLOY_KEY"].DefaultValue != nil {
		t.Fatalf("password default must be scrubbed: %+v", byName["DEPLOY_KEY"])
	}
	if byName["DEPLOY_KEY"].Type != "PasswordParameterDefinition" {
		t.Fatalf("DEPLOY_KEY type: %+v", byName["DEPLOY_KEY"])
	}
	// type from _class only
	if byName["FROM_CLASS_ONLY"].Type != "StringParameterDefinition" {
		t.Fatalf("FROM_CLASS_ONLY: %+v", byName["FROM_CLASS_ONLY"])
	}
	// newline-separated choices
	if got := byName["CHOICE_NL"].Choices; len(got) != 3 || got[1] != "beta" {
		t.Fatalf("CHOICE_NL: %v", got)
	}
}

func TestGetJobParameterDefinitions(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	f.jobJSON["job/param-demo"] = paramDefsJobJSON

	defs, err := f.opts().GetJobParameterDefinitions(context.Background(), "param-demo")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, d := range defs {
		names = append(names, d.Name)
		if d.Name == "DEPLOY_KEY" && d.DefaultValue != nil {
			t.Fatalf("secret default leaked: %#v", d.DefaultValue)
		}
	}
	joined := strings.Join(names, ",")
	for _, want := range []string{"BRANCH", "ENV", "DEBUG", "DEPLOY_KEY"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %s in %v", want, names)
		}
	}
}

func TestParseParameterDefinitions_Empty(t *testing.T) {
	if got := parseParameterDefinitions(nil); got == nil || len(got) != 0 {
		t.Fatalf("%#v", got)
	}
}

func TestFlexibleChoicesJSON(t *testing.T) {
	var wrap struct {
		Choices flexibleChoices `json:"choices"`
	}
	if err := json.Unmarshal([]byte(`{"choices":["a","b"]}`), &wrap); err != nil {
		t.Fatal(err)
	}
	if len(wrap.Choices) != 2 {
		t.Fatalf("%v", wrap.Choices)
	}
	wrap.Choices = nil
	if err := json.Unmarshal([]byte(`{"choices":"x\ny"}`), &wrap); err != nil {
		t.Fatal(err)
	}
	if len(wrap.Choices) != 2 || wrap.Choices[0] != "x" {
		t.Fatalf("%v", wrap.Choices)
	}
}

func TestIsSecretParameterType(t *testing.T) {
	for _, typ := range []string{
		"PasswordParameterDefinition",
		"hudson.model.PasswordParameterDefinition",
		"CredentialsParameterDefinition",
		"Secret",
	} {
		if !isSecretParameterType(typ) {
			t.Fatalf("want secret: %s", typ)
		}
	}
	if isSecretParameterType("StringParameterDefinition") {
		t.Fatal("string not secret")
	}
}
