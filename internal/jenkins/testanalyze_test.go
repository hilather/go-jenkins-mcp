package jenkins

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

func TestAnalyzeTestFailures_NewFlakyKnown(t *testing.T) {
	current := &TestReport{
		JobName:     "demo",
		BuildNumber: 10,
		Available:   true,
		FailCount:   3,
		FailedTests: []FailedTest{
			{Name: "newOne", ClassName: "C", Status: "FAILED", Age: 1},
			{Name: "flakyOne", ClassName: "C", Status: "FAILED", Age: 1},
			{Name: "oldOne", ClassName: "C", Status: "FAILED", Age: 5},
		},
	}
	history := []CompactBuildTests{
		{
			BuildNumber: 9, Available: true,
			Cases: []CompactCaseOutcome{
				{Key: TestCaseKey("C", "flakyOne"), Name: "flakyOne", ClassName: "C", Status: "PASSED", Failed: false},
				{Key: TestCaseKey("C", "oldOne"), Name: "oldOne", ClassName: "C", Status: "FAILED", Failed: true},
			},
		},
		{
			BuildNumber: 8, Available: true,
			Cases: []CompactCaseOutcome{
				{Key: TestCaseKey("C", "flakyOne"), Name: "flakyOne", ClassName: "C", Status: "FAILED", Failed: true},
				{Key: TestCaseKey("C", "oldOne"), Name: "oldOne", ClassName: "C", Status: "FAILED", Failed: true},
			},
		},
	}

	out := AnalyzeTestFailures("demo", 10, 5, current, history, 50)
	if out.SampleSize != 2 {
		t.Fatalf("sampleSize = %d", out.SampleSize)
	}
	byKey := map[string]TestClassification{}
	for _, c := range out.Classifications {
		if c.Kind == ClassDurationRegression {
			continue
		}
		byKey[c.Key] = c
	}
	if byKey[TestCaseKey("C", "newOne")].Kind != ClassNewFailure {
		t.Fatalf("newOne = %+v", byKey[TestCaseKey("C", "newOne")])
	}
	if byKey[TestCaseKey("C", "flakyOne")].Kind != ClassFlaky {
		t.Fatalf("flakyOne = %+v", byKey[TestCaseKey("C", "flakyOne")])
	}
	if byKey[TestCaseKey("C", "oldOne")].Kind != ClassKnownFailure {
		t.Fatalf("oldOne = %+v", byKey[TestCaseKey("C", "oldOne")])
	}
	// Confidence reflects sample size.
	if byKey[TestCaseKey("C", "flakyOne")].Confidence == "" {
		t.Fatal("expected confidence")
	}
}

func TestAnalyzeTestFailures_DurationRegression(t *testing.T) {
	current := &TestReport{
		Available: true, FailCount: 1,
		FailedTests: []FailedTest{{
			Name: "slow", ClassName: "C", Status: "FAILED",
			Duration: DurationMS(10 * time.Second),
		}},
	}
	history := []CompactBuildTests{{
		BuildNumber: 1, Available: true,
		Cases: []CompactCaseOutcome{{
			Key: TestCaseKey("C", "slow"), Name: "slow", ClassName: "C",
			Status: "PASSED", Failed: false, DurationSec: 1.0,
		}},
	}, {
		BuildNumber: 2, Available: true,
		Cases: []CompactCaseOutcome{{
			Key: TestCaseKey("C", "slow"), Name: "slow", ClassName: "C",
			Status: "PASSED", Failed: false, DurationSec: 1.2,
		}},
	}, {
		BuildNumber: 3, Available: true,
		Cases: []CompactCaseOutcome{{
			Key: TestCaseKey("C", "slow"), Name: "slow", ClassName: "C",
			Status: "PASSED", Failed: false, DurationSec: 0.9,
		}},
	}}

	out := AnalyzeTestFailures("demo", 4, 5, current, history, 50)
	found := false
	for _, c := range out.Classifications {
		if c.Kind == ClassDurationRegression {
			found = true
			if c.BaselineSec < 0.5 {
				t.Fatalf("baseline = %v", c.BaselineSec)
			}
		}
	}
	if !found {
		t.Fatalf("expected duration_regression in %+v", out.Classifications)
	}
}

func TestAnalyzeTestFailures_MaxResultsBound(t *testing.T) {
	fails := make([]FailedTest, 0, 20)
	for i := 0; i < 20; i++ {
		fails = append(fails, FailedTest{Name: "t" + strconv.Itoa(i), ClassName: "C", Status: "FAILED"})
	}
	current := &TestReport{Available: true, FailCount: 20, FailedTests: fails}
	out := AnalyzeTestFailures("demo", 1, 5, current, nil, 5)
	if len(out.Classifications) != 5 {
		t.Fatalf("len = %d", len(out.Classifications))
	}
	if !out.Truncated {
		t.Fatal("expected truncated")
	}
}

func TestAnalyzeTestFailures_MissingCurrent(t *testing.T) {
	out := AnalyzeTestFailures("demo", 1, 5, &TestReport{Available: false, Message: "no test report for this build"}, nil, 10)
	if out.CurrentAvailable {
		t.Fatal("expected unavailable")
	}
	if !strings.Contains(out.Message, "no test report") {
		t.Fatalf("msg = %q", out.Message)
	}
}

func TestAnalyzeTests_FixtureHistory(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	f.setPlugins(pluginJUnit)

	// Current build 10: fails flaky + new
	f.setTestReport(BuildJobPath("demo"), 10, `{
	  "failCount": 2, "passCount": 1, "skipCount": 0, "totalCount": 3, "duration": 1,
	  "suites": [{"name": "S", "cases": [
	    {"name": "flaky", "className": "C", "status": "FAILED", "duration": 0.5, "errorDetails": "e", "age": 1, "skipped": false},
	    {"name": "brandNew", "className": "C", "status": "FAILED", "duration": 0.1, "errorDetails": "e", "age": 1, "skipped": false},
	    {"name": "ok", "className": "C", "status": "PASSED", "duration": 0.1, "skipped": false}
	  ]}]
	}`)
	// Prior 9: flaky passed
	f.setTestReport(BuildJobPath("demo"), 9, `{
	  "failCount": 0, "passCount": 2, "skipCount": 0, "totalCount": 2, "duration": 1,
	  "suites": [{"name": "S", "cases": [
	    {"name": "flaky", "className": "C", "status": "PASSED", "duration": 0.4, "skipped": false},
	    {"name": "ok", "className": "C", "status": "PASSED", "duration": 0.1, "skipped": false}
	  ]}]
	}`)
	// Prior 8: flaky failed
	f.setTestReport(BuildJobPath("demo"), 8, `{
	  "failCount": 1, "passCount": 1, "skipCount": 0, "totalCount": 2, "duration": 1,
	  "suites": [{"name": "S", "cases": [
	    {"name": "flaky", "className": "C", "status": "FAILED", "duration": 0.4, "errorDetails": "e", "age": 1, "skipped": false},
	    {"name": "ok", "className": "C", "status": "PASSED", "duration": 0.1, "skipped": false}
	  ]}]
	}`)

	out, err := f.opts().AnalyzeTests(context.Background(), "demo", 10, 5, 50)
	if err != nil {
		t.Fatal(err)
	}
	if !out.CurrentAvailable || out.SampleSize < 2 {
		t.Fatalf("out = %+v", out)
	}
	kinds := map[string]TestClassificationKind{}
	for _, c := range out.Classifications {
		if c.Kind != ClassDurationRegression {
			kinds[c.Name] = c.Kind
		}
	}
	if kinds["brandNew"] != ClassNewFailure {
		t.Fatalf("brandNew = %v", kinds["brandNew"])
	}
	if kinds["flaky"] != ClassFlaky {
		t.Fatalf("flaky = %v", kinds["flaky"])
	}
}

func TestAnalyzeTests_CapabilityMissing(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	_, err := f.opts().AnalyzeTests(context.Background(), "demo", 1, 3, 10)
	if err == nil || !apperr.IsCode(err, apperr.CodeCapabilityMissing) {
		t.Fatalf("err = %v", err)
	}
}

func TestTestCaseKey_MatchingRules(t *testing.T) {
	if TestCaseKey("com.A", "t[1]") != "com.A/t[1]" {
		t.Fatal(TestCaseKey("com.A", "t[1]"))
	}
	// Parameterized identity is exact name string only.
	if TestCaseKey("com.A", "t[1]") == TestCaseKey("com.A", "t[2]") {
		t.Fatal("parameterized cases must not collapse")
	}
	if TestCaseKey("", "solo") != "solo" {
		t.Fatal(TestCaseKey("", "solo"))
	}
}
