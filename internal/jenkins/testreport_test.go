package jenkins

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

const sampleTestReport = `{
  "failCount": 2,
  "passCount": 10,
  "skipCount": 1,
  "totalCount": 13,
  "duration": 12.5,
  "suites": [
    {
      "name": "com.example.AppTest",
      "cases": [
        {
          "name": "testOk",
          "className": "com.example.AppTest",
          "status": "PASSED",
          "duration": 0.1,
          "errorDetails": null,
          "errorStackTrace": null,
          "age": 0,
          "skipped": false
        },
        {
          "name": "testFails",
          "className": "com.example.AppTest",
          "status": "FAILED",
          "duration": 0.2,
          "errorDetails": "expected true but was false",
          "errorStackTrace": "java.lang.AssertionError: expected true but was false\n\tat com.example.AppTest.testFails(AppTest.java:42)\n",
          "age": 3,
          "skipped": false
        },
        {
          "name": "testSkipped",
          "className": "com.example.AppTest",
          "status": "SKIPPED",
          "duration": 0,
          "skipped": true
        }
      ]
    },
    {
      "name": "com.example.OtherTest",
      "cases": [
        {
          "name": "testRegress",
          "className": "com.example.OtherTest",
          "status": "REGRESSION",
          "duration": 1.5,
          "errorDetails": "boom",
          "errorStackTrace": "trace",
          "age": 1,
          "skipped": false
        }
      ]
    }
  ]
}`

func TestGetTestReport_SummaryAndFailedList(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	f.setPlugins(pluginJUnit)
	f.setTestReport(BuildJobPath("demo"), 7, sampleTestReport)

	rep, err := f.opts().GetTestReport(context.Background(), "demo", 7, 25)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Available {
		t.Fatal("expected available")
	}
	if rep.PassCount != 10 || rep.FailCount != 2 || rep.SkipCount != 1 || rep.TotalCount != 13 {
		t.Fatalf("counts = pass=%d fail=%d skip=%d total=%d",
			rep.PassCount, rep.FailCount, rep.SkipCount, rep.TotalCount)
	}
	if len(rep.FailedTests) != 2 {
		t.Fatalf("failed = %+v", rep.FailedTests)
	}
	if rep.FailedTests[0].Name != "testFails" || rep.FailedTests[0].ClassName != "com.example.AppTest" {
		t.Fatalf("first fail = %+v", rep.FailedTests[0])
	}
	if !strings.Contains(rep.FailedTests[0].ErrorDetails, "expected true") {
		t.Fatalf("error details = %q", rep.FailedTests[0].ErrorDetails)
	}
	if rep.FailedTests[1].Name != "testRegress" || rep.FailedTests[1].Status != "REGRESSION" {
		t.Fatalf("second fail = %+v", rep.FailedTests[1])
	}
	if rep.FailedTestsTruncated {
		t.Fatal("should not be truncated")
	}
}

func TestGetTestReport_MaxFailedBound(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	f.setPlugins(pluginJUnit)
	// Build a report with many failures.
	var cases []string
	for i := 0; i < 50; i++ {
		cases = append(cases, `{
		  "name": "t`+strconv.Itoa(i)+`",
		  "className": "C",
		  "status": "FAILED",
		  "duration": 0.01,
		  "errorDetails": "e",
		  "errorStackTrace": "s",
		  "age": 1,
		  "skipped": false
		}`)
	}
	body := `{
	  "failCount": 50,
	  "passCount": 0,
	  "skipCount": 0,
	  "totalCount": 50,
	  "duration": 1,
	  "suites": [{"name": "S", "cases": [` + strings.Join(cases, ",") + `]}]
	}`
	f.setTestReport(BuildJobPath("demo"), 1, body)

	rep, err := f.opts().GetTestReport(context.Background(), "demo", 1, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.FailedTests) != 5 {
		t.Fatalf("len failed = %d", len(rep.FailedTests))
	}
	if !rep.FailedTestsTruncated {
		t.Fatal("expected truncated")
	}
}

func TestGetTestReport_MissingReportEmpty(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	f.setPlugins(pluginJUnit)
	// No testReport registered → 404 empty (not invented success).

	rep, err := f.opts().GetTestReport(context.Background(), "demo", 7, 10)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Available {
		t.Fatal("expected unavailable")
	}
	if rep.PassCount != 0 || rep.FailCount != 0 {
		t.Fatalf("must not invent counts: %+v", rep)
	}
	if rep.Message == "" {
		t.Fatal("expected clarity message")
	}
}

func TestGetTestReport_ErrorMessageTruncation(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	f.setPlugins(pluginJUnit)
	long := strings.Repeat("x", maxTestErrorMessageRunes+500)
	body := `{
	  "failCount": 1, "passCount": 0, "skipCount": 0, "totalCount": 1, "duration": 1,
	  "suites": [{"name": "S", "cases": [{
	    "name": "big", "className": "C", "status": "FAILED", "duration": 1,
	    "errorDetails": "` + long + `",
	    "errorStackTrace": "` + long + `",
	    "age": 1, "skipped": false
	  }]}]
	}`
	f.setTestReport(BuildJobPath("demo"), 2, body)

	rep, err := f.opts().GetTestReport(context.Background(), "demo", 2, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.FailedTests) != 1 {
		t.Fatalf("failed = %+v", rep.FailedTests)
	}
	// Truncation adds ellipsis; rune count of content before ellipsis ≤ max.
	if utf8.RuneCountInString(rep.FailedTests[0].ErrorDetails) > maxTestErrorMessageRunes+1 {
		t.Fatalf("errorDetails too long: %d", utf8.RuneCountInString(rep.FailedTests[0].ErrorDetails))
	}
}
