package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/gateway/qualify"
)

func TestGatewayQualifyOffline(t *testing.T) {
	// Capture stdout JSON summary.
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	errRun := runGatewayQualify([]string{"--offline"})
	_ = w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatal(err)
	}
	_ = r.Close()
	if errRun != nil {
		t.Fatalf("run: %v\nstdout=%s", errRun, buf.String())
	}
	var sum qualify.Summary
	if err := json.Unmarshal(buf.Bytes(), &sum); err != nil {
		t.Fatalf("json: %v body=%s", err, buf.String())
	}
	if !sum.OK || sum.Failed != 0 {
		t.Fatalf("summary: %+v", sum)
	}
	if strings.Contains(buf.String(), qualify.CanaryToken) {
		t.Fatal("canary in CLI output")
	}
}

func TestGatewayQualifyRequiresOffline(t *testing.T) {
	err := runGatewayQualify(nil)
	if err == nil {
		t.Fatal("expected --offline required")
	}
}

func TestGatewayUnknownSubcommand(t *testing.T) {
	err := runGateway([]string{"nope"})
	if err == nil {
		t.Fatal("expected error")
	}
}
