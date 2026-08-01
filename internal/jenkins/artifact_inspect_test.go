package jenkins

import (
	"archive/zip"
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

func TestInspectArtifact_Text(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	f.setArtifact(BuildJobPath("demo"), 1, "notes.txt", []byte("hello world\n"))

	ins, err := f.opts().InspectArtifact(context.Background(), "demo", 1, "notes.txt", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if ins.Kind != InspectKindText || ins.Text != "hello world\n" {
		t.Fatalf("%+v", ins)
	}
}

func TestInspectArtifact_JSON(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	f.setArtifact(BuildJobPath("demo"), 1, "data.json", []byte(`{"ok":true,"n":1}`))

	ins, err := f.opts().InspectArtifact(context.Background(), "demo", 1, "data.json", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if ins.Kind != InspectKindJSON || !ins.JSONValid {
		t.Fatalf("%+v", ins)
	}
}

func TestInspectArtifact_XML(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	f.setArtifact(BuildJobPath("demo"), 1, "report.xml", []byte(`<?xml version="1.0"?><root><a>1</a></root>`))

	ins, err := f.opts().InspectArtifact(context.Background(), "demo", 1, "report.xml", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if ins.Kind != InspectKindXML || !ins.XMLValid {
		t.Fatalf("%+v", ins)
	}
}

func TestInspectArtifact_ZipInventory(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("inside/a.txt")
	_, _ = w.Write([]byte("payload"))
	_ = zw.Close()
	f.setArtifact(BuildJobPath("demo"), 1, "bundle.zip", buf.Bytes())

	ins, err := f.opts().InspectArtifact(context.Background(), "demo", 1, "bundle.zip", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if ins.Kind != InspectKindArchive || ins.Archive == nil || ins.Archive.Count != 1 {
		t.Fatalf("%+v", ins)
	}
	if ins.Archive.Members[0].Name != "inside/a.txt" {
		t.Fatalf("member = %+v", ins.Archive.Members[0])
	}
}

func TestInspectArtifact_ZipSlipBlocked(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("../../evil.txt")
	_, _ = w.Write([]byte("x"))
	_ = zw.Close()
	f.setArtifact(BuildJobPath("demo"), 1, "bad.zip", buf.Bytes())

	ins, err := f.opts().InspectArtifact(context.Background(), "demo", 1, "bad.zip", 0, 0)
	if err != nil {
		// Structured block returns nil error with Message set.
		t.Fatalf("unexpected transport err: %v", err)
	}
	if ins.Archive == nil || !ins.Archive.Blocked {
		t.Fatalf("expected blocked inventory: %+v", ins)
	}
	if ins.Message == "" {
		t.Fatal("expected message")
	}
}

func TestInspectArtifact_RefuseExecExt(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	f.setArtifact(BuildJobPath("demo"), 1, "lib.so", []byte{0x7f, 'E', 'L', 'F'})

	ins, err := f.opts().InspectArtifact(context.Background(), "demo", 1, "lib.so", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if ins.Kind != InspectKindBinary {
		t.Fatalf("%+v", ins)
	}
	if f.artifactHits.Load() != 0 {
		t.Fatal("must not download refused binary")
	}
}

func TestInspectArtifact_PathTraversal(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	_, err := f.opts().InspectArtifact(context.Background(), "demo", 1, "../secret", 0, 0)
	if err == nil || !apperr.IsCode(err, apperr.CodeInvalidArgument) {
		t.Fatalf("err = %v", err)
	}
}

func TestInspectArtifact_InvalidJSON(t *testing.T) {
	f := newJenkinsFixture()
	defer f.close()
	f.setArtifact(BuildJobPath("demo"), 1, "bad.json", []byte(`{not json`))

	ins, err := f.opts().InspectArtifact(context.Background(), "demo", 1, "bad.json", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if ins.JSONValid || ins.ParseError == "" {
		t.Fatalf("%+v", ins)
	}
	if strings.Contains(ins.Text, "\x00") {
		t.Fatal("nul in text")
	}
}
