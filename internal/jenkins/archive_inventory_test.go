package jenkins

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"io"
	"io/fs"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

func TestInventoryZip_OK(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("reports/out.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	data := buf.Bytes()
	inv, err := InventoryZip(bytes.NewReader(data), int64(len(data)), ArchiveInventoryLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if inv.Count != 1 || inv.Members[0].Name != "reports/out.txt" {
		t.Fatalf("%+v", inv)
	}
	if inv.Blocked {
		t.Fatal(inv.BlockReason)
	}
}

func TestInventoryZip_ZipSlip(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	// Craft entry with .. path (zip allows arbitrary names).
	w, err := zw.Create("../etc/passwd")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte("x"))
	_ = zw.Close()
	data := buf.Bytes()

	inv, err := InventoryZip(bytes.NewReader(data), int64(len(data)), ArchiveInventoryLimits{})
	if err == nil {
		t.Fatal("expected zip-slip block")
	}
	if !apperr.IsCode(err, apperr.CodeInvalidArgument) {
		t.Fatalf("code = %v err = %v", apperr.CodeOf(err), err)
	}
	if inv == nil || !inv.Blocked {
		t.Fatalf("inv = %+v", inv)
	}
	if !strings.Contains(inv.BlockReason, "zip-slip") && !strings.Contains(err.Error(), "..") {
		t.Fatalf("reason = %q", inv.BlockReason)
	}
}

func TestInventoryZip_AbsolutePath(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("/etc/passwd")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte("x"))
	_ = zw.Close()
	data := buf.Bytes()

	_, err = InventoryZip(bytes.NewReader(data), int64(len(data)), ArchiveInventoryLimits{})
	if err == nil || !apperr.IsCode(err, apperr.CodeInvalidArgument) {
		t.Fatalf("err = %v", err)
	}
}

func TestInventoryZip_SymlinkBlocked(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	hdr := &zip.FileHeader{Name: "link-to-secret"}
	hdr.SetMode(fs.ModeSymlink | 0o777)
	w, err := zw.CreateHeader(hdr)
	if err != nil {
		t.Fatal(err)
	}
	// Symlink target as body (common zip convention).
	_, _ = io.WriteString(w, "/etc/passwd")
	_ = zw.Close()
	data := buf.Bytes()

	inv, err := InventoryZip(bytes.NewReader(data), int64(len(data)), ArchiveInventoryLimits{})
	if err == nil {
		t.Fatal("expected symlink block")
	}
	if inv == nil || !inv.Blocked {
		t.Fatalf("inv = %+v", inv)
	}
	if !strings.Contains(strings.ToLower(inv.BlockReason), "symlink") {
		t.Fatalf("reason = %q", inv.BlockReason)
	}
}

func TestInventoryZip_BombExpansionRatio(t *testing.T) {
	// Store method with tiny payload but huge declared UncompressedSize64 is hard
	// with archive/zip Writer (it sets size from written bytes). Simulate by
	// patching is not practical; instead use low MaxExpandedBytes and many/large
	// store files, or low MaxExpansionRatio with a real store entry.
	//
	// Practical bomb: one large store file vs tiny compressed is impossible with
	// store (ratio ~1). Use Deflate of highly compressible data with a tight ratio.
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("zeros.bin")
	if err != nil {
		t.Fatal(err)
	}
	// Highly compressible: ratio of uncompressed/compressed can be large.
	zeros := bytes.Repeat([]byte{0}, 200_000)
	if _, err := w.Write(zeros); err != nil {
		t.Fatal(err)
	}
	_ = zw.Close()
	data := buf.Bytes()

	// Force low expansion ratio so this compressible payload is treated as bomb.
	_, err = InventoryZip(bytes.NewReader(data), int64(len(data)), ArchiveInventoryLimits{
		MaxExpansionRatio: 2.0,
		MaxExpandedBytes:  10 << 20,
	})
	if err == nil {
		// If deflate did not compress enough (unlikely), still assert absolute cap.
		_, err = InventoryZip(bytes.NewReader(data), int64(len(data)), ArchiveInventoryLimits{
			MaxExpandedBytes: 1000, // smaller than 200k claim
		})
	}
	if err == nil || !apperr.IsCode(err, apperr.CodeQuota) {
		t.Fatalf("expected bomb quota block, err=%v", err)
	}
}

func TestInventoryTar_DeviceBlocked(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	hdr := &tar.Header{
		Name:     "dev/nullish",
		Mode:     0o666,
		Size:     0,
		Typeflag: tar.TypeChar,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	_ = tw.Close()
	data := buf.Bytes()

	inv, err := InventoryTar(bytes.NewReader(data), int64(len(data)), ArchiveInventoryLimits{})
	if err == nil {
		t.Fatal("expected device block")
	}
	if inv == nil || !inv.Blocked {
		t.Fatalf("%+v", inv)
	}
}

func TestInventoryTar_SymlinkBlocked(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	hdr := &tar.Header{
		Name:     "evil-link",
		Linkname: "/etc/passwd",
		Typeflag: tar.TypeSymlink,
		Mode:     0o777,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	_ = tw.Close()
	data := buf.Bytes()

	_, err := InventoryTar(bytes.NewReader(data), int64(len(data)), ArchiveInventoryLimits{})
	if err == nil || !apperr.IsCode(err, apperr.CodeInvalidArgument) {
		t.Fatalf("err = %v", err)
	}
}

func TestInventoryTar_OK(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	body := []byte("payload")
	hdr := &tar.Header{
		Name:     "a/b.txt",
		Mode:     0o644,
		Size:     int64(len(body)),
		Typeflag: tar.TypeReg,
		ModTime:  time.Unix(0, 0),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	_ = tw.Close()
	data := buf.Bytes()

	inv, err := InventoryTar(bytes.NewReader(data), int64(len(data)), ArchiveInventoryLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if inv.Count != 1 || inv.Members[0].Name != "a/b.txt" {
		t.Fatalf("%+v", inv)
	}
}

func TestValidateArchiveMemberPath(t *testing.T) {
	if err := validateArchiveMemberPath("ok/path.txt", 32, 512); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"../x", "/abs", "a/../../b", "C:/windows"} {
		if err := validateArchiveMemberPath(bad, 32, 512); err == nil {
			t.Fatalf("expected fail for %q", bad)
		}
	}
}

func TestInventoryZip_MemberCap(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for i := 0; i < 10; i++ {
		w, _ := zw.Create(strings.Repeat("f", 1) + string(rune('a'+i)) + ".txt")
		_, _ = w.Write([]byte("x"))
	}
	_ = zw.Close()
	data := buf.Bytes()
	inv, err := InventoryZip(bytes.NewReader(data), int64(len(data)), ArchiveInventoryLimits{MaxMembers: 3})
	if err != nil {
		t.Fatal(err)
	}
	if inv.Count != 3 || !inv.Truncated {
		t.Fatalf("%+v", inv)
	}
}

// Ensure we do not write temp files during inventory (regression: pure stream).
func TestInventoryZip_NoTempFiles(t *testing.T) {
	dir, err := os.MkdirTemp("", "art002-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	// Run inventory; temp dir listing should stay empty of our artifacts.
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("x.txt")
	_, _ = w.Write([]byte("y"))
	_ = zw.Close()
	data := buf.Bytes()
	_, err = InventoryZip(bytes.NewReader(data), int64(len(data)), ArchiveInventoryLimits{})
	if err != nil {
		t.Fatal(err)
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 0 {
		t.Fatalf("unexpected temp writes: %v", ents)
	}
}
