package jenkins

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"path"
	"strings"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// Archive inventory bounds (ART-002). Inventory-only — never extract or execute.
const (
	DefaultMaxArchiveMembers       = 200
	MaxArchiveMembersHardCap       = 1000
	DefaultMaxArchiveExpandedBytes = 64 << 20 // 64 MiB claimed expanded
	DefaultMaxArchiveDownloadBytes = 4 << 20  // 4 MiB compressed download
	MaxArchiveDownloadBytesHardCap = 16 << 20 // 16 MiB
	DefaultMaxArchivePathDepth     = 32
	DefaultMaxArchiveNameBytes     = 512
	// DefaultMaxExpansionRatio is claimed_uncompressed / compressed_download size.
	// Zip bombs claim huge UncompressedSize with tiny compressed bodies.
	DefaultMaxExpansionRatio = 100.0
	// DefaultArchiveInventoryTimeout bounds CPU for pathological central directories.
	DefaultArchiveInventoryTimeout = 5 * time.Second
)

// ArchiveMember is one inventory row (name/size/method only — no content).
type ArchiveMember struct {
	// Name is the sanitized relative member path (never absolute / ..).
	Name string `json:"name"`
	// Size is uncompressed size when known (from headers; not expanded).
	Size int64 `json:"size"`
	// CompressedSize is the compressed size when known (zip).
	CompressedSize int64 `json:"compressedSize,omitempty"`
	// Method is a short compression/method label (e.g. "deflate", "store", "tar").
	Method string `json:"method,omitempty"`
	// Mode is a coarse type label: file, dir (others are rejected before listing).
	Mode string `json:"mode,omitempty"`
}

// ArchiveInventory is a safe listing of archive members (ART-002).
type ArchiveInventory struct {
	// Format is "zip", "tar", or "tar.gz" etc. when recognized.
	Format string `json:"format"`
	// Members is the bounded inventory (never extracted content).
	Members []ArchiveMember `json:"members"`
	// Count is len(Members).
	Count int `json:"count"`
	// TotalUncompressed is the sum of claimed uncompressed sizes (headers only).
	TotalUncompressed int64 `json:"totalUncompressed"`
	// CompressedBytes is the downloaded compressed byte count used for ratio checks.
	CompressedBytes int64 `json:"compressedBytes"`
	// Truncated is true when member cap stopped enumeration.
	Truncated bool `json:"truncated,omitempty"`
	// Blocked is true when a safety limit rejected the archive.
	Blocked bool `json:"blocked,omitempty"`
	// BlockReason explains why inventory was refused or partial.
	BlockReason string `json:"blockReason,omitempty"`
}

// ArchiveInventoryLimits controls pure inventory functions.
type ArchiveInventoryLimits struct {
	MaxMembers        int
	MaxExpandedBytes  int64
	MaxExpansionRatio float64
	MaxPathDepth      int
	MaxNameBytes      int
	// Deadline when non-zero stops inventory (CPU/time cap).
	Deadline time.Time
}

// Normalize applies defaults and hard caps.
func (l ArchiveInventoryLimits) Normalize() ArchiveInventoryLimits {
	if l.MaxMembers <= 0 {
		l.MaxMembers = DefaultMaxArchiveMembers
	}
	if l.MaxMembers > MaxArchiveMembersHardCap {
		l.MaxMembers = MaxArchiveMembersHardCap
	}
	if l.MaxExpandedBytes <= 0 {
		l.MaxExpandedBytes = DefaultMaxArchiveExpandedBytes
	}
	if l.MaxExpansionRatio <= 0 {
		l.MaxExpansionRatio = DefaultMaxExpansionRatio
	}
	if l.MaxPathDepth <= 0 {
		l.MaxPathDepth = DefaultMaxArchivePathDepth
	}
	if l.MaxNameBytes <= 0 {
		l.MaxNameBytes = DefaultMaxArchiveNameBytes
	}
	return l
}

// InventoryZip streams a zip central directory / file headers into a bounded inventory.
// Does not extract member content. Rejects zip-slip, absolute paths, symlinks, and bombs.
func InventoryZip(r io.ReaderAt, size int64, lim ArchiveInventoryLimits) (*ArchiveInventory, error) {
	lim = lim.Normalize()
	out := &ArchiveInventory{
		Format:          "zip",
		CompressedBytes: size,
		Members:         make([]ArchiveMember, 0),
	}
	if size < 0 {
		return nil, apperr.New(apperr.CodeInvalidArgument, "invalid zip size")
	}
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeInvalidArgument, "invalid zip archive", err)
	}

	var totalUnc int64
	// Scan all central-directory headers for slip/symlink/bomb; only return MaxMembers.
	for _, f := range zr.File {
		if !lim.Deadline.IsZero() && time.Now().After(lim.Deadline) {
			out.Blocked = true
			out.BlockReason = "archive inventory time budget exceeded"
			return out, apperr.New(apperr.CodeTimeout, out.BlockReason)
		}
		name := f.Name
		if err := validateArchiveMemberPath(name, lim.MaxPathDepth, lim.MaxNameBytes); err != nil {
			out.Blocked = true
			out.BlockReason = err.Error()
			return out, err
		}
		// Symlink / non-regular: zip mode bit (Unix) in external attrs.
		if isZipSymlinkOrSpecial(f) {
			out.Blocked = true
			out.BlockReason = "archive contains symlink or special file; inventory refused"
			return out, apperr.New(apperr.CodeInvalidArgument, out.BlockReason)
		}
		unc := int64(f.UncompressedSize64)
		if unc < 0 {
			out.Blocked = true
			out.BlockReason = "negative uncompressed size"
			return out, apperr.New(apperr.CodeInvalidArgument, out.BlockReason)
		}
		// Overflow-safe accumulate (full archive, not just returned page).
		if unc > 0 && totalUnc > lim.MaxExpandedBytes-unc {
			out.Blocked = true
			out.BlockReason = "archive expanded byte claim exceeds limit (archive bomb)"
			return out, apperr.New(apperr.CodeQuota, out.BlockReason)
		}
		totalUnc += unc

		if len(out.Members) >= lim.MaxMembers {
			out.Truncated = true
			continue
		}
		mode := "file"
		if f.FileInfo().IsDir() || strings.HasSuffix(name, "/") {
			mode = "dir"
		}
		out.Members = append(out.Members, ArchiveMember{
			Name:           path.Clean(strings.ReplaceAll(name, "\\", "/")),
			Size:           unc,
			CompressedSize: int64(f.CompressedSize64),
			Method:         zipMethodName(f.Method),
			Mode:           mode,
		})
	}

	out.Count = len(out.Members)
	out.TotalUncompressed = totalUnc
	if err := checkExpansionRatio(totalUnc, size, lim.MaxExpansionRatio); err != nil {
		out.Blocked = true
		out.BlockReason = err.Error()
		return out, err
	}
	return out, nil
}

// InventoryTar streams a tar (optionally from already-decompressed bytes) into inventory.
// Does not extract; rejects absolute/.. paths, symlinks, devices, and bombs.
func InventoryTar(r io.Reader, compressedSize int64, lim ArchiveInventoryLimits) (*ArchiveInventory, error) {
	lim = lim.Normalize()
	out := &ArchiveInventory{
		Format:          "tar",
		CompressedBytes: compressedSize,
		Members:         make([]ArchiveMember, 0),
	}
	tr := tar.NewReader(r)
	var totalUnc int64
	// Scan full stream for slip/device/bomb; only return MaxMembers rows.
	for {
		if !lim.Deadline.IsZero() && time.Now().After(lim.Deadline) {
			out.Blocked = true
			out.BlockReason = "archive inventory time budget exceeded"
			return out, apperr.New(apperr.CodeTimeout, out.BlockReason)
		}
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, apperr.Wrap(apperr.CodeInvalidArgument, "invalid tar archive", err)
		}
		if err := validateArchiveMemberPath(hdr.Name, lim.MaxPathDepth, lim.MaxNameBytes); err != nil {
			out.Blocked = true
			out.BlockReason = err.Error()
			return out, err
		}
		switch hdr.Typeflag {
		case tar.TypeReg, tar.TypeRegA, tar.TypeDir, tar.TypeGNUSparse:
			// allowed
		case tar.TypeSymlink, tar.TypeLink:
			out.Blocked = true
			out.BlockReason = "archive contains symlink or hardlink; inventory refused"
			return out, apperr.New(apperr.CodeInvalidArgument, out.BlockReason)
		case tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
			out.Blocked = true
			out.BlockReason = "archive contains device or fifo; inventory refused"
			return out, apperr.New(apperr.CodeInvalidArgument, out.BlockReason)
		default:
			// Unknown types: refuse (fail closed).
			out.Blocked = true
			out.BlockReason = fmt.Sprintf("archive contains unsupported entry type %q", string(hdr.Typeflag))
			return out, apperr.New(apperr.CodeInvalidArgument, out.BlockReason)
		}
		sz := hdr.Size
		if sz < 0 {
			out.Blocked = true
			out.BlockReason = "negative tar size"
			return out, apperr.New(apperr.CodeInvalidArgument, out.BlockReason)
		}
		if sz > 0 && totalUnc > lim.MaxExpandedBytes-sz {
			out.Blocked = true
			out.BlockReason = "archive expanded byte claim exceeds limit (archive bomb)"
			return out, apperr.New(apperr.CodeQuota, out.BlockReason)
		}
		totalUnc += sz
		// Skip body without materializing (inventory only).
		if _, err := io.Copy(io.Discard, tr); err != nil {
			return nil, apperr.Wrap(apperr.CodeInvalidArgument, "failed to skip tar member body", err)
		}
		if len(out.Members) >= lim.MaxMembers {
			out.Truncated = true
			continue
		}
		mode := "file"
		if hdr.Typeflag == tar.TypeDir || strings.HasSuffix(hdr.Name, "/") {
			mode = "dir"
		}
		out.Members = append(out.Members, ArchiveMember{
			Name:   path.Clean(strings.ReplaceAll(hdr.Name, "\\", "/")),
			Size:   sz,
			Method: "tar",
			Mode:   mode,
		})
	}
	out.Count = len(out.Members)
	out.TotalUncompressed = totalUnc
	if compressedSize > 0 {
		if err := checkExpansionRatio(totalUnc, compressedSize, lim.MaxExpansionRatio); err != nil {
			out.Blocked = true
			out.BlockReason = err.Error()
			return out, err
		}
	}
	return out, nil
}

// InventoryArchiveBytes detects zip vs tar from path/magic and inventories without extract.
func InventoryArchiveBytes(data []byte, artifactPath string, lim ArchiveInventoryLimits) (*ArchiveInventory, error) {
	lim = lim.Normalize()
	if lim.Deadline.IsZero() {
		lim.Deadline = time.Now().Add(DefaultArchiveInventoryTimeout)
	}
	ext := strings.ToLower(path.Ext(artifactPath))
	base := strings.ToLower(artifactPath)
	switch {
	case ext == ".zip" || (len(data) >= 2 && data[0] == 'P' && data[1] == 'K'):
		return InventoryZip(bytes.NewReader(data), int64(len(data)), lim)
	case strings.HasSuffix(base, ".tar.gz") || strings.HasSuffix(base, ".tgz"):
		// Residual: gzip-wrapped tar not decompressed here without bound.
		// Treat as unsupported nested format for v1 inventory.
		return nil, apperr.New(apperr.CodeInvalidArgument,
			"tar.gz inventory requires streaming gunzip (use .tar or .zip); residual ART-002")
	case ext == ".tar" || isTarMagic(data):
		return InventoryTar(bytes.NewReader(data), int64(len(data)), lim)
	default:
		return nil, apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("unsupported archive type for path %q", artifactPath))
	}
}

func isTarMagic(data []byte) bool {
	// ustar at offset 257
	if len(data) < 262 {
		return false
	}
	return string(data[257:262]) == "ustar"
}

// validateArchiveMemberPath rejects absolute paths, .., empty, and over-deep names (zip-slip).
func validateArchiveMemberPath(name string, maxDepth, maxNameBytes int) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return apperr.New(apperr.CodeInvalidArgument, "archive member has empty name")
	}
	if maxNameBytes > 0 && len(name) > maxNameBytes {
		return apperr.New(apperr.CodeInvalidArgument, "archive member name too long")
	}
	// Normalize separators for checks.
	n := strings.ReplaceAll(name, "\\", "/")
	if strings.HasPrefix(n, "/") || strings.HasPrefix(n, "//") {
		return apperr.New(apperr.CodeInvalidArgument, "archive member path is absolute (zip-slip)")
	}
	// Windows drive / UNC-like
	if len(n) >= 2 && n[1] == ':' {
		return apperr.New(apperr.CodeInvalidArgument, "archive member path looks absolute (drive)")
	}
	if strings.Contains(n, "://") {
		return apperr.New(apperr.CodeInvalidArgument, "archive member path must not be a URL")
	}
	parts := strings.Split(n, "/")
	depth := 0
	for _, p := range parts {
		if p == "" || p == "." {
			continue
		}
		if p == ".." {
			return apperr.New(apperr.CodeInvalidArgument, "archive member path contains .. (zip-slip)")
		}
		depth++
	}
	if maxDepth > 0 && depth > maxDepth {
		return apperr.New(apperr.CodeInvalidArgument, "archive member path nesting exceeds limit")
	}
	cleaned := path.Clean(n)
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return apperr.New(apperr.CodeInvalidArgument, "archive member path escapes root (zip-slip)")
	}
	return nil
}

func isZipSymlinkOrSpecial(f *zip.File) bool {
	mode := f.Mode()
	if mode&fs.ModeSymlink != 0 {
		return true
	}
	if mode&fs.ModeDevice != 0 || mode&fs.ModeNamedPipe != 0 || mode&fs.ModeSocket != 0 {
		return true
	}
	// Non-regular, non-dir entries are refused (fail closed).
	if mode != 0 && !mode.IsRegular() && !mode.IsDir() {
		return true
	}
	return false
}

func zipMethodName(m uint16) string {
	switch m {
	case zip.Store:
		return "store"
	case zip.Deflate:
		return "deflate"
	default:
		return fmt.Sprintf("method-%d", m)
	}
}

func checkExpansionRatio(uncompressed, compressed int64, maxRatio float64) error {
	if compressed <= 0 {
		// Empty / unknown compressed: only absolute expanded cap applies.
		return nil
	}
	if uncompressed <= 0 {
		return nil
	}
	ratio := float64(uncompressed) / float64(compressed)
	if ratio > maxRatio {
		return apperr.New(apperr.CodeQuota,
			fmt.Sprintf("archive expansion ratio %.1f exceeds limit %.1f (archive bomb)", ratio, maxRatio))
	}
	return nil
}
