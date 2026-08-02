package update_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/update"
)

// QA-001 Wave 21: update manifest + LKG parsers (UPD-001).
// Fail closed on garbage; never panic.

const fuzzMaxJSON = 32 << 10 // 32 KiB

// FuzzParseManifest feeds random JSON (and near-valid schemas) to ParseManifest.
func FuzzParseManifest(f *testing.F) {
	f.Add([]byte(``))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{`))
	f.Add([]byte(`null`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`{"schema_version":1,"channel":"stable","latest":{"version":"1.0.0"}}`))
	f.Add([]byte(`{"schema_version":1,"channel":"stable","version":"1.2.3"}`))
	f.Add([]byte(`{"schema_version":2,"channel":"stable","version":"1.2.3","artifacts":{"linux/amd64":{"url":"https://example.corp/a.tar.gz","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}}`))
	f.Add([]byte(`{"schema_version":99,"version":"1.0.0"}`))
	f.Add([]byte(`{"schema_version":2,"channel":"beta","version":"0.1.0","artifacts":{}}`))
	f.Add([]byte(`{"schema_version":1,"latest":{"version":""}}`))
	f.Add([]byte(`{"schema_version":2,"channel":"stable","version":"1.0.0","not_after":"not-a-date","artifacts":{"linux/amd64":{"url":"https://x/y","sha256":"bb"}}}`))
	f.Add([]byte(`{"schema_version":2,"channel":"stable","version":"1.0.0","signatures":[{"alg":"ed25519","key_id":"k","signature":"AAAA"}],"artifacts":{"linux/amd64":{"url":"http://insecure/x","sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}}}`))
	// Huge-ish but capped by fuzzer later.
	f.Add([]byte(`{"schema_version":1,"channel":"` + strings.Repeat("x", 200) + `","version":"1.0.0"}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > fuzzMaxJSON {
			return
		}
		m, err := update.ParseManifest(data)
		if err != nil {
			if m != nil {
				t.Fatalf("error with non-nil manifest: %v", err)
			}
			return
		}
		if m == nil {
			t.Fatal("nil manifest without error")
		}
		// Structure/crypto-adjacent helpers must not panic on accepted parse.
		_ = m.ValidateStructure()
		_ = m.HasSignatures()
		_, _ = m.ArtifactFor("linux", "amd64")
		_, _, _ = m.ParseNotAfter()
		if raw, err := update.CanonicalSigningBytes(m); err == nil && raw == nil {
			t.Fatal("canonical bytes nil without error")
		}
		_, _ = update.MarshalManifest(m)
		_ = update.SignatureKeyIDsFromManifest(m)
	})
}

// FuzzLoadLKG writes random JSON to a temp path and loads via LoadLKG.
// Corrupt / incomplete records fail closed; missing file is ok.
func FuzzLoadLKG(f *testing.F) {
	goodSHA := strings.Repeat("ab", 32)
	f.Add([]byte(``))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{`))
	f.Add([]byte(`null`))
	f.Add([]byte(`{"schema_version":1,"version":"1.0.0","channel":"stable","artifact_sha256":"` + goodSHA + `","path_basename":"pkg.tar.gz","timestamp":"2026-08-01T00:00:00Z"}`))
	f.Add([]byte(`{"schema_version":1,"version":"1.0.0","artifact_sha256":"short"}`))
	f.Add([]byte(`{"schema_version":1,"version":"","artifact_sha256":"` + goodSHA + `"}`))
	f.Add([]byte(`{"schema_version":1,"version":"1.0.0","artifact_sha256":"` + goodSHA + `","path_basename":"https://evil.example/x"}`))
	f.Add([]byte(`{"schema_version":1,"version":"1.0.0","artifact_sha256":"` + goodSHA + `","path_basename":"/abs/path"}`))
	f.Add([]byte(`{"schema_version":1,"version":"1.0.0","artifact_sha256":"` + goodSHA + `","path_basename":"..\\x"}`))
	f.Add([]byte(`{"password":"leak","version":"1","artifact_sha256":"` + goodSHA + `"}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > fuzzMaxJSON {
			return
		}
		// Pure Validate path when JSON binds (no I/O).
		var rec update.LKGRecord
		if err := json.Unmarshal(data, &rec); err == nil {
			_ = rec.Validate()
		}

		dir := t.TempDir()
		path := filepath.Join(dir, "last_known_good.json")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := update.LoadLKG(path)
		if err != nil {
			if got != nil {
				t.Fatalf("error with non-nil LKG: %v", err)
			}
			return
		}
		// Empty file may yield nil,nil only for missing; present empty is corrupt.
		if got != nil {
			if strings.TrimSpace(got.Version) == "" {
				t.Fatal("loaded LKG with empty version")
			}
			if len(got.ArtifactSHA256) != 64 {
				t.Fatalf("loaded LKG with bad sha len %d", len(got.ArtifactSHA256))
			}
		}

		// Empty path / missing path paths.
		if r, e := update.LoadLKG(""); e != nil || r != nil {
			t.Fatalf("empty path: %v %v", r, e)
		}
		if r, e := update.LoadLKG(filepath.Join(dir, "missing.json")); e != nil || r != nil {
			t.Fatalf("missing: %v %v", r, e)
		}
	})
}
