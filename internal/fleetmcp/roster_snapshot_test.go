package fleetmcp_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/fleetmcp"
)

func TestRosterSnapshot_ApplyAndLKG(t *testing.T) {
	t.Parallel()
	s := fleetmcp.NewRosterSnapshot(fleetmcp.SnapshotOptions{})
	r1, err := fleetmcp.ParseRoster([]byte(`{
	  "schema_version":1,"fleet_id":"corp","bundle_seq":1,
	  "members":[{"id":"a","peer_url":"https://a.example"}]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Apply(r1); err != nil {
		t.Fatal(err)
	}
	if s.Current().MemberByID("a") == nil {
		t.Fatal("missing a")
	}

	// Valid advance.
	r2, err := fleetmcp.ParseRoster([]byte(`{
	  "schema_version":1,"fleet_id":"corp","bundle_seq":2,
	  "members":[
	    {"id":"a","peer_url":"https://a.example"},
	    {"id":"b","peer_url":"https://b.example"}
	  ]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Apply(r2); err != nil {
		t.Fatal(err)
	}
	if s.Current().MemberByID("b") == nil || s.Previous() == nil || s.Previous().MemberByID("b") != nil {
		t.Fatalf("current/prev: cur=%+v prev=%+v", s.Current(), s.Previous())
	}

	// Rollback rejected; LKG kept.
	r0, err := fleetmcp.ParseRoster([]byte(`{
	  "schema_version":1,"fleet_id":"corp","bundle_seq":1,
	  "members":[{"id":"a","peer_url":"https://a.example"}]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	err = s.Apply(r0)
	if err == nil {
		t.Fatal("expected rollback reject")
	}
	if apperr.CodeOf(err) != apperr.CodeInvalidArgument {
		t.Fatalf("code: %v err=%v", apperr.CodeOf(err), err)
	}
	if s.Current().BundleSeq != 2 || s.Current().MemberByID("b") == nil {
		t.Fatalf("LKG lost: %+v", s.Current())
	}

	// Authorized rollback path.
	s.SetAllowBundleSeqRollback(true)
	if err := s.Apply(r0); err != nil {
		t.Fatal(err)
	}
	if s.Current().BundleSeq != 1 {
		t.Fatalf("rollback: %d", s.Current().BundleSeq)
	}
}

func TestRosterSnapshot_ReloadCorruptKeepsLKG(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.json")
	good := []byte(`{
	  "schema_version":1,"fleet_id":"corp","bundle_seq":3,
	  "members":[{"id":"edge-a","peer_url":"http://127.0.0.1:9443"}]
	}`)
	if err := os.WriteFile(path, good, 0o600); err != nil {
		t.Fatal(err)
	}
	s := fleetmcp.NewRosterSnapshot(fleetmcp.SnapshotOptions{Path: path})
	if err := s.LoadFile(path); err != nil {
		t.Fatal(err)
	}
	// Corrupt file.
	if err := os.WriteFile(path, []byte(`{not json`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(); err == nil {
		t.Fatal("expected parse error")
	}
	if s.Current() == nil || s.Current().MemberByID("edge-a") == nil || s.Current().BundleSeq != 3 {
		t.Fatalf("LKG lost after corrupt reload: %+v", s.Current())
	}
}

func TestRosterSnapshot_ReloadMissingFileKeepsLKG(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.json")
	if err := os.WriteFile(path, []byte(`{
	  "schema_version":1,"fleet_id":"corp","bundle_seq":1,
	  "members":[{"id":"a","peer_url":"https://a.example"}]
	}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s := fleetmcp.NewRosterSnapshot(fleetmcp.SnapshotOptions{Path: path})
	if err := s.LoadFile(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(); err == nil {
		t.Fatal("expected missing file error")
	}
	if s.Current().MemberByID("a") == nil {
		t.Fatal("LKG lost")
	}
}

func TestRosterSnapshot_ConcurrentReaders(t *testing.T) {
	t.Parallel()
	s := fleetmcp.NewRosterSnapshot(fleetmcp.SnapshotOptions{})
	r, err := fleetmcp.ParseRoster([]byte(`{
	  "schema_version":1,"fleet_id":"corp","bundle_seq":1,
	  "members":[{"id":"a","peer_url":"https://a.example"}]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Apply(r); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errCh := make(chan error, 32)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				cur := s.Current()
				if cur == nil || cur.MemberByID("a") == nil {
					errCh <- errors.New("nil or incomplete roster")
					return
				}
			}
		}()
	}
	// Concurrent applies with increasing seq.
	for seq := 2; seq <= 10; seq++ {
		seq := seq
		wg.Add(1)
		go func() {
			defer wg.Done()
			rr, err := fleetmcp.ParseRoster([]byte(fmt.Sprintf(`{
			  "schema_version":1,"fleet_id":"corp","bundle_seq":%d,
			  "members":[{"id":"a","peer_url":"https://a.example"}]
			}`, seq)))
			if err != nil {
				errCh <- err
				return
			}
			_ = s.Apply(rr) // may race; some rollbacks ok
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	if s.Current() == nil {
		t.Fatal("no current")
	}
}
