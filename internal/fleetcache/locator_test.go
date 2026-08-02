package fleetcache_test

import (
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/fleetcache"
)

// fleetcacheGoldenLocatorHash is SHA-256 hex of CanonicalBytes for:
// fleet-corp / jenkins-prod-logs / jenkins-prod / folder/job / 42 (schema v1).
// Update only with LocatorSchemaVersion or CanonicalBytes format ADR bump.
const fleetcacheGoldenLocatorHash = "ce8a0c03c2a0d6cad0dd35e636481bb26b95d7bfc33d8f57869e2046ba3840a2"

func TestNewConsoleLogLocator_StableHash(t *testing.T) {
	t.Parallel()
	a, err := fleetcache.NewConsoleLogLocator("fleet-corp", "jenkins-prod-logs", "jenkins-prod", "folder/job", 42)
	if err != nil {
		t.Fatal(err)
	}
	h1, err := a.Hash()
	if err != nil {
		t.Fatal(err)
	}
	b, err := fleetcache.NewConsoleLogLocator("fleet-corp", "jenkins-prod-logs", "jenkins-prod", "folder/job", 42)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := b.Hash()
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Fatalf("non-deterministic: %s vs %s", h1, h2)
	}
	if len(h1) != 64 {
		t.Fatalf("hash len %d", len(h1))
	}
	can, err := a.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	cs := string(can)
	for _, need := range []string{
		"fleet_id=fleet-corp\n",
		"cache_pool=jenkins-prod-logs\n",
		"controller_id=jenkins-prod\n",
		"object_kind=console_log\n",
		"job_full_name=folder/job\n",
		"build_number=42\n",
		"locator_schema_version=1\n",
	} {
		if !strings.Contains(cs, need) {
			t.Fatalf("canonical missing %q in %q", need, cs)
		}
	}
	if h1 != fleetcacheGoldenLocatorHash {
		t.Fatalf("golden locator hash changed: got %s want %s (update golden if format intentionally changed)", h1, fleetcacheGoldenLocatorHash)
	}
}

func TestNewConsoleLogLocator_DiffersByField(t *testing.T) {
	t.Parallel()
	base, _ := fleetcache.NewConsoleLogLocator("f", "p", "c", "job", 1)
	hBase, _ := base.Hash()
	cases := []struct {
		name string
		loc  func() (fleetcache.Locator, error)
	}{
		{"fleet", func() (fleetcache.Locator, error) {
			return fleetcache.NewConsoleLogLocator("other", "p", "c", "job", 1)
		}},
		{"pool", func() (fleetcache.Locator, error) {
			return fleetcache.NewConsoleLogLocator("f", "other", "c", "job", 1)
		}},
		{"controller", func() (fleetcache.Locator, error) {
			return fleetcache.NewConsoleLogLocator("f", "p", "other", "job", 1)
		}},
		{"job", func() (fleetcache.Locator, error) {
			return fleetcache.NewConsoleLogLocator("f", "p", "c", "other-job", 1)
		}},
		{"build", func() (fleetcache.Locator, error) {
			return fleetcache.NewConsoleLogLocator("f", "p", "c", "job", 2)
		}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			l, err := tc.loc()
			if err != nil {
				t.Fatal(err)
			}
			h, err := l.Hash()
			if err != nil {
				t.Fatal(err)
			}
			if h == hBase {
				t.Fatalf("expected different hash for %s", tc.name)
			}
		})
	}
}

func TestNewConsoleLogLocator_RejectsLocalIDsAndBadJobs(t *testing.T) {
	t.Parallel()
	// Local store key form profile|job|build must not become a locator.
	if _, err := fleetcache.NewConsoleLogLocator("f", "p", "c", "myprofile|folder/job|99", 99); err == nil {
		t.Fatal("expected reject store-key shaped job")
	}
	// Bad jobs
	for _, job := range []string{"", "../x", "/abs", "http://evil/job", "a//b"} {
		if _, err := fleetcache.NewConsoleLogLocator("f", "p", "c", job, 1); err == nil {
			t.Fatalf("expected reject job %q", job)
		}
	}
	// Missing controller / pool / fleet / build
	if _, err := fleetcache.NewConsoleLogLocator("", "p", "c", "job", 1); err == nil {
		t.Fatal("fleet")
	}
	if _, err := fleetcache.NewConsoleLogLocator("f", "", "c", "job", 1); err == nil {
		t.Fatal("pool")
	}
	if _, err := fleetcache.NewConsoleLogLocator("f", "p", "", "job", 1); err == nil {
		t.Fatal("controller")
	}
	if _, err := fleetcache.NewConsoleLogLocator("f", "p", "c", "job", 0); err == nil {
		t.Fatal("build")
	}
}

func TestLocator_CanonicalExcludesLocalIDs(t *testing.T) {
	t.Parallel()
	l, err := fleetcache.NewConsoleLogLocator("fleet", "pool", "ctrl", "j", 7)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := l.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, banned := range []string{"profile_id", "generation", "generation_id", "sqlite", "127.0.0.1", "user_id", "subject"} {
		if strings.Contains(strings.ToLower(s), banned) {
			t.Fatalf("canonical contains banned %q: %s", banned, s)
		}
	}
}
