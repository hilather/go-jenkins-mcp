package fleetcache_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/fleetcache"
	"github.com/klauspost/compress/zstd"
)

func zstdFrame(t *testing.T, raw []byte) []byte {
	t.Helper()
	enc, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedDefault), zstd.WithEncoderCRC(true))
	if err != nil {
		t.Fatal(err)
	}
	defer enc.Close()
	return enc.EncodeAll(raw, nil)
}

func shaHex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func makeSealedManifest(t *testing.T, parts [][]byte) (fleetcache.WireManifest, []fleetcache.ImportFrameBytes) {
	t.Helper()
	loc, err := fleetcache.NewConsoleLogLocator("fleet", "pool", "ctrl", "job/a", 7)
	if err != nil {
		t.Fatal(err)
	}
	lh, err := loc.Hash()
	if err != nil {
		t.Fatal(err)
	}
	var frames []fleetcache.FrameDescriptor
	var importFrames []fleetcache.ImportFrameBytes
	var rawOff, lineOff int64
	var totalLines int64
	for i, raw := range parts {
		z := zstdFrame(t, raw)
		// count lines
		lines := int64(0)
		for _, b := range raw {
			if b == '\n' {
				lines++
			}
		}
		if len(raw) > 0 && raw[len(raw)-1] != '\n' {
			lines++
		}
		fd := fleetcache.FrameDescriptor{
			Seq: i, RawStart: rawOff, RawEnd: rawOff + int64(len(raw)),
			LineStart: lineOff, LineEnd: lineOff + lines,
			DecodedSize: int64(len(raw)), DecodedSHA256: shaHex(raw),
			ZstdSize: int64(len(z)), ZstdSHA256: shaHex(z),
		}
		frames = append(frames, fd)
		importFrames = append(importFrames, fleetcache.ImportFrameBytes{Seq: i, PureZstd: z})
		rawOff += int64(len(raw))
		lineOff += lines
		totalLines += lines
	}
	wm, err := fleetcache.PublishSealed(fleetcache.SealedPublishInput{
		FleetID: "fleet", CachePool: "pool", ControllerID: "ctrl",
		JobFullName: "job/a", BuildNumber: 7, Sealed: true, Frames: frames,
	})
	if err != nil {
		// Fallback construct if PublishSealed needs different shape
		t.Fatalf("PublishSealed: %v", err)
	}
	if wm.LocatorHash == "" {
		wm.LocatorHash = lh
	}
	return wm, importFrames
}

func TestPlanImport_IdempotentAndConflict(t *testing.T) {
	t.Parallel()
	raw := []byte("hello\nworld\n")
	wm, _ := makeSealedManifest(t, [][]byte{raw})
	digest := wm.ManifestDigest
	// Start
	plan, err := fleetcache.PlanImport(nil, wm)
	if err != nil || plan.Action != fleetcache.ImportActionStart {
		t.Fatalf("%+v %v", plan, err)
	}
	// Idempotent
	plan, err = fleetcache.PlanImport(&fleetcache.CommittedMapping{
		LocatorHash: wm.LocatorHash, ManifestDigest: digest, Status: "committed", GenerationID: 9,
	}, wm)
	if err != nil || plan.Action != fleetcache.ImportActionIdempotent {
		t.Fatalf("%+v %v", plan, err)
	}
	// Conflict
	_, err = fleetcache.PlanImport(&fleetcache.CommittedMapping{
		LocatorHash: wm.LocatorHash, ManifestDigest: strings.Repeat("00", 32), Status: "committed",
	}, wm)
	if err == nil {
		t.Fatal("expected conflict")
	}
	if apperr.CodeOf(err) != apperr.CodePolicyDenial {
		t.Fatalf("code %s", apperr.CodeOf(err))
	}
}

func TestValidateImportFrames_HashAndAEAD(t *testing.T) {
	t.Parallel()
	wm, frames := makeSealedManifest(t, [][]byte{[]byte("a\n"), []byte("b\n")})
	if err := fleetcache.ValidateImportFrames(wm, frames); err != nil {
		t.Fatal(err)
	}
	// Corrupt hash
	bad := append([]fleetcache.ImportFrameBytes{}, frames...)
	bad[0].PureZstd = append([]byte{}, bad[0].PureZstd...)
	bad[0].PureZstd[len(bad[0].PureZstd)-1] ^= 0xff
	if err := fleetcache.ValidateImportFrames(wm, bad); err == nil {
		t.Fatal("expected hash fail")
	}
	// AEAD magic
	aead := append([]byte("JME1"), frames[0].PureZstd...)
	if err := fleetcache.ValidateImportFrames(wm, []fleetcache.ImportFrameBytes{
		{Seq: frames[0].Seq, PureZstd: aead},
		frames[1],
	}); err == nil {
		t.Fatal("expected AEAD reject")
	}
}

// memSink for pure RunImport / ReplicateSealed state machine tests.
// Implements fleetcache.StagingLookupSink for FLC-043 resume tests.
// Tracks committed frame body hashes for partition mixed-content assertions (FLC-045).
type memSink struct {
	mu        sync.Mutex
	committed map[string]fleetcache.CommittedMapping
	// committedFrameHashes maps locator → ordered zstd sha256 of committed frames.
	committedFrameHashes map[string][]string
	// commitCount maps locator → number of successful Commit calls (idempotent path must not bump).
	commitCount map[string]int
	staging     map[int64]*memStaging
	nextID      int64
	nextGen     int64
	failAt      int // WriteFrame fails when wrote+1 == failAt
}

type memStaging struct {
	gen     int64
	digest  string
	lh      string
	frames  int
	wrote   int
	present map[int]struct{}
	// frameHash by seq for body identity checks after commit.
	frameHash map[int]string
}

func (s *memSink) GetCommitted(_ context.Context, lh string) (fleetcache.CommittedMapping, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.committed[lh]
	return m, ok, nil
}

func (s *memSink) Begin(_ context.Context, m fleetcache.WireManifest) (int64, int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextID++
	s.nextGen++
	id, gen := s.nextID, s.nextGen
	if s.staging == nil {
		s.staging = make(map[int64]*memStaging)
	}
	s.staging[id] = &memStaging{
		gen: gen, digest: m.ManifestDigest, lh: m.LocatorHash,
		frames: len(m.Frames), present: make(map[int]struct{}),
		frameHash: make(map[int]string),
	}
	return id, gen, nil
}

func (s *memSink) GetStaging(_ context.Context, locatorHash, manifestDigest string) (
	importID, generationID int64, presentSeqs []int, ok bool, err error,
) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var bestID int64
	var best *memStaging
	for id, st := range s.staging {
		if st.lh == locatorHash && strings.EqualFold(st.digest, manifestDigest) {
			if id >= bestID {
				bestID, best = id, st
			}
		}
	}
	if best == nil {
		return 0, 0, nil, false, nil
	}
	seqs := make([]int, 0, len(best.present))
	for seq := range best.present {
		seqs = append(seqs, seq)
	}
	return bestID, best.gen, seqs, true, nil
}

func (s *memSink) WriteFrame(_ context.Context, importID, generationID int64, wf fleetcache.WireFrame, pureZstd []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.staging[importID]
	if !ok || st.gen != generationID {
		return apperr.New(apperr.CodePolicyDenial, "not staging")
	}
	if _, dup := st.present[wf.Seq]; dup {
		return apperr.New(apperr.CodePolicyDenial, "duplicate frame seq")
	}
	st.wrote++
	st.present[wf.Seq] = struct{}{}
	if st.frameHash == nil {
		st.frameHash = make(map[int]string)
	}
	st.frameHash[wf.Seq] = shaHex(pureZstd)
	if s.failAt > 0 && st.wrote == s.failAt {
		return apperr.New(apperr.CodeInternal, "injected write fail")
	}
	return nil
}

func (s *memSink) Commit(_ context.Context, importID, generationID int64, m fleetcache.WireManifest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.staging[importID]
	if !ok || st.gen != generationID {
		return apperr.New(apperr.CodePolicyDenial, "not staging")
	}
	if len(st.present) != st.frames {
		return apperr.New(apperr.CodePolicyDenial, "incomplete frames")
	}
	if s.committed == nil {
		s.committed = make(map[string]fleetcache.CommittedMapping)
	}
	if s.committedFrameHashes == nil {
		s.committedFrameHashes = make(map[string][]string)
	}
	if s.commitCount == nil {
		s.commitCount = make(map[string]int)
	}
	// Snapshot frame hashes in manifest order (proves no mixed-manifest interleave).
	hashes := make([]string, 0, len(m.Frames))
	for _, wf := range m.Frames {
		hashes = append(hashes, st.frameHash[wf.Seq])
	}
	s.committed[m.LocatorHash] = fleetcache.CommittedMapping{
		LocatorHash: m.LocatorHash, ManifestDigest: m.ManifestDigest,
		GenerationID: generationID, Status: "committed",
	}
	s.committedFrameHashes[m.LocatorHash] = hashes
	s.commitCount[m.LocatorHash]++
	delete(s.staging, importID)
	return nil
}

func (s *memSink) Abort(_ context.Context, importID int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.staging, importID)
	return nil
}

// DeleteCommitted implements fleetcache.PurgeSink for FLC-051 purge tests.
func (s *memSink) DeleteCommitted(_ context.Context, locatorHash, manifestDigest string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	locatorHash = strings.ToLower(strings.TrimSpace(locatorHash))
	manifestDigest = strings.ToLower(strings.TrimSpace(manifestDigest))
	m, ok := s.committed[locatorHash]
	if !ok {
		return nil // idempotent
	}
	if manifestDigest != "" && !strings.EqualFold(m.ManifestDigest, manifestDigest) {
		return nil // digest-scoped miss = success (nothing matching to delete)
	}
	delete(s.committed, locatorHash)
	if s.committedFrameHashes != nil {
		delete(s.committedFrameHashes, locatorHash)
	}
	// Drop open staging for this locator as well (purge honesty).
	for id, st := range s.staging {
		if st != nil && st.lh == locatorHash {
			if manifestDigest == "" || strings.EqualFold(st.digest, manifestDigest) {
				delete(s.staging, id)
			}
		}
	}
	return nil
}

func TestRunImport_CommitIdempotentPartial(t *testing.T) {
	t.Parallel()
	wm, frames := makeSealedManifest(t, [][]byte{[]byte("line1\n"), []byte("line2\n")})
	sink := &memSink{}
	res, err := fleetcache.RunImport(context.Background(), sink, wm, frames)
	if err != nil || res.Status != fleetcache.ImportStatusCommitted {
		t.Fatalf("%+v %v", res, err)
	}
	// Idempotent
	res2, err := fleetcache.RunImport(context.Background(), sink, wm, frames)
	if err != nil || res2.Status != fleetcache.ImportStatusIdempotent {
		t.Fatalf("%+v %v", res2, err)
	}
	// Partial fail: no committed mapping for new locator
	wm2, frames2 := makeSealedManifest(t, [][]byte{[]byte("x\n"), []byte("y\n")})
	// Force different locator by re-publish with different job via direct fields — use fail sink
	sink2 := &memSink{failAt: 1}
	res3, err := fleetcache.RunImport(context.Background(), sink2, wm2, frames2)
	if err == nil || res3.Status != fleetcache.ImportStatusAborted {
		t.Fatalf("expected abort %+v %v", res3, err)
	}
	// No committed for wm2 locator
	if _, ok, _ := sink2.GetCommitted(context.Background(), wm2.LocatorHash); ok {
		t.Fatal("partial must not be committed")
	}
}
