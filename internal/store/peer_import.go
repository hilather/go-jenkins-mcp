package store

import (
	"context"
	"strings"
	"sync"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/fleetcache"
)

// PeerImportSink adapts Meta + Frames to fleetcache.ImportSink (FLC-023).
// Mapping is published only on Commit; partial imports stay journal-only.
type PeerImportSink struct {
	Meta   *Meta
	Frames *Frames

	mu         sync.Mutex
	framesDone map[int64]int // importID → frames written
}

// NewPeerImportSink builds a sink. Meta and Frames required.
func NewPeerImportSink(meta *Meta, frames *Frames) *PeerImportSink {
	return &PeerImportSink{
		Meta: meta, Frames: frames,
		framesDone: make(map[int64]int),
	}
}

// GetCommitted implements fleetcache.ImportSink.
func (s *PeerImportSink) GetCommitted(ctx context.Context, locatorHash string) (fleetcache.CommittedMapping, bool, error) {
	if s == nil || s.Meta == nil {
		return fleetcache.CommittedMapping{}, false, apperr.New(apperr.CodeInternal, "import sink closed")
	}
	m, ok, err := s.Meta.GetCommittedFleetMapping(ctx, locatorHash)
	if err != nil || !ok {
		return fleetcache.CommittedMapping{}, ok, err
	}
	return fleetcache.CommittedMapping{
		LocatorHash: m.LocatorHash, ManifestDigest: m.ManifestDigest,
		GenerationID: m.GenerationID, Status: m.Status,
	}, true, nil
}

// Begin implements fleetcache.ImportSink.
func (s *PeerImportSink) Begin(ctx context.Context, m fleetcache.WireManifest) (importID, generationID int64, err error) {
	if s == nil || s.Meta == nil {
		return 0, 0, apperr.New(apperr.CodeInternal, "import sink closed")
	}
	digest := m.ManifestDigest
	if digest == "" {
		digest, err = fleetcache.DigestWireManifest(m)
		if err != nil {
			return 0, 0, err
		}
	}
	id, gen, err := s.Meta.BeginFleetImport(ctx, m.LocatorHash, digest, m.FleetID, m.CachePool, m.ControllerID, len(m.Frames))
	if err != nil {
		return 0, 0, err
	}
	s.mu.Lock()
	s.framesDone[id] = 0
	s.mu.Unlock()
	return id, gen, nil
}

// GetStaging implements fleetcache.StagingLookupSink (FLC-043 resume).
func (s *PeerImportSink) GetStaging(ctx context.Context, locatorHash, manifestDigest string) (
	importID, generationID int64, presentSeqs []int, ok bool, err error,
) {
	if s == nil || s.Meta == nil {
		return 0, 0, nil, false, apperr.New(apperr.CodeInternal, "import sink closed")
	}
	j, seqs, found, err := s.Meta.GetStagingFleetImport(ctx, locatorHash, manifestDigest)
	if err != nil || !found {
		return 0, 0, nil, found, err
	}
	// Seed in-memory progress from durable journal so resume increments correctly.
	s.mu.Lock()
	s.framesDone[j.ID] = j.FramesDone
	if len(seqs) > s.framesDone[j.ID] {
		s.framesDone[j.ID] = len(seqs)
	}
	s.mu.Unlock()
	return j.ID, j.GenerationID, seqs, true, nil
}

// WriteFrame implements fleetcache.ImportSink.
func (s *PeerImportSink) WriteFrame(ctx context.Context, importID, generationID int64, wf fleetcache.WireFrame, pureZstd []byte) error {
	if s == nil || s.Frames == nil || s.Meta == nil {
		return apperr.New(apperr.CodeInternal, "import sink closed")
	}
	// Ensure journal still staging.
	j, err := s.Meta.GetFleetImport(ctx, importID)
	if err != nil {
		return err
	}
	if j.Status != FleetImportStaging || j.GenerationID != generationID {
		return apperr.New(apperr.CodePolicyDenial, "import not staging")
	}
	spec := PureZstdImportSpec{
		Seq:           wf.Seq,
		RawStart:      wf.RawStart,
		RawEnd:        wf.RawEnd,
		LineStart:     wf.LineStart,
		LineEnd:       wf.LineEnd,
		DecodedSize:   wf.DecodedSize,
		DecodedSHA256: wf.DecodedSHA256,
		ZstdSize:      wf.ZstdSize,
		ZstdSHA256:    wf.ZstdSHA256,
		PureZstd:      pureZstd,
	}
	if err := s.Frames.ImportPureZstdFrame(ctx, generationID, spec); err != nil {
		return err
	}
	// Prefer durable journal frames_done so resume across sink instances stays correct.
	s.mu.Lock()
	base := j.FramesDone
	if cur, ok := s.framesDone[importID]; ok && cur > base {
		base = cur
	}
	done := base + 1
	s.framesDone[importID] = done
	s.mu.Unlock()
	return s.Meta.AdvanceFleetImportFrames(ctx, importID, done)
}

// Commit implements fleetcache.ImportSink.
func (s *PeerImportSink) Commit(ctx context.Context, importID, generationID int64, m fleetcache.WireManifest) error {
	if s == nil || s.Meta == nil {
		return apperr.New(apperr.CodeInternal, "import sink closed")
	}
	digest := m.ManifestDigest
	if digest == "" {
		var err error
		digest, err = fleetcache.DigestWireManifest(m)
		if err != nil {
			return err
		}
	}
	totalRaw := m.TotalRawBytes
	if totalRaw <= 0 {
		for _, f := range m.Frames {
			if f.RawEnd > totalRaw {
				totalRaw = f.RawEnd
			}
		}
	}
	return s.Meta.CommitFleetImport(ctx, importID, generationID,
		strings.ToLower(m.LocatorHash), digest, m.FleetID, m.CachePool, m.ControllerID, totalRaw)
}

// Abort implements fleetcache.ImportSink.
func (s *PeerImportSink) Abort(ctx context.Context, importID int64) error {
	if s == nil || s.Meta == nil {
		return nil
	}
	s.mu.Lock()
	delete(s.framesDone, importID)
	s.mu.Unlock()
	return s.Meta.AbortFleetImport(ctx, importID)
}

// ResolveFleetSealed maps a locator to LocalSealedObject for owner backends.
func (s *PeerImportSink) ResolveFleetSealed(ctx context.Context, locatorHash string) (fleetcache.LocalSealedObject, bool, error) {
	m, ok, err := s.Meta.GetCommittedFleetMapping(ctx, locatorHash)
	if err != nil || !ok {
		return fleetcache.LocalSealedObject{}, ok, err
	}
	return fleetcache.LocalSealedObject{
		GenerationID: m.GenerationID, Sealed: true, Materialized: true,
		ManifestDigest: m.ManifestDigest, FleetID: m.FleetID,
	}, true, nil
}
