package logmirror_test

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/logmirror"
)

// fakePeer records TryRead calls for FLC-032 coordinator tests.
type fakePeer struct {
	hits    atomic.Int64
	calls   atomic.Int64
	hit     bool
	data    []byte
	err     error
	modeOff bool // hit=false, no error (simulates mode off / miss)
	deny    bool
}

func (f *fakePeer) TryRead(ctx context.Context, req logmirror.PeerReadRequest) (logmirror.PeerReadOutcome, bool, error) {
	f.calls.Add(1)
	if f.deny {
		return logmirror.PeerReadOutcome{}, false, apperr.New(apperr.CodeAuthorization, "policy denied before peer")
	}
	if f.modeOff || !f.hit {
		return logmirror.PeerReadOutcome{}, false, nil
	}
	if err := ctx.Err(); err != nil {
		return logmirror.PeerReadOutcome{}, false, err
	}
	f.hits.Add(1)
	data := f.data
	if req.Kind == logmirror.PeerReadByteRange && req.Length > 0 && int64(len(data)) > req.Length {
		data = data[:req.Length]
	}
	if req.Kind == logmirror.PeerReadTailBytes && req.TailN > 0 && int64(len(data)) > req.TailN {
		data = data[int64(len(data))-req.TailN:]
	}
	return logmirror.PeerReadOutcome{
		Data: data, Offset: int(req.Start), Length: len(data),
		TotalSize: len(f.data), Sealed: true, Source: "peer",
	}, true, nil
}

func TestResolveAndReadRange_ModeOffOriginOnly(t *testing.T) {
	raw := []byte(strings.Repeat("origin-body-line\n", 30))
	src := &logmirror.FakeSource{Log: raw, Running: false}
	a, _ := openAccess(t, src)
	// Nil peer: same as EnsureMirrored + ReadRange.
	ctx := context.Background()
	logs, meta, err := a.ResolveAndReadRange(ctx, "demo", 7, 0, 40, logmirror.ResolveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if logs != string(raw[:40]) {
		t.Fatalf("got %q", logs)
	}
	if meta.Length != 40 {
		t.Fatalf("%+v", meta)
	}
	if src.FetchCount < 1 {
		t.Fatal("expected origin fetch when peer nil")
	}
}

func TestResolveAndReadRange_PeerHitSkipsOrigin(t *testing.T) {
	raw := []byte(strings.Repeat("should-not-fetch-from-jenkins\n", 20))
	src := &logmirror.FakeSource{Log: raw, Running: false}
	a, _ := openAccess(t, src)
	peerBody := []byte("peer-decoded-prefix-XXXXXXXX")
	fp := &fakePeer{hit: true, data: peerBody}
	a.Peer = fp
	ctx := context.Background()
	logs, meta, err := a.ResolveAndReadRange(ctx, "demo", 7, 0, 16, logmirror.ResolveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if logs != string(peerBody[:16]) {
		t.Fatalf("got %q want peer", logs)
	}
	if meta.Sealed != true || meta.Length != 16 {
		t.Fatalf("%+v", meta)
	}
	if src.FetchCount != 0 {
		t.Fatalf("peer hit must not Jenkins-fetch: fetches=%d", src.FetchCount)
	}
	if fp.calls.Load() != 1 || fp.hits.Load() != 1 {
		t.Fatalf("peer calls=%d hits=%d", fp.calls.Load(), fp.hits.Load())
	}
}

func TestResolveAndReadRange_PeerMissFallsBackOrigin(t *testing.T) {
	raw := []byte(strings.Repeat("from-origin-now\n", 25))
	src := &logmirror.FakeSource{Log: raw, Running: false}
	a, _ := openAccess(t, src)
	fp := &fakePeer{hit: false} // miss
	a.Peer = fp
	ctx := context.Background()
	logs, _, err := a.ResolveAndReadRange(ctx, "demo", 7, 0, 20, logmirror.ResolveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if logs != string(raw[:20]) {
		t.Fatalf("got %q", logs)
	}
	if src.FetchCount < 1 {
		t.Fatal("miss must fall back to origin")
	}
	if fp.calls.Load() != 1 {
		t.Fatalf("peer calls=%d", fp.calls.Load())
	}
}

func TestResolveAndReadRange_PeerTimeoutLikeMiss(t *testing.T) {
	// Unavailable is modeled as hit=false, err=nil (client maps timeout → unavailable → miss path).
	raw := []byte("timeout-fallback-body-enough-bytes-here")
	src := &logmirror.FakeSource{Log: raw, Running: false}
	a, _ := openAccess(t, src)
	a.Peer = &fakePeer{hit: false}
	logs, _, err := a.ResolveAndReadRange(context.Background(), "demo", 7, 0, 10, logmirror.ResolveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if logs != string(raw[:10]) {
		t.Fatalf("%q", logs)
	}
	if src.FetchCount < 1 {
		t.Fatal("expected origin after peer miss/timeout")
	}
}

func TestResolveAndReadRange_PolicyDenyBeforeDataPlane(t *testing.T) {
	raw := []byte("must-not-fetch")
	src := &logmirror.FakeSource{Log: raw, Running: false}
	a, _ := openAccess(t, src)
	a.Peer = &fakePeer{deny: true}
	_, _, err := a.ResolveAndReadRange(context.Background(), "demo", 7, 0, 8, logmirror.ResolveOptions{})
	if err == nil {
		t.Fatal("expected policy deny")
	}
	if apperr.CodeOf(err) != apperr.CodeAuthorization {
		t.Fatalf("code %s", apperr.CodeOf(err))
	}
	if src.FetchCount != 0 {
		t.Fatalf("policy deny must not origin-fetch: %d", src.FetchCount)
	}
}

func TestResolveAndReadRange_LocalHitSkipsPeerAndOrigin(t *testing.T) {
	raw := []byte(strings.Repeat("local-first\n", 20))
	src := &logmirror.FakeSource{Log: raw, Running: false}
	a, _ := openAccess(t, src)
	ctx := context.Background()
	if err := a.EnsureMirrored(ctx, "demo", 7); err != nil {
		t.Fatal(err)
	}
	fetches := src.FetchCount
	fp := &fakePeer{hit: true, data: []byte("peer-should-not-win")}
	a.Peer = fp
	logs, _, err := a.ResolveAndReadRange(ctx, "demo", 7, 0, 12, logmirror.ResolveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if logs != string(raw[:12]) {
		t.Fatalf("local should win: %q", logs)
	}
	if fp.calls.Load() != 0 {
		t.Fatal("local hit must not contact peer")
	}
	if src.FetchCount != fetches {
		t.Fatal("local hit must not re-fetch origin")
	}
}

func TestResolveAndTail_PeerHit(t *testing.T) {
	src := &logmirror.FakeSource{Log: []byte("unused"), Running: false}
	a, _ := openAccess(t, src)
	body := []byte("abcdefghijklmnopqrstuvwxyz")
	a.Peer = &fakePeer{hit: true, data: body}
	logs, meta, err := a.ResolveAndTail(context.Background(), "demo", 7, 5, logmirror.ResolveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if logs != "vwxyz" {
		t.Fatalf("tail %q", logs)
	}
	if meta.Length != 5 {
		t.Fatalf("%+v", meta)
	}
	if src.FetchCount != 0 {
		t.Fatal("peer tail must skip origin")
	}
}

func TestResolveAndReadRange_SkipOrigin(t *testing.T) {
	src := &logmirror.FakeSource{Log: []byte("nope"), Running: false}
	a, _ := openAccess(t, src)
	a.Peer = &fakePeer{hit: false}
	_, _, err := a.ResolveAndReadRange(context.Background(), "demo", 7, 0, 4, logmirror.ResolveOptions{SkipOrigin: true})
	if err == nil {
		t.Fatal("expected not found")
	}
	if src.FetchCount != 0 {
		t.Fatal("SkipOrigin must not fetch")
	}
}

// Contract for tools.MirrorLogAccess preferPartialMirror: when Ensure hits
// CodeQuota but left durable frames, ResolveAnd returns non-empty logs WITH err.
func TestResolveAndReadRange_PartialEnsureReturnsDataAndErr(t *testing.T) {
	raw := []byte(strings.Repeat("quota-partial-line-\n", 80))
	src := &logmirror.FakeSource{Log: raw, Running: true}
	a, m := openAccess(t, src)
	a.MaxBytes = 96
	a.MaxPolls = 8
	a.Peer = nil
	status := logmirror.NewFakeBuildStatus()
	status.DefaultComplete = false
	status.Set("demo", 7, false)
	a.Status = status
	m.FetchBytes = 64

	logs, meta, err := a.ResolveAndReadRange(context.Background(), "demo", 7, 0, 24, logmirror.ResolveOptions{})
	if err == nil {
		t.Fatal("expected Ensure residual error (quota/budget)")
	}
	if apperr.CodeOf(err) != apperr.CodeQuota {
		t.Logf("code=%s (still require partial body)", apperr.CodeOf(err))
	}
	if len(logs) == 0 {
		t.Fatalf("must return partial body with err for tool preferPartialMirror; meta=%+v err=%v", meta, err)
	}
	if !strings.HasPrefix(string(raw), logs) {
		t.Fatalf("partial prefix mismatch %q", logs)
	}
}
