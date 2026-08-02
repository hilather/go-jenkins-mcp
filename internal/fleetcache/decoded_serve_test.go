package fleetcache_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/fleetcache"
)

// memBackend implements resolver+reader for ServeDecodedRead unit tests.
type memBackend struct {
	objects   map[string]fleetcache.LocalSealedObject
	body      []byte
	readCalls int
}

func (m *memBackend) ResolveSealed(lh string) (fleetcache.LocalSealedObject, bool) {
	o, ok := m.objects[lh]
	return o, ok
}

func (m *memBackend) ReadRange(ctx context.Context, genID int64, start, length int64) (fleetcache.DecodedReadResult, error) {
	if err := ctx.Err(); err != nil {
		return fleetcache.DecodedReadResult{}, err
	}
	m.readCalls++
	if start > int64(len(m.body)) {
		return fleetcache.DecodedReadResult{RawStart: start, RawEnd: start, Sealed: true}, nil
	}
	end := start + length
	if end > int64(len(m.body)) {
		end = int64(len(m.body))
	}
	return fleetcache.DecodedReadResult{
		Data:     append([]byte(nil), m.body[start:end]...),
		RawStart: start, RawEnd: end, RequestedBytes: length,
		DecompressedBytes: end - start, FramesOpened: 1, Sealed: true,
	}, nil
}

func (m *memBackend) ReadLineRange(ctx context.Context, genID int64, startLine, lineCount int64) (fleetcache.DecodedReadResult, error) {
	m.readCalls++
	lines := strings.SplitAfter(string(m.body), "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	if startLine >= int64(len(lines)) {
		return fleetcache.DecodedReadResult{LineStart: startLine, LineEnd: startLine, Sealed: true}, nil
	}
	end := startLine + lineCount
	if end > int64(len(lines)) {
		end = int64(len(lines))
	}
	var b strings.Builder
	for i := startLine; i < end; i++ {
		b.WriteString(lines[i])
	}
	data := []byte(b.String())
	return fleetcache.DecodedReadResult{
		Data: data, LineStart: startLine, LineEnd: end,
		RequestedBytes: int64(len(data)), FramesOpened: 1, Sealed: true,
	}, nil
}

func (m *memBackend) TailBytes(ctx context.Context, genID int64, n int64) (fleetcache.DecodedReadResult, error) {
	start := int64(len(m.body)) - n
	if start < 0 {
		start = 0
	}
	return m.ReadRange(ctx, genID, start, int64(len(m.body))-start)
}

func (m *memBackend) TailLines(ctx context.Context, genID int64, n int64) (fleetcache.DecodedReadResult, error) {
	lines := strings.SplitAfter(string(m.body), "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	start := int64(len(lines)) - n
	if start < 0 {
		start = 0
	}
	return m.ReadLineRange(ctx, genID, start, int64(len(lines))-start)
}

func TestServeDecodedRead_ScopeDenyNoDisk(t *testing.T) {
	t.Parallel()
	key := testKey(t)
	lh := strings.Repeat("11", 32)
	// Large body; deny must not read it.
	body := make([]byte, 256<<10)
	for i := range body {
		body[i] = 'x'
	}
	backend := &memBackend{
		body: body,
		objects: map[string]fleetcache.LocalSealedObject{
			lh: {GenerationID: 1, Sealed: true, Materialized: true, FleetID: "fleet"},
		},
	}
	now := time.Now().UTC()
	// Assertion scoped to 64 bytes only.
	a, err := fleetcache.IssueAssertion(key, fleetcache.AssertionClaims{
		FleetID: "fleet", RequestingMemberID: "edge", LocatorHash: lh,
		Operation: fleetcache.OpRead, MaxDecodedBytes: 64,
		IssuedAt: now, ExpiresAt: now.Add(20 * time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	// Request asks for more than claim budget.
	req := fleetcache.DecodedReadRequest{
		LocatorHash: lh, Kind: fleetcache.ReadKindByteRange, Length: 1024,
	}
	res, err := fleetcache.ServeDecodedRead(context.Background(), backend, backend, req, a, fleetcache.ServeDecodedReadOptions{
		AssertionKey: key, Nonces: fleetcache.NewMemoryNonceStore(), Now: now, FleetID: "fleet",
	})
	if err == nil {
		t.Fatal("expected deny")
	}
	if apperr.CodeOf(err) != apperr.CodeAuthorization {
		t.Fatalf("code %s", apperr.CodeOf(err))
	}
	if backend.readCalls != 0 {
		t.Fatalf("deny-before-body: readCalls=%d", backend.readCalls)
	}
	if res.Status != fleetcache.DecodedReadScopeDenied {
		t.Fatalf("status %s", res.Status)
	}
	// Wrong MAC.
	a2 := a
	a2.MAC = strings.Repeat("0", 64)
	_, err = fleetcache.ServeDecodedRead(context.Background(), backend, backend, fleetcache.DecodedReadRequest{
		LocatorHash: lh, Kind: fleetcache.ReadKindByteRange, Length: 10,
	}, a2, fleetcache.ServeDecodedReadOptions{
		AssertionKey: key, Nonces: fleetcache.NewMemoryNonceStore(), Now: now, FleetID: "fleet",
	})
	if err == nil || backend.readCalls != 0 {
		t.Fatalf("bad mac must deny before read: calls=%d err=%v", backend.readCalls, err)
	}
}

func TestServeDecodedRead_ParityAndCeiling(t *testing.T) {
	t.Parallel()
	key := testKey(t)
	lh := strings.Repeat("22", 32)
	// Body larger than default ceiling (64 KiB); request only first 1 KiB.
	body := []byte(strings.Repeat("line-content-ABCDEF\n", 4000)) // ~80 KiB
	if len(body) < 70<<10 {
		t.Fatalf("need large body, got %d", len(body))
	}
	backend := &memBackend{
		body: body,
		objects: map[string]fleetcache.LocalSealedObject{
			lh: {GenerationID: 7, Sealed: true, Materialized: true, FleetID: "fleet", ManifestDigest: strings.Repeat("ab", 32)},
		},
	}
	now := time.Now().UTC()
	const wantLen = 1024
	a, err := fleetcache.IssueAssertion(key, fleetcache.AssertionClaims{
		FleetID: "fleet", RequestingMemberID: "edge", LocatorHash: lh,
		Operation: fleetcache.OpRead, MaxDecodedBytes: 64 << 10,
		IssuedAt: now, ExpiresAt: now.Add(20 * time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	req := fleetcache.DecodedReadRequest{
		LocatorHash: lh, Kind: fleetcache.ReadKindByteRange, Start: 0, Length: wantLen,
	}
	res, err := fleetcache.ServeDecodedRead(context.Background(), backend, backend, req, a, fleetcache.ServeDecodedReadOptions{
		AssertionKey: key, Nonces: fleetcache.NewMemoryNonceStore(), Now: now, FleetID: "fleet",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != fleetcache.DecodedReadOK {
		t.Fatalf("%+v", res)
	}
	if int64(len(res.Data)) != wantLen {
		t.Fatalf("decoded len %d want %d (must not stream full %d object)", len(res.Data), wantLen, len(body))
	}
	if !strings.HasPrefix(string(body), string(res.Data)) {
		t.Fatal("parity mismatch vs local body prefix")
	}
	if backend.readCalls != 1 {
		t.Fatalf("readCalls=%d", backend.readCalls)
	}
}

func TestServeDecodedRead_NotMaterialized(t *testing.T) {
	t.Parallel()
	key := testKey(t)
	lh := strings.Repeat("33", 32)
	backend := &memBackend{
		body: []byte("secret-should-not-read"),
		objects: map[string]fleetcache.LocalSealedObject{
			lh: {GenerationID: 1, Sealed: true, Materialized: false, FleetID: "fleet"},
		},
	}
	now := time.Now().UTC()
	a, err := fleetcache.IssueAssertion(key, fleetcache.AssertionClaims{
		FleetID: "fleet", RequestingMemberID: "edge", LocatorHash: lh,
		Operation: fleetcache.OpRead, MaxDecodedBytes: 1024,
		IssuedAt: now, ExpiresAt: now.Add(20 * time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := fleetcache.ServeDecodedRead(context.Background(), backend, backend, fleetcache.DecodedReadRequest{
		LocatorHash: lh, Kind: fleetcache.ReadKindByteRange, Length: 10,
	}, a, fleetcache.ServeDecodedReadOptions{
		AssertionKey: key, Nonces: fleetcache.NewMemoryNonceStore(), Now: now, FleetID: "fleet",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != fleetcache.DecodedReadNotMaterialized {
		t.Fatalf("%+v", res)
	}
	if backend.readCalls != 0 {
		t.Fatal("must not read when not materialized")
	}
}

func TestServeDecodedRead_Cancel(t *testing.T) {
	t.Parallel()
	key := testKey(t)
	lh := strings.Repeat("44", 32)
	backend := &memBackend{
		body: []byte("hello\n"),
		objects: map[string]fleetcache.LocalSealedObject{
			lh: {GenerationID: 1, Sealed: true, Materialized: true, FleetID: "fleet"},
		},
	}
	now := time.Now().UTC()
	a, err := fleetcache.IssueAssertion(key, fleetcache.AssertionClaims{
		FleetID: "fleet", RequestingMemberID: "edge", LocatorHash: lh,
		Operation: fleetcache.OpRead, MaxDecodedBytes: 1024,
		IssuedAt: now, ExpiresAt: now.Add(20 * time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := fleetcache.ServeDecodedRead(ctx, backend, backend, fleetcache.DecodedReadRequest{
		LocatorHash: lh, Kind: fleetcache.ReadKindByteRange, Length: 5,
	}, a, fleetcache.ServeDecodedReadOptions{
		AssertionKey: key, Nonces: fleetcache.NewMemoryNonceStore(), Now: now, FleetID: "fleet",
	})
	if err == nil {
		t.Fatal("expected cancel")
	}
	if res.Status != fleetcache.DecodedReadCancelled {
		t.Fatalf("%+v", res)
	}
}

func TestServeDecodedRead_LineAndTail(t *testing.T) {
	t.Parallel()
	key := testKey(t)
	lh := strings.Repeat("55", 32)
	backend := &memBackend{
		body: []byte("a\nb\nc\nd\n"),
		objects: map[string]fleetcache.LocalSealedObject{
			lh: {GenerationID: 1, Sealed: true, Materialized: true, FleetID: "fleet"},
		},
	}
	now := time.Now().UTC()
	issue := func() fleetcache.Assertion {
		a, err := fleetcache.IssueAssertion(key, fleetcache.AssertionClaims{
			FleetID: "fleet", RequestingMemberID: "edge", LocatorHash: lh,
			Operation: fleetcache.OpRead, MaxDecodedBytes: 1024,
			IssuedAt: now, ExpiresAt: now.Add(20 * time.Second),
		})
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	// Line range.
	res, err := fleetcache.ServeDecodedRead(context.Background(), backend, backend, fleetcache.DecodedReadRequest{
		LocatorHash: lh, Kind: fleetcache.ReadKindLineRange, StartLine: 1, LineCount: 2,
	}, issue(), fleetcache.ServeDecodedReadOptions{
		AssertionKey: key, Nonces: fleetcache.NewMemoryNonceStore(), Now: now, FleetID: "fleet",
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(res.Data) != "b\nc\n" {
		t.Fatalf("lines got %q", res.Data)
	}
	// Tail bytes.
	res2, err := fleetcache.ServeDecodedRead(context.Background(), backend, backend, fleetcache.DecodedReadRequest{
		LocatorHash: lh, Kind: fleetcache.ReadKindTailBytes, TailN: 4,
	}, issue(), fleetcache.ServeDecodedReadOptions{
		AssertionKey: key, Nonces: fleetcache.NewMemoryNonceStore(), Now: now, FleetID: "fleet",
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(res2.Data) != "c\nd\n" {
		t.Fatalf("tail got %q", res2.Data)
	}
}
