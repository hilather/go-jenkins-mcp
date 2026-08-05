package resourcecache

import (
	"context"
	"io"
)

// SourceMetadata accompanies a fetch from Jenkins (or another origin).
type SourceMetadata struct {
	ContentType   string
	ETag          string
	ContentLength int64 // -1 if unknown
	Building      bool
	// Completeness of this fetch: Complete, Partial (intentional bound), never Incomplete here.
	Completeness Completeness
	// Extra is non-secret kind metadata (e.g. stage id resolved).
	Extra map[string]string
}

// FetchResult is either a streaming body (blobs) or structured value (JSON-serializable).
type FetchResult struct {
	// Body is optional streaming content; caller or cache closes it.
	Body io.ReadCloser
	// Structured is a canonical Go value for structured kinds (JSON marshaled).
	Structured any
	// Bytes is optional pre-buffered body (tests / small structured raw).
	Bytes []byte
	Meta  SourceMetadata
}

// SourceFetcher fetches canonical origin data for a key.
type SourceFetcher interface {
	Fetch(ctx context.Context, key ResourceKey, previous *Entry) (FetchResult, error)
}

// SourceFunc adapts a function to SourceFetcher.
type SourceFunc func(ctx context.Context, key ResourceKey, previous *Entry) (FetchResult, error)

func (f SourceFunc) Fetch(ctx context.Context, key ResourceKey, previous *Entry) (FetchResult, error) {
	return f(ctx, key, previous)
}
