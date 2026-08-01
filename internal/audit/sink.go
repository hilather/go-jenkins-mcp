package audit

import (
	"context"
)

// Sink persists audit events. Implementations must not store secrets or content.
// Emit must be safe for concurrent use. Failures must not authorize work.
type Sink interface {
	Emit(ctx context.Context, e Event) error
	Close() error
}

// Nop is a no-op sink (tests / when audit is disabled).
type Nop struct{}

// Emit implements Sink.
func (Nop) Emit(context.Context, Event) error { return nil }

// Close implements Sink.
func (Nop) Close() error { return nil }

type ctxKey struct{}

// WithSink returns a child context carrying sink for best-effort emit.
func WithSink(ctx context.Context, sink Sink) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if sink == nil {
		return ctx
	}
	return context.WithValue(ctx, ctxKey{}, sink)
}

// FromContext returns the Sink stored by WithSink, or nil.
func FromContext(ctx context.Context) Sink {
	if ctx == nil {
		return nil
	}
	s, _ := ctx.Value(ctxKey{}).(Sink)
	return s
}

// Emit is best-effort: no-op when sink is nil or ctx has no sink.
// Sanitize/normalize always runs when a sink is present.
// Errors from the sink are returned but callers should not gate authorization on them.
func Emit(ctx context.Context, sink Sink, e Event) error {
	if sink == nil {
		sink = FromContext(ctx)
	}
	if sink == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	// Prefer cancel awareness but do not fail open on cancellation mid-emit:
	// still try to record when the sink is local and non-blocking.
	return sink.Emit(ctx, e.Normalize())
}
