package cachecontrol

import "github.com/hilather/go-jenkins-mcp/internal/resourcecache"

// ResourceModePolicy adapts Service to resourcecache.ModePolicy.
type ResourceModePolicy struct {
	Gate interface {
		AllowLookup(kind string) bool
		AllowFill(kind string) bool
	}
}

// NewResourceModePolicy wraps a Service for resourcecache.Config.Modes.
func NewResourceModePolicy(s *Service) *ResourceModePolicy {
	if s == nil {
		return nil
	}
	return &ResourceModePolicy{Gate: s}
}

// AllowLookup implements resourcecache.ModePolicy.
func (p *ResourceModePolicy) AllowLookup(kind resourcecache.ResourceKind) bool {
	if p == nil || p.Gate == nil {
		return true
	}
	return p.Gate.AllowLookup(string(kind))
}

// AllowFill implements resourcecache.ModePolicy.
func (p *ResourceModePolicy) AllowFill(kind resourcecache.ResourceKind) bool {
	if p == nil || p.Gate == nil {
		return true
	}
	return p.Gate.AllowFill(string(kind))
}

var _ resourcecache.ModePolicy = (*ResourceModePolicy)(nil)

// ResourceEpochProvider adapts Service purge epochs for resourcecache.
type ResourceEpochProvider struct {
	Svc *Service
}

// NewResourceEpochProvider wraps a Service for resourcecache.Config.Epochs.
func NewResourceEpochProvider(s *Service) *ResourceEpochProvider {
	if s == nil {
		return nil
	}
	return &ResourceEpochProvider{Svc: s}
}

// PurgeEpoch implements resourcecache.EpochProvider.
func (p *ResourceEpochProvider) PurgeEpoch(kind resourcecache.ResourceKind) uint64 {
	if p == nil || p.Svc == nil {
		return 0
	}
	return p.Svc.PurgeEpoch(TypeID(kind))
}

var _ resourcecache.EpochProvider = (*ResourceEpochProvider)(nil)

// ResourceTelemetry adapts TelemetryRecorder to resourcecache.TelemetrySink.
type ResourceTelemetry struct {
	Rec *TelemetryRecorder
}

// NewResourceTelemetry wraps the service recorder.
func NewResourceTelemetry(s *Service) *ResourceTelemetry {
	if s == nil || s.Telemetry() == nil {
		return nil
	}
	return &ResourceTelemetry{Rec: s.Telemetry()}
}

// OnResourceEvent implements resourcecache.TelemetrySink.
func (t *ResourceTelemetry) OnResourceEvent(kind resourcecache.ResourceKind, layer, outcome string, bytes int64, reason string) {
	if t == nil || t.Rec == nil {
		return
	}
	t.Rec.Record(TelemetryEvent{
		TypeID:  TypeID(kind),
		Layer:   layer,
		Outcome: outcome,
		Reason:  reason,
		Bytes:   bytes,
	})
}

var _ resourcecache.TelemetrySink = (*ResourceTelemetry)(nil)

// ConsoleModeAdapter adapts Service for logmirror.Access.Modes (duck-typed).
type ConsoleModeAdapter struct {
	Svc *Service
}

// NewConsoleModeAdapter wraps a Service for console_log mode gates.
func NewConsoleModeAdapter(s *Service) *ConsoleModeAdapter {
	if s == nil {
		return nil
	}
	return &ConsoleModeAdapter{Svc: s}
}

// AllowConsoleLookup implements logmirror.ConsoleModePolicy.
func (a *ConsoleModeAdapter) AllowConsoleLookup() bool {
	if a == nil || a.Svc == nil {
		return true
	}
	return a.Svc.AllowLookup(string(TypeConsoleLog))
}

// AllowConsoleFill implements logmirror.ConsoleModePolicy.
func (a *ConsoleModeAdapter) AllowConsoleFill() bool {
	if a == nil || a.Svc == nil {
		return true
	}
	return a.Svc.AllowFill(string(TypeConsoleLog))
}

// ConsoleTelemetryAdapter adapts TelemetryRecorder for logmirror.ConsoleTelemetry.
type ConsoleTelemetryAdapter struct {
	Rec *TelemetryRecorder
}

// NewConsoleTelemetryAdapter wraps the service recorder for console_log events.
func NewConsoleTelemetryAdapter(s *Service) *ConsoleTelemetryAdapter {
	if s == nil || s.Telemetry() == nil {
		return nil
	}
	return &ConsoleTelemetryAdapter{Rec: s.Telemetry()}
}

// OnConsoleEvent implements logmirror.ConsoleTelemetry.
func (t *ConsoleTelemetryAdapter) OnConsoleEvent(layer, outcome string, bytes int64, reason string) {
	if t == nil || t.Rec == nil {
		return
	}
	t.Rec.Record(TelemetryEvent{
		TypeID:  TypeConsoleLog,
		Layer:   layer,
		Outcome: outcome,
		Reason:  reason,
		Bytes:   bytes,
	})
}

// TypeModeGate is a generic gate for survey_summary / diagnostic_fetch tools.
type TypeModeGate struct {
	Svc    *Service
	TypeID TypeID
}

// AllowLookup reports whether the type may be read from cache.
func (g TypeModeGate) AllowLookup() bool {
	if g.Svc == nil {
		return true
	}
	return g.Svc.AllowLookup(string(g.TypeID))
}

// AllowFill reports whether the type may be written.
func (g TypeModeGate) AllowFill() bool {
	if g.Svc == nil {
		return true
	}
	return g.Svc.AllowFill(string(g.TypeID))
}
