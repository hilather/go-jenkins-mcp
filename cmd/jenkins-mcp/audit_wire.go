package main

import (
	"context"
	"strings"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/audit"
	"github.com/simonfxr/go-jenkins-mcp/internal/auth"
	"github.com/simonfxr/go-jenkins-mcp/internal/config"
	"github.com/simonfxr/go-jenkins-mcp/internal/profile"
)

// profileDataDir resolves the on-disk data root for audit/cache (non-secret).
func profileDataDir(p *profile.Profile, profileFlag string) string {
	if p != nil && strings.TrimSpace(p.DataDir) != "" {
		return p.DataDir
	}
	id := profileFlag
	if p != nil && p.ID != "" {
		id = string(p.ID)
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return ""
	}
	paths, err := config.Resolve()
	if err != nil {
		return ""
	}
	return paths.ProfileDataDir(id)
}

func openServeAuditSink(p *profile.Profile, profileFlag string) (audit.Sink, error) {
	dir := profileDataDir(p, profileFlag)
	if dir == "" {
		return audit.Nop{}, nil
	}
	return audit.OpenProfileSink(dir)
}

func emitLoginAudit(p *profile.Profile, principalID, decision, reason string) {
	if p == nil {
		return
	}
	sink, err := audit.OpenProfileSink(profileDataDir(p, string(p.ID)))
	if err != nil || sink == nil {
		return
	}
	defer func() { _ = sink.Close() }()
	typ := audit.TypeLoginSuccess
	if decision != audit.DecisionSuccess {
		typ = audit.TypeLoginFail
	}
	// Never pass tokens/passwords into Event fields.
	_ = audit.Emit(context.Background(), sink, audit.Event{
		Time:        time.Now().UTC(),
		Type:        typ,
		ProfileID:   string(p.ID),
		PrincipalID: principalID,
		Action:      "login",
		Decision:    decision,
		ReasonCode:  reason,
	})
}

func emitServeAuthFail(sink audit.Sink, p *profile.Profile, profileFlag, principalID, reason string) {
	pid := profileFlag
	if p != nil && p.ID != "" {
		pid = string(p.ID)
	}
	_ = audit.Emit(context.Background(), sink, audit.Event{
		Time:        time.Now().UTC(),
		Type:        audit.TypeAuthFail,
		ProfileID:   pid,
		PrincipalID: principalID,
		Action:      "serve",
		Decision:    audit.DecisionFail,
		ReasonCode:  reason,
	})
}

func authSourceLabel(usedLegacy bool, sess auth.Session) string {
	if usedLegacy {
		return "legacy_bootstrap"
	}
	if sess.ProfileID != "" {
		return "keyring"
	}
	return "unknown"
}

// auditReasonFromErr maps verify failures to stable, non-secret reason codes
// (AUTH-004 identity mismatch residual).
func auditReasonFromErr(err error) string {
	if err == nil {
		return "ok"
	}
	msg := err.Error()
	if strings.Contains(msg, "does not match expected user") {
		return "identity_mismatch"
	}
	if strings.Contains(msg, "anonymous") {
		return "anonymous_identity"
	}
	if c := apperr.CodeOf(err); c != "" {
		return string(c)
	}
	return "verify_failed"
}
