package fleetcache

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/contracts"
)

// Identity schema versions (bump only with golden-vector updates).
const (
	// LocatorSchemaVersion is the canonical locator field set version.
	LocatorSchemaVersion = 1
	// ObjectKindConsoleLog is the only v1 production object class (ADR 0016).
	ObjectKindConsoleLog = "console_log"
	// ProtocolV1 is the wire protocol id advertised on roster cache.protocols.
	ProtocolV1 = "fleet-cache/1"
)

// Locator is the cross-node identity for a cacheable object.
// It must never include local profile IDs, SQLite generation IDs, user IDs,
// credentials, or load-balancer addresses.
type Locator struct {
	FleetID               string
	CachePool             string
	ControllerID          string
	ObjectKind            string
	JobFullNameNormalized string
	BuildNumber           int64
	LocatorSchemaVersion  int
}

// NewConsoleLogLocator builds a validated sealed-log locator.
// jobFullName is normalized via contracts.ParseJobFullName (fail closed).
func NewConsoleLogLocator(fleetID, cachePool, controllerID, jobFullName string, buildNumber int64) (Locator, error) {
	fleetID = strings.TrimSpace(fleetID)
	cachePool = strings.TrimSpace(cachePool)
	controllerID = strings.TrimSpace(controllerID)
	if fleetID == "" {
		return Locator{}, apperr.New(apperr.CodeInvalidArgument, "fleet_id is required for cache locator")
	}
	if cachePool == "" {
		return Locator{}, apperr.New(apperr.CodeInvalidArgument, "cache_pool is required for cache locator")
	}
	if controllerID == "" {
		return Locator{}, apperr.New(apperr.CodeInvalidArgument, "controller_id is required for cache locator")
	}
	if buildNumber < 1 {
		return Locator{}, apperr.New(apperr.CodeInvalidArgument, "build_number must be >= 1")
	}
	// Reject inputs that look like local generation keys or profile-prefixed store keys.
	if looksLikeLocalStoreKey(jobFullName) {
		return Locator{}, apperr.New(apperr.CodeInvalidArgument,
			"job full name must not be a local store key (profile|job|build)")
	}
	ref, err := contracts.ParseJobFullName("job_full_name", jobFullName)
	if err != nil {
		return Locator{}, apperr.New(apperr.CodeInvalidArgument, "invalid job_full_name for cache locator")
	}
	return Locator{
		FleetID:               fleetID,
		CachePool:             cachePool,
		ControllerID:          controllerID,
		ObjectKind:            ObjectKindConsoleLog,
		JobFullNameNormalized: ref.FullName,
		BuildNumber:           buildNumber,
		LocatorSchemaVersion:  LocatorSchemaVersion,
	}, nil
}

// CanonicalBytes returns the deterministic UTF-8 serialization used for hashing.
// Field order is fixed; values are newline-terminated; no local IDs appear.
func (l Locator) CanonicalBytes() ([]byte, error) {
	if err := l.validate(); err != nil {
		return nil, err
	}
	var b strings.Builder
	// Stable multi-line form (one field per line, order is the protocol).
	fmt.Fprintf(&b, "fleet_id=%s\n", l.FleetID)
	fmt.Fprintf(&b, "cache_pool=%s\n", l.CachePool)
	fmt.Fprintf(&b, "controller_id=%s\n", l.ControllerID)
	fmt.Fprintf(&b, "object_kind=%s\n", l.ObjectKind)
	fmt.Fprintf(&b, "job_full_name=%s\n", l.JobFullNameNormalized)
	fmt.Fprintf(&b, "build_number=%d\n", l.BuildNumber)
	fmt.Fprintf(&b, "locator_schema_version=%d\n", l.LocatorSchemaVersion)
	return []byte(b.String()), nil
}

// Hash returns lowercase hex SHA-256 of CanonicalBytes (locator_hash).
func (l Locator) Hash() (string, error) {
	raw, err := l.CanonicalBytes()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func (l Locator) validate() error {
	if strings.TrimSpace(l.FleetID) == "" ||
		strings.TrimSpace(l.CachePool) == "" ||
		strings.TrimSpace(l.ControllerID) == "" ||
		strings.TrimSpace(l.JobFullNameNormalized) == "" {
		return apperr.New(apperr.CodeInvalidArgument, "locator missing required fields")
	}
	// FLC-082: explicit object-class admission (default deny unknown kinds).
	if err := RequireObjectClass(l.ObjectKind, 0); err != nil {
		return err
	}
	if l.LocatorSchemaVersion != LocatorSchemaVersion {
		return apperr.New(apperr.CodeInvalidArgument, "unsupported locator_schema_version")
	}
	if l.BuildNumber < 1 {
		return apperr.New(apperr.CodeInvalidArgument, "build_number must be >= 1")
	}
	// Defense: never allow generation-like pure integers as "job" identity alone was already
	// validated; still reject embedded NUL.
	if strings.ContainsRune(l.JobFullNameNormalized, 0) {
		return apperr.New(apperr.CodeInvalidArgument, "job_full_name contains NUL")
	}
	return nil
}

// looksLikeLocalStoreKey rejects store.LogKey-shaped strings "profile|job|build".
func looksLikeLocalStoreKey(s string) bool {
	s = strings.TrimSpace(s)
	parts := strings.Split(s, "|")
	if len(parts) != 3 {
		return false
	}
	// Third segment must parse as build number for the store key form.
	if _, err := strconv.ParseInt(parts[2], 10, 64); err != nil {
		return false
	}
	return parts[0] != "" && parts[1] != ""
}
