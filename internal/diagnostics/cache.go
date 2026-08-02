package diagnostics

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/config"
	"github.com/hilather/go-jenkins-mcp/internal/profile"
	"github.com/hilather/go-jenkins-mcp/internal/store"
	"github.com/hilather/go-jenkins-mcp/internal/telemetry"
)

// CacheStatusOptions configures cache status (OPS-001).
type CacheStatusOptions struct {
	Profile *profile.Profile
	Paths   *config.Paths
	Metrics *telemetry.Metrics
}

// RunCacheStatus reports L1 data-dir + store schema without secrets.
func RunCacheStatus(ctx context.Context, opts CacheStatusOptions) (CacheStatus, error) {
	if opts.Profile == nil {
		return CacheStatus{}, apperr.New(apperr.CodeInvalidArgument, "profile is required")
	}
	out := CacheStatus{
		ProfileID:      string(opts.Profile.ID),
		ExpectedSchema: store.CurrentSchemaVersion,
	}
	paths, err := resolvePaths(opts.Paths)
	if err != nil {
		out.DataDirOK = false
		out.DataDirMessage = "failed to resolve XDG paths"
		return out, nil
	}
	dataDir, err := resolveDataDir(opts.Profile, paths)
	if err != nil {
		out.DataDirOK = false
		out.DataDirMessage = apperr.ModelMessage(err)
		return out, nil
	}
	out.DataDir = dataDir
	if err := store.ValidateDir(dataDir); err != nil {
		out.DataDirOK = false
		out.DataDirMessage = apperr.ModelMessage(err)
	} else {
		out.DataDirOK = true
		if fi, err := os.Stat(dataDir); err == nil {
			out.DataDirMode = fmt.Sprintf("%04o", fi.Mode().Perm())
		}
	}

	meta, err := store.Open(dataDir)
	if err != nil {
		out.StoreOpen = false
		out.StoreMessage = apperr.ModelMessage(err)
		out.SchemaOK = false
		return out, nil
	}
	defer func() { _ = meta.Close() }()
	out.StoreOpen = true
	st, err := meta.Stats(ctx)
	if err != nil {
		out.StoreMessage = apperr.ModelMessage(err)
		out.SchemaOK = false
		return out, nil
	}
	out.SchemaVersion = st.SchemaVersion
	out.Generations = st.Generations
	out.Chunks = st.Chunks
	out.SchemaOK = st.SchemaVersion == store.CurrentSchemaVersion
	if !out.SchemaOK {
		out.StoreMessage = fmt.Sprintf("schema version %d (expected %d)", st.SchemaVersion, store.CurrentSchemaVersion)
	}

	if opts.Metrics == nil {
		if g := telemetry.Global(); g != nil {
			opts.Metrics = g.Metrics
		}
	}
	if opts.Metrics != nil {
		snap := opts.Metrics.Snapshot()
		out.Metrics = &snap
	}
	// Prefer base-only path in CLI when absolute paths are sensitive; keep full
	// for local operator use but never put secrets there.
	_ = filepath.Base(dataDir)
	return out, nil
}
