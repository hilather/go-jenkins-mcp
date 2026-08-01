package mcpserver

import (
	"context"
	"io"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// DefaultServerName is the Implementation.Name used by the jenkins-mcp binary.
const DefaultServerName = "jenkins-mcp-go"

// NewServer constructs an MCP server with the given name and version.
// Callers register tools on the returned *mcp.Server (internal/tools).
func NewServer(name, version string) *mcp.Server {
	if name == "" {
		name = DefaultServerName
	}
	if version == "" {
		version = "dev"
	}
	return mcp.NewServer(&mcp.Implementation{Name: name, Version: version}, nil)
}

// StdioOptions configures optional overrides for RunStdio (tests).
type StdioOptions struct {
	// LogWriter receives LoggingTransport RPC logs. Default: os.Stderr.
	LogWriter io.Writer
}

// RunStdio serves MCP over stdio using LoggingTransport (stderr by default).
// This is the pilot default transport (ADR 0002). Blocks until the session ends
// or ctx is cancelled.
func RunStdio(ctx context.Context, server *mcp.Server) error {
	return RunStdioWith(ctx, server, StdioOptions{})
}

// RunStdioWith is RunStdio with optional log writer override.
func RunStdioWith(ctx context.Context, server *mcp.Server, opts StdioOptions) error {
	if server == nil {
		return apperr.New(apperr.CodeInternal, "mcp server is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	w := opts.LogWriter
	if w == nil {
		w = os.Stderr
	}
	t := &mcp.LoggingTransport{
		Transport: &mcp.StdioTransport{},
		Writer:    w,
	}
	if err := server.Run(ctx, t); err != nil {
		// Context cancel on clean host shutdown is not a hard failure.
		if ctx.Err() != nil {
			return nil
		}
		return apperr.Wrap(apperr.CodeInternal, "mcp stdio server error", err)
	}
	return nil
}
