package fleetmcp

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// Peer server lifecycle defaults (FLC-015). Sized for fleet ops JSON today;
// streaming cache routes (later) may use longer write timeouts per-handler.
const (
	DefaultPeerReadHeaderTimeout = 5 * time.Second
	DefaultPeerReadTimeout       = 30 * time.Second
	DefaultPeerWriteTimeout      = 30 * time.Second
	DefaultPeerIdleTimeout       = 60 * time.Second
	DefaultPeerMaxHeaderBytes    = 1 << 16 // 64 KiB
	DefaultPeerShutdownTimeout   = 5 * time.Second
)

// PeerServerOptions configures managed peer HTTP server timeouts/limits.
type PeerServerOptions struct {
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	MaxHeaderBytes    int
	// BaseContext optional; defaults to context.Background.
	BaseContext func(net.Listener) context.Context
}

// DefaultPeerServerOptions returns production-safe defaults (all timeouts non-zero).
func DefaultPeerServerOptions() PeerServerOptions {
	return PeerServerOptions{
		ReadHeaderTimeout: DefaultPeerReadHeaderTimeout,
		ReadTimeout:       DefaultPeerReadTimeout,
		WriteTimeout:      DefaultPeerWriteTimeout,
		IdleTimeout:       DefaultPeerIdleTimeout,
		MaxHeaderBytes:    DefaultPeerMaxHeaderBytes,
	}
}

// PeerServer is a managed http.Server for /fleet/v1 (and future cache routes).
// Prefer ListenPeer + Serve over fire-and-forget http.ListenAndServe.
type PeerServer struct {
	Server *http.Server
	ln     net.Listener
	addr   string

	mu       sync.Mutex
	serving  bool
	done     chan struct{}
	serveErr error
}

// ListenPeer binds addr and returns a PeerServer ready for Serve.
// Bind failure is returned immediately (fail closed) — does not start Serve.
func ListenPeer(addr string, handler http.Handler, opts PeerServerOptions) (*PeerServer, error) {
	addr = trimSpace(addr)
	if addr == "" {
		return nil, apperr.New(apperr.CodeInvalidArgument, "fleet peer listen address is empty")
	}
	if handler == nil {
		return nil, apperr.New(apperr.CodeInvalidArgument, "fleet peer handler is nil")
	}
	opts = normalizePeerOpts(opts)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeInvalidArgument, "fleet peer listen bind failed", err)
	}
	base := opts.BaseContext
	if base == nil {
		base = func(net.Listener) context.Context { return context.Background() }
	}
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: opts.ReadHeaderTimeout,
		ReadTimeout:       opts.ReadTimeout,
		WriteTimeout:      opts.WriteTimeout,
		IdleTimeout:       opts.IdleTimeout,
		MaxHeaderBytes:    opts.MaxHeaderBytes,
		BaseContext:       base,
	}
	return &PeerServer{
		Server: srv,
		ln:     ln,
		addr:   ln.Addr().String(),
		done:   make(chan struct{}),
	}, nil
}

// Addr returns the bound address (may differ from requested if port 0).
func (p *PeerServer) Addr() string {
	if p == nil {
		return ""
	}
	return p.addr
}

// Serve runs the HTTP server until Shutdown or fatal error.
// Safe to call once; blocks. Prefer go p.Serve() after ListenPeer.
func (p *PeerServer) Serve() error {
	if p == nil || p.Server == nil || p.ln == nil {
		return apperr.New(apperr.CodeInternal, "fleet peer server not initialized")
	}
	p.mu.Lock()
	if p.serving {
		p.mu.Unlock()
		return apperr.New(apperr.CodeInternal, "fleet peer server already serving")
	}
	p.serving = true
	p.mu.Unlock()

	err := p.Server.Serve(p.ln)
	p.mu.Lock()
	p.serveErr = err
	p.mu.Unlock()
	close(p.done)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Done is closed when Serve returns.
func (p *PeerServer) Done() <-chan struct{} {
	if p == nil {
		ch := make(chan struct{})
		close(ch)
		return ch
	}
	return p.done
}

// Shutdown gracefully stops the server (drain in-flight within ctx).
func (p *PeerServer) Shutdown(ctx context.Context) error {
	if p == nil || p.Server == nil {
		return nil
	}
	if ctx == nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), DefaultPeerShutdownTimeout)
		defer cancel()
	}
	return p.Server.Shutdown(ctx)
}

// StartPeerServer ListenPeer + Serve in a goroutine. Returns after bind succeeds.
// On Serve error (other than ErrServerClosed), errCh receives the error (non-blocking send once).
func StartPeerServer(addr string, handler http.Handler, opts PeerServerOptions) (srv *PeerServer, errCh <-chan error, err error) {
	ps, err := ListenPeer(addr, handler, opts)
	if err != nil {
		return nil, nil, err
	}
	ch := make(chan error, 1)
	go func() {
		if err := ps.Serve(); err != nil {
			ch <- err
		}
		close(ch)
	}()
	return ps, ch, nil
}

func normalizePeerOpts(opts PeerServerOptions) PeerServerOptions {
	d := DefaultPeerServerOptions()
	if opts.ReadHeaderTimeout <= 0 {
		opts.ReadHeaderTimeout = d.ReadHeaderTimeout
	}
	if opts.ReadTimeout <= 0 {
		opts.ReadTimeout = d.ReadTimeout
	}
	if opts.WriteTimeout <= 0 {
		opts.WriteTimeout = d.WriteTimeout
	}
	if opts.IdleTimeout <= 0 {
		opts.IdleTimeout = d.IdleTimeout
	}
	if opts.MaxHeaderBytes <= 0 {
		opts.MaxHeaderBytes = d.MaxHeaderBytes
	}
	return opts
}

func trimSpace(s string) string { return strings.TrimSpace(s) }
