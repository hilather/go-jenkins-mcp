package jenkins

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewTransport_Construction(t *testing.T) {
	cfg := DefaultTransportConfig()
	cfg.MaxIdleConns = 42
	cfg.MaxIdleConnsPerHost = 7
	cfg.IdleConnTimeout = 11 * time.Second
	cfg.TLSHandshakeTimeout = 3 * time.Second
	cfg.ResponseHeaderTimeout = 4 * time.Second
	cfg.ForceAttemptHTTP2 = true

	tr, err := NewTransport(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if tr.MaxIdleConns != 42 {
		t.Fatalf("MaxIdleConns = %d", tr.MaxIdleConns)
	}
	if tr.MaxIdleConnsPerHost != 7 {
		t.Fatalf("MaxIdleConnsPerHost = %d", tr.MaxIdleConnsPerHost)
	}
	if tr.IdleConnTimeout != 11*time.Second {
		t.Fatalf("IdleConnTimeout = %v", tr.IdleConnTimeout)
	}
	if tr.TLSHandshakeTimeout != 3*time.Second {
		t.Fatalf("TLSHandshakeTimeout = %v", tr.TLSHandshakeTimeout)
	}
	if tr.ResponseHeaderTimeout != 4*time.Second {
		t.Fatalf("ResponseHeaderTimeout = %v", tr.ResponseHeaderTimeout)
	}
	if !tr.ForceAttemptHTTP2 {
		t.Fatal("ForceAttemptHTTP2 want true")
	}
	if !tr.DisableCompression {
		t.Fatal("DisableCompression must be true (explicit gzip control)")
	}
	if tr.TLSClientConfig == nil || tr.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("TLS MinVersion = %v", tr.TLSClientConfig)
	}
	if tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("default must not skip TLS verify")
	}
}

func TestNewHTTPClients_ShareTransport(t *testing.T) {
	hc, err := NewHTTPClients(DefaultTransportConfig())
	if err != nil {
		t.Fatal(err)
	}
	if hc.API == nil || hc.Logs == nil || hc.Transport == nil {
		t.Fatal("nil clients/transport")
	}
	if hc.API.Transport != hc.Transport || hc.Logs.Transport != hc.Transport {
		t.Fatal("API and Logs must share Transport")
	}
	if hc.API.Timeout != defaultAPIClientTimeout {
		t.Fatalf("API timeout = %v", hc.API.Timeout)
	}
	if hc.Logs.Timeout != defaultLogsClientTimeout {
		t.Fatalf("Logs timeout = %v", hc.Logs.Timeout)
	}
}

func TestClient_WithTransport_CloseIdle(t *testing.T) {
	c := &Client{URL: "https://jenkins.example.com", User: "u", Token: "t"}
	if _, err := c.WithTransport(DefaultTransportConfig()); err != nil {
		t.Fatal(err)
	}
	if c.Client == nil || c.LogsClient == nil {
		t.Fatal("expected clients")
	}
	if c.sharedTransport == nil {
		t.Fatal("expected shared transport")
	}
	c.CloseIdleConnections() // must not panic
}

func TestCallJenkins_CancelContextAborts(t *testing.T) {
	started := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		// Block until the request context is cancelled.
		<-r.Context().Done()
	}))
	defer srv.Close()

	cfg := DefaultTransportConfig()
	cfg.APIClientTimeout = 0 // rely on context only
	c := &Client{URL: srv.URL, User: "u", Token: "t"}
	if _, err := c.WithTransport(cfg); err != nil {
		t.Fatal(err)
	}
	c.WithResilience(ResilienceConfig{MaxRetries: 0, MaxJSONBodyBytes: 1 << 20})

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		_, err := c.CallJenkins(ctx, c.Client, http.MethodGet, "/slow", nil, nil)
		errCh <- err
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not start")
	}
	cancel()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected cancel error")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("CallJenkins did not return after cancel")
	}
}

func TestWrapResponseBody_GzipCounters(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		var buf bytes.Buffer
		gw := gzip.NewWriter(&buf)
		_, _ = io.WriteString(gw, "hello-decoded")
		_ = gw.Close()
		_, _ = w.Write(buf.Bytes())
	}))
	defer srv.Close()

	counters := &AtomicByteCounters{}
	c := &Client{
		URL:        srv.URL,
		User:       "u",
		Token:      "t",
		Client:     srv.Client(),
		acceptGzip: true,
		counters:   counters,
	}
	c.WithResilience(ResilienceConfig{MaxRetries: 0, MaxJSONBodyBytes: 1 << 20})

	resp, err := c.CallJenkins(context.Background(), c.Client, http.MethodGet, "/", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "hello-decoded" {
		t.Fatalf("body = %q", data)
	}
	if counters.Decoded.Load() < int64(len("hello-decoded")) {
		t.Fatalf("decoded counter = %d", counters.Decoded.Load())
	}
	if counters.Wire.Load() == 0 {
		t.Fatal("wire counter should be > 0 for gzip")
	}
	t.Logf("wire=%d decoded=%d", counters.Wire.Load(), counters.Decoded.Load())
}

func TestConnectionReuse_SharedTransport(t *testing.T) {
	var newConns atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			newConns.Add(1)
		}
	}
	srv.Start()
	defer srv.Close()

	hc, err := NewHTTPClients(DefaultTransportConfig())
	if err != nil {
		t.Fatal(err)
	}
	// Zero client timeout; use context only. Keep connection pool.
	hc.API.Timeout = 0
	c := &Client{
		URL:             srv.URL,
		User:            "u",
		Token:           "t",
		Client:          hc.API,
		LogsClient:      hc.Logs,
		sharedTransport: hc.Transport,
	}
	c.WithResilience(ResilienceConfig{MaxRetries: 0, MaxJSONBodyBytes: 1 << 20})

	for i := 0; i < 5; i++ {
		resp, err := c.CallJenkins(context.Background(), c.Client, http.MethodGet, "/api/json", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	// Expect a single TCP connection reused (allow 1–2 for races/startup).
	n := newConns.Load()
	if n > 2 {
		t.Fatalf("new connections = %d, want reuse (≤2)", n)
	}
	if n < 1 {
		t.Fatal("expected at least one connection")
	}
}

func TestDefaultTransportConfig_GzipOff(t *testing.T) {
	cfg := DefaultTransportConfig()
	if cfg.AcceptGzip {
		t.Fatal("AcceptGzip default must be false (opt-in; document residual)")
	}
}
