# Reverse proxy and TLS

**Support status:** Supported (configuration patterns)

## Goals

- Terminate TLS at the proxy (or mesh)
- Forward to loopback MCP/gateway HTTP
- Exact `AllowedOrigins` / host allow lists — **no wildcard CORS**
- Preserve or set required headers per [gateway/deployment.md](../gateway/deployment.md)

## Checklist

1. Obtain certificate for public hostname  
2. Proxy `https://mcp.example/` → `http://127.0.0.1:<mcp-port>/`  
3. Configure path prefix if using `JENKINS_MCP_HTTP_PATH_PREFIX`  
4. Restrict admin BFF to loopback or separate auth  
5. Verify `/healthz` and `/readyz` through the proxy without leaking secrets  

Site-specific mTLS and corporate CA trust remain operator validation.
