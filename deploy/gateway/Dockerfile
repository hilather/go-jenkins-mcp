# GWY-004 / HOST-005 MVP scaffold Dockerfile — optional near-source gateway image.
# Tier-1: linux/amd64 (aarch64 when your registry builds it). Windows out of scope.
#
# Hardening:
#   - Multi-stage build; runtime is distroless static nonroot (UID/GID 65532)
#   - No shell, package manager, or package cache in final image
#   - Do not bake secrets, tokens, private keys, or .env into layers
#   - Writable state must be volume-mounted (XDG config/data/cache)
#
# Residuals (explicit):
#   - Live AgentCore sidecar not included
#   - Image signing / provenance (cosign, SBOM attach) is org pipeline work
#   - Health HTTP probes need a peer with curl or k8s probe (no curl in distroless)
#
# Build (from repo root):
#   docker build -f deploy/gateway/Dockerfile -t jenkins-mcp-gateway:dev .

# syntax=docker/dockerfile:1
# Match go.mod toolchain (operators may pin a different patch).
FROM golang:1.25-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILDTIME=unknown
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
  -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildTime=${BUILDTIME}" \
  -o /out/jenkins-mcp ./cmd/jenkins-mcp

# Minimal non-root runtime (distroless static). No shell / no curl.
FROM gcr.io/distroless/static-debian12:nonroot
# Explicit nonroot (already default for this tag; documented for operators).
USER nonroot:nonroot
COPY --from=build /out/jenkins-mcp /usr/bin/jenkins-mcp
# Expose is documentation only; compose/k8s map ports.
EXPOSE 8081
ENTRYPOINT ["/usr/bin/jenkins-mcp"]
# Default args overridden by compose/k8s; keep help/version as safe default.
CMD ["version", "--json"]
