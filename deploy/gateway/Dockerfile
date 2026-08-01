# GWY-004 MVP scaffold Dockerfile — optional near-source gateway image.
# Tier-1: linux/amd64 (aarch64 when your registry builds it). Windows out of scope.
#
# Residuals (explicit):
#   - Live AgentCore sidecar not included
#   - Image signing / provenance (cosign, SBOM attach) is org pipeline work
#   - Do not bake secrets, tokens, or private keys into layers
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

# Minimal non-root runtime (distroless static).
FROM gcr.io/distroless/static-debian12:nonroot
USER nonroot:nonroot
COPY --from=build /out/jenkins-mcp /usr/bin/jenkins-mcp
ENTRYPOINT ["/usr/bin/jenkins-mcp"]
# Default args overridden by compose/k8s; keep help as safe default.
CMD ["version", "--json"]
