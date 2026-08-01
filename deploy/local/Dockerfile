# syntax=docker/dockerfile:1
# Local / support Docker image for jenkins-mcp (stdio default remains host Cursor path).
# Tier-1: linux/amd64. Windows out of scope.
#
# Purpose: easy supportability — admin console (real SPA baked in), doctor,
# support-bundle, optional HTTP serve in a disposable container.
# NOT a multi-tenant production gateway (see deploy/gateway).
#
# Build (from repo root):
#   docker build -f deploy/local/Dockerfile \
#     --build-arg VERSION=dev --build-arg COMMIT=unknown --build-arg BUILDTIME=unknown \
#     -t jenkins-mcp-local:dev .
#
# Optional: skip SPA stage (embed/placeholder only; no Node layers content):
#   docker build -f deploy/local/Dockerfile --build-arg SKIP_SPA=1 -t jenkins-mcp-local:dev .
#
# Residuals:
#   - Secret Service / OS keyring not available inside the container by default
#   - Cursor MCP stdio integration is still host-native; use HTTP/admin here for support
#   - No production secrets baked into layers
#   - Host does not need npm after the image is built (SPA built in spa stage)

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILDTIME=unknown
ARG SKIP_SPA=0

# --- SPA stage: production Vite build → /out/admin-ui (UI-008 packaged path) ---
FROM node:22-bookworm AS spa
ARG VERSION=dev
ARG SKIP_SPA=0
WORKDIR /spa

# Layer cache: install deps before full source copy when building SPA.
COPY web/admin/package.json web/admin/package-lock.json ./
RUN if [ "${SKIP_SPA}" = "1" ] || [ "${SKIP_SPA}" = "true" ] || [ "${SKIP_SPA}" = "yes" ]; then \
      echo "spa: SKIP_SPA=${SKIP_SPA} — skipping npm ci"; \
    else \
      npm ci; \
    fi

COPY web/admin/ ./
RUN set -e; \
    mkdir -p /out/admin-ui; \
    if [ "${SKIP_SPA}" = "1" ] || [ "${SKIP_SPA}" = "true" ] || [ "${SKIP_SPA}" = "yes" ]; then \
      echo "spa: SKIP_SPA=${SKIP_SPA} — empty package path (embed/placeholder at runtime)"; \
      # No index.html → PackagedAssetsDir resolution fails closed to embed. \
      printf 'skipped\n' > /out/admin-ui/.spa_skipped; \
    else \
      npm run build; \
      # Vite outDir is dist/; stamp secret-free UI_BUILD (package-linux parity). \
      if [ ! -f dist/index.html ]; then \
        echo "spa: FAIL — dist/index.html missing after npm run build" >&2; \
        exit 1; \
      fi; \
      cp -a dist/. /out/admin-ui/; \
      if [ ! -f /out/admin-ui/UI_BUILD ]; then \
        printf '%s\n' "${VERSION}" > /out/admin-ui/UI_BUILD; \
      fi; \
      echo "spa: built UI_BUILD=$(tr -d '\r\n' < /out/admin-ui/UI_BUILD | head -c 128)"; \
    fi

# --- Go stage: CGO-free static binary ---
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

# --- Runtime: binary + packaged SPA at /usr/share/jenkins-mcp/admin-ui ---
FROM debian:bookworm-slim
RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates curl tini \
  && rm -rf /var/lib/apt/lists/* \
  && groupadd -g 65532 nonroot \
  && useradd -u 65532 -g nonroot -m -d /home/nonroot -s /bin/bash nonroot

COPY --from=build /out/jenkins-mcp /usr/bin/jenkins-mcp
COPY deploy/local/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

# UI-008: packaged SPA root (auto-resolved by admin.PackagedAssetsDir when index.html exists).
# SKIP_SPA builds leave this without index.html → uiembed placeholder residual.
COPY --from=spa /out/admin-ui /usr/share/jenkins-mcp/admin-ui

RUN chmod 0755 /usr/local/bin/docker-entrypoint.sh /usr/bin/jenkins-mcp \
  && mkdir -p /home/nonroot/.config/jenkins-mcp \
              /home/nonroot/.local/share/jenkins-mcp \
              /home/nonroot/.cache/jenkins-mcp \
  && chown -R nonroot:nonroot /home/nonroot /usr/share/jenkins-mcp

USER nonroot:nonroot
ENV HOME=/home/nonroot \
    XDG_CONFIG_HOME=/home/nonroot/.config \
    XDG_DATA_HOME=/home/nonroot/.local/share \
    XDG_CACHE_HOME=/home/nonroot/.cache

WORKDIR /home/nonroot
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/docker-entrypoint.sh"]
CMD ["admin"]
