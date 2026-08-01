# Disposable OAuth lab peers (HOST-012…015). Not for production.
# Builds the multi-command authlab binary from the module root.
#
# Build context must be the repository root:
#   docker build -f testdata/oauth-lab/Dockerfile -t go-jenkins-mcp/oauth-lab .

FROM golang:1.25-alpine AS build
WORKDIR /src
RUN apk add --no-cache git ca-certificates
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/authlab ./cmd/authlab

FROM alpine:3.21
RUN apk add --no-cache ca-certificates curl \
	&& adduser -D -H -u 65532 lab
COPY --from=build /out/authlab /usr/local/bin/authlab
COPY testdata/oauth-lab/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh \
	&& mkdir -p /lab-keys \
	&& chown lab:lab /lab-keys
USER lab
ENV LAB_KEYS_DIR=/lab-keys
ENTRYPOINT ["/entrypoint.sh"]
# Default command overridden per service in compose.
CMD ["oidc"]
