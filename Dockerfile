# syntax=docker/dockerfile:1.7

FROM node:24.19.0-alpine3.23@sha256:244cc2b53f46f9e876304391d17682b0ddae9ac33491f4857e25e35a36ba7995 AS web
WORKDIR /src/web
RUN npm install --global pnpm@11.19.0
COPY web/package.json web/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY web/ ./
RUN pnpm test && pnpm build

FROM golang:1.27.1-alpine3.23@sha256:d9e2f2f07b10cc922da3e80e035c3058810b328d5aef82d2c63680967c5e2ec9 AS backend
ARG VERSION=0.1.0-dev
ARG COMMIT=unknown
ARG BUILT_AT=unknown
WORKDIR /src
RUN apk add --no-cache ca-certificates
COPY go.mod ./
COPY cmd/ ./cmd/
COPY internal/ ./internal/
RUN go test ./...
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -buildvcs=false \
    -ldflags "-s -w -X model-integrity-inspector.local/mii/internal/buildinfo.version=${VERSION} -X model-integrity-inspector.local/mii/internal/buildinfo.commit=${COMMIT} -X model-integrity-inspector.local/mii/internal/buildinfo.builtAt=${BUILT_AT}" \
    -o /out/mii ./cmd/mii

FROM scratch
ARG VERSION=0.1.0-dev
ARG COMMIT=unknown
ARG BUILT_AT=unknown
ARG SOURCE=unknown
LABEL org.opencontainers.image.title="Model Integrity Inspector" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.created="${BUILT_AT}" \
      org.opencontainers.image.source="${SOURCE}"
COPY --from=backend /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=backend /out/mii /mii
COPY --from=web /src/web/dist /web
USER 65532:65532
ENV APP_ROLE=all MII_ADDR=0.0.0.0:8080
EXPOSE 8080
ENTRYPOINT ["/mii"]
