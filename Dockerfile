# syntax=docker/dockerfile:1.7

FROM node:24.19.0-alpine3.23@sha256:244cc2b53f46f9e876304391d17682b0ddae9ac33491f4857e25e35a36ba7995 AS web
WORKDIR /src/web
RUN npm install --global pnpm@11.19.0
COPY web/package.json web/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY web/ ./
RUN pnpm test && pnpm build

FROM golang:1.26.7-alpine3.23@sha256:b17af760035fc2f338eed92d448a6c67f2d45438844fc6c60678fa5f99e44b57 AS backend
ARG VERSION=0.1.0-dev
ARG COMMIT=unknown
ARG BUILT_AT=unknown
WORKDIR /src
RUN apk add --no-cache ca-certificates
COPY go.mod go.sum ./
COPY cmd/ ./cmd/
COPY internal/ ./internal/
COPY migrations/ ./migrations/
COPY tests/ ./tests/
COPY docs/ ./docs/
COPY *.md ./
COPY Dockerfile ./
COPY scripts/package.ps1 ./scripts/package.ps1
COPY scripts/test-replay-netns.ps1 ./scripts/test-replay-netns.ps1
COPY .github/workflows/ci.yml ./.github/workflows/ci.yml
COPY .dockerignore ./.dockerignore
# Keep source evidence in the test/build stage; the scratch image only receives
# the compiled binary (with production assets), certificates and notices.
COPY web/ ./web/
COPY --from=web /src/web/dist ./web/dist/
# Both database snapshots and authenticated-file tests need about 50 MiB each
# on the same default 64 MiB /dev/shm when this build layer is overlay. Keep all
# packages/cases and their internal concurrency; serialize only test binaries.
RUN go test -p 1 ./...
RUN go test -tags webassets ./web ./internal/app
RUN CGO_ENABLED=0 GOOS=linux go build -tags webassets -trimpath -buildvcs=false \
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
COPY --from=backend /src/internal/integrity/tokenizer/THIRD_PARTY_NOTICES.md /licenses/THIRD_PARTY_NOTICES.md
USER 65532:65532
ENV APP_ROLE=all MII_ADDR=0.0.0.0:8080 MII_ALLOW_INSECURE_LOOPBACK=false
EXPOSE 8080
ENTRYPOINT ["/mii"]
