# HAOS Exporter image. The build context is this folder: the Supervisor builds
# it on the device (no `image:` in config.yaml) and passes BUILD_ARCH and
# BUILD_VERSION. build.yaml is deprecated and not used.
#
# Both base images are pinned by index digest; the tag is kept for readability
# and for Dependabot. No `# syntax=` line: that would pull an unpinned
# Dockerfile frontend image.

# The builder runs on the build host's platform and cross-compiles, so an
# arm64 image never needs emulation.
FROM --platform=$BUILDPLATFORM golang:1.27.1-alpine3.24@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS builder

# Set by BuildKit (buildx) for the target platform.
ARG TARGETOS
ARG TARGETARCH
# Passed by the Supervisor.
ARG BUILD_VERSION=dev
# Not passed by the Supervisor (.git is outside the build context); CI sets them.
ARG BUILD_REVISION=unknown
ARG BUILD_BRANCH=unknown
ARG BUILD_DATE=unknown

# Never download a different Go toolchain than the pinned image's.
ENV CGO_ENABLED=0 \
    GOTOOLCHAIN=local

WORKDIR /src

# One step downloads the modules, builds, and deletes both Go caches, so
# the layer holds only /out. The Supervisor builds on the
# data partition this app watches and keeps every layer as build cache,
# which nothing reclaims: kept in layers, the Go build cache (~165 MB) came
# back on every source change and a separate `go mod download` layer
# (~105 MB) would on every go.mod change. go.sum still verifies every module.
COPY go.mod go.sum ./
COPY cmd ./cmd
COPY internal ./internal

RUN GOOS="${TARGETOS:-linux}" GOARCH="${TARGETARCH}" \
    go build -trimpath \
      -ldflags "-s -w \
        -X github.com/prometheus/common/version.Version=${BUILD_VERSION} \
        -X github.com/prometheus/common/version.Revision=${BUILD_REVISION} \
        -X github.com/prometheus/common/version.Branch=${BUILD_BRANCH} \
        -X github.com/prometheus/common/version.BuildDate=${BUILD_DATE}" \
      -o /out/haos-exporter ./cmd/haos-exporter \
 && go clean -cache -modcache

# distroless static, nonroot variant: no shell, no package manager, uid 65532.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3

ARG BUILD_ARCH
ARG BUILD_VERSION=dev

LABEL \
    io.hass.type="app" \
    io.hass.arch="${BUILD_ARCH}" \
    io.hass.version="${BUILD_VERSION}" \
    org.opencontainers.image.title="HAOS Exporter" \
    org.opencontainers.image.description="Prometheus exporter for Home Assistant OS, shipped as an unprivileged Home Assistant app" \
    org.opencontainers.image.source="https://github.com/TBording/haos-exporter" \
    org.opencontainers.image.licenses="Apache-2.0" \
    org.opencontainers.image.version="${BUILD_VERSION}"

# Root-owned and not writable by the runtime user.
COPY --from=builder /out/haos-exporter /haos-exporter

# The Supervisor sets no User, so this one applies.
USER 65532:65532
EXPOSE 9100
ENTRYPOINT ["/haos-exporter"]
