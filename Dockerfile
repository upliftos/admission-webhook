# upliftos-admission — the §3.4.1 admission-webhook fallback server.
#
# MUST be published to a PUBLIC registry (ghcr.io/upliftos/upliftos-admission):
# the customer cluster pulls it during connect, before any UpliftOS pull secret
# exists — exactly like the alpine/k8s connect Job image. Tag immutably per
# release (never :latest); the bootstrap manifest pins the tag.
#
# Final image is distroless/static:nonroot — no shell, no package manager, one
# static binary running as uid 65532 (matches the Deployment/Job securityContext).

# Builder runs NATIVELY on the build host and cross-compiles to the target arch
# (TARGETOS/TARGETARCH are set by buildx per --platform) — a pure-Go, CGO-off
# binary cross-compiles without QEMU, so a multi-arch build stays fast.
FROM --platform=$BUILDPLATFORM golang:1.22-alpine AS builder
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod ./
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -ldflags="-s -w" -o /out/upliftos-admission .

FROM gcr.io/distroless/static:nonroot
COPY --from=builder /out/upliftos-admission /usr/local/bin/upliftos-admission
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/upliftos-admission"]
