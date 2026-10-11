# Build: Go cross-kompiliert, daher kein QEMU nötig.
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
ARG TARGETOS TARGETARCH
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# timetzdata: Zeitzonen eingebettet, damit TZ=Europe/Berlin im scratch-Image wirkt
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -tags timetzdata -ldflags "-s -w -X main.version=${VERSION}" -o /out/shelly-watcher . \
 && mkdir -p /out/data

# Laufzeit: nur das Binary + CA-Zertifikate (für die Gen1-Firmwareliste per HTTPS).
FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /out/shelly-watcher /shelly-watcher
COPY --from=build --chown=65534:65534 /out/data /data
ENV DATA_DIR=/data \
    LISTEN=:8080 \
    GOMEMLIMIT=24MiB
USER 65534:65534
EXPOSE 8080/tcp 5683/udp
VOLUME /data
HEALTHCHECK --interval=60s --timeout=5s --start-period=10s CMD ["/shelly-watcher", "healthcheck"]
ENTRYPOINT ["/shelly-watcher"]
