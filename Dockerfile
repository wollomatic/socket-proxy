# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.27.4-alpine3.24@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS build
WORKDIR /application
COPY . ./
ARG TARGETOS
ARG TARGETARCH
ARG VERSION
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -tags=netgo -gcflags=all=-d=checkptr -ldflags="-w -s -X 'main.version=${VERSION}'" -trimpath \
    -o / ./...

FROM scratch
LABEL org.opencontainers.image.title="wollomatic/socket-proxy" \
      org.opencontainers.image.description="A lightweight Unix socket proxy with configurable access controls" \
      org.opencontainers.image.url="https://github.com/wollomatic/socket-proxy" \
      org.opencontainers.image.source="https://github.com/wollomatic/socket-proxy" \
      org.opencontainers.image.documentation="https://github.com/wollomatic/socket-proxy/blob/main/README.md" \
      org.opencontainers.image.licenses="MIT AND Apache-2.0"
USER 65534:65534
VOLUME /var/run/docker.sock
EXPOSE 2375
ENTRYPOINT ["/socket-proxy"]
COPY --from=build ./healthcheck ./socket-proxy /
