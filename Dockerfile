# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.27.1-alpine3.24@sha256:cf6fca6641884b8433441b2b0652976f975e1d0fdd26d177eaaf8596087f3125 AS build
WORKDIR /application
COPY . ./
ARG TARGETOS
ARG TARGETARCH
ARG VERSION
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -tags=netgo -gcflags=all=-d=checkptr -ldflags="-w -s -X 'main.version=${VERSION}'" -trimpath \
    -o / ./...

FROM scratch
LABEL org.opencontainers.image.source=https://github.com/wollomatic/socket-proxy \
      org.opencontainers.image.description="A lightweight and secure unix socket proxy" \
      org.opencontainers.image.licenses=MIT
USER 65534:65534
VOLUME /var/run/docker.sock
EXPOSE 2375
ENTRYPOINT ["/socket-proxy"]
COPY --from=build ./healthcheck ./socket-proxy /
