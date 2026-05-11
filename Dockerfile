# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.26.3-alpine3.23@sha256:91eda9776261207ea25fd06b5b7fed8d397dd2c0a283e77f2ab6e91bfa71079d AS build
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
