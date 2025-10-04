# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.25.1-alpine3.22 AS build
WORKDIR /application
COPY . ./
ARG TARGETOS
ARG TARGETARCH
ARG VERSION
RUN go mod tidy
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
