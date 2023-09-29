FROM --platform=$BUILDPLATFORM golang:1.21-alpine AS build
WORKDIR /application
COPY . ./
ARG TARGETOS
ARG TARGETARCH
ARG VERSION
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -tags=netgo -gcflags=all=-d=checkptr -ldflags="-w -s -X 'main.version=${VERSION}'" -o / ./...

FROM scratch
LABEL org.opencontainers.image.source=https://github.com/wollomatic/socket-proxy \
      org.opencontainers.image.description="A lightweight and secure unix socket proxy" \
      org.opencontainers.image.licenses=MIT
USER 65534:65534
VOLUME /var/run/docker.sock
EXPOSE 2375
ENTRYPOINT ["/socket-proxy"]
COPY --from=build ./healthcheck ./socket-proxy /
