FROM --platform=$BUILDPLATFORM golang:1.21-alpine AS build
WORKDIR /application
#COPY go.mod go.sum ./
COPY application/go.mod ./
RUN go mod download && go mod verify
COPY application/*.go ./
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build --tags netgo -ldflags="-w -s" -o /socket-proxy .

FROM scratch
LABEL org.opencontainers.image.source=https://github.com/wollomatic/socket-proxy
LABEL org.opencontainers.image.description="A lightweight and secure unix socket proxy"
LABEL org.opencontainers.image.licenses=MIT
VOLUME /var/run/docker.sock
EXPOSE 2375
ENTRYPOINT ["/socket-proxy"]
WORKDIR /
COPY --from=build ./socket-proxy /socket-proxy
