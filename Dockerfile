FROM --platform=$BUILDPLATFORM golang:1.21-alpine AS build
WORKDIR /application
#COPY go.mod go.sum ./
COPY application/go.mod ./
RUN go mod download && go mod verify
COPY application/*.go ./
ARG TARGETOS
ARG TARGETARCH
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH go build --tags netgo -ldflags="-w -s" -o /socket-proxy .

FROM scratch
LABEL org.opencontainers.image.source=https://github.com/wollomatic/socket-proxy
LABEL org.opencontainers.image.description="A lightweight secure by default docker socket proxy for Traefik or Caddyserver"
LABEL org.opencontainers.image.licenses=MIT
LABEL securitytxt="https://wollomatic.de/.well-known/security.txt"
VOLUME /var/run/docker.sock
EXPOSE 2375
ENTRYPOINT ["/socket-proxy"]
WORKDIR /
COPY ./README.md /README.md
COPY --from=build ./socket-proxy /socket-proxy
