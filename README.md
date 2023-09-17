# socket-proxy

## Table of Contents
+ [About](#about)
+ [Getting Started](#getting_started)
+ [License: MIT](#license)
+ [Aknowledgements](#aknowledgements)

## About <a name = "about"></a>
socket-proxy is a lightweight, secure by default docker socket proxy for Traefik.
It is heavily inspired by [tecnativa/docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy).
It can be used in docker environments to secure the docker socket and run Traefik in a non-root container.

The advantage over other solutions is the very slim container image ("FROM scratch") without any external dependencies (no OS, no packages, just the Go standard library).

socket-proxy could work with Caddyserver, too (see [lucaslorentz/caddy-docker-proxy](https://github.com/lucaslorentz/caddy-docker-proxy)), but this has not been tested yet.

In the current state, socket-proxy may work but is not tested in production environments. Use at your own risk.

## Getting Started <a name = "getting_started"></a>

### Prerequisites

You need a working docker / docker compose environment.

You need to know how to install Traefik in this environment. See [wollomatic/traefik2-hardened](https://github.com/wollomatic/traefik2-hardened) for an example (that repo still uses tecnativa's socket proxy).

### Warning

You should know what you are doing. Accidentally exposing the docker socket to the public internet by misconfiguration is a security nightmare.

### Installing

The container image is available on [Docker Hub: wollomatic/socket-proxy](https://hub.docker.com/r/wollomatic/socket-proxy).

As of the early stage of this project, there is only an image with the "testing" tag available: ``wollomatic/socket-proxy:testing``

The image can be deployed with docker-compose:

``` compose.yaml
services:
  dockerproxy:
    image: wollomatic/socket-proxy:testing
    read_only: true
    restart: unless-stopped
    # uncomment the following line to log all requests to stdout
    # command:
    #   - -log
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    networks:
      - docker-proxynet    # NEVER EVER expose this to the public internet!

  traefik:
    # [...] see github.com/wollomatic/traefik2-hardened for a full example
    depends_on:
      - dockerproxy
    networks:
      - traefik-servicenet # this is the common traefik network
      - docker-proxynet    # this should be only restricted to traefik and socket-proxy
  
networks:
  traefik-servicenet:
    external: true
  docker-proxynet:
    driver: bridge
    internal: true
```

### Parameters

Use ``-log`` to log all requests to stdout. Otherwise, only bad requests and some startup/shutdown information are logged.

## License <a name = "license"></a>

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Aknowledgements <a name = "aknowledgements"></a>

+ [Chris Wiegman's blog post about securing the docker socket](https://www.chriswiegman.com/2019/09/securing-the-docker-socket/)
+ [tecnativa/docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy) (Apache Licensed)