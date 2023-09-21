# socket-proxy

## About
`socket-proxy` is a lightweight, secure-by-default unix socket proxy. Although it was created to proxy the docker socket to Traefik, it can be used for other purposes, too.
It is heavily inspired by [tecnativa/docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy). 

The advantage over other solutions is the very slim container image ("FROM scratch") without any external dependencies (no OS, no packages, just the Go standard library).
It is designed with security in mind, so there are secure defaults, and there is an extra security layer (IP address-based access control).

Configuration of the allowlist is done for each http method separately using the Go regexp syntax. This allows fine-grained control over the allowed http methods.

In the current state, socket-proxy may work but is not tested in production environments. Use at your own risk.

## Getting Started

### Prerequisites

You need a working docker / docker compose environment.

### Warning

You should know what you are doing. Accidentally exposing a Unix socket to the public internet by misconfiguration is a security nightmare.

### Installing

The container image is available on [Docker Hub: wollomatic/socket-proxy](https://hub.docker.com/r/wollomatic/socket-proxy).

### Setting up the allowlist

You must set up regular expressions for each HTTP method the client application needs access to.

The name of a parameter should be "-allow", followed by the HTTP method name (for example, `-allowGET`). If that parameter is set and the incoming request matches the method and path matching the regex, the request will be allowed. If it is not set, then the corresponding HTTP method will not be allowed.

Use Go's regexp syntax to create the patterns for these parameters. To avoid insecure configurations, the characters ^ at the beginning of the string and $ at the end of the string are automatically added. Note: invalid regex results in program termination.

Examples:
+ `'-allowGET=/v1\..{1,2}/(version|containers/.*|events.*)'` could be used for allowing access to the docker socket for Traefik v2.
+ `'-allowHEAD=.*` allows all HEAD requests.

For more information, refer to the [Go regexp documentation](https://golang.org/pkg/regexp/syntax/).

A good online regex tester is [regex101.com](https://regex101.com/).

To determine which HTTP requests your client application uses, you could switch socket-proxy to debug log level and look at the log output while allowing all requests in a secure environment.

### Example for proxying the docker socket to Traefik

As of the early stage of this project, there is only an image with the "testing" tag available: ``wollomatic/socket-proxy:testing``

You need to know how to install Traefik in this environment. See [wollomatic/traefik2-hardened](https://github.com/wollomatic/traefik2-hardened) for an example (that repo still uses tecnativa's socket proxy).

The image can be deployed with docker compose:

``` compose.yaml
services:
  dockerproxy:
    image: wollomatic/socket-proxy:testing
    restart: unless-stopped
    user: "65534:<<your docker group id>>"
    read_only: true
    command:
      - -loglevel=DEBUG
      - -allowfrom=0.0.0.0/0 # allow all IPv4 addresses (know what you are doing!)
      - '-allowGET=/v1\..{1,2}/(version|containers/.*|events.*)'
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

| Parameter   | Default Value        | Description                                                                                                                                                                                                                                                                                                                                                                                                                                    |
|-------------|----------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `-allowfrom`  | `127.0.0.1/32`         | Specifies the IP addresses of the clients allowed to connect to the proxy. The default value is `127.0.0.1/32`, which means only localhost is allowed. This default configuration may not be useful in most cases, but it is because of a secure-by-default design. To allow all IPv4 addresses, set `-allowfrom=0.0.0.0/0`. Please remember that socket-proxy should never be exposed to a public network, regardless of this extra security layer. |
| `-logjson`    | (not set)            | If set, it enables logging in JSON format. If unset, docker-proxy logs in plain text format.                                                                                                                                                                                                                                                                                                                                                   |
| `-loglevel`   | `INFO`                 | Sets the log level. Accepted values are: `DEBUG`, `INFO`, `WARN`, `ERROR`.                                                                                                                                                                                                                                                                                                                                                                      |
| `-proxyport`  | `2375`                 | Defines the TCP port the proxy listens to.                                                                                                                                                                                                                                                                                                                                                                                                     |
| `-socketpath` | `/var/run/docker.sock` | Specifies the UNIX socket path to connect to. By default, it connects to the Docker daemon socket.                                                                                                                                                                                                                                                                                                                                             |

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Aknowledgements

+ [Chris Wiegman's blog post about securing the docker socket](https://www.chriswiegman.com/2019/09/securing-the-docker-socket/) - @ChrisWiegman
+ [tecnativa/docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy) - @Tecnativa