# socket-proxy

## About
`socket-proxy` is a lightweight, secure-by-default unix socket proxy. Although it was created to proxy the docker socket to Traefik, it can be also used for other purposes.
It is heavily inspired by [tecnativa/docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy). 

The advantage over other solutions is the very slim container image ("FROM scratch") without any external dependencies (no OS, no packages, just the Go standard library).
It is designed with security in mind, so there are secure defaults, and there is an extra security layer (IP address-based access control).

Configuration of the allowlist is done for each http method separately using the Go regexp syntax. This allows fine-grained control over the allowed http methods.

## Getting Started

### Warning

You should know what you are doing. Accidentally exposing a Unix socket to the public internet by misconfiguration is a security nightmare.

### Installing

The container image is available on [Docker Hub: wollomatic/socket-proxy](https://hub.docker.com/r/wollomatic/socket-proxy).

### Allowing access

Because of the secure-by-default design, you need to explicitly allow every access.

This is meant to be an additional layer of security. It is not a replacement for other security measures, such as firewalls, network segmentation, etc. Do not expose socket-proxy to a public network.

#### Setting up the TCP listener

Socket-proxy listens per default only on `127.0.0.1`. Depending what you need, you may want to set another listener address with the `-listenip` parameter.

#### Setting up the IP address allowlist

Per default, only `127.0.0.1/32` ist allowed to connect to socket-proxy. Depending on your needs, you may want to set another allowlist with the `-allowfrom` parameter.

#### Setting up the allowlist for requests

You must set up regular expressions for each HTTP method the client application needs access to.

The name of a parameter should be "-allow", followed by the HTTP method name (for example, `-allowGET`). If that parameter is set and the incoming request matches the method and path matching the regexp, the request will be allowed. If it is not set, then the corresponding HTTP method will not be allowed.

Use Go's regexp syntax to create the patterns for these parameters. To avoid insecure configurations, the characters ^ at the beginning of the string and $ at the end of the string are automatically added. Note: invalid regexp results in program termination.

Examples:
+ `'-allowGET=/v1\..{1,2}/(version|containers/.*|events.*)'` could be used for allowing access to the docker socket for Traefik v2.
+ `'-allowHEAD=.*` allows all HEAD requests.

For more information, refer to the [Go regexp documentation](https://golang.org/pkg/regexp/syntax/).

A good online regexp tester is [regex101.com](https://regex101.com/).

To determine which HTTP requests your client application uses, you could switch socket-proxy to debug log level and look at the log output while allowing all requests in a secure environment.

### Container health check

Health checks are disables by default. As the socket-proxy container may not be exposed to a public network, there is a separate health check binary included in the container image. To activate the health check, the `-allowhealthcheck` parameter must be set. Then, a health check is possible for example with the following docker-compose snippet:

``` compose.yaml
# [...]
    healthcheck:
      test: ["CMD", "./healthcheck"]
      interval: 10s
      timeout: 5s
      retries: 2
# [...]
```


### Example for proxying the docker socket to Traefik

You need to know how to install Traefik in this environment. See [wollomatic/traefik2-hardened](https://github.com/wollomatic/traefik2-hardened) for an example (that repo still uses tecnativa's socket proxy).

The image can be deployed with docker compose:

``` compose.yaml
services:
  dockerproxy:
    image: wollomatic/socket-proxy:<<version>> # choose most recent image
    restart: unless-stopped
    user: "65534:<<your docker group id>>"
    mem_limit: 64M
    read_only: true
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges
    command:
      - -loglevel=DEBUG
      - -allowfrom=0.0.0.0/0 # allow all IPv4 addresses (know what you are doing!)
      - '-allowGET=/v1\..{1,2}/(version|containers/.*|events.*)'
      - watchdoginterval=3600 # check once per hour for socket availability
      - shutdowngracetime=5 # wait 5 seconds before shutting down
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    networks:
      - docker-proxynet    # NEVER EVER expose this to the public internet!
                           # this is a private network only for traefik and socket-proxy
                           # it is not the same as the traefik-servicenet

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

| Parameter           | Default Value          | Description                                                                                                                                                                                                                                                                                                                                                                                                                                          |
|---------------------|------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `-allowfrom`        | `127.0.0.1/32`         | Specifies the IP addresses of the clients allowed to connect to the proxy. The default value is `127.0.0.1/32`, which means only localhost is allowed. This default configuration may not be useful in most cases, but it is because of a secure-by-default design. To allow all IPv4 addresses, set `-allowfrom=0.0.0.0/0`. Please remember that socket-proxy should never be exposed to a public network, regardless of this extra security layer. |
| `-allowhealthcheck` | (not set)              | If set, it allows the included health check binary to check the socket connection via TCP port 55555 (socket-proxy then listens on `127.0.0.1:55555/health`)                                                                                                                                                                                                                                                                                         |
| `-listenip`         | `127.0.0.1`            | Specifies the IP address the server will bind on. Default is only the internal network.                                                                                                                                                                                                                                                                                                                                                              |
| `-logjson`          | (not set)              | If set, it enables logging in JSON format. If unset, docker-proxy logs in plain text format.                                                                                                                                                                                                                                                                                                                                                         |
| `-loglevel`         | `INFO`                 | Sets the log level. Accepted values are: `DEBUG`, `INFO`, `WARN`, `ERROR`.                                                                                                                                                                                                                                                                                                                                                                           |
| `-proxyport`        | `2375`                 | Defines the TCP port the proxy listens to.                                                                                                                                                                                                                                                                                                                                                                                                           |
| `-shutdowngracetime`| `10`                   | Defines the time in seconds to wait before forcing the shutdown after sigtern or sigint (socket-proxy first tries to graceful shut down the TCP server)                                                                                                                                                                                                                                                                                              |
| `-socketpath`       | `/var/run/docker.sock` | Specifies the UNIX socket path to connect to. By default, it connects to the Docker daemon socket.                                                                                                                                                                                                                                                                                                                                                   |
| `-stoponwatchdog`   | (not set)              | If set, socket-proxy will be stopped if the watchdog detects that the unix socket is not available.                                                                                                                                                                                                                                                                                                                                                  |
| `-watchdoginterval` | `0`                    | Check for socket availabibity every x seconds (disable checks, if not set or value is 0)                                                                                                                                                                                                                                                                                                                                                             |

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Aknowledgements

+ [Chris Wiegman: Protecting Your Docker Socket With Traefik 2](https://chriswiegman.com/2019/11/protecting-your-docker-socket-with-traefik-2/) [@ChrisWiegman](https://github.com/ChrisWiegman)
+ [tecnativa/docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy)