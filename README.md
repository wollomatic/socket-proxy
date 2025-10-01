# socket-proxy

## Latest image
- `wollomatic/socket-proxy:1.10.0` / `ghcr.io/wollomatic/socket-proxy:1.10.0`
- `wollomatic/socket-proxy:1` / `ghcr.io/wollomatic/socket-proxy:1`

## About
`socket-proxy` is a lightweight, secure-by-default unix socket proxy. Although it was created to proxy the docker socket to Traefik, it can also be used for other purposes.
It is heavily inspired by [tecnativa/docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy).

As an additional benefit, socket-proxy can be used to examine the API calls of the client application.

The advantage over other solutions is the very slim container image (from-scratch-image) without any external dependencies (no OS, no packages, just the Go standard library).
It is designed with security in mind, so there are secure defaults and an additional security layer (IP address-based access control) compared to most other solutions.

The allowlist is configured for each HTTP method separately using the Go regexp syntax, allowing fine-grained control over the allowed HTTP methods.

The source code is available on [GitHub: wollomatic/socket-proxy](https://github.com/wollomatic/socket-proxy)

> [!NOTE]
> Starting with version 1.6.0, the socket-proxy container image is also available on GHCR.  

## Getting Started

Some examples can be found in the [wiki](https://github.com/wollomatic/socket-proxy/wiki) and in the `examples` directory of the repo.

### Warning

You should know what you are doing. Never expose socket-proxy to a public network. It is meant to be used in a secure environment only.

### Installing

The container image is available on [Docker Hub (wollomatic/socket-proxy)](https://hub.docker.com/r/wollomatic/socket-proxy) 
and on the [GitHub Container Registry (ghcr.io/wollomatic/socket-proxy)](https://github.com/wollomatic/socket-proxy/pkgs/container/socket-proxy).

To pin one specific version, use the version tag (for example, `wollomatic/socket-proxy:1.10.0` or `ghcr.io/wollomatic/socket-proxy:1.10.0`).
To always use the most recent version, use the `1` tag (`wollomatic/socket-proxy:1` or `ghcr.io/wollomatic/socket-proxy:1`). This tag will be valid as long as there is no breaking change in the deployment.

There may be an additional docker image with the `testing`-tag. This image is only for testing. Likely, documentation for the `testing` image could only be found in the GitHub commit messages. It is not recommended to use the `testing` image in production.

Every socket-proxy release image is signed with Cosign. The public key is available on [GitHub: wollomatic/socket-proxy/main/cosign.pub](https://raw.githubusercontent.com/wollomatic/socket-proxy/main/cosign.pub) and [https://wollomatic.de/socket-proxy/cosign.pub](https://wollomatic.de/socket-proxy/cosign.pub). For more information, please refer to the [Security Policy](https://github.com/wollomatic/socket-proxy/blob/main/SECURITY.md).
As of version 1.6, all multi-arch images are signed.

### Allowing access

Because of the secure-by-default design, you need to allow every access explicitly.

This is meant to be an additional layer of security. It does not replace other security measures, such as firewalls, network segmentation, etc. Do not expose socket-proxy to a public network.

#### Setting up the TCP listener

Socket-proxy listens per default only on `127.0.0.1`. Depending on what you need, you may want to set another listener address with the `-listenip` parameter. In almost every use case, `-listenip=0.0.0.0` will be the correct configuration when using socket-proxy in a docker image.

#### Using a unix socket instead of a TCP listener

If you want to proxy/filter the unix socket to a new unix socket instead to a TCP listener,
you need to set the `-proxysocketendpoint` parameter or the `SP_PROXYSOCKETENDPOINT` env variable to the socket path of the new unix socket.
This will also disable the TCP listener.

For example `-proxysocketendpoint=/tmp/filtered-socket.sock`

> [!NOTE]
> Versions prior to 1.10.0 of socket-proxy set the default file permissions of the Unix socket to 0400, instead of 0600 as stated in the documentation.

#### Setting up the IP address or hostname allowlist

Per default, only `127.0.0.1/32` is allowed to connect to socket-proxy. You may want to set another allowlist with the `-allowfrom` parameter, depending on your needs.

Alternatively, not only IP networks but also hostnames can be configured. So it is now possible to explicitly allow one or more specific hostnames to connect to the proxy, for example, `-allowfrom=traefik`, or `-allowfrom=traefik,dozzle`.

Using the hostname is an easy-to-configure way to have more security. Access to the socket proxy will not even be permitted from the host system.

#### Setting up the allowlist for requests

You must set up regular expressions for each HTTP method the client application needs access to.

The name of a parameter should be "-allow", followed by the HTTP method name (for example, `-allowGET`). The request will be allowed if that parameter is set and the incoming request matches the method and path matching the regexp. If it is not set, then the corresponding HTTP method will not be allowed.

It is also possible to configure the allowlist via environment variables. The variables are called "SP_ALLOW_", followed by the HTTP method (for example, `SP_ALLLOW_GET`).

If both commandline parameter and environment variable are configured for a particular HTTP method, the environment variable is ignored.

Use Go's regexp syntax to create the patterns for these parameters. To avoid insecure configurations, the characters ^ at the beginning and $ at the end of the string are automatically added. Note: invalid regexp results in program termination.

Examples (command line):
+ `'-allowGET=/v1\..{1,2}/(version|containers/.*|events.*)'` could be used for allowing access to the docker socket for Traefik v2.
+ `'-allowHEAD=.*` allows all HEAD requests.

Examples (env variables):
+ `'SP_ALLOW_GET="/v1\..{1,2}/(version|containers/.*|events.*)"'` could be used for allowing access to the docker socket for Traefik v2.
+ `'SP_ALLOW_HEAD=".*"` allows all HEAD requests.

For more information, refer to the [Go regexp documentation](https://golang.org/pkg/regexp/syntax/).

An excellent online regexp tester is [regex101.com](https://regex101.com/).

To determine which HTTP requests your client application uses, you could switch socket-proxy to debug log level and look at the log output while allowing all requests in a secure environment.

#### Setting up bind mount restrictions

By default, socket-proxy does not restrict bind mounts. If you want to add an additional layer of security by restricting which directories can be used as bind mount sources, you can use the `-allowbindmountfrom` parameter or the `SP_ALLOWBINDMOUNTFROM` environment variable.

When configured, only bind mounts from the specified directories or their subdirectories are allowed. Each directory must start with `/`. Multiple directories can be specified separated by commas.

For example:
+ `-allowbindmountfrom=/home,/var/log` allows bind mounts from `/home`, `/var/log`, and any subdirectories like `/home/user/data` or `/var/log/app`
+ `SP_ALLOWBINDMOUNTFROM="/app/data,/tmp"` allows bind mounts from `/app/data` and `/tmp` directories

Bind mount restrictions are applied to relevant Docker API endpoints and work with both legacy bind mount syntax (`-v /host/path:/container/path`) and modern mount syntax.

**Note**: This feature only restricts bind mounts. Other mount types (volumes, tmpfs, etc.) are not affected by this restriction.

### Container health check

Health checks are disabled by default. As the socket-proxy container may not be exposed to a public network, a separate health check binary is included in the container image. To activate the health check, the `-allowhealthcheck` parameter or the environment variable `SP_ALLOWHEALTHCHECK=true` must be set. Then, a health check is possible for example with the following docker-compose snippet:

``` compose.yaml
# [...]
    healthcheck:
      test: ["CMD", "./healthcheck"]
      interval: 10s
      timeout: 5s
      retries: 2
# [...]
```
### Socket watchdog

In certain circumstances (for example, after a Docker engine update), the socket connection may break, causing the client application to fail. To prevent this, the socket-proxy can be configured to check the socket availability at regular intervals. If the socket is not available, the socket-proxy will be stopped so the container orchestrator can restart it. This feature is disabled by default. To enable it, set the `-watchdoginterval` parameter (or `SP_WATCHDOGINTERVAL` env variable) to the desired interval in seconds and set the `-stoponwatchdog` parameter (or `SP_STOPONWATCHDOG=true`). If `-stoponwatchdog`is not set, the watchdog will only log an error message and continue to run (the problem would still exist in that case).

### Example for proxying the docker socket to Traefik

You need to know how to install Traefik in this environment. See [wollomatic/traefik2-hardened](https://github.com/wollomatic/traefik2-hardened) for an example.

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
      - '-loglevel=info'
      - '-listenip=0.0.0.0'
      - '-allowfrom=traefik' # allow only hostname "traefik" to connect
      - '-allowGET=/v1\..{1,2}/(version|containers/.*|events.*)'
      - '-allowbindmountfrom=/var/log,/tmp' # restrict bind mounts to specific directories
      - '-watchdoginterval=3600' # check once per hour for socket availability
      - '-stoponwatchdog' # halt program on error and let compose restart it
      - '-shutdowngracetime=5' # wait 5 seconds before shutting down
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    networks:
      - docker-proxynet    # NEVER EVER expose this to the public internet!
                           # this is a private network only for traefik and socket-proxy
                           # it is not the same as the traefik-servicenet

  traefik:
    # [...] see github.com/wollomatic/traefik-hardened for a full example
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

### Examining the API calls of the client application

To log the API calls of the client application, set the log level to `DEBUG` and allow all requests. Then, you can examine the log output to determine which requests the client application makes. Allowing all requests can be done by setting the following parameters:
```
- '-loglevel=debug'
- '-allowGET=.*'
- '-allowHEAD=.*'
- '-allowPOST=.*'
- '-allowPUT=.*'
- '-allowPATCH=.*'
- '-allowDELETE=.*'
- '-allowCONNECT=.*'
- '-allowTRACE=.*'
- '-allowOPTIONS=.*'
```

### all parameters and environment variables

socket-proxy can be configured via command line parameters or via environment variables. If both command line parameters and environment variables are set, the environment variable will be ignored.

| Parameter                      | Environment Variable             | Default Value          | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
|--------------------------------|----------------------------------|------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `-allowfrom`                   | `SP_ALLOWFROM`                   | `127.0.0.1/32`         | Specifies the IP addresses or hostnames (comma-separated) of the clients or the hostname of one specific client allowed to connect to the proxy. The default value is `127.0.0.1/32`, which means only localhost is allowed. This default configuration may not be useful in most cases, but it is because of a secure-by-default design. To allow all IPv4 addresses, set `-allowfrom=0.0.0.0/0`. Alternatively, hostnames can be set, for example `-allowfrom=traefik`, or `-allowfrom=traefik,dozzle`. Please remember that socket-proxy should never be exposed to a public network, regardless of this extra security layer. |
| `-allowbindmountfrom`          | `SP_ALLOWBINDMOUNTFROM`          | (not set)              | Specifies the directories (comma-separated) that are allowed as bind mount sources. If not set, no bind mount restrictions are applied. When set, only bind mounts from the specified directories or their subdirectories are allowed. Each directory must start with `/`. For example, `-allowbindmountfrom=/home,/var/log` allows bind mounts from `/home`, `/var/log`, and any subdirectories.                                                                                                                                                                                                                                 |
| `-allowhealthcheck`            | `SP_ALLOWHEALTHCHECK`            | (not set/false)        | If set, it allows the included health check binary to check the socket connection via TCP port 55555 (socket-proxy then listens on `127.0.0.1:55555/health`)                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| `-listenip`                    | `SP_LISTENIP`                    | `127.0.0.1`            | Specifies the IP address the server will bind on. Default is only the internal network.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `-logjson`                     | `SP_LOGJSON`                     | (not set/false)        | If set, it enables logging in JSON format. If unset, docker-proxy logs in plain text format.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| `-loglevel`                    | `SP_LOGLEVEL`                    | `INFO`                 | Sets the log level. Accepted values are: `DEBUG`, `INFO`, `WARN`, `ERROR`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `-proxyport`                   | `SP_PROXYPORT`                   | `2375`                 | Defines the TCP port the proxy listens to.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `-shutdowngracetime`           | `SP_SHUTDOWNGRACETIME`           | `10`                   | Defines the time in seconds to wait before forcing the shutdown after sigtern or sigint (socket-proxy first tries to graceful shut down the TCP server)                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `-socketpath`                  | `SP_SOCKETPATH`                  | `/var/run/docker.sock` | Specifies the UNIX socket path to connect to. By default, it connects to the Docker daemon socket.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `-stoponwatchdog`              | `SP_STOPONWATCHDOG`              | (not set/false)        | If set, socket-proxy will be stopped if the watchdog detects that the unix socket is not available.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `-watchdoginterval`            | `SP_WATCHDOGINTERVAL`            | `0`                    | Check for socket availability every x seconds (disable checks, if not set or value is 0)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| `-proxysocketendpoint`         | `SP_PROXYSOCKETENDPOINT`         | (not set)              | Proxy to the given unix socket instead of a TCP port                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `-proxysocketendpointfilemode` | `SP_PROXYSOCKETENDPOINTFILEMODE` | `0600`                 | Explicitly set the file mode for the filtered unix socket endpoint (only useful with `-proxysocketendpoint`)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |

### Changelog

1.0 - initial release

1.1 - add hostname support for `-allowfrom` parameter

1.2 - reformat logging of allowlist on program start

1.3 - allow multiple, comma-separated hostnames in `-allowfrom` parameter (thanks [@ildyria](https://github.com/ildyria))

1.4 - allow configuration from env variables

1.5 - allow unix socket as proxied/filtered endpoint

1.6 - Cosign: sign a multi-arch container image AND all referenced, discrete images. Image is also available on GHCR.

1.7 - also allow comma-separated CIDRs in `-allowfrom` (not only hostnames as in versions > 1.3)

1.8 - add optional bind mount restrictions (thanks [@powerman](https://github.com/powerman), [@C4tWithShell](https://github.com/C4tWithShell))

1.9 - add IPv6 support to `-listenip` (thanks [@op3](https://github.com/op3))

1.10 - fix socket file mode (thanks [@amanda-wee](https://github.com/amanda-wee)), optimize build actions (thanks [@reneleonhardt](https://github.com/reneleonhardt))

## License
This project is licensed under the MIT License – see the [LICENSE](LICENSE) file for details.

Parts of the file `cmd/internal/bindmount.go` are licensed under the Apache 2.0 License.  
See the comments in this file and the LICENSE file for more information.

## Aknowledgements

+ [Chris Wiegman: Protecting Your Docker Socket With Traefik 2](https://chriswiegman.com/2019/11/protecting-your-docker-socket-with-traefik-2/) [@ChrisWiegman](https://github.com/ChrisWiegman)
+ [tecnativa/docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy)
+ [@justsomescripts](https://github.com/justsomescripts) fix parsing environment variable to configure unix socket

## Alternatives

+ [hectorm/cetusguard](https://github.com/hectorm/cetusguard)
+ [11notes/docker-socket-proxy](https://github.com/11notes/docker-socket-proxy)