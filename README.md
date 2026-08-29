# socket-proxy

## Latest image
- `wollomatic/socket-proxy:1.13.1` / `ghcr.io/wollomatic/socket-proxy:1.13.1`
- `wollomatic/socket-proxy:1` / `ghcr.io/wollomatic/socket-proxy:1`

> [!IMPORTANT]
> ## Usage with Traefik >= 2.11.31 / >= 3.6.1
> [Due to a change in how Traefik retrieves the Docker API version](https://github.com/traefik/traefik/pull/12256), the Socket-proxy configuration for Traefik must be updated to allow `HEAD` requests to `/_ping`:
>
>      - '-allowHEAD=/_ping'
>
> Otherwise, Traefik would fall back to API version 1.51, which would break the Docker provider on older Docker versions.

## About
Socket-proxy is a lightweight, secure-by-default Unix socket proxy. It was originally created to proxy the Docker socket to Traefik and found lots of other purposes since.
It is heavily inspired by [tecnativa/docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy).

As an additional benefit, socket-proxy can be used to examine the API calls of the client application.

The advantage over other solutions is the very slim container image (from-scratch-image) without any external dependencies (no OS, no packages, just the Go standard library).
It is designed with security in mind, so there are secure defaults and an additional security layer (IP address-based access control) compared to most other solutions.

The allowlist is configured for each HTTP method separately using the Go regexp syntax, allowing fine-grained control over the allowed API calls. In bridge network mode, each container that uses socket-proxy can be configured with its own allowlist using Docker labels.

The source code is available on the [wollomatic/socket-proxy GitHub repository](https://github.com/wollomatic/socket-proxy)

## Getting Started

Some examples can be found in this repository's [wiki](https://github.com/wollomatic/socket-proxy/wiki) and the [`examples` directory](https://github.com/wollomatic/socket-proxy/tree/main/examples/docker-compose).

> [!WARNING]
> You should know what you are doing. Never expose socket-proxy to a public network. It is meant to be used in a secure environment only.

### Installing

The container image is available on [Docker Hub (wollomatic/socket-proxy)](https://hub.docker.com/r/wollomatic/socket-proxy) 
and on the [GitHub Container Registry (ghcr.io/wollomatic/socket-proxy)](https://github.com/wollomatic/socket-proxy/pkgs/container/socket-proxy).

To pin one specific version, use the version tag (for example, `wollomatic/socket-proxy:1.13.0` or `ghcr.io/wollomatic/socket-proxy:1.13.0`).
To always use the most recent version, use the `1` tag (`wollomatic/socket-proxy:1` or `ghcr.io/wollomatic/socket-proxy:1`). This tag will be valid as long as there is no breaking change in the deployment.

There may be an additional docker image with the `testing`-tag. This image is only for testing. Likely, documentation for the `testing` image could only be found in the GitHub commit messages. It is not recommended to use the `testing` image in production.

Every socket-proxy release image is signed with Cosign. The public key is available on [GitHub: wollomatic/socket-proxy/main/cosign.pub](https://raw.githubusercontent.com/wollomatic/socket-proxy/main/cosign.pub) and [https://wollomatic.de/socket-proxy/cosign.pub](https://wollomatic.de/socket-proxy/cosign.pub). For more information, please refer to the [Security Policy](https://github.com/wollomatic/socket-proxy/blob/main/SECURITY.md).
As of version 1.6, all multi-arch images are signed.

### Migrating from other Docker socket proxies

> [!TIP]
> If you are coming from [tecnativa's docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy) or [linuxserver's docker-socket-proxy](https://github.com/linuxserver/docker-socket-proxy), configuring a regular expression allowlist may seem more complex at first.
>
> To simplify this migration, we provide a [Socket Proxy Configuration Converter](https://socket-proxy-configurator.wollomatic.dev/). The tool runs entirely in your browser and converts your existing docker-socket-proxy environment variable configurations into equivalent regular expression allowlists for [wollomatic's socket-proxy](https://github.com/wollomatic/socket-proxy).
>
> The converter's source code is available at [wollomatic/socket-proxy-configurator](https://github.com/wollomatic/socket-proxy-configurator).

### Allowing access

Socket-proxy uses a secure-by-default design: you need to allow every access explicitly.

This is an additional layer of security that does not replace other security measures such as firewalls, network segmentation, etc.

#### Setting up the TCP listener

Socket-proxy's default behavior is to listen on `127.0.0.1`.
It is possible to change the listening address using the `-listenip` parameter or the `SP_LISTENIP` environment variable.
When using socket-proxy as a Docker container, configure the TCP listener to port `0.0.0.0` (e.g. `-listenip=0.0.0.0`) and ensure that it is on the same network as the container using it.

**Do not expose socket-proxy to a public network!**

```yaml
services:
  socket-proxy:
    image: docker.io/wollomatic/socket-proxy:1
    container_name: socket-proxy # Uses a fixed name for networking
    command:
      - '-allowfrom=dozzle' # Only allow the dozzle container
      - '-listenip=0.0.0.0'
      - '-allowHEAD=/_ping' # Example allow rule
    expose:
      - 2375 # Exposes port 2375 only to containers on the docker-proxy-net network
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    networks:
      - docker-proxy-net # Uses a common network
      
  dozzle:
    image: docker.io/amir20/dozzle:latest
    container_name: dozzle # Uses a fixed name for allowfrom
    depends_on:
      - socket-proxy
    environment:
      DOZZLE_REMOTE_HOST: tcp://socket-proxy:2375 # Sets the TCP listener as a Docker socket
    networks:
      - docker-proxy-net # Uses a common network

# Example hardened network
networks:
  docker-proxy-net:
    driver: bridge
    internal: true
    attachable: false

```

A full compose example is available [on the repository's wiki](https://github.com/wollomatic/socket-proxy/wiki#dozzle).

#### Using a Unix socket instead of a TCP listener

Socket-proxy can proxy the Unix socket to a new Unix socket instead of a TCP listener.
This is enabled by setting the path of the proxied Unix socket with the `-proxysocketendpoint` parameter or the `SP_PROXYSOCKETENDPOINT` environment variable (e.g. `-proxysocketendpoint=/tmp/proxy.sock`).
The Unix socket endpoint's file permissions default to `0600` and can be modified with the `-proxysocketendpointfilemode` parameter or the `SP_PROXYSOCKETENDPOINTFILEMODE` environment variable.
Using this setting will also disable the TCP listener.
When using a Unix socket proxy in a Docker environment, the socket's path should be in a volume mounted by both socket-proxy and the container using it.

**Do not expose socket-proxy on a shared filesystem!**

```yaml
services:

  socket-proxy:
    image: docker.io/wollomatic/socket-proxy:1
    environment:
      SP_ALLOWFROM: traefik # Only allow the traefik container
      SP_ALLOW_HEAD: /_ping # Example allow rule
      SP_PROXYSOCKETENDPOINT: /socket/proxy.sock # Creates the Unix socket in the /socket-vol volume
      SP_PROXYSOCKETENDPOINTFILEMODE: 0600
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - socket-vol:/socket-vol/ # Mounts a common volume
    network_mode: none

  traefik:
    image: docker.io/traefik:v3
    container_name: traefik # Uses a fixed name for allowfrom
    depends_on:
      - socket-proxy
    volumes:
      - socket-vol/proxy.sock:/var/run/docker.sock:ro # Mounts the proxied Unix socket as a Docker socket

# Example hardened volume
volumes:
  socket-vol:
    driver: local
    driver_opts:
      type: tmpfs
      device: tmpfs
      o: size=1k,uid=65530,gid=0,mode=0700,noexec
```

A full compose example is available [on the repository's wiki](https://github.com/wollomatic/socket-proxy/wiki#using-socket-instead-of-tcp-example-with-traefik).

> [!NOTE]
> Prior to version 1.10.0, socket-proxy was setting the Unix socket's default file permissions to `0400` instead of `0600`.

#### Setting up the IP address or hostname allowlist

Per default, only `127.0.0.1/32` is allowed to connect to socket-proxy. You may want to set another allowlist with the `-allowfrom` parameter, depending on your needs.

Alternatively, not only IP networks but also hostnames can be configured. So it is now possible to explicitly allow one or more specific hostnames to connect to the proxy, for example, `-allowfrom=traefik`, or `-allowfrom=traefik,dozzle`.

Using the hostname is an easy-to-configure way to have more security. Access to the socket proxy will not even be permitted from the host system.

#### Setting up the allowlist for requests

You must set up regular expressions for each HTTP method the client application needs access to.

The name of a parameter should be "-allow", followed by the HTTP method name (for example, `-allowGET`). The request will be allowed if that parameter is set and the incoming request matches the method and path matching the regexp. If unset, the corresponding HTTP method is disallowed.

It is also possible to configure the allowlist via environment variables. The variables are called "SP_ALLOW_", followed by the HTTP method (for example, `SP_ALLOW_GET`).

If both command-line parameter and environment variable are configured for a particular HTTP method, the environment variable is ignored.

Use Go's regexp syntax to create the patterns for these parameters. To avoid insecure configurations, `^` and `$` are added automatically to the start and end of the pattern. Note: invalid regexp results in program termination.

| Examples                                         | Command-line parameters                                      | Environment variables                                             | Docker labels                                                             |
| ------------------------------------------------ | ------------------------------------------------------------ | ----------------------------------------------------------------- | ------------------------------------------------------------------------- |
| Allow access to the docker socket for Traefik v2 | `'-allowGET=/v1\..{1,2}/(version\|containers/.*\|events.*)'` | `'SP_ALLOW_GET="/v1\..{1,2}/(version\|containers/.*\|events.*)"'` | `'socket-proxy.allow.get=/v1\..{1,2}/(version\|containers/.*\|events.*)'` |
| Allow all `HEAD` requests                        | `'-allowHEAD=.*'`                                            | `'SP_ALLOW_HEAD=".*"'`                                            | `'socket-proxy.allow.head=".*"'`                                          |
| Support for multiple "allow `GET`" entries       | `'-allowGET=/version -allowGET=/_ping'`                      | `'SP_ALLOW_GET="/version" SP_ALLOW_GET_2="/_ping"'`               | `'socket-proxy.allow.get=/version socket-proxy.allow.get=/_ping'`         |

For more information, refer to the [Go regexp documentation](https://golang.org/pkg/regexp/syntax/).

An excellent online regexp tester is [regex101.com](https://regex101.com/).

To determine which HTTP requests your client application uses, you could switch socket-proxy to debug log level and look at the log output while allowing all requests in a secure environment.

> [!NOTE]
> Starting with version 1.12.0, socket-proxy supports using multiple -allow* entries in parameters, environment variables, and Docker labels.

#### Setting up bind mount restrictions

By default, socket-proxy does not restrict bind mounts. If you want to add an additional layer of security by restricting which directories can be used as bind mount sources, you can use the `-allowbindmountfrom` parameter or the `SP_ALLOWBINDMOUNTFROM` environment variable.

When configured, socket-proxy inspects supported Docker API requests and only allows direct host bind sources from the specified directories or their subdirectories. Each directory must start with `/`. Multiple directories can be specified separated by commas.

For example:
+ `-allowbindmountfrom=/home,/var/log` allows bind mounts from `/home`, `/var/log`, and any subdirectories like `/home/user/data` or `/var/log/app`
+ `SP_ALLOWBINDMOUNTFROM="/app/data,/tmp"` allows bind mounts from `/app/data` and `/tmp` directories

Bind mount restrictions are applied to versioned and unversioned container, Swarm service, and volume-create endpoints. They cover legacy bind syntax (`-v /host/path:/container/path`), modern bind mounts, and local volume-driver options that use `o=bind` or `o=rbind`. `VolumesFrom` is rejected while this restriction is active because the referenced container's mount sources are not present in the request being checked. Other volume types, including ordinary named volumes, NFS, CIFS, block-device volumes, and custom volume drivers, are not treated as host bind mounts.

> [!WARNING]
> This option is a request filter, not a sandbox for otherwise untrusted Docker API clients. It cannot resolve host-side symbolic links, inspect a named volume that was created outside the filtered `/volumes/create` endpoint, or determine what a custom volume plugin exposes. It also does not restrict other host-access mechanisms such as privileged containers, host namespaces, added capabilities, or device mappings. Do not grant container- or service-creation endpoints to clients that must not control the Docker host; use the HTTP method/path allowlists, network isolation, and Docker authorization controls as additional boundaries.

#### Setting up per-container allowlists

Allowlists for both requests and bind mount restrictions can be specified for particular containers. To do this:

1. Set the `-proxycontainername` parameter or the `SP_PROXYCONTAINERNAME` environment variable to the name of the socket-proxy container.
2. Make sure that each container that will use the socket-proxy is in a Docker network that the socket-proxy container is also in.
3. Use the same regex syntax for request allowlists and for bind mount restrictions that were discussed earlier, but for labels on each container that will use the socket proxy. Each label name has the prefix `<dockerlabelprefix>.allow.`; by default this is `socket-proxy.allow.`, with `socket-proxy.allow.bindmountfrom` for bind mount restrictions. Set `-dockerlabelprefix` or `SP_DOCKERLABELPREFIX` when multiple socket proxies share a Docker daemon. For example, `-dockerlabelprefix=traefik-socket-proxy` uses labels beginning with `traefik-socket-proxy.allow.`.

```yaml
services:
  traefik:
    # [...] see github.com/wollomatic/traefik-hardened for a full example
    networks:
      - traefik-servicenet # this is the common traefik network
      - docker-proxynet    # this should be only restricted to traefik and socket-proxy
    labels:
      - 'socket-proxy.allow.get=.*' # allow all GET requests to socket-proxy
      - 'socket-proxy.allow.head=/version' # HEAD `/version` requests to socket-proxy
      - 'socket-proxy.allow.head.1=/exec' # another HEAD `exec` requests to socket-proxy
```

When this is used, it is not necessary to specify the container in `-allowfrom` as the presence of the allowlist labels will grant corresponding access.

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

In certain circumstances (e.g. after a Docker engine update), the socket connection may break, causing the client application to fail. To prevent this, the socket-proxy can be configured to check the socket availability at regular intervals. If the Docker socket is not available, the socket-proxy stops itself so the container orchestrator can restart it. This feature is disabled by default. To enable it, set the `-watchdoginterval` parameter (or `SP_WATCHDOGINTERVAL` environment variable) to the desired interval in seconds and set the `-stoponwatchdog` parameter (or `SP_STOPONWATCHDOG=true`). If `-stoponwatchdog` is not set, the watchdog will only log an error message and continue to run (the problem would still exist in that case).

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

To log the API calls of the client application, set the log level (`-loglevel` or `SP_LOGLEVEL`) to `DEBUG` and allow all requests. Then, you can examine the log output to determine which requests the client application makes. Allowing all requests can be done by setting the following parameters:
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

### All parameters and environment variables

socket-proxy can be configured via command-line parameters or environment variables. If both are set, the command-line parameters take priority and the environment variables are ignored.

| Parameter                      | Environment Variable             | Default Value          | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
|--------------------------------|----------------------------------|------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `-allowfrom`                   | `SP_ALLOWFROM`                   | `127.0.0.1/32`         | Specifies the IP addresses or hostnames (comma-separated) of the clients or the hostname of one specific client allowed to connect to the proxy. The default value is `127.0.0.1/32`, which means only localhost is allowed. This default configuration may not be useful in most cases, but it is because of a secure-by-default design. To allow all IPv4 addresses, set `-allowfrom=0.0.0.0/0`. Alternatively, hostnames can be set, for example `-allowfrom=traefik`, or `-allowfrom=traefik,dozzle`. Please remember that socket-proxy should never be exposed to a public network, regardless of this extra security layer. |
| `-allowbindmountfrom`          | `SP_ALLOWBINDMOUNTFROM`          | (not set)              | Restricts direct host bind sources found in supported Docker API requests to the specified directories and their subdirectories. It covers legacy and modern binds plus local volume-driver `bind`/`rbind` options, and rejects `VolumesFrom`. It is a request filter with the limitations documented above, not a sandbox for untrusted Docker API clients. Each comma-separated directory must start with `/`.                                                                                                                                                                                                                         |
| `-allowhealthcheck`            | `SP_ALLOWHEALTHCHECK`            | (not set/false)        | If set, it allows the included health check binary to check the socket connection via TCP port 55555 (socket-proxy then listens on `127.0.0.1:55555/health`)                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| `-listenip`                    | `SP_LISTENIP`                    | `127.0.0.1`            | Specifies the IP address the server will bind on. Default is only the internal network.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `-logjson`                     | `SP_LOGJSON`                     | (not set/false)        | If set, it enables logging in JSON format. If unset, socket-proxy logs in plain text format.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| `-loglevel`                    | `SP_LOGLEVEL`                    | `INFO`                 | Sets the log level. Accepted values are: `DEBUG`, `INFO`, `WARN`, `ERROR`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `-proxyport`                   | `SP_PROXYPORT`                   | `2375`                 | Defines the TCP port the proxy listens to.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `-shutdowngracetime`           | `SP_SHUTDOWNGRACETIME`           | `10`                   | Defines the time in seconds to wait before forcing the shutdown after SIGTERM or SIGINT (socket-proxy first tries to gracefully shut down the TCP server)                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `-socketpath`                  | `SP_SOCKETPATH`                  | `/var/run/docker.sock` | Specifies the UNIX socket path to connect to. By default, it connects to the Docker daemon socket.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `-stoponwatchdog`              | `SP_STOPONWATCHDOG`              | (not set/false)        | If set, socket-proxy will be stopped if the watchdog detects that the unix socket is not available.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `-watchdoginterval`            | `SP_WATCHDOGINTERVAL`            | `0`                    | Check for socket availability every x seconds (disable checks, if not set or value is 0)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| `-proxysocketendpoint`         | `SP_PROXYSOCKETENDPOINT`         | (not set)              | Proxy to the given unix socket instead of a TCP port                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `-proxysocketendpointfilemode` | `SP_PROXYSOCKETENDPOINTFILEMODE` | `0600`                 | Explicitly set the file mode for the filtered unix socket endpoint (only useful with `-proxysocketendpoint`)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| `-dockerlabelprefix`           | `SP_DOCKERLABELPREFIX`           | `socket-proxy`         | Specifies the prefix before `.allow.` in Docker container labels used for per-container allowlists. It must contain only lowercase letters, digits, dots, and hyphens. For example, `-dockerlabelprefix=traefik-socket-proxy` recognizes `traefik-socket-proxy.allow.get`.                                                                                                                                                                                                                                                                                                                            |
| `-proxycontainername`          | `SP_PROXYCONTAINERNAME`          | (not set)              | Provides the name of the socket proxy container to enable per-container allowlists specified by Docker container labels (not available with `-proxysocketendpoint`)                                                                                                                                                                                                                                                                                                                                                                                                                                                               |

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

1.11 - add per-container allowlists specified by Docker container labels (thanks [@amanda-wee](https://github.com/amanda-wee))

1.12 - support use of allow* multiple times in env, flag and docker labels (thanks [@qianlongzt](https://github.com/qianlongzt))

1.13 - harden bind mount restrictions (thanks [@shotintoeternity]), improve Docker label handling, fix IPv6 healthcheck bug

## License

Parts of this project, specifically the file `cmd/socket-proxy/bindmount.go` and
the files in the `internal/docker` and `internal/go-connections` folders,
contain source code licensed under the Apache License 2.0. See the comments
in the applicable files for details.
The rest of the project is licensed under the MIT License – see the [LICENSE](LICENSE) file for details.

## Acknowledgements

+ [Chris Wiegman: Protecting Your Docker Socket With Traefik 2](https://chriswiegman.com/2019/11/protecting-your-docker-socket-with-traefik-2/) [@ChrisWiegman](https://github.com/ChrisWiegman)
+ [tecnativa/docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy)
+ [@justsomescripts](https://github.com/justsomescripts) fix parsing environment variable to configure unix socket

## Alternatives

+ [hectorm/cetusguard](https://github.com/hectorm/cetusguard)
+ [11notes/docker-socket-proxy](https://github.com/11notes/docker-socket-proxy)
