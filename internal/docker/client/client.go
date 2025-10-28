/*
Package client is a Go client for the Docker Engine API.

For more information about the Engine API, see the documentation:
https://docs.docker.com/reference/api/engine/

This was modified from:
https://github.com/moby/moby/blob/v28.5.1/client/client.go
*/
package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wollomatic/socket-proxy/internal/docker/api"
	"github.com/wollomatic/socket-proxy/internal/docker/api/types"
	"github.com/wollomatic/socket-proxy/internal/docker/api/types/versions"
	"github.com/wollomatic/socket-proxy/internal/go-connections/sockets"
)

// DefaultDockerHost defines default host
const DefaultDockerHost = "unix:///var/run/docker.sock"

// DummyHost is a hostname used for local communication.
const DummyHost = "api.moby.localhost"

// fallbackAPIVersion is the version to fallback to if API-version negotiation
// fails. This version is the highest version of the API before API-version
// negotiation was introduced. If negotiation fails (or no API version was
// included in the API response), we assume the API server uses the most
// recent version before negotiation was introduced.
const fallbackAPIVersion = "1.24"

// Client is the API client that performs all operations
// against a docker server.
type Client struct {
	// scheme sets the scheme for the client
	scheme string
	// host holds the server address to connect to
	host string
	// proto holds the client protocol i.e. unix.
	proto string
	// addr holds the client address.
	addr string
	// basePath holds the path to prepend to the requests.
	basePath string
	// client used to send and receive http requests.
	client *http.Client
	// version of the server to talk to.
	version string
	// userAgent is the User-Agent header to use for HTTP requests. It takes
	// precedence over User-Agent headers set in customHTTPHeaders, and other
	// header variables. When set to an empty string, the User-Agent header
	// is removed, and no header is sent.
	userAgent *string
	// custom HTTP headers configured by users.
	customHTTPHeaders map[string]string

	// negotiateVersion indicates if the client should automatically negotiate
	// the API version to use when making requests. API version negotiation is
	// performed on the first request, after which negotiated is set to "true"
	// so that subsequent requests do not re-negotiate.
	negotiateVersion bool

	// negotiated indicates that API version negotiation took place
	negotiated atomic.Bool

	// negotiateLock is used to single-flight the version negotiation process
	negotiateLock sync.Mutex

	// When the client transport is an *http.Transport (default) we need to do some extra things (like closing idle connections).
	// Store the original transport as the http.Client transport will be wrapped with tracing libs.
	baseTransport *http.Transport
}

// ErrRedirect is the error returned by checkRedirect when the request is non-GET.
var ErrRedirect = errors.New("unexpected redirect in response")

// CheckRedirect specifies the policy for dealing with redirect responses. It
// can be set on [http.Client.CheckRedirect] to prevent HTTP redirects for
// non-GET requests. It returns an [ErrRedirect] for non-GET request, otherwise
// returns a [http.ErrUseLastResponse], which is special-cased by http.Client
// to use the last response.
//
// Go 1.8 changed behavior for HTTP redirects (specifically 301, 307, and 308)
// in the client. The client (and by extension API client) can be made to send
// a request like "POST /containers//start" where what would normally be in the
// name section of the URL is empty. This triggers an HTTP 301 from the daemon.
//
// In go 1.8 this 301 is converted to a GET request, and ends up getting
// a 404 from the daemon. This behavior change manifests in the client in that
// before, the 301 was not followed and the client did not generate an error,
// but now results in a message like "Error response from daemon: page not found".
func CheckRedirect(_ *http.Request, via []*http.Request) error {
	if via[0].Method == http.MethodGet {
		return http.ErrUseLastResponse
	}
	return ErrRedirect
}

// NewClientWithOpts initializes a new API client with a default HTTPClient, and
// default API host and version. It also initializes the custom HTTP headers to
// add to each request.
func NewClientWithOpts(ops ...Opt) (*Client, error) {
	hostURL, err := ParseHostURL(DefaultDockerHost)
	if err != nil {
		return nil, err
	}

	client, err := defaultHTTPClient(hostURL)
	if err != nil {
		return nil, err
	}
	c := &Client{
		host:    DefaultDockerHost,
		version: api.DefaultVersion,
		client:  client,
		proto:   hostURL.Scheme,
		addr:    hostURL.Host,
		scheme:  "http",
	}

	for _, op := range ops {
		if err := op(c); err != nil {
			return nil, err
		}
	}

	if tr, ok := c.client.Transport.(*http.Transport); ok {
		// Store the base transport
		// This is used, as an example, to close idle connections when the client is closed
		c.baseTransport = tr
	}

	return c, nil
}

func defaultHTTPClient(hostURL *url.URL) (*http.Client, error) {
	transport := &http.Transport{}
	// Necessary to prevent long-lived processes using the
	// client from leaking connections due to idle connections
	// not being released.
	transport.MaxIdleConns = 6
	transport.IdleConnTimeout = 30 * time.Second
	err := sockets.ConfigureTransport(transport, hostURL.Scheme, hostURL.Host)
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Transport:     transport,
		CheckRedirect: CheckRedirect,
	}, nil
}

// Close the transport used by the client
func (cli *Client) Close() error {
	if cli.baseTransport != nil {
		cli.baseTransport.CloseIdleConnections()
		return nil
	}
	return nil
}

// checkVersion manually triggers API version negotiation (if configured).
// This allows for version-dependent code to use the same version as will
// be negotiated when making the actual requests, and for which cases
// we cannot do the negotiation lazily.
func (cli *Client) checkVersion(ctx context.Context) error {
	if cli.negotiateVersion && !cli.negotiated.Load() {
		// Ensure exclusive write access to version and negotiated fields
		cli.negotiateLock.Lock()
		defer cli.negotiateLock.Unlock()

		// May have been set during last execution of critical zone
		if cli.negotiated.Load() {
			return nil
		}

		ping, err := cli.Ping(ctx)
		if err != nil {
			return err
		}
		cli.negotiateAPIVersionPing(ping)
	}
	return nil
}

// getAPIPath returns the versioned request path to call the API.
// It appends the query parameters to the path if they are not empty.
func (cli *Client) getAPIPath(ctx context.Context, p string, query url.Values) string {
	var apiPath string
	_ = cli.checkVersion(ctx)
	if cli.version != "" {
		apiPath = path.Join(cli.basePath, "/v"+strings.TrimPrefix(cli.version, "v"), p)
	} else {
		apiPath = path.Join(cli.basePath, p)
	}
	return (&url.URL{Path: apiPath, RawQuery: query.Encode()}).String()
}

// negotiateAPIVersionPing queries the API and updates the version to match the
// API version from the ping response.
func (cli *Client) negotiateAPIVersionPing(pingResponse types.Ping) {
	// default to the latest version before versioning headers existed
	if pingResponse.APIVersion == "" {
		pingResponse.APIVersion = fallbackAPIVersion
	}

	// if the client is not initialized with a version, start with the latest supported version
	if cli.version == "" {
		cli.version = api.DefaultVersion
	}

	// if server version is lower than the client version, downgrade
	if versions.LessThan(pingResponse.APIVersion, cli.version) {
		cli.version = pingResponse.APIVersion
	}

	// Store the results, so that automatic API version negotiation (if enabled)
	// won't be performed on the next request.
	if cli.negotiateVersion {
		cli.negotiated.Store(true)
	}
}

// ParseHostURL parses a url string, validates the string is a host url, and
// returns the parsed URL
func ParseHostURL(host string) (*url.URL, error) {
	proto, addr, ok := strings.Cut(host, "://")
	if !ok || addr == "" {
		return nil, fmt.Errorf("unable to parse docker host `%s`", host)
	}

	var basePath string
	if proto == "tcp" {
		parsed, err := url.Parse("tcp://" + addr)
		if err != nil {
			return nil, err
		}
		addr = parsed.Host
		basePath = parsed.Path
	}
	return &url.URL{
		Scheme: proto,
		Host:   addr,
		Path:   basePath,
	}, nil
}
