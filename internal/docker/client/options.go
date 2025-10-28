package client

/*
This was modified from:
https://github.com/moby/moby/blob/v28.5.1/client/options.go
*/

import (
	"fmt"
	"net/http"

	"github.com/wollomatic/socket-proxy/internal/go-connections/sockets"
)

// Opt is a configuration option to initialize a [Client].
type Opt func(*Client) error

// WithHost overrides the client host with the specified one.
func WithHost(host string) Opt {
	return func(c *Client) error {
		hostURL, err := ParseHostURL(host)
		if err != nil {
			return err
		}
		c.host = host
		c.proto = hostURL.Scheme
		c.addr = hostURL.Host
		c.basePath = hostURL.Path
		if transport, ok := c.client.Transport.(*http.Transport); ok {
			return sockets.ConfigureTransport(transport, c.proto, c.addr)
		}
		return fmt.Errorf("cannot apply host to transport: %v", c.client.Transport)
	}
}

// WithAPIVersionNegotiation enables automatic API version negotiation for the client.
// With this option enabled, the client automatically negotiates the API version
// to use when making requests. API version negotiation is performed on the first
// request; subsequent requests do not re-negotiate.
func WithAPIVersionNegotiation() Opt {
	return func(c *Client) error {
		c.negotiateVersion = true
		return nil
	}
}
