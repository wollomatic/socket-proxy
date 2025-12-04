package client

/*
This was modified from:
https://github.com/moby/moby/blob/v28.5.1/client/request.go
*/

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/wollomatic/socket-proxy/internal/docker/api/types"
	"github.com/wollomatic/socket-proxy/internal/docker/api/types/versions"
)

// get sends an http request to the docker API using the method GET with a specific Go context.
func (cli *Client) get(ctx context.Context, path string, query url.Values, headers http.Header) (*http.Response, error) {
	return cli.sendRequest(ctx, http.MethodGet, path, query, nil, headers)
}

func (cli *Client) buildRequest(ctx context.Context, method, path string, body io.Reader, headers http.Header) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, path, body)
	if err != nil {
		return nil, err
	}
	req = cli.addHeaders(req, headers)
	req.URL.Scheme = cli.scheme
	req.URL.Host = cli.addr

	if cli.proto == "unix" {
		// Override host header for non-tcp connections.
		req.Host = DummyHost
	}

	if body != nil && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "text/plain")
	}
	return req, nil
}

func (cli *Client) sendRequest(ctx context.Context, method, path string, query url.Values, body io.Reader, headers http.Header) (*http.Response, error) {
	req, err := cli.buildRequest(ctx, method, cli.getAPIPath(ctx, path, query), body, headers)
	if err != nil {
		return nil, err
	}

	resp, err := cli.doRequest(req)
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return nil, err
	case err == nil:
		return resp, cli.checkResponseErr(resp)
	default:
		return resp, err
	}
}

func (cli *Client) doRequest(req *http.Request) (*http.Response, error) {
	resp, err := cli.client.Do(req)
	if err != nil {
		// Don't decorate context sentinel errors; users may be comparing to
		// them directly.
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}

		var uErr *url.Error
		if errors.As(err, &uErr) {
			var nErr *net.OpError
			if errors.As(uErr.Err, &nErr) {
				if os.IsPermission(nErr.Err) {
					return nil, errConnectionFailed{fmt.Errorf("permission denied while trying to connect to the Docker daemon socket at %v: %v", cli.host, err)}
				}
			}
		}

		var nErr net.Error
		if errors.As(err, &nErr) {
			if nErr.Timeout() {
				return nil, connectionFailed(cli.host)
			}
			if strings.Contains(nErr.Error(), "connection refused") || strings.Contains(nErr.Error(), "dial unix") {
				return nil, connectionFailed(cli.host)
			}
		}

		return nil, errConnectionFailed{fmt.Errorf("error during connect: %v", err)}
	}

	return resp, nil
}

func (cli *Client) checkResponseErr(serverResp *http.Response) (retErr error) {
	if serverResp == nil {
		return nil
	}
	if serverResp.StatusCode >= http.StatusOK && serverResp.StatusCode < http.StatusBadRequest {
		return nil
	}
	defer func() {
		if retErr != nil {
			retErr = fmt.Errorf("HTTP error %d: %v", serverResp.StatusCode, retErr)
		}
	}()

	var body []byte
	var err error
	var reqURL string
	if serverResp.Request != nil {
		reqURL = serverResp.Request.URL.String()
	}
	statusMsg := serverResp.Status
	if statusMsg == "" {
		statusMsg = http.StatusText(serverResp.StatusCode)
	}
	if serverResp.Body != nil {
		bodyMax := 1 * 1024 * 1024 // 1 MiB
		bodyR := &io.LimitedReader{
			R: serverResp.Body,
			N: int64(bodyMax),
		}
		body, err = io.ReadAll(bodyR)
		if err != nil {
			return err
		}
		if bodyR.N == 0 {
			if reqURL != "" {
				return fmt.Errorf("request returned %s with a message (> %d bytes) for API route and version %s, check if the server supports the requested API version", statusMsg, bodyMax, reqURL)
			}
			return fmt.Errorf("request returned %s with a message (> %d bytes); check if the server supports the requested API version", statusMsg, bodyMax)
		}
	}
	if len(body) == 0 {
		if reqURL != "" {
			return fmt.Errorf("request returned %s for API route and version %s, check if the server supports the requested API version", statusMsg, reqURL)
		}
		return fmt.Errorf("request returned %s; check if the server supports the requested API version", statusMsg)
	}

	var daemonErr error
	if serverResp.Header.Get("Content-Type") == "application/json" {
		var errorResponse types.ErrorResponse
		if err := json.Unmarshal(body, &errorResponse); err != nil {
			return fmt.Errorf("error reading JSON: %v", err)
		}
		if errorResponse.Message == "" {
			// Error-message is empty, which means that we successfully parsed the
			// JSON-response (no error produced), but it didn't contain an error
			// message. This could either be because the response was empty, or
			// the response was valid JSON, but not with the expected schema
			// ([types.ErrorResponse]).
			//
			// We cannot use "strict" JSON handling (json.NewDecoder with DisallowUnknownFields)
			// due to the API using an open schema (we must anticipate fields
			// being added to [types.ErrorResponse] in the future, and not
			// reject those responses.
			//
			// For these cases, we construct an error with the status-code
			// returned, but we could consider returning (a truncated version
			// of) the actual response as-is.

			daemonErr = fmt.Errorf(`API returned a %d (%s) but provided no error-message`,
				serverResp.StatusCode,
				http.StatusText(serverResp.StatusCode),
			)
		} else {
			daemonErr = errors.New(strings.TrimSpace(errorResponse.Message))
		}
	} else {
		// Fall back to returning the response as-is for API versions < 1.24
		// that didn't support JSON error responses, and for situations
		// where a plain text error is returned. This branch may also catch
		// situations where a proxy is involved, returning a HTML response.
		daemonErr = errors.New(strings.TrimSpace(string(body)))
	}
	return fmt.Errorf("error response from daemon: %v", daemonErr)
}

func (cli *Client) addHeaders(req *http.Request, headers http.Header) *http.Request {
	// Add CLI Config's HTTP Headers BEFORE we set the Docker headers
	// then the user can't change OUR headers
	for k, v := range cli.customHTTPHeaders {
		if versions.LessThan(cli.version, "1.25") && http.CanonicalHeaderKey(k) == "User-Agent" {
			continue
		}
		req.Header.Set(k, v)
	}

	for k, v := range headers {
		req.Header[http.CanonicalHeaderKey(k)] = v
	}

	if cli.userAgent != nil {
		if *cli.userAgent == "" {
			req.Header.Del("User-Agent")
		} else {
			req.Header.Set("User-Agent", *cli.userAgent)
		}
	}
	return req
}

func ensureReaderClosed(response *http.Response) {
	if response != nil && response.Body != nil {
		// Drain up to 512 bytes and close the body to let the Transport reuse the connection
		// see https://github.com/google/go-github/pull/317/files#r57536827

		_, _ = io.CopyN(io.Discard, response.Body, 512)
		_ = response.Body.Close()
	}
}
