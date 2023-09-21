package main

import (
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
)

// handleHttpRequest checks if the request is allowed and sends it to the proxy.
// Otherwise, it returns a 405 Method Not Allowed error.
// In case of an error, it returns a 500 Internal Server Error.
func handleHttpRequest(w http.ResponseWriter, r *http.Request) {

	// check if the client's IP is allowed to access
	allowedIP, err := isAllowedIP(r.RemoteAddr)
	if err != nil {
		slog.Error("invalid RemoteAddr format", "reason", err, "method", r.Method, "URL", r.URL, "client", r.RemoteAddr)
		sendHTTPError(w, http.StatusInternalServerError)
		return
	}
	if !allowedIP {
		slog.Warn("blocked request", "reason", "forbidden IP", "method", r.Method, "URL", r.URL, "client", r.RemoteAddr)
		sendHTTPError(w, http.StatusForbidden)
		return
	}

	// iterate over the list of http methods and check if the request is allowed
	for _, allowed := range mr {
		// stop if the method does not match or the method is not allowed (no compiled regex)
		if (allowed.method != r.Method) || (allowed.regexCompiled == nil) {
			continue
		}
		// check if the request URL path matches the allowed regex
		if allowed.regexCompiled.MatchString(r.URL.Path) {
			slog.Debug("allowed request", "method", r.Method, "URL", r.URL, "client", r.RemoteAddr)
			socketProxy.ServeHTTP(w, r) // proxy the request
			return
		}
	}

	// at this point no allowed method/path was found, so block the request
	slog.Warn("blocked request", "reason", "no allowed method/path matched", "method", r.Method, "URL", r.URL, "client", r.RemoteAddr)
	sendHTTPError(w, http.StatusForbidden)
}

// sendHTTPError sends a HTTP error with the given status code.
func sendHTTPError(w http.ResponseWriter, status int) {
	http.Error(w, http.StatusText(status), status)
}

// isAllowedIP checks if the given remote address is allowed to connect to the proxy.
// The IP address is extracted from a RemoteAddr string (the part before the colon).
func isAllowedIP(remoteAddr string) (bool, error) {
	// extract IP address from remoteAddr
	var ipStr string
	index := strings.Index(remoteAddr, ":")
	if index > -1 {
		ipStr = remoteAddr[:index]
	} else {
		return false, errors.New("colon missing")
	}
	// parse IP address
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false, errors.New("IP parse error")
	}
	// check if IP address is in allowed network
	if allowedNetwork.Contains(ip) {
		return true, nil // allowed, no error
	}
	return false, nil // not allowed, no error
}
