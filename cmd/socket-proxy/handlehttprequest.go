package main

import (
	"errors"
	"github.com/wollomatic/socket-proxy/internal/config"
	"log/slog"
	"net"
	"net/http"
)

// handleHttpRequest checks if the request is allowed and sends it to the proxy.
// Otherwise, it returns a "405 Method Not Allowed" or a "403 Forbidden" error.
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
		communicateBlockedRequest(w, r, "forbidden IP", http.StatusForbidden)
		return
	}

	// check if the request is allowed
	allowed, exists := config.AllowedRequests[r.Method]
	if !exists { // method not in map -> not allowed
		communicateBlockedRequest(w, r, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !allowed.MatchString(r.URL.Path) { // path does not match regex -> not allowed
		communicateBlockedRequest(w, r, "path not allowed", http.StatusForbidden)
		return
	}

	// finally log and proxy the request
	slog.Debug("allowed request", "method", r.Method, "URL", r.URL, "client", r.RemoteAddr)
	socketProxy.ServeHTTP(w, r) // proxy the request
}

// isAllowedIP checks if the given remote address is allowed to connect to the proxy.
// The IP address is extracted from a RemoteAddr string (the part before the colon).
func isAllowedIP(remoteAddr string) (bool, error) {
	// Get the IP address from the remote address string
	ipStr, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return false, err
	}
	// Parse the IP address
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false, errors.New("invalid IP format")
	}
	// check if IP address is in allowed network
	if !config.AllowedNetwork.Contains(ip) {
		return false, nil
	}
	return true, nil
}

// sendHTTPError sends a HTTP error with the given status code.
func sendHTTPError(w http.ResponseWriter, status int) {
	http.Error(w, http.StatusText(status), status)
}

// communicateBlockedRequest logs a blocked request and sends a HTTP error.
func communicateBlockedRequest(w http.ResponseWriter, r *http.Request, reason string, status int) {
	slog.Warn("blocked request", "reason", reason, "method", r.Method, "URL", r.URL, "client", r.RemoteAddr, "response", status)
	sendHTTPError(w, status)
}
