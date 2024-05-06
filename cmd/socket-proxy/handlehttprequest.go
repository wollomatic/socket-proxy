package main

import (
	"errors"
	"github.com/wollomatic/socket-proxy/internal/config"
	"log/slog"
	"net"
	"net/http"
	"strings"
)

// handleHttpRequest checks if the request is allowed and sends it to the proxy.
// Otherwise, it returns a "405 Method Not Allowed" or a "403 Forbidden" error.
// In case of an error, it returns a 500 Internal Server Error.
func handleHttpRequest(w http.ResponseWriter, r *http.Request) {

	// check if the client's IP is allowed to access
	allowedIP, err := isAllowedClient(r.RemoteAddr)
	if err != nil {
		slog.Warn("cannot get valid IP address for client allowlist check", "reason", err, "method", r.Method, "URL", r.URL, "client", r.RemoteAddr)
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

// isAllowedClient checks if the given remote address is allowed to connect to the proxy.
// The IP address is extracted from a RemoteAddr string (the part before the colon).
func isAllowedClient(remoteAddr string) (bool, error) {
	// Get the client IP address from the remote address string
	clientIPStr, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return false, err
	}
	// Parse the IP address
	clientIP := net.ParseIP(clientIPStr)
	if clientIP == nil {
		return false, errors.New("invalid IP format")
	}

	_, allowedIPNet, err := net.ParseCIDR(cfg.AllowFrom)
	if err == nil {
		// AllowFrom is a valid CIDR, so check if IP address is in allowed network
		return allowedIPNet.Contains(clientIP), nil
	} else {
		// AllowFrom is not a valid CIDR, so try to resolve it via DNS
		// split over comma to support multiple hostnames
		allowFroms := strings.Split(cfg.AllowFrom, ",")
		for _, allowFrom := range allowFroms {
			ips, err := net.LookupIP(allowFrom)
			if err != nil {
				slog.Warn("error looking up allowed client hostname", "hostname", allowFrom, "error", err.Error())
			}
			for _, ip := range ips {
				// Check if IP address is one of the resolved IPs
				if ip.Equal(clientIP) {
					return true, nil
				}
			}
		}
		return false, nil
	}
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
