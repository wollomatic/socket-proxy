package main

import (
	"errors"
	"log/slog"
	"net"
	"net/http"

	"github.com/wollomatic/socket-proxy/internal/config"
)

// handleHTTPRequest checks if the request is allowed and sends it to the proxy.
// Otherwise, it returns a "405 Method Not Allowed" or a "403 Forbidden" error.
// In case of an error, it returns a 500 Internal Server Error.
func handleHTTPRequest(w http.ResponseWriter, r *http.Request) {
	allowList, ok := determineAllowList(r)
	if !ok {
		communicateBlockedRequest(w, r, "forbidden IP", http.StatusForbidden)
		return
	}

	allowed, exists := allowList.AllowedRequests[r.Method]
	if !exists { // method not in map -> not allowed
		communicateBlockedRequest(w, r, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !allowed.MatchString(r.URL.Path) { // path does not match regex -> not allowed
		communicateBlockedRequest(w, r, "path not allowed", http.StatusForbidden)
		return
	}

	// check bind mount restrictions
	if err := checkBindMountRestrictions(allowList.AllowedBindMounts, r); err != nil {
		communicateBlockedRequest(w, r, "bind mount restriction: "+err.Error(), http.StatusForbidden)
		return
	}

	// finally, log and proxy the request
	slog.Debug("allowed request", "method", r.Method, "URL", r.URL, "client", r.RemoteAddr) // #nosec G706 - structured logging (slog) safely encodes values
	socketProxy.ServeHTTP(w, r)                                                             // #nosec G704 - Request target is always the specified socket
}

// return the relevant allowlist
func determineAllowList(r *http.Request) (config.AllowList, bool) {
	if cfg.ProxySocketEndpoint == "" { // do not perform this check if we proxy to a unix socket
		// Get the client IP address from the remote address string
		clientIPStr, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			slog.Warn("cannot get valid IP address from request", "reason", err, "method", r.Method, "URL", r.URL, "client", r.RemoteAddr) // #nosec G706 - structured logging (slog) safely encodes values
			return config.AllowList{}, false
		}

		// If applicable, get the non-default allowlist corresponding to the client IP address
		if cfg.ProxyContainerName != "" {
			allowList, found := cfg.AllowLists.FindByIP(clientIPStr)
			if found {
				return allowList, true
			}
		}

		// Check if client is allowed for the default allowlist:
		allowedIP, err := isAllowedClient(clientIPStr)
		if err != nil {
			slog.Warn("cannot get valid IP address for client allowlist check", "reason", err, "method", r.Method, "URL", r.URL, "client", r.RemoteAddr) // #nosec G706 - structured logging (slog) safely encodes values
		}
		if !allowedIP {
			return config.AllowList{}, false
		}
	}

	return cfg.AllowLists.Default, true
}

// isAllowedClient checks if the given remote address is allowed to connect to the proxy.
// The IP address is extracted from a RemoteAddr string (the part before the colon).
func isAllowedClient(clientIPStr string) (bool, error) {
	// Parse the IP address
	clientIP := net.ParseIP(clientIPStr)
	if clientIP == nil {
		return false, errors.New("invalid IP format")
	}

	for _, allowFromItem := range cfg.AllowFrom {

		// first try to handle as an CIDR
		_, allowedIPNet, err := net.ParseCIDR(allowFromItem)
		if err == nil {
			// AllowFrom is a valid CIDR, so check if IP address is in allowed network
			return allowedIPNet.Contains(clientIP), nil
		}

		// AllowFrom is not a valid CIDR, so try to resolve it via DNS
		// We intentionally do not cache the DNS lookups.
		// In our use case, the resolver should be a local service, and we don't want to cause DNS caching errors.
		ips, err := net.LookupIP(allowFromItem)
		if err != nil {
			slog.Warn("error looking up allowed client hostname", "hostname", allowFromItem, "error", err.Error())
		}
		for _, ip := range ips {
			// Check if the IP address is one of the resolved IPs
			if ip.Equal(clientIP) {
				return true, nil
			}
		}
	}

	// If we get here, the IP address is not allowed
	return false, nil
}

// sendHTTPError sends an HTTP error with the given status code.
func sendHTTPError(w http.ResponseWriter, status int) {
	http.Error(w, http.StatusText(status), status)
}

// communicateBlockedRequest logs a blocked request and sends a HTTP error.
func communicateBlockedRequest(w http.ResponseWriter, r *http.Request, reason string, status int) {
	slog.Warn("blocked request", "reason", reason, "method", r.Method, "URL", r.URL, "client", r.RemoteAddr, "response", status) // #nosec G706 - structured logging (slog) safely encodes values
	sendHTTPError(w, status)
}
