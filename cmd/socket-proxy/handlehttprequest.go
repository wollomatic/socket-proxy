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
	allowList := determineAllowList(w, r)
	if allowList == nil {
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
	slog.Debug("allowed request", "method", r.Method, "URL", r.URL, "client", r.RemoteAddr)
	socketProxy.ServeHTTP(w, r) // proxy the request
}

// return the relevant allowlist, or nil if the request has been blocked
func determineAllowList(w http.ResponseWriter, r *http.Request) *config.AllowList {
	if cfg.ProxySocketEndpoint == "" { // do not perform this check if we proxy to a unix socket
		if cfg.ProxyContainerName != "" {
			allowList := checkForAllowListByIP(w, r)
			if allowList != nil {
				return allowList
			}
		}

		// Check if client is allowed for the default allowlist:
		allowedIP, err := isAllowedClient(r.RemoteAddr)
		if err != nil {
			slog.Warn("cannot get valid IP address for client allowlist check", "reason", err, "method", r.Method, "URL", r.URL, "client", r.RemoteAddr)
		}
		if !allowedIP {
			communicateBlockedRequest(w, r, "forbidden IP", http.StatusForbidden)
			return nil
		}
	}

	return cfg.AllowLists.Default
}

// return the allowlist corresponding to the container by IP address used to make the request,
// or nil if none is found
func checkForAllowListByIP(w http.ResponseWriter, r *http.Request) *config.AllowList {
	clientIPStr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return nil
	}

	cfg.AllowLists.Mutex.RLock()
	defer cfg.AllowLists.Mutex.RUnlock()

	allowList, found := cfg.AllowLists.ByIP[clientIPStr]
	if !found {
		return nil
	}
	return allowList
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
	slog.Warn("blocked request", "reason", reason, "method", r.Method, "URL", r.URL, "client", r.RemoteAddr, "response", status)
	sendHTTPError(w, status)
}
