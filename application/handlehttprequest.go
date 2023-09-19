package main

import (
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"strings"
)

// allowedPaths is a list of path substrings that are allowed to be proxied.
// If the request URL path does not contain any of these substrings, the request is blocked.
var allowedPaths = []string{
	"version",
	"events",
	"containers",
}

var (
	allowedRegexString = `^/v1\..{1,2}/(version|containers/.*|events\?filters=%7B%22type%22%3A%7B%22container%22%3Atrue%7D%7D)$`
	allowedRegex       *regexp.Regexp
)

func init() {
	allowedRegex = regexp.MustCompile(allowedRegexString)
}

// handleHttpRequest checks if the request is allowed and sends it to the proxy.
// Otherwise, it returns a 405 Method Not Allowed error.
// In case of an error, it returns a 500 Internal Server Error.
func handleHttpRequest(w http.ResponseWriter, r *http.Request) {
	// extract IP from RemoteAddr and check if it is allowed to connect
	var (
		ipStr string
		ip    net.IP
	)
	index := strings.Index(r.RemoteAddr, ":")
	if index > -1 {
		ipStr = r.RemoteAddr[:index]
	} else {
		slog.Error("invalid RemoteAddr format", "reason", "colon missing", "method", r.Method, "URL", r.URL, "client", r.RemoteAddr)
		sendHTTPError(w, http.StatusInternalServerError)
		return
	}
	ip = net.ParseIP(ipStr)
	if ip == nil {
		slog.Error("invalid RemoteAddr format", "reason", "parse error", "method", r.Method, "URL", r.URL, "client", r.RemoteAddr)
		sendHTTPError(w, http.StatusInternalServerError)
		return
	}
	if !allowedNetwork.Contains(ip) {
		slog.Warn("blocked request", "reason", "forbidden IP", "method", r.Method, "URL", r.URL, "client", r.RemoteAddr)
		sendHTTPError(w, http.StatusForbidden)
		return
	}

	// only allow GET and HEAD requests
	if (r.Method != http.MethodGet) && (r.Method != http.MethodHead) {
		slog.Warn("blocked request", "reason", "forbidden method", "method", r.Method, "URL", r.URL, "client", r.RemoteAddr)
		sendHTTPError(w, http.StatusMethodNotAllowed)
		return
	}

	// check the request URL path
	if allowedRegex.MatchString(r.URL.Path) {
		slog.Debug("allowed request", "method", r.Method, "URL", r.URL, "client", r.RemoteAddr)
		socketProxy.ServeHTTP(w, r) // proxy the request
		return
	}

	// request URL path does not contain any of the allowed paths, so block the request
	slog.Warn("blocked request", "reason", "forbidden request path", "method", r.Method, "URL", r.URL, "client", r.RemoteAddr)
	sendHTTPError(w, http.StatusForbidden)
}

// sendHTTPError sends a HTTP error with the given status code.
func sendHTTPError(w http.ResponseWriter, status int) {
	http.Error(w, http.StatusText(status), status)
}
