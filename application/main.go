package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"
)

// allowedPaths is a list of path substrings that are allowed to be proxied.
// If the request URL path does not contain any of these substrings, the request is blocked.
var allowedPaths = []string{
	"version",
	"events",
	"containers",
}

var (
	allowedNetwork *net.IPNet
	socketProxy    *httputil.ReverseProxy
)

func main() {
	slog.Info("starting socket-proxy", "version", version, "os", runtime.GOOS, "arch", runtime.GOARCH, "runtime", runtime.Version(), "URL", programUrl)
	initConfig()
	slog.Info("configuration is", "socketpath", socketPath, "proxyport", proxyPort, "loglevel", logLevel, "logjson", logJSON, "allowcidr", allowFrom)
	fmt.Println(allowedNetwork)

	// define the reverse proxy
	socketUrlDummy, _ := url.Parse("http://localhost") // dummy URL - we use the unix socket
	socketProxy = httputil.NewSingleHostReverseProxy(socketUrlDummy)
	socketProxy.Transport = &http.Transport{
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", socketPath)
		},
	}

	// start the server in a goroutine
	srv := &http.Server{
		Addr:    ":" + proxyPort,
		Handler: http.HandlerFunc(handleGetHeadRequest),
	}
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("http server problem", "error", err)
			os.Exit(2)
		}
	}()

	// Wait for stop signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	// Try to shut down gracefully
	slog.Info("received stop signal - shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), maxGracefulShutdownTime*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		slog.Warn("timeout stopping server (maybe client still running?) - forcing shutdown", "error", err)
		os.Exit(3)
	}
	slog.Info("graceful shutdown complete - exiting")
}

// handleGetHeadRequest checks if the request is a GET or HEAD request and sends it to the proxy.
// otherwise it returns a 405 Method Not Allowed error.
func handleGetHeadRequest(w http.ResponseWriter, r *http.Request) {

	var (
		ipStr string
		ip    net.IP
	)

	index := strings.Index(r.RemoteAddr, ":")
	if index > -1 {
		ipStr = r.RemoteAddr[:index]
	} else {
		slog.Error("invalid RemoteAddr format", "reason", "colon missing", "method", r.Method, "URL", r.URL, "client", r.RemoteAddr)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	ip = net.ParseIP(ipStr)
	if ip == nil {
		slog.Error("invalid RemoteAddr format", "reason", "parse error", "method", r.Method, "URL", r.URL, "client", r.RemoteAddr)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	if !allowedNetwork.Contains(ip) {
		slog.Warn("blocked request", "reason", "forbidden IP", "method", r.Method, "URL", r.URL, "client", r.RemoteAddr)
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	// only allow GET and HEAD requests
	if (r.Method != http.MethodGet) && (r.Method != http.MethodHead) {
		slog.Warn("blocked request", "reason", "forbidden method", "method", r.Method, "URL", r.URL, "client", r.RemoteAddr)
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	// check if the request URL path contains any of the allowed paths
	for _, path := range allowedPaths {
		// TODO: change this due to security reasons
		if strings.Contains(r.URL.Path, path) {
			slog.Debug("allowed request", "method", r.Method, "URL", r.URL, "client", r.RemoteAddr)
			socketProxy.ServeHTTP(w, r) // proxy the request
			return
		}
	}

	// request URL path does not contain any of the allowed paths, so block the request
	slog.Warn("blocked request", "reason", "forbidden request path", "method", r.Method, "URL", r.URL, "client", r.RemoteAddr)
	http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
}
