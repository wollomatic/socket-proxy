package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	version                 = "0.1.0"
	programUrl              = "github.com/wollomatic/socket-proxy"
	logSourcePosition       = true // set to true to log the source position (file and line) of the log message
	maxGracefulShutdownTime = 10   // Maximum time in seconds to wait for the server to shut down gracefully
)

var (
	socketPath    = ""     // path to the unix socket
	tcpServerPort = "2375" // tcp port to listen on
)

// allowedPaths is a list of path substrings that are allowed to be proxied.
// If the request URL path does not contain any of these substrings, the request is blocked.
var allowedPaths = []string{
	"version",
	"events",
	"containers",
}

var socketProxy *httputil.ReverseProxy

// init parses the command line flags and sets up the logger.
func init() {
	var (
		logLevelStr string
		logLevel    slog.Level
		logJson     bool
		logger      *slog.Logger
	)

	flag.StringVar(&socketPath, "socket", "/var/run/docker.sock", "set socket path to connect to (default: /var/run/docker.sock)")
	flag.StringVar(&tcpServerPort, "port", "2375", "tcp port to listen on (default: 2375)")
	flag.StringVar(&logLevelStr, "loglevel", "INFO", "set log level: DEBUG, INFO, WARN, ERROR (default: INFO)")
	flag.BoolVar(&logJson, "json", false, "log in JSON format")
	flag.Parse()

	switch strings.ToUpper(logLevelStr) {
	case "DEBUG":
		logLevel = slog.LevelDebug
	case "INFO":
		logLevel = slog.LevelInfo
	case "WARN":
		logLevel = slog.LevelWarn
	case "ERROR":
		logLevel = slog.LevelError
	default:
		fmt.Fprintln(os.Stderr, "Invalid log level. Supported levels are DEBUG, INFO, WARN, ERROR")
		os.Exit(1)
	}

	logOps := &slog.HandlerOptions{
		AddSource: logSourcePosition,
		Level:     logLevel,
	}
	if logJson {
		logger = slog.New(slog.NewJSONHandler(os.Stdout, logOps))
	} else {
		logger = slog.New(slog.NewTextHandler(os.Stdout, logOps))
	}
	slog.SetDefault(logger)
}

func main() {
	slog.Info("starting socket-proxy", "version", version, "os", runtime.GOOS, "arch", runtime.GOARCH, "runtime", runtime.Version(), "URL", programUrl)

	// parse tcpServerPort to check if it is a valid port number
	port, err := strconv.Atoi(tcpServerPort)
	if err != nil || port < 1 || port > 65535 {
		slog.Error("port number has to be between 1 and 65535")
		os.Exit(2)
	}

	slog.Info("proxy configuration", "socket", socketPath, "port", tcpServerPort)

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
		Addr:    ":" + tcpServerPort,
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
