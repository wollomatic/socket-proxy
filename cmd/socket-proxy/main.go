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

	"github.com/wollomatic/socket-proxy/internal/config"
)

const (
	programURL   = "github.com/wollomatic/socket-proxy"
	logAddSource = false // set to true to log the source position (file and line) of the log message
)

var (
	version     = "dev" // will be overwritten by build system
	socketProxy *httputil.ReverseProxy
	cfg         *config.Config
)

func main() {
	var err error
	cfg, err = config.InitConfig()
	if err != nil {
		slog.Error("error initializing config", "error", err)
		os.Exit(1)
	}

	// setup channels for graceful shutdown
	internalQuit := make(chan int, 1)       // send to this channel to invoke graceful shutdown, int is the exit code
	externalQuit := make(chan os.Signal, 1) // configure listener for SIGINT and SIGTERM
	signal.Notify(externalQuit, syscall.SIGINT, syscall.SIGTERM)

	// setup logging
	logOpts := &slog.HandlerOptions{
		AddSource: logAddSource,
		Level:     cfg.LogLevel,
	}
	var logger *slog.Logger
	if cfg.LogJSON {
		logger = slog.New(slog.NewJSONHandler(os.Stdout, logOpts))
	} else {
		logger = slog.New(slog.NewTextHandler(os.Stdout, logOpts))
	}
	slog.SetDefault(logger)

	// setup non-default allowlists
	if cfg.ProxySocketEndpoint == "" && cfg.ProxyContainerName != "" {
		go cfg.UpdateAllowLists()
	}

	// print configuration
	slog.Info("starting socket-proxy", "version", version, "os", runtime.GOOS, "arch", runtime.GOARCH, "runtime", runtime.Version(), "URL", programURL)
	if cfg.ProxySocketEndpoint == "" {
		// join the cfg.AllowFrom slice to a string to avoid the brackets in the logging (avoid confusion with IPv6 addresses)
		allowFromString := strings.Join(cfg.AllowFrom, ",")
		slog.Info("configuration info", "socketpath", cfg.SocketPath, "listenaddress", cfg.ListenAddress, "loglevel", cfg.LogLevel, "logjson", cfg.LogJSON, "allowfrom", allowFromString, "shutdowngracetime", cfg.ShutdownGraceTime)
	} else {
		slog.Info("configuration info", "socketpath", cfg.SocketPath, "proxysocketendpoint", cfg.ProxySocketEndpoint, "proxysocketendpointfilemode", cfg.ProxySocketEndpointFileMode, "loglevel", cfg.LogLevel, "logjson", cfg.LogJSON, "shutdowngracetime", cfg.ShutdownGraceTime)
		slog.Info("proxysocketendpoint is set, so the TCP listener is deactivated")
	}
	if cfg.WatchdogInterval > 0 {
		slog.Info("watchdog enabled", "interval", cfg.WatchdogInterval, "stoponwatchdog", cfg.StopOnWatchdog)
	} else {
		slog.Info("watchdog disabled")
	}
	if len(cfg.AllowLists.Default.AllowedBindMounts) > 0 {
		slog.Info("Docker bind mount restrictions enabled", "allowbindmountfrom", cfg.AllowLists.Default.AllowedBindMounts)
	} else {
		// we only log this on DEBUG level because bind mount restrictions are a very special use case
		slog.Debug("no Docker bind mount restrictions")
	}
	if len(cfg.ProxyContainerName) > 0 {
		slog.Info("Proxy container name provided", "proxycontainername", cfg.ProxyContainerName)
	} else {
		// we only log this on DEBUG level because providing the socket-proxy container name
		// enables the use of labels to specify per-container allowlists
		slog.Debug("no proxy container name provided")
	}
	if len(cfg.AllowLists.Networks) > 0 {
		slog.Info("socket proxy networks detected", "socketproxynetworks", cfg.AllowLists.Networks)
	} else {
		// we only log this on DEBUG level because the socket proxy networks are used for per-container allowlists
		slog.Debug("no socket proxy networks detected")
	}

	// print default request allowlist
	cfg.AllowLists.PrintDefault(cfg.LogJSON)

	// check if the socket is available
	err = checkSocketAvailability(cfg.SocketPath)
	if err != nil {
		slog.Error("socket not available", "error", err)
		os.Exit(2)
	}

	// define the reverse proxy
	socketURLDummy, _ := url.Parse("http://localhost") // dummy URL - we use the unix socket
	socketProxy = httputil.NewSingleHostReverseProxy(socketURLDummy)
	socketProxy.Transport = &http.Transport{
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", cfg.SocketPath)
		},
	}

	var l net.Listener
	if cfg.ProxySocketEndpoint != "" {
		if _, err = os.Stat(cfg.ProxySocketEndpoint); err == nil {
			slog.Warn(fmt.Sprintf("%s already exists, removing existing file", cfg.ProxySocketEndpoint))
			if err = os.Remove(cfg.ProxySocketEndpoint); err != nil {
				slog.Error("error removing existing socket file", "error", err)
				os.Exit(2)
			}
		}
		l, err = net.Listen("unix", cfg.ProxySocketEndpoint)
		if err != nil {
			slog.Error("error creating socket", "error", err)
			os.Exit(2)
		}
		if err = os.Chmod(cfg.ProxySocketEndpoint, cfg.ProxySocketEndpointFileMode); err != nil {
			slog.Error("error setting socket file permissions", "error", err)
			os.Exit(2)
		}
	} else {
		l, err = net.Listen("tcp", cfg.ListenAddress)
		if err != nil {
			slog.Error("error listening on address", "error", err)
			os.Exit(2)
		}
	}

	srv := &http.Server{ // #nosec G112 -- intentionally do not time out the client
		Handler: http.HandlerFunc(handleHTTPRequest), // #nosec G112
	} // #nosec G112

	// start the server in a goroutine
	go func() {
		if err := srv.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("http server problem", "error", err)
			os.Exit(2)
		}
	}()

	slog.Info("socket-proxy running and listening...")

	// start the watchdog if configured
	if cfg.WatchdogInterval > 0 {
		go startSocketWatchdog(cfg.SocketPath, int64(cfg.WatchdogInterval), cfg.StopOnWatchdog, internalQuit) // #nosec G115 - we validated the integer size in config.go
		slog.Debug("watchdog running")
	}

	// start the health check server if configured
	if cfg.AllowHealthcheck {
		go healthCheckServer(cfg.SocketPath)
		slog.Debug("healthcheck ready")
	}

	// Wait for stop signal
	exitCode := 0
	select {
	case <-externalQuit:
		slog.Info("received stop signal - shutting down")
	case value := <-internalQuit:
		slog.Info("received internal shutdown - shutting down")
		exitCode = value
	}
	// Try to shut down gracefully
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(int64(cfg.ShutdownGraceTime))*time.Second) // #nosec G115 - we validated the integer size in config.go
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		slog.Warn("timeout stopping server", "error", err)
	}
	slog.Info("shutdown finished - exiting", "exit code", exitCode)
	os.Exit(exitCode)
}
