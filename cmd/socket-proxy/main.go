package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/wollomatic/socket-proxy/internal/config"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"
)

const (
	programUrl   = "github.com/wollomatic/socket-proxy"
	logAddSource = true // set to true to log the source position (file and line) of the log message
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

	// print configuration
	slog.Info("starting socket-proxy", "version", version, "os", runtime.GOOS, "arch", runtime.GOARCH, "runtime", runtime.Version(), "URL", programUrl)
	if cfg.ProxySocketEndpoint == "" {
		slog.Info("configuration info", "socketpath", cfg.SocketPath, "listenaddress", cfg.ListenAddress, "loglevel", cfg.LogLevel, "logjson", cfg.LogJSON, "allowfrom", cfg.AllowFrom, "shutdowngracetime", cfg.ShutdownGraceTime)
	} else {
		slog.Info("configuration info", "socketpath", cfg.SocketPath, "proxysocketendpoint", cfg.ProxySocketEndpoint, "loglevel", cfg.LogLevel, "logjson", cfg.LogJSON, "allowfrom", cfg.AllowFrom, "shutdowngracetime", cfg.ShutdownGraceTime)
		slog.Info("proxysocketendpoint is set, so the TCP listener is deactivated")
	}
	if cfg.WatchdogInterval > 0 {
		slog.Info("watchdog enabled", "interval", cfg.WatchdogInterval, "stoponwatchdog", cfg.StopOnWatchdog)
	} else {
		slog.Info("watchdog disabled")
	}

	// print request allow list
	if cfg.LogJSON {
		for method, regex := range cfg.AllowedRequests {
			slog.Info("configured allowed request", "method", method, "regex", regex)
		}
	} else {
		// don't use slog here, as we want to print the regexes as they are
		// see https://github.com/wollomatic/socket-proxy/issues/11
		fmt.Printf("Request allowlist:\n   %-8s %s\n", "Method", "Regex")
		for method, regex := range cfg.AllowedRequests {
			fmt.Printf("   %-8s %s\n", method, regex)
		}
	}

	// check if the socket is available
	err = checkSocketAvailability(cfg.SocketPath)
	if err != nil {
		slog.Error("socket not available", "error", err)
		os.Exit(2)
	}

	// define the reverse proxy
	socketUrlDummy, _ := url.Parse("http://localhost") // dummy URL - we use the unix socket
	socketProxy = httputil.NewSingleHostReverseProxy(socketUrlDummy)
	socketProxy.Transport = &http.Transport{
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", cfg.SocketPath)
		},
	}

	var l net.Listener
	if cfg.ProxySocketEndpoint != "" {
		if _, err := os.Stat(cfg.ProxySocketEndpoint); err == nil {
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
		if err = os.Chmod(cfg.ProxySocketEndpoint, 0660); err != nil {
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
		Handler: http.HandlerFunc(handleHttpRequest), // #nosec G112
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
		go startSocketWatchdog(cfg.SocketPath, cfg.WatchdogInterval, cfg.StopOnWatchdog, internalQuit)
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
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.ShutdownGraceTime)*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		slog.Warn("timeout stopping server", "error", err)
	}
	slog.Info("shutdown finished - exiting", "exit code", exitCode)
	os.Exit(exitCode)
}
