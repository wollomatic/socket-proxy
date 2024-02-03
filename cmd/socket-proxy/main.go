package main

import (
	"context"
	"errors"
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
	programUrl = "github.com/wollomatic/socket-proxy"
)

var (
	version     = "0.1.0"
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

	// setup logging
	logOpts := &slog.HandlerOptions{
		AddSource: config.LogSourcePosition,
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
	slog.Info("configuration info", "socketpath", cfg.SocketPath, "listenaddress", cfg.ListenAddress, "loglevel", cfg.LogLevel, "logjson", cfg.LogJSON, "allowfrom", cfg.AllowFrom, "shutdowngracetime", cfg.ShutdownGraceTime)
	if cfg.WatchdogInterval > 0 {
		slog.Info("watchdog enabled", "interval", cfg.WatchdogInterval, "stoponwatchdog", cfg.StopOnWatchdog)
	} else {
		slog.Info("watchdog disabled")
	}
	for method, regex := range config.AllowedRequests {
		slog.Info("configured allowed request", "method", method, "regex", regex)
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

	// start the server in a goroutine
	srv := &http.Server{ // #nosec G112 -- intentionally do not timeout the client
		Addr:    cfg.ListenAddress,                   // #nosec G112
		Handler: http.HandlerFunc(handleHttpRequest), // #nosec G112
	} // #nosec G112
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("http server problem", "error", err)
			os.Exit(2)
		}
	}()

	// start the watchdog if configured
	if cfg.WatchdogInterval > 0 {
		go startSocketWatchdog(cfg.SocketPath, cfg.WatchdogInterval, cfg.StopOnWatchdog)
	}

	// start the health check server if configured
	if cfg.AllowHealthcheck {
		go healthCheckServer(cfg.SocketPath)
	}

	// Wait for stop signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	// Try to shut down gracefully
	slog.Info("received stop signal - shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.ShutdownGraceTime)*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		slog.Warn("timeout stopping server (maybe client still running?) - forcing shutdown", "error", err)
		os.Exit(0) // timeout is no error, so we exit with 0
	}
	slog.Info("graceful shutdown complete - exiting")
}
