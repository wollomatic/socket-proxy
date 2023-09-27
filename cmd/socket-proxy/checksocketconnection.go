package main

import (
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"
)

const dialTimeout = 5 // timeout in seconds for the socket connection

// checkSocketAvailability tries to connect to the socket and returns an error if it fails.
func checkSocketAvailability(socketPath string) error {
	slog.Debug("checking socket availability")
	conn, err := net.DialTimeout("unix", socketPath, dialTimeout*time.Second)
	if err != nil {
		return err
	}
	err = conn.Close()
	if err != nil {
		slog.Warn("Watchdog: Error closing socket", "error", err)
	}
	return nil
}

// startSocketWatchdog starts a watchdog that checks the socket availability every n seconds.
func startSocketWatchdog(socketPath string, interval uint, stopOnWatchdog bool) {
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		if err := checkSocketAvailability(socketPath); err != nil {
			slog.Warn("Watchdog: Socket is unavailable", "error", err)
			if stopOnWatchdog {
				os.Exit(10)
			}
		}
	}
}

func healthCheckServer(socketPath string) {
	slog.Info("starting health check server")
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		err := checkSocketAvailability(socketPath)
		if err != nil {
			slog.Warn("health check failed", "error", err)
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	err := http.ListenAndServe("127.0.0.1:55555", nil)
	if err != nil {
		slog.Error("error starting health check server", "error", err)
	}
}
