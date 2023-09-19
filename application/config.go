package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
)

const (
	version                 = "0.1.0"
	programUrl              = "github.com/wollomatic/socket-proxy"
	logSourcePosition       = false // set to true to log the source position (file and line) of the log message
	maxGracefulShutdownTime = 10    // Maximum time in seconds to wait for the server to shut down gracefully
)

var (
	allowFrom  = "0.0.0.0/0"            // allowed IPs to connect to the proxy
	logJSON    = false                  // if true, log in JSON format
	logLevel   = "INFO"                 // log level as string
	proxyPort  = "2375"                 // tcp port to listen on
	socketPath = "/var/run/docker.sock" // path to the unix socket
)

// init parses the command line flags and sets up the logger.
func initConfig() {
	var (
		slogLevel slog.Level
		logger    *slog.Logger
	)

	flag.StringVar(&allowFrom, "allowfrom", allowFrom, "allowed IPs to connect to the proxy")
	flag.BoolVar(&logJSON, "logjson", logJSON, "log in JSON format (otherwise log in plain text")
	flag.StringVar(&logLevel, "loglevel", logLevel, "set log level: DEBUG, INFO, WARN, ERROR")
	flag.StringVar(&proxyPort, "proxyport", proxyPort, "tcp port to listen on")
	flag.StringVar(&socketPath, "socketpath", socketPath, "unix socket path to connect to")
	flag.Parse()

	var err error
	_, allowedNetwork, err = net.ParseCIDR(allowFrom)
	if err != nil {
		fmt.Println(err)
		return
	}

	// parse proxyPort to check if it is a valid port number
	port, err := strconv.Atoi(proxyPort)
	if err != nil || port < 1 || port > 65535 {
		slog.Error("port number has to be between 1 and 65535")
		os.Exit(2)
	}

	switch strings.ToUpper(logLevel) {
	case "DEBUG":
		slogLevel = slog.LevelDebug
	case "INFO":
		slogLevel = slog.LevelInfo
	case "WARN":
		slogLevel = slog.LevelWarn
	case "ERROR":
		slogLevel = slog.LevelError
	default:
		_, _ = fmt.Fprintln(os.Stderr, "Invalid log level. Supported levels are DEBUG, INFO, WARN, ERROR")
		os.Exit(1)
	}

	logOps := &slog.HandlerOptions{
		AddSource: logSourcePosition,
		Level:     slogLevel,
	}
	if logJSON {
		logger = slog.New(slog.NewJSONHandler(os.Stdout, logOps))
	} else {
		logger = slog.New(slog.NewTextHandler(os.Stdout, logOps))
	}
	slog.SetDefault(logger)
}
