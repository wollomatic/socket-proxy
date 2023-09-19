package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
)

const (
	version                 = "0.1.0"
	programUrl              = "github.com/wollomatic/socket-proxy"
	logSourcePosition       = true // set to true to log the source position (file and line) of the log message
	maxGracefulShutdownTime = 10   // Maximum time in seconds to wait for the server to shut down gracefully
)

var (
	logLevel      = "INFO"                 // log level as string
	logJSON       = false                  // log in JSON format
	socketPath    = "/var/run/docker.sock" // path to the unix socket
	tcpServerPort = "2375"                 // tcp port to listen on
)

// init parses the command line flags and sets up the logger.
func initConfig() {
	var (
		slogLevel slog.Level
		logger    *slog.Logger
	)

	flag.StringVar(&socketPath, "socket", socketPath, "unix socket path to connect to")
	flag.StringVar(&tcpServerPort, "port", tcpServerPort, "tcp port to listen on")
	flag.StringVar(&logLevel, "loglevel", logLevel, "set log level: DEBUG, INFO, WARN, ERROR")
	flag.BoolVar(&logJSON, "logjson", logJSON, "log in JSON format (otherwise log in plain text")
	flag.Parse()

	// parse tcpServerPort to check if it is a valid port number
	port, err := strconv.Atoi(tcpServerPort)
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
		fmt.Fprintln(os.Stderr, "Invalid log level. Supported levels are DEBUG, INFO, WARN, ERROR")
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
