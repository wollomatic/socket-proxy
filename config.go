package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
)

const (
	version           = "0.1.0"
	programUrl        = "github.com/wollomatic/socket-proxy"
	logSourcePosition = false // set to true to log the source position (file and line) of the log message
)

var (
	allowFrom         = "127.0.0.1/32"         // allowed IPs to connect to the proxy
	logJSON           = false                  // if true, log in JSON format
	logLevel          = "INFO"                 // log level as string
	proxyPort         = "2375"                 // tcp port to listen on
	socketPath        = "/var/run/docker.sock" // path to the unix socket
	shutdownGraceTime = uint(10)               // Maximum time in seconds to wait for the server to shut down gracefully
	watchdog          = uint(0)                // watchdog interval in seconds (0 to disable)
	stopOnWatchdog    = false                  // set to true to stop the program when the socket gets unavailable (otherwise log only)
)

var allowedRequests map[string]*regexp.Regexp

// used for list of allowed requests
type methodRegex struct {
	method      string
	regexString string
}

// mr is the allowlist of requests per http method
// default: regegString is empty, so regexCompiled stays nil and the request is blocked
// if regexString is set with a command line parameter, all requests matching the method and path matching the regex are allowed
var mr = []methodRegex{
	{method: http.MethodGet},
	{method: http.MethodHead},
	{method: http.MethodPost},
	{method: http.MethodPut},
	{method: http.MethodPatch},
	{method: http.MethodDelete},
	{method: http.MethodConnect},
	{method: http.MethodTrace},
	{method: http.MethodOptions},
}

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
	flag.UintVar(&shutdownGraceTime, "shutdowngracetime", shutdownGraceTime, "maximum time in seconds to wait for the server to shut down gracefully")
	flag.UintVar(&watchdog, "watchdog", watchdog, "watchdog interval in seconds (0 to disable)")
	flag.BoolVar(&stopOnWatchdog, "stoponwatchdog", stopOnWatchdog, "stop the program when the socket gets unavailable (otherwise log only)")
	for i := 0; i < len(mr); i++ {
		flag.StringVar(&mr[i].regexString, "allow"+mr[i].method, mr[i].regexString, "regex for "+mr[i].method+" requests (not set means method is not allowed)")
	}
	flag.Parse()

	// parse allowFrom to check if it is a valid CIDR
	var err error
	_, allowedNetwork, err = net.ParseCIDR(allowFrom)
	if err != nil {
		slog.Error("invalid CIDR in allowfrom parameter", "error", err)
		os.Exit(1)
	}

	// parse proxyPort to check if it is a valid port number
	port, err := strconv.Atoi(proxyPort)
	if err != nil || port < 1 || port > 65535 {
		slog.Error("port number has to be between 1 and 65535")
		os.Exit(1)
	}

	// parse logLevel and setup logging handler depending on logJSON
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
	logOpts := &slog.HandlerOptions{
		AddSource: logSourcePosition,
		Level:     slogLevel,
	}
	if logJSON {
		logger = slog.New(slog.NewJSONHandler(os.Stdout, logOpts))
	} else {
		logger = slog.New(slog.NewTextHandler(os.Stdout, logOpts))
	}
	slog.SetDefault(logger)

	// compile regexes for allowed requests
	allowedRequests = make(map[string]*regexp.Regexp)
	for _, rx := range mr {
		if rx.regexString != "" {
			r, err := regexp.Compile("^" + rx.regexString + "$")
			if err != nil {
				slog.Error("invalid regex", "method", rx.method, "regex", rx.regexString, "error", err)
				os.Exit(1)
			}
			allowedRequests[rx.method] = r
		}
	}
}
