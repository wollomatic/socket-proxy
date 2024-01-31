package config

import (
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"strings"
)

const LogSourcePosition = false // set to true to log the source position (file and line) of the log message

const (
	defaultAllowFrom         = "127.0.0.1/32"         // allowed IPs to connect to the proxy
	defaultAllowHealthcheck  = false                  // allow health check requests (HEAD http://localhost:55555/health)
	defaultLogJSON           = false                  // if true, log in JSON format
	defaultLogLevel          = "INFO"                 // log level as string
	defaultListenIP          = "127.0.0.1"            // ip address to bind the server to
	defaultProxyPort         = 2375                   // tcp port to listen on
	defaultSocketPath        = "/var/run/docker.sock" // path to the unix socket
	defaultShutdownGraceTime = uint(10)               // Maximum time in seconds to wait for the server to shut down gracefully
	defaultWatchdogInterval  = uint(0)                // watchdog interval in seconds (0 to disable)
	defaultStopOnWatchdog    = false                  // set to true to stop the program when the socket gets unavailable (otherwise log only)
)

type Config struct {
	AllowFrom         string
	AllowHealthcheck  bool
	LogJSON           bool
	StopOnWatchdog    bool
	ShutdownGraceTime uint
	WatchdogInterval  uint
	LogLevel          slog.Level
	ListenAddress     string
	SocketPath        string
}

var (
	AllowedNetwork  *net.IPNet // TODO: remove
	AllowedRequests map[string]*regexp.Regexp
)

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

func InitConfig() (*Config, error) {
	var (
		cfg       Config
		listenIP  string
		proxyPort uint
		logLevel  string
	)
	flag.StringVar(&cfg.AllowFrom, "allowfrom", defaultAllowFrom, "allowed IPs or hostname to connect to the proxy")
	flag.BoolVar(&cfg.AllowHealthcheck, "allowhealthcheck", defaultAllowHealthcheck, "allow health check requests (HEAD http://localhost:55555/health)")
	flag.BoolVar(&cfg.LogJSON, "logjson", defaultLogJSON, "log in JSON format (otherwise log in plain text")
	flag.StringVar(&listenIP, "listenip", defaultListenIP, "ip address to listen on")
	flag.StringVar(&logLevel, "loglevel", defaultLogLevel, "set log level: DEBUG, INFO, WARN, ERROR")
	flag.UintVar(&proxyPort, "proxyport", defaultProxyPort, "tcp port to listen on")
	flag.UintVar(&cfg.ShutdownGraceTime, "shutdowngracetime", defaultShutdownGraceTime, "maximum time in seconds to wait for the server to shut down gracefully")
	flag.StringVar(&cfg.SocketPath, "socketpath", defaultSocketPath, "unix socket path to connect to")
	flag.BoolVar(&cfg.StopOnWatchdog, "stoponwatchdog", defaultStopOnWatchdog, "stop the program when the socket gets unavailable (otherwise log only)")
	flag.UintVar(&cfg.WatchdogInterval, "watchdoginterval", defaultWatchdogInterval, "watchdog interval in seconds (0 to disable)")
	for i := 0; i < len(mr); i++ {
		flag.StringVar(&mr[i].regexString, "allow"+mr[i].method, mr[i].regexString, "regex for "+mr[i].method+" requests (not set means method is not allowed)")
	}
	flag.Parse()

	// pcheck listenIP and proxyPort
	if net.ParseIP(listenIP) == nil {
		return nil, fmt.Errorf("invalid IP \"%s\" for listenip", listenIP)
	}
	if proxyPort < 1 || proxyPort > 65535 {
		return nil, errors.New("port number has to be between 1 and 65535")
	}
	cfg.ListenAddress = fmt.Sprintf("%s:%d", listenIP, proxyPort)

	// parse defaultLogLevel and setup logging handler depending on defaultLogJSON
	switch strings.ToUpper(logLevel) {
	case "DEBUG":
		cfg.LogLevel = slog.LevelDebug
	case "INFO":
		cfg.LogLevel = slog.LevelInfo
	case "WARN":
		cfg.LogLevel = slog.LevelWarn
	case "ERROR":
		cfg.LogLevel = slog.LevelError
	default:
		return nil, errors.New("invalid log level " + logLevel + ": Supported levels are DEBUG, INFO, WARN, ERROR")
	}

	// compile regexes for allowed requests
	AllowedRequests = make(map[string]*regexp.Regexp)
	for _, rx := range mr {
		if rx.regexString != "" {
			r, err := regexp.Compile("^" + rx.regexString + "$")
			if err != nil {
				return nil, fmt.Errorf("invalid regex \"%s\" for method %s: %s", rx.regexString, rx.method, err)
			}
			AllowedRequests[rx.method] = r
		}
	}
	return &cfg, nil
}
