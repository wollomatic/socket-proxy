package config

import (
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
)

var (
	defaultAllowFrom                   = "127.0.0.1/32"         // allowed IPs to connect to the proxy
	defaultAllowHealthcheck            = false                  // allow health check requests (HEAD http://localhost:55555/health)
	defaultLogJSON                     = false                  // if true, log in JSON format
	defaultLogLevel                    = "INFO"                 // log level as string
	defaultListenIP                    = "127.0.0.1"            // ip address to bind the server to
	defaultProxyPort                   = uint(2375)             // tcp port to listen on
	defaultSocketPath                  = "/var/run/docker.sock" // path to the unix socket
	defaultShutdownGraceTime           = uint(10)               // Maximum time in seconds to wait for the server to shut down gracefully
	defaultWatchdogInterval            = uint(0)                // watchdog interval in seconds (0 to disable)
	defaultStopOnWatchdog              = false                  // set to true to stop the program when the socket gets unavailable (otherwise log only)
	defaultProxySocketEndpoint         = ""                     // empty string means no socket listener, but regular TCP listener
	defaultProxySocketEndpointFileMode = uint(0o400)            // set the file mode of the unix socket endpoint
)

type Config struct {
	AllowedRequests             map[string]*regexp.Regexp
	AllowFrom                   string
	AllowHealthcheck            bool
	LogJSON                     bool
	StopOnWatchdog              bool
	ShutdownGraceTime           uint
	WatchdogInterval            uint
	LogLevel                    slog.Level
	ListenAddress               string
	SocketPath                  string
	ProxySocketEndpoint         string
	ProxySocketEndpointFileMode os.FileMode
}

// used for list of allowed requests
type methodRegex struct {
	method               string
	regexStringFromEnv   string
	regexStringFromParam string
}

// mr is the allowlist of requests per http method
// default: regexStringFromEnv and regexStringFromParam are empty, so regexCompiled stays nil and the request is blocked
// if regexStringParam is set with a command line parameter, all requests matching the method and path matching the regex are allowed
// else if regexStringEnv from Environment ist checked
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
		cfg              Config
		listenIP         string
		proxyPort        uint
		logLevel         string
		endpointFileMode uint
	)

	if val, ok := os.LookupEnv("SP_ALLOWFROM"); ok && val != "" {
		defaultAllowFrom = val
	}
	if val, ok := os.LookupEnv("SP_ALLOWHEALTHCHECK"); ok {
		if parsedVal, err := strconv.ParseBool(val); err == nil {
			defaultAllowHealthcheck = parsedVal
		}
	}
	if val, ok := os.LookupEnv("SP_LOGJSON"); ok {
		if parsedVal, err := strconv.ParseBool(val); err == nil {
			defaultLogJSON = parsedVal
		}
	}
	if val, ok := os.LookupEnv("SP_LISTENIP"); ok && val != "" {
		defaultListenIP = val
	}
	if val, ok := os.LookupEnv("SP_LOGLEVEL"); ok && val != "" {
		defaultLogLevel = val
	}
	if val, ok := os.LookupEnv("SP_PROXYPORT"); ok && val != "" {
		if parsedVal, err := strconv.ParseUint(val, 10, 32); err == nil {
			defaultProxyPort = uint(parsedVal)
		}
	}
	if val, ok := os.LookupEnv("SP_SHUTDOWNGRACETIME"); ok && val != "" {
		if parsedVal, err := strconv.ParseUint(val, 10, 32); err == nil {
			defaultShutdownGraceTime = uint(parsedVal)
		}
	}
	if val, ok := os.LookupEnv("SP_SOCKETPATH"); ok && val != "" {
		defaultSocketPath = val
	}
	if val, ok := os.LookupEnv("SP_STOPONWATCHDOG"); ok {
		if parsedVal, err := strconv.ParseBool(val); err == nil {
			defaultStopOnWatchdog = parsedVal
		}
	}
	if val, ok := os.LookupEnv("SP_WATCHDOGINTERVAL"); ok && val != "" {
		if parsedVal, err := strconv.ParseUint(val, 10, 32); err == nil {
			defaultWatchdogInterval = uint(parsedVal)
		}
	}
	if val, ok := os.LookupEnv("SP_PROXYSOCKETENDPOINT"); ok && val != "" {
		defaultProxySocketEndpoint = val
	}
	if val, ok := os.LookupEnv("SP_PROXYSOCKETENDPOINTFILEMODE"); ok {
		if parsedVal, err := strconv.ParseUint(val, 8, 32); err == nil {
			defaultProxySocketEndpointFileMode = uint(parsedVal)
		}
	}

	for i := range mr {
		if val, ok := os.LookupEnv("SP_ALLOW_" + mr[i].method); ok && val != "" {
			mr[i].regexStringFromEnv = val
		}
	}

	flag.StringVar(&cfg.AllowFrom, "allowfrom", defaultAllowFrom, "allowed IPs or hostname to connect to the proxy")
	flag.BoolVar(&cfg.AllowHealthcheck, "allowhealthcheck", defaultAllowHealthcheck, "allow health check requests (HEAD http://localhost:55555/health)")
	flag.BoolVar(&cfg.LogJSON, "logjson", defaultLogJSON, "log in JSON format (otherwise log in plain text")
	flag.StringVar(&listenIP, "listenip", defaultListenIP, "ip address to listen on")
	flag.StringVar(&logLevel, "loglevel", defaultLogLevel, "set log level: DEBUG, INFO, WARN, ERROR")
	flag.UintVar(&proxyPort, "proxyport", defaultProxyPort, "tcp port to listen on")
	flag.UintVar(&cfg.ShutdownGraceTime, "shutdowngracetime", defaultShutdownGraceTime, "maximum time in seconds to wait for the server to shut down gracefully")
	if cfg.ShutdownGraceTime > math.MaxInt {
		return nil, fmt.Errorf("shutdowngracetime has to be smaller than %i", math.MaxInt) // this maximum value has no practical significance
	}
	flag.StringVar(&cfg.SocketPath, "socketpath", defaultSocketPath, "unix socket path to connect to")
	flag.BoolVar(&cfg.StopOnWatchdog, "stoponwatchdog", defaultStopOnWatchdog, "stop the program when the socket gets unavailable (otherwise log only)")
	flag.UintVar(&cfg.WatchdogInterval, "watchdoginterval", defaultWatchdogInterval, "watchdog interval in seconds (0 to disable)")
	if cfg.WatchdogInterval > math.MaxInt {
		return nil, fmt.Errorf("watchdoginterval has to be smaller than %i", math.MaxInt) // this maximum value has no practical significance
	}
	flag.StringVar(&cfg.ProxySocketEndpoint, "proxysocketendpoint", defaultProxySocketEndpoint, "unix socket endpoint (if set, used instead of the TCP listener)")
	flag.UintVar(&endpointFileMode, "proxysocketendpointfilemode", defaultProxySocketEndpointFileMode, "set the file mode of the unix socket endpoint")
	for i := range mr {
		flag.StringVar(&mr[i].regexStringFromParam, "allow"+mr[i].method, "", "regex for "+mr[i].method+" requests (not set means method is not allowed)")
	}
	flag.Parse()

	// check listenIP and proxyPort
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

	if endpointFileMode > 0o777 {
		return nil, errors.New("file mode has to be between 0 and 0o777")
	}
	cfg.ProxySocketEndpointFileMode = os.FileMode(uint32(endpointFileMode))

	// compile regexes for allowed requests
	cfg.AllowedRequests = make(map[string]*regexp.Regexp)
	for _, rx := range mr {
		if rx.regexStringFromParam != "" {
			r, err := regexp.Compile("^" + rx.regexStringFromParam + "$")
			if err != nil {
				return nil, fmt.Errorf("invalid regex \"%s\" for method %s in command line parameter: %w", rx.regexStringFromParam, rx.method, err)
			}
			cfg.AllowedRequests[rx.method] = r
		} else if rx.regexStringFromEnv != "" {
			r, err := regexp.Compile("^" + rx.regexStringFromEnv + "$")
			if err != nil {
				return nil, fmt.Errorf("invalid regex \"%s\" for method %s in env variable: %w", rx.regexStringFromParam, rx.method, err)
			}
			cfg.AllowedRequests[rx.method] = r
		}
	}
	return &cfg, nil
}
