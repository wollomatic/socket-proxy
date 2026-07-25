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
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

const (
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
	defaultProxySocketEndpointFileMode = uint(0o600)            // set the file mode of the unix socket endpoint
	defaultAllowBindMountFrom          = ""                     // empty string means no bind mount restrictions
	defaultProxyContainerName          = ""                     // socket-proxy Docker container name (empty string disables container labels for allowlists)
)

type Config struct {
	allowListsRefresh           allowListsRefreshState
	AllowLists                  *AllowListRegistry
	AllowFrom                   []string
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
	ProxyContainerName          string
}

type AllowList struct {
	ID                string                      // Container ID (empty for the default allowlist)
	AllowedRequests   map[string][]*regexp.Regexp // map of request methods to request path regex patterns (no requests allowed if empty)
	AllowedBindMounts []string                    // list of from portion of allowed bind mounts (all bind mounts allowed if empty)
}

// used for list of allowed requests
type methodRegex struct {
	method       string
	regexStrings arrayParams
}

var supportedHTTPMethods = []string{
	http.MethodGet,
	http.MethodHead,
	http.MethodPost,
	http.MethodPut,
	http.MethodPatch,
	http.MethodDelete,
	http.MethodConnect,
	http.MethodTrace,
	http.MethodOptions,
}

// InitConfig reads configuration from environment variables and command-line
// flags, validates the resulting values, and returns the initialized Config.
func InitConfig() (*Config, error) {
	var (
		cfg                                     Config
		allowFromString                         string
		listenIP                                string
		proxyPort                               uint
		logLevel                                string
		endpointFileMode                        uint
		allowBindMountFromString                string
		defaultAllowFromValue                   = defaultAllowFrom
		defaultAllowHealthcheckValue            = defaultAllowHealthcheck
		defaultLogJSONValue                     = defaultLogJSON
		defaultListenIPValue                    = defaultListenIP
		defaultLogLevelValue                    = defaultLogLevel
		defaultProxyPortValue                   = defaultProxyPort
		defaultShutdownGraceTimeValue           = defaultShutdownGraceTime
		defaultSocketPathValue                  = defaultSocketPath
		defaultStopOnWatchdogValue              = defaultStopOnWatchdog
		defaultWatchdogIntervalValue            = defaultWatchdogInterval
		defaultProxySocketEndpointValue         = defaultProxySocketEndpoint
		defaultProxySocketEndpointFileModeValue = defaultProxySocketEndpointFileMode
		defaultAllowBindMountFromValue          = defaultAllowBindMountFrom
		defaultProxyContainerNameValue          = defaultProxyContainerName
	)

	if val, ok := os.LookupEnv("SP_ALLOWFROM"); ok && val != "" {
		defaultAllowFromValue = val
	}
	if val, ok := os.LookupEnv("SP_ALLOWHEALTHCHECK"); ok {
		if parsedVal, err := strconv.ParseBool(val); err == nil {
			defaultAllowHealthcheckValue = parsedVal
		}
	}
	if val, ok := os.LookupEnv("SP_LOGJSON"); ok {
		if parsedVal, err := strconv.ParseBool(val); err == nil {
			defaultLogJSONValue = parsedVal
		}
	}
	if val, ok := os.LookupEnv("SP_LISTENIP"); ok && val != "" {
		defaultListenIPValue = val
	}
	if val, ok := os.LookupEnv("SP_LOGLEVEL"); ok && val != "" {
		defaultLogLevelValue = val
	}
	if val, ok := os.LookupEnv("SP_PROXYPORT"); ok && val != "" {
		if parsedVal, err := strconv.ParseUint(val, 10, 32); err == nil {
			defaultProxyPortValue = uint(parsedVal)
		}
	}
	if val, ok := os.LookupEnv("SP_SHUTDOWNGRACETIME"); ok && val != "" {
		if parsedVal, err := strconv.ParseUint(val, 10, 32); err == nil {
			defaultShutdownGraceTimeValue = uint(parsedVal)
		}
	}
	if val, ok := os.LookupEnv("SP_SOCKETPATH"); ok && val != "" {
		defaultSocketPathValue = val
	}
	if val, ok := os.LookupEnv("SP_STOPONWATCHDOG"); ok {
		if parsedVal, err := strconv.ParseBool(val); err == nil {
			defaultStopOnWatchdogValue = parsedVal
		}
	}
	if val, ok := os.LookupEnv("SP_WATCHDOGINTERVAL"); ok && val != "" {
		if parsedVal, err := strconv.ParseUint(val, 10, 32); err == nil {
			defaultWatchdogIntervalValue = uint(parsedVal)
		}
	}
	if val, ok := os.LookupEnv("SP_PROXYSOCKETENDPOINT"); ok && val != "" {
		defaultProxySocketEndpointValue = val
	}
	if val, ok := os.LookupEnv("SP_PROXYSOCKETENDPOINTFILEMODE"); ok {
		if parsedVal, err := strconv.ParseUint(val, 8, 32); err == nil {
			defaultProxySocketEndpointFileModeValue = uint(parsedVal)
		}
	}
	if val, ok := os.LookupEnv("SP_ALLOWBINDMOUNTFROM"); ok && val != "" {
		defaultAllowBindMountFromValue = val
	}
	if val, ok := os.LookupEnv("SP_PROXYCONTAINERNAME"); ok && val != "" {
		defaultProxyContainerNameValue = val
	}

	methodAllowLists := newMethodRegexes()

	// multiple values per method
	// like SP_ALLOW_GET_0, SP_ALLOW_GET_1, ...
	allowFromEnv := getAllowFromEnv(os.Environ())
	for i := range methodAllowLists {
		if val, ok := allowFromEnv[methodAllowLists[i].method]; ok && len(val) > 0 {
			for _, v := range val {
				methodAllowLists[i].regexStrings = append(methodAllowLists[i].regexStrings, param{value: v, from: fromEnv})
			}
		}
	}

	flag.StringVar(&allowFromString, "allowfrom", defaultAllowFromValue, "allowed IPs or hostname to connect to the proxy")
	flag.BoolVar(&cfg.AllowHealthcheck, "allowhealthcheck", defaultAllowHealthcheckValue, "allow health check requests (HEAD http://localhost:55555/health)")
	flag.BoolVar(&cfg.LogJSON, "logjson", defaultLogJSONValue, "log in JSON format (otherwise log in plain text")
	flag.StringVar(&listenIP, "listenip", defaultListenIPValue, "ip address to listen on")
	flag.StringVar(&logLevel, "loglevel", defaultLogLevelValue, "set log level: DEBUG, INFO, WARN, ERROR")
	flag.UintVar(&proxyPort, "proxyport", defaultProxyPortValue, "tcp port to listen on")
	flag.UintVar(&cfg.ShutdownGraceTime, "shutdowngracetime", defaultShutdownGraceTimeValue, "maximum time in seconds to wait for the server to shut down gracefully")
	flag.StringVar(&cfg.SocketPath, "socketpath", defaultSocketPathValue, "unix socket path to connect to")
	flag.BoolVar(&cfg.StopOnWatchdog, "stoponwatchdog", defaultStopOnWatchdogValue, "stop the program when the socket gets unavailable (otherwise log only)")
	flag.UintVar(&cfg.WatchdogInterval, "watchdoginterval", defaultWatchdogIntervalValue, "watchdog interval in seconds (0 to disable)")
	flag.StringVar(&cfg.ProxySocketEndpoint, "proxysocketendpoint", defaultProxySocketEndpointValue, "unix socket endpoint (if set, used instead of the TCP listener)")
	flag.UintVar(&endpointFileMode, "proxysocketendpointfilemode", defaultProxySocketEndpointFileModeValue, "set the file mode of the unix socket endpoint")
	flag.StringVar(&allowBindMountFromString, "allowbindmountfrom", defaultAllowBindMountFromValue, "allowed directories for bind mounts (comma-separated)")
	flag.StringVar(&cfg.ProxyContainerName, "proxycontainername", defaultProxyContainerNameValue, "socket-proxy Docker container name")
	for i := range methodAllowLists {
		flag.Var(&methodAllowLists[i].regexStrings, "allow"+methodAllowLists[i].method, "regex for "+methodAllowLists[i].method+" requests (not set means method is not allowed)")
	}
	flag.Parse()

	// init allowlist registry to configure default allowlist
	cfg.AllowLists = &AllowListRegistry{}

	// parse comma-separeted allowFromString into allowFrom slice
	cfg.AllowFrom = strings.Split(allowFromString, ",")

	// parse allowBindMountFromString into default allowlist AllowedBindMounts slice and validate
	if allowBindMountFromString != "" {
		allowedBindMounts, err := parseAllowedBindMounts(allowBindMountFromString)
		if err != nil {
			return nil, err
		}
		cfg.AllowLists.Default.AllowedBindMounts = allowedBindMounts
	}

	// check listenIP and proxyPort
	if proxyPort < 1 || proxyPort > 65535 {
		return nil, errors.New("port number has to be between 1 and 65535")
	}
	if cfg.ShutdownGraceTime > math.MaxInt {
		return nil, fmt.Errorf("shutdowngracetime has to be smaller than %d", math.MaxInt) // this maximum value has no practical significance
	}
	if cfg.WatchdogInterval > math.MaxInt {
		return nil, fmt.Errorf("watchdoginterval has to be smaller than %d", math.MaxInt) // this maximum value has no practical significance
	}
	ip := net.ParseIP(listenIP)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP \"%s\" for listenip", listenIP)
	}

	// Properly format address for both IPv4 and IPv6
	if ip.To4() == nil {
		cfg.ListenAddress = fmt.Sprintf("[%s]:%d", listenIP, proxyPort)
	} else {
		cfg.ListenAddress = fmt.Sprintf("%s:%d", listenIP, proxyPort)
	}

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

	// compile regexes for default allowed requests
	cfg.AllowLists.Default.AllowedRequests = make(map[string][]*regexp.Regexp)
	for _, rx := range methodAllowLists {
		for _, regexString := range effectiveMethodParams(rx.regexStrings) {
			if regexString.value != "" {
				location := ""
				switch regexString.from {
				case fromEnv:
					location = "env variable"
				case fromParam:
					location = "command line parameter"
				}
				r, err := compileRegexp(regexString.value, rx.method, location)
				if err != nil {
					return nil, err
				}
				cfg.AllowLists.Default.AllowedRequests[rx.method] = append(cfg.AllowLists.Default.AllowedRequests[rx.method], r)
			}
		}
	}

	// populate list of socket proxy networks if applicable
	if cfg.ProxySocketEndpoint == "" && cfg.ProxyContainerName != "" {
		var err error
		cfg.AllowLists.networks, err = listSocketProxyNetworks(cfg.SocketPath, cfg.ProxyContainerName)
		if err != nil {
			return nil, err
		}
	}

	return &cfg, nil
}

// Print prints the allowlist, including the IP address of the associated container if it is not empty,
// and in JSON format if logJSON is true
func (allowList AllowList) Print(ip string, logJSON bool) {
	// print allowed requests
	if logJSON {
		if ip == "" {
			for method, regex := range allowList.AllowedRequests {
				slog.Info("configured default request allowlist", "method", method, "regex", regex)
			}
		} else {
			for method, regex := range allowList.AllowedRequests {
				slog.Info("configured request allowlist",
					"id", allowList.ID[:12],
					"ip", ip,
					"method", method,
					"regex", regex,
				)
			}
		}
	} else {
		// don't use slog here, as we want to print the regexes as they are
		// see https://github.com/wollomatic/socket-proxy/issues/11
		if ip == "" {
			fmt.Printf("Default request allowlist:\n   %-8s %s\n", "Method", "Regex")
		} else {
			fmt.Printf("Request allowlist for %s (%s):\n   %-8s %s\n", allowList.ID[:12], ip, "Method", "Regex")
		}
		for method, regex := range allowList.AllowedRequests {
			fmt.Printf("   %-8s %s\n", method, regex)
		}
	}
	// print allowed bind mounts
	if len(allowList.AllowedBindMounts) > 0 {
		if ip == "" {
			slog.Info("Default Docker bind mount restrictions enabled",
				"allowbindmountfrom", allowList.AllowedBindMounts,
			)
		} else {
			slog.Info("Docker bind mount restrictions enabled",
				"allowbindmountfrom", allowList.AllowedBindMounts,
				"id", allowList.ID[:12],
				"ip", ip,
			)
		}
	} else {
		// we only log this on DEBUG level because bind mount restrictions are a very special use case
		if ip == "" {
			slog.Debug("no default Docker bind mount restrictions")
		} else {
			slog.Debug("no Docker bind mount restrictions", "id", allowList.ID[:12], "ip", ip)
		}
	}
}

// compile allowed requests regex pattern
func compileRegexp(regex, method, configLocation string) (*regexp.Regexp, error) {
	r, err := regexp.Compile("^" + regex + "$")
	if err != nil {
		return nil, fmt.Errorf("invalid regex \"%s\" for method %s in %s: %w", regex, method, configLocation, err)
	}
	return r, nil
}

// newMethodRegexes returns one methodRegex entry for each supported HTTP method.
func newMethodRegexes() []methodRegex {
	methods := make([]methodRegex, 0, len(supportedHTTPMethods))
	for _, method := range supportedHTTPMethods {
		methods = append(methods, methodRegex{method: method})
	}
	return methods
}

// effectiveMethodParams returns the parameters that should be applied for one
// HTTP method, preferring command-line values over environment values when both
// are present.
func effectiveMethodParams(params arrayParams) []param {
	if slices.ContainsFunc(params, func(p param) bool { return p.from == fromParam }) {
		return slices.DeleteFunc(slices.Clone(params), func(p param) bool { return p.from == fromEnv })
	}
	return params
}

// parse bind mount from string into list of allowed bind mounts
func parseAllowedBindMounts(allowBindMountFromString string) ([]string, error) {
	allowedBindMounts := strings.Split(allowBindMountFromString, ",")
	for i, dir := range allowedBindMounts {
		if !strings.HasPrefix(dir, "/") {
			return nil, fmt.Errorf("bind mount directory must start with /: %q", dir)
		}
		allowedBindMounts[i] = filepath.Clean(dir)
	}
	return allowedBindMounts, nil
}
