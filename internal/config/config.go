package config

import (
	"context"
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
	"sync"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
)

const allowedDockerLabelPrefix = "socket-proxy.allow."

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
	defaultProxySocketEndpointFileMode = uint(0o600)            // set the file mode of the unix socket endpoint
	defaultAllowBindMountFrom          = ""                     // empty string means no bind mount restrictions
	defaultProxyContainerName          = ""                     // socket-proxy Docker container name (empty string disables container labels for allowlists)
)

type AllowList struct {
	ID                string                    // Container ID (empty for the default allow-list)
	AllowedRequests   map[string]*regexp.Regexp // map of request methods to request path regex patterns (no requests allowed if empty)
	AllowedBindMounts []string                  // list of from portion of allowed bind mounts (all bind mounts allowed if empty)
}

type AllowListRegistry struct {
	Default *AllowList
	ByIP     map[string]*AllowList
	Mutex    sync.RWMutex
}

type Config struct {
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
	ProxyContainerNetworks      []string
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
		cfg                      Config
		allowLists               AllowListRegistry
		defaultAllowList         AllowList
		allowFromString          string
		listenIP                 string
		proxyPort                uint
		logLevel                 string
		endpointFileMode         uint
		allowBindMountFromString string
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
	if val, ok := os.LookupEnv("SP_ALLOWBINDMOUNTFROM"); ok && val != "" {
		defaultAllowBindMountFrom = val
	}
	if val, ok := os.LookupEnv("SP_PROXYCONTAINERNAME"); ok && val != "" {
		defaultProxyContainerName = val
	}

	for i := range mr {
		if val, ok := os.LookupEnv("SP_ALLOW_" + mr[i].method); ok && val != "" {
			mr[i].regexStringFromEnv = val
		}
	}

	flag.StringVar(&allowFromString, "allowfrom", defaultAllowFrom, "allowed IPs or hostname to connect to the proxy")
	flag.BoolVar(&cfg.AllowHealthcheck, "allowhealthcheck", defaultAllowHealthcheck, "allow health check requests (HEAD http://localhost:55555/health)")
	flag.BoolVar(&cfg.LogJSON, "logjson", defaultLogJSON, "log in JSON format (otherwise log in plain text")
	flag.StringVar(&listenIP, "listenip", defaultListenIP, "ip address to listen on")
	flag.StringVar(&logLevel, "loglevel", defaultLogLevel, "set log level: DEBUG, INFO, WARN, ERROR")
	flag.UintVar(&proxyPort, "proxyport", defaultProxyPort, "tcp port to listen on")
	flag.UintVar(&cfg.ShutdownGraceTime, "shutdowngracetime", defaultShutdownGraceTime, "maximum time in seconds to wait for the server to shut down gracefully")
	if cfg.ShutdownGraceTime > math.MaxInt {
		return nil, fmt.Errorf("shutdowngracetime has to be smaller than %d", math.MaxInt) // this maximum value has no practical significance
	}
	flag.StringVar(&cfg.SocketPath, "socketpath", defaultSocketPath, "unix socket path to connect to")
	flag.BoolVar(&cfg.StopOnWatchdog, "stoponwatchdog", defaultStopOnWatchdog, "stop the program when the socket gets unavailable (otherwise log only)")
	flag.UintVar(&cfg.WatchdogInterval, "watchdoginterval", defaultWatchdogInterval, "watchdog interval in seconds (0 to disable)")
	if cfg.WatchdogInterval > math.MaxInt {
		return nil, fmt.Errorf("watchdoginterval has to be smaller than %d", math.MaxInt) // this maximum value has no practical significance
	}
	flag.StringVar(&cfg.ProxySocketEndpoint, "proxysocketendpoint", defaultProxySocketEndpoint, "unix socket endpoint (if set, used instead of the TCP listener)")
	flag.UintVar(&endpointFileMode, "proxysocketendpointfilemode", defaultProxySocketEndpointFileMode, "set the file mode of the unix socket endpoint")
	flag.StringVar(&allowBindMountFromString, "allowbindmountfrom", defaultAllowBindMountFrom, "allowed directories for bind mounts (comma-separated)")
	flag.StringVar(&cfg.ProxyContainerName, "proxycontainername", defaultProxyContainerName, "socket-proxy Docker container name")
	for i := range mr {
		flag.StringVar(&mr[i].regexStringFromParam, "allow"+mr[i].method, "", "regex for "+mr[i].method+" requests (not set means method is not allowed)")
	}
	flag.Parse()

	// parse comma-separeted allowFromString into allowFrom slice
	cfg.AllowFrom = strings.Split(allowFromString, ",")

	// parse allowBindMountFromString into AllowBindMountFrom slice and validate
	if allowBindMountFromString != "" {
		allowedBindMounts, err := parseAllowedBindMounts(allowBindMountFromString)
		if err != nil {
			return nil, err
		}
		defaultAllowList.AllowedBindMounts = allowedBindMounts
	}

	// check listenIP and proxyPort
	if proxyPort < 1 || proxyPort > 65535 {
			return nil, errors.New("port number has to be between 1 and 65535")
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

	// compile regexes for allowed requests
	defaultAllowList.AllowedRequests = make(map[string]*regexp.Regexp)
	for _, rx := range mr {
		if rx.regexStringFromParam != "" {
			r, err := compileRegexp(rx.regexStringFromParam, rx.method, "command line parameter")
			if err != nil {
				return nil, err
			}
			defaultAllowList.AllowedRequests[rx.method] = r
		} else if rx.regexStringFromEnv != "" {
			r, err := compileRegexp(rx.regexStringFromEnv, rx.method, "env variable")
			if err != nil {
				return nil, err
			}
			defaultAllowList.AllowedRequests[rx.method] = r
		}
	}

	cfg.AllowLists = &allowLists
	cfg.AllowLists.Default = &defaultAllowList
	if cfg.ProxySocketEndpoint == "" && cfg.ProxyContainerName != "" {
		var err error
		cfg.ProxyContainerNetworks, err = readProxyContainerNetworks(cfg.ProxyContainerName)
		if err != nil {
			return nil, err
		}
		cfg.AllowLists.ByIP, err = readContainerLabelAllowLists(cfg.ProxyContainerNetworks)
		if err != nil {
			return nil, err
		}

		go updateAllowLists(&cfg)
	}

	return &cfg, nil
}

func compileRegexp(regex, method, configLocation string) (*regexp.Regexp, error) {
	r, err := regexp.Compile("^" + regex + "$")
	if err != nil {
		return nil, fmt.Errorf("invalid regex \"%s\" for method %s in %s: %w", regex, method, configLocation, err)
	}
	return r, nil
}

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

// return list of docker networks that the socket-proxy container is in
func readProxyContainerNetworks(proxyContainerName string) ([]string, error) {
	var networks []string
	dockerClient, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return nil, err
	}
	defer dockerClient.Close()

	filter := filters.NewArgs()
	filter.Add("name", proxyContainerName)
	containers, err := dockerClient.ContainerList(context.Background(), container.ListOptions{Filters: filter})
	if err != nil {
		return nil, err
	}
	if len(containers) == 0 {
		return nil, fmt.Errorf("socket-proxy container \"%s\" was not found", proxyContainerName)
	}

	for networkID, _ := range containers[0].NetworkSettings.Networks {
		networks = append(networks, networkID)
	}

	return networks, nil
}

// return AllowListRegistry with allowlists specified by docker container labels
func readContainerLabelAllowLists(networks []string) (map[string]*AllowList, error) {
	allowListsByIP := make(map[string]*AllowList)

	dockerClient, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return nil, err
	}
	defer dockerClient.Close()

	var methods []string
	for _, rx := range mr {
		methods = append(methods, rx.method)
	}

	ctx := context.Background()
	for _, network := range networks {
		filter := filters.NewArgs()
		filter.Add("network", network)
		containers, err := dockerClient.ContainerList(ctx, container.ListOptions{Filters: filter})
		if err != nil {
			return nil, err
		}

		for _, cntr := range containers {
			allowedRequests, allowedBindMounts, err := extractLabelData(cntr, methods)
			if err != nil {
				return nil, err
			}

			if len(allowedRequests) > 0 || len(allowedBindMounts) > 0 {
				allowList := AllowList{
					ID: cntr.ID,
					AllowedRequests: allowedRequests,
					AllowedBindMounts: allowedBindMounts,
				}

				ipv4Address := cntr.NetworkSettings.Networks[network].IPAddress
				if len(ipv4Address) > 0 {
					allowListsByIP[ipv4Address] = &allowList
				}
				ipv6Address := cntr.NetworkSettings.Networks[network].GlobalIPv6Address
				if len(ipv6Address) > 0 {
					allowListsByIP[ipv6Address] = &allowList
				}
			}
		}
	}

	return allowListsByIP, nil
}

func extractLabelData(cntr container.Summary, methods []string) (map[string]*regexp.Regexp, []string, error) {
	allowedRequests := make(map[string]*regexp.Regexp)
	allowedBindMounts := []string{}
	for labelName, labelValue := range cntr.Labels {
		if strings.HasPrefix(labelName, allowedDockerLabelPrefix) && labelValue != "" {
			allowSpec := strings.ToUpper(strings.TrimPrefix(labelName, allowedDockerLabelPrefix))
			if slices.Contains(methods, allowSpec) {
				r, err := compileRegexp(labelValue, allowSpec, "docker container label")
				if err != nil {
					return nil, nil, err
				}
				allowedRequests[allowSpec] = r
			} else if allowSpec == "BINDMOUNTFROM" {
				var err error
				allowedBindMounts, err = parseAllowedBindMounts(labelValue)
				if err != nil {
					return nil, nil, err
				}
			}
		}
	}
	return allowedRequests, allowedBindMounts, nil
}

func updateAllowLists(cfg *Config) {
	dockerClient, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		slog.Error("failed to create Docker client", "error", err)
		return
	}
	defer dockerClient.Close()

	ctx := context.Background()
	filter := filters.NewArgs()
	filter.Add("type", "container")
	filter.Add("event", "start")
	filter.Add("event", "die")
	eventsChan, errChan := dockerClient.Events(ctx, events.ListOptions{Filters: filter})
	if err != nil {
		slog.Error("failed to subscribe to Docker event stream", "error", err)
		return
	}

	select {
	case event := <- eventsChan:
		updateErr := updateAllowListsFromEvent(cfg, dockerClient, event)
		if updateErr != nil {
			slog.Error("error when updating allowlists", "error", updateErr)
			return
		}
	case err := <- errChan:
		slog.Error("received error from Docker event stream", "error", err)
		return
	}
}

func updateAllowListsFromEvent(cfg *Config, dockerClient *client.Client, event events.Message) error {
	containerID := event.Actor.ID

	switch event.Action {
	case "start":
		err := addAllowList(cfg, dockerClient, containerID)
		if err != nil {
			return err
		}
	case "die":
		removeAllowList(cfg, containerID)
	}
	return nil
}

func addAllowList(cfg *Config, dockerClient *client.Client, containerID string) error {
	cfg.AllowLists.Mutex.Lock()
	defer cfg.AllowLists.Mutex.Unlock()

	var methods []string
	for _, rx := range mr {
		methods = append(methods, rx.method)
	}

	filter := filters.NewArgs()
	filter.Add("id", containerID)
	containers, err := dockerClient.ContainerList(context.Background(), container.ListOptions{Filters: filter})
	if err != nil {
		return err
	}
	if len(containers) == 0 {
		return fmt.Errorf("newly started container ID \"%s\" was not found", containerID)
	}
	cntr := containers[0]

	allowedRequests, allowedBindMounts, err := extractLabelData(cntr, methods)

	if len(allowedRequests) > 0 || len(allowedBindMounts) > 0 {
		allowList := AllowList{
			ID: cntr.ID,
			AllowedRequests: allowedRequests,
			AllowedBindMounts: allowedBindMounts,
		}

		for networkID, cntrNetwork := range cntr.NetworkSettings.Networks {
			if slices.Contains(cfg.ProxyContainerNetworks, networkID) {
				ipv4Address := cntrNetwork.IPAddress
				if len(ipv4Address) > 0 {
					cfg.AllowLists.ByIP[ipv4Address] = &allowList
				}
				ipv6Address := cntrNetwork.GlobalIPv6Address
				if len(ipv6Address) > 0 {
					cfg.AllowLists.ByIP[ipv6Address] = &allowList
				}
			}
		}
	}

	return nil
}

func removeAllowList(cfg *Config, containerID string) {
	cfg.AllowLists.Mutex.Lock()
	defer cfg.AllowLists.Mutex.Unlock()

	for ip, allowList := range cfg.AllowLists.ByIP {
		if allowList.ID == containerID {
			delete(cfg.AllowLists.ByIP, ip)
		}
	}
}
