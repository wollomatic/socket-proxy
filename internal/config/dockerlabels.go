package config

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/wollomatic/socket-proxy/internal/docker/api/types/container"
	"github.com/wollomatic/socket-proxy/internal/docker/api/types/events"
	"github.com/wollomatic/socket-proxy/internal/docker/api/types/filters"
	"github.com/wollomatic/socket-proxy/internal/docker/client"
)

const (
	allowedDockerLabelPrefix        = "socket-proxy.allow."
	allowListsRefreshCooldown       = time.Second
	defaultAllowListsRefreshTimeout = 10 * time.Second
)

type allowListsRefreshState struct {
	mutex      sync.Mutex
	inFlight   *allowListsRefresh
	completed  time.Time
	lastResult *AllowListRegistry
	lastError  error
	timeout    time.Duration // zero uses defaultAllowListsRefreshTimeout
}

type allowListsRefresh struct {
	done       chan struct{}
	allowLists *AllowListRegistry
	err        error
}

type AllowListRegistry struct {
	mutex    sync.RWMutex         // mutex to control read/write of byIP and revision
	revision uint64               // generation used to detect updates during Docker snapshots
	networks []string             // names of networks in which socket proxy access is allowed for non-default allowlists
	Default  AllowList            // default allowlist
	byIP     map[string]AllowList // map container IP address to allowlist for that container
}

// UpdateAllowLists populates the byIP allowlists then keeps them updated.
func (cfg *Config) UpdateAllowLists() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dockerClient, err := client.NewClientWithOpts(
		client.WithHost("unix://"+cfg.SocketPath),
		client.WithAPIVersionNegotiation(),
	)
	if err != nil {
		slog.Error("failed to create Docker client", "error", err)
		return
	}
	defer func(dockerClient *client.Client) {
		err := dockerClient.Close()
		if err != nil {
			slog.Error("failed to close Docker client", "error", err)
		}
	}(dockerClient)

	err = cfg.AllowLists.initByIP(ctx, dockerClient)
	if err != nil {
		slog.Error("failed to initialise non-default allowlists", "error", err)
		return
	}
	slog.Debug("initialised non-default allowlists")

	filter := filters.NewArgs()
	filter.Add("type", "container")
	filter.Add("event", "start")
	filter.Add("event", "restart")
	filter.Add("event", "die")
	eventsChan, errChan := dockerClient.Events(ctx, events.ListOptions{Filters: filter})
	slog.Debug("subscribed to Docker event stream to update allowlists")

	// print non-default request allowlists
	cfg.AllowLists.PrintByIP(cfg.LogJSON)

	// handle Docker events to update allowlists
	for {
		select {
		case event, ok := <-eventsChan:
			if !ok {
				slog.Info("Docker event stream closed")
				return
			}
			containerName := eventContainerName(event)
			slog.Debug("received Docker container event", "action", event.Action, "container", containerName)
			addedIPs, removedIPs, updateErr := cfg.AllowLists.updateFromEvent(ctx, dockerClient, event)
			if updateErr != nil {
				slog.Warn("failed to update allowlists from container event", "error", updateErr)
				continue
			}
			for _, ip := range addedIPs {
				cfg.AllowLists.mutex.RLock()
				allowList, found := cfg.AllowLists.byIP[ip]
				cfg.AllowLists.mutex.RUnlock()
				if found {
					allowList.Print(ip, cfg.LogJSON)
				}
			}
			for _, ip := range removedIPs {
				slog.Info("removed allowlist for container", "container", containerName, "ip", ip)
			}
		case err := <-errChan:
			if err != nil {
				slog.Error("received error from Docker event stream", "error", err)
				return
			}
		}
	}
}

// RefreshAllowLists updates the per-container allowlists from Docker. Concurrent
// callers share an in-flight refresh, and recently completed results are reused
// to avoid repeatedly scanning Docker during bursts of rejected requests.
func (cfg *Config) RefreshAllowLists(ctx context.Context) (*AllowListRegistry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	state := &cfg.allowListsRefresh
	state.mutex.Lock()
	if refresh := state.inFlight; refresh != nil {
		state.mutex.Unlock()
		return waitForAllowListsRefresh(ctx, refresh)
	}
	if time.Since(state.completed) < allowListsRefreshCooldown {
		allowLists, err := state.lastResult, state.lastError
		state.mutex.Unlock()
		return allowLists, err
	}
	refresh := &allowListsRefresh{done: make(chan struct{})}
	state.inFlight = refresh
	timeout := state.timeout
	if timeout <= 0 {
		timeout = defaultAllowListsRefreshTimeout
	}
	state.mutex.Unlock()

	refreshCtx, cancel := context.WithTimeout(context.Background(), timeout)
	go func() {
		defer cancel()
		cfg.refreshAllowLists(refreshCtx, refresh)
	}()
	return waitForAllowListsRefresh(ctx, refresh)
}

func (cfg *Config) refreshAllowLists(ctx context.Context, refresh *allowListsRefresh) {
	dockerClient, err := client.NewClientWithOpts(
		client.WithHost("unix://"+cfg.SocketPath),
		client.WithAPIVersionNegotiation(),
	)
	if err == nil {
		err = cfg.AllowLists.initByIP(ctx, dockerClient)
		if closeErr := dockerClient.Close(); closeErr != nil {
			slog.Error("failed to close Docker client", "error", closeErr)
		}
	}

	state := &cfg.allowListsRefresh
	state.mutex.Lock()
	refresh.allowLists = cfg.AllowLists
	refresh.err = err
	state.lastResult = refresh.allowLists
	state.lastError = err
	state.completed = time.Now()
	state.inFlight = nil
	close(refresh.done)
	state.mutex.Unlock()
}

func waitForAllowListsRefresh(ctx context.Context, refresh *allowListsRefresh) (*AllowListRegistry, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-refresh.done:
		return refresh.allowLists, refresh.err
	}
}

// PrintNetworks prints the allowed networks.
func (allowLists *AllowListRegistry) PrintNetworks() {
	if len(allowLists.networks) > 0 {
		slog.Info("socket proxy networks detected", "socketproxynetworks", allowLists.networks)
	} else {
		// we only log this on DEBUG level because the socket proxy networks are used for per-container allowlists
		slog.Debug("no socket proxy networks detected")
	}
}

// PrintDefault prints the default allowlist.
func (allowLists *AllowListRegistry) PrintDefault(logJSON bool) {
	allowLists.Default.Print("", logJSON)
}

// PrintByIP prints the non-default allowlists.
func (allowLists *AllowListRegistry) PrintByIP(logJSON bool) {
	allowLists.mutex.RLock()
	defer allowLists.mutex.RUnlock()
	for ip, allowList := range allowLists.byIP {
		allowList.Print(ip, logJSON)
	}
}

// FindByIP returns the allowlist corresponding to the given IP address if found.
func (allowLists *AllowListRegistry) FindByIP(ip string) (AllowList, bool) {
	allowLists.mutex.RLock()
	defer allowLists.mutex.RUnlock()
	allowList, found := allowLists.byIP[ip]
	return allowList, found
}

// initialise allowlist registry byIP allowlists
func (allowLists *AllowListRegistry) initByIP(ctx context.Context, dockerClient *client.Client) error {
	filter := filters.NewArgs()
	for _, network := range allowLists.networks {
		filter.Add("network", network)
	}

	var containers []container.Summary
	for {
		allowLists.mutex.RLock()
		snapshotRevision := allowLists.revision
		allowLists.mutex.RUnlock()

		var err error
		containers, err = dockerClient.ContainerList(ctx, container.ListOptions{Filters: filter})
		if err != nil {
			return err
		}

		allowLists.mutex.Lock()
		if allowLists.revision == snapshotRevision {
			break
		}
		allowLists.mutex.Unlock()
	}
	defer allowLists.mutex.Unlock()

	allowLists.byIP = make(map[string]AllowList)

	for _, cntr := range containers {
		allowedRequests, allowedBindMounts, err := extractLabelData(cntr)
		if err != nil {
			allowLists.byIP = nil
			allowLists.revision++
			return err
		}

		if len(allowedRequests) > 0 || len(allowedBindMounts) > 0 {
			for networkID, cntrNetwork := range cntr.NetworkSettings.Networks {
				if slices.Contains(allowLists.networks, networkID) {
					allowList := AllowList{
						ID:                cntr.ID,
						ContainerName:     containerName(cntr),
						AllowedRequests:   allowedRequests,
						AllowedBindMounts: allowedBindMounts,
					}

					if len(cntrNetwork.IPAddress) > 0 {
						allowLists.byIP[cntrNetwork.IPAddress] = allowList
					}
					if len(cntrNetwork.GlobalIPv6Address) > 0 {
						allowLists.byIP[cntrNetwork.GlobalIPv6Address] = allowList
					}
				}
			}
		}
	}

	allowLists.revision++
	return nil
}

// update the allowlist registry based on the Docker event
func (allowLists *AllowListRegistry) updateFromEvent(
	ctx context.Context, dockerClient *client.Client, event events.Message,
) ([]string, []string, error) {
	allowLists.mutex.Lock()
	allowLists.revision++
	allowLists.mutex.Unlock()

	containerID := event.Actor.ID
	var (
		addedIPs   []string
		removedIPs []string
		err        error
	)

	switch event.Action {
	case "start", "restart":
		addedIPs, err = allowLists.add(ctx, dockerClient, containerID)
		if err != nil {
			return nil, nil, err
		}
	case "die":
		removedIPs = allowLists.remove(containerID)
	}
	return addedIPs, removedIPs, nil
}

// add the allowlist for the container with the given ID to the allowlist registry
// if it has at least one socket-proxy allow label and is in a same network as the socket-proxy
func (allowLists *AllowListRegistry) add(
	ctx context.Context, dockerClient *client.Client, containerID string,
) ([]string, error) {
	filter := filters.NewArgs()
	filter.Add("id", containerID)
	for _, network := range allowLists.networks {
		filter.Add("network", network)
	}
	containers, err := dockerClient.ContainerList(ctx, container.ListOptions{Filters: filter})
	if err != nil {
		return nil, err
	}
	if len(containers) == 0 {
		slog.Debug("container is not in a network with socket-proxy or may have stopped", "id", shortContainerID(containerID))
		return nil, nil
	}
	cntr := containers[0]

	allowedRequests, allowedBindMounts, err := extractLabelData(cntr)
	if err != nil {
		return nil, err
	}

	var ips []string
	if len(allowedRequests) > 0 || len(allowedBindMounts) > 0 {
		allowList := AllowList{
			ID:                cntr.ID,
			ContainerName:     containerName(cntr),
			AllowedRequests:   allowedRequests,
			AllowedBindMounts: allowedBindMounts,
		}

		allowLists.mutex.Lock()
		defer allowLists.mutex.Unlock()

		if allowLists.byIP == nil {
			allowLists.byIP = make(map[string]AllowList)
		}

		for networkID, cntrNetwork := range cntr.NetworkSettings.Networks {
			if slices.Contains(allowLists.networks, networkID) {
				ipv4Address := cntrNetwork.IPAddress
				if len(ipv4Address) > 0 {
					allowLists.byIP[ipv4Address] = allowList
					ips = append(ips, ipv4Address)
				}
				ipv6Address := cntrNetwork.GlobalIPv6Address
				if len(ipv6Address) > 0 {
					allowLists.byIP[ipv6Address] = allowList
					ips = append(ips, ipv6Address)
				}
			}
		}
	}

	return ips, nil
}

// remove allowlists having the given container ID from the allowlist registry
func (allowLists *AllowListRegistry) remove(containerID string) []string {
	allowLists.mutex.Lock()
	defer allowLists.mutex.Unlock()

	var removedIPs []string
	for ip, allowList := range allowLists.byIP {
		if allowList.ID == containerID {
			delete(allowLists.byIP, ip)
			removedIPs = append(removedIPs, ip)
		}
	}
	return removedIPs
}

// containerName returns Docker's container name without its leading slash.
// It falls back to the short container ID for unusual responses without a name.
func containerName(cntr container.Summary) string {
	for _, name := range cntr.Names {
		if name = strings.TrimPrefix(name, "/"); name != "" {
			return name
		}
	}
	return shortContainerID(cntr.ID)
}

// eventContainerName returns the name Docker includes with container events.
// It falls back to the short container ID when the event has no name.
func eventContainerName(event events.Message) string {
	if name := event.Actor.Attributes["name"]; name != "" {
		return name
	}
	return shortContainerID(event.Actor.ID)
}

func shortContainerID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// return list of docker networks that the socket proxy container is in
func listSocketProxyNetworks(socketPath, proxyContainerName string) ([]string, error) {
	cntr, err := getSocketProxyContainerSummary(socketPath, proxyContainerName)
	if err != nil {
		return nil, err
	}

	networks := make([]string, 0, len(cntr.NetworkSettings.Networks))
	for networkID := range cntr.NetworkSettings.Networks {
		networks = append(networks, networkID)
	}
	return networks, nil
}

// return Docker container summary for the socket proxy container
func getSocketProxyContainerSummary(socketPath, proxyContainerName string) (container.Summary, error) {
	const maxTries = 3

	dockerClient, err := client.NewClientWithOpts(
		client.WithHost("unix://"+socketPath),
		client.WithAPIVersionNegotiation(),
	)
	if err != nil {
		return container.Summary{}, err
	}
	defer func(dockerClient *client.Client) {
		err := dockerClient.Close()
		if err != nil {
			slog.Error("failed to close Docker client", "error", err)
		}
	}(dockerClient)

	ctx := context.Background()
	filter := filters.NewArgs()
	filter.Add("name", proxyContainerName)
	var containers []container.Summary
	for i := 1; i <= maxTries; i++ {
		containers, err = dockerClient.ContainerList(ctx, container.ListOptions{Filters: filter})
		if err != nil {
			return container.Summary{}, err
		}
		if len(containers) > 0 {
			return containers[0], nil
		}
		if i < maxTries {
			time.Sleep(time.Duration(i) * time.Second)
		}
	}
	return container.Summary{}, fmt.Errorf("socket-proxy container \"%s\" was not found after %d attempts; verify the container name is correct and the container is running", proxyContainerName, maxTries)
}

// extract Docker container allowlist label data from the container summary
func extractLabelData(cntr container.Summary) (map[string][]*regexp.Regexp, []string, error) {
	allowedRequests := make(map[string][]*regexp.Regexp)
	var allowedBindMounts []string
	for labelName, labelValue := range cntr.Labels {
		if strings.HasPrefix(labelName, allowedDockerLabelPrefix) && labelValue != "" {
			allowSpec := strings.ToUpper(strings.TrimPrefix(labelName, allowedDockerLabelPrefix))
			method, _, _ := strings.Cut(allowSpec, ".")
			if slices.Contains(supportedHTTPMethods, method) {
				r, err := compileRegexp(labelValue, method, "docker container label")
				if err != nil {
					return nil, nil, err
				}
				allowedRequests[method] = append(allowedRequests[method], r)
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
