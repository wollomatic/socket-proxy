package config

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wollomatic/socket-proxy/internal/docker/api/types/container"
	"github.com/wollomatic/socket-proxy/internal/docker/api/types/events"
	"github.com/wollomatic/socket-proxy/internal/docker/api/types/network"
)

func Test_extractLabelData(t *testing.T) {
	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		cntr    container.Summary
		prefix  string
		want    map[string][]*regexp.Regexp
		want2   []string
		wantErr bool
	}{
		{
			name: "valid labels with multiple methods and regexes",
			cntr: container.Summary{
				Labels: map[string]string{
					"socket-proxy.allow.get.0": "regex1",
					"socket-proxy.allow.get.1": "regex2",
					"socket-proxy.allow.post":  "regex3",
				},
			},
			want: map[string][]*regexp.Regexp{
				"GET":  {regexp.MustCompile("^regex1$"), regexp.MustCompile("^regex2$")},
				"POST": {regexp.MustCompile("^regex3$")},
			},
			want2:   nil,
			wantErr: false,
		},
		{
			name: "invalid regex in label value",
			cntr: container.Summary{
				Labels: map[string]string{
					"socket-proxy.allow.get": "invalid[regex",
				},
			},
			want:    nil,
			want2:   nil,
			wantErr: true,
		},
		{
			name: "custom label prefix ignores the default prefix",
			cntr: container.Summary{
				Labels: map[string]string{
					"socket-proxy.allow.get":            "default",
					"gameserver-socket-proxy.allow.get": "custom",
				},
			},
			prefix: "gameserver-socket-proxy",
			want: map[string][]*regexp.Regexp{
				"GET": {regexp.MustCompile("^custom$")},
			},
		},
		{
			name: "non-allow labels are ignored",
			cntr: container.Summary{
				Labels: map[string]string{
					"socket-proxy.allow.get": "regex1",
					"other.label":            "value",
				},
			},
			want: map[string][]*regexp.Regexp{
				"GET": {regexp.MustCompile("^regex1$")},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			previousPrefix := allowedDockerLabelPrefix
			defer func() { allowedDockerLabelPrefix = previousPrefix }()
			allowedDockerLabelPrefix = defaultDockerLabelPrefix + ".allow."
			if tt.prefix != "" {
				allowedDockerLabelPrefix = tt.prefix + ".allow."
			}
			got, got2, gotErr := extractLabelData(tt.cntr)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("extractLabelData() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("extractLabelData() succeeded unexpectedly")
			}
			if !regexMapsEqual(got, tt.want) {
				t.Errorf("extractLabelData() = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got2, tt.want2) {
				t.Errorf("extractLabelData() = %v, want %v", got2, tt.want2)
			}
		})
	}
}

func TestContainerName(t *testing.T) {
	tests := []struct {
		name string
		cntr container.Summary
		want string
	}{
		{
			name: "uses the first Docker container name",
			cntr: container.Summary{ID: "0123456789abcdef", Names: []string{"/traefik", "/ignored"}},
			want: "traefik",
		},
		{
			name: "falls back to the short ID when Docker provides no name",
			cntr: container.Summary{ID: "0123456789abcdef"},
			want: "0123456789ab",
		},
		{
			name: "does not panic for a short fallback ID",
			cntr: container.Summary{ID: "short"},
			want: "short",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := containerName(tt.cntr); got != tt.want {
				t.Errorf("containerName() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestEventContainerName(t *testing.T) {
	tests := []struct {
		name  string
		event events.Message
		want  string
	}{
		{
			name:  "uses the container name from event attributes",
			event: events.Message{Actor: events.Actor{ID: "0123456789abcdef", Attributes: map[string]string{"name": "traefik"}}},
			want:  "traefik",
		},
		{
			name:  "falls back to the short ID when the event has no name",
			event: events.Message{Actor: events.Actor{ID: "0123456789abcdef"}},
			want:  "0123456789ab",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := eventContainerName(tt.event); got != tt.want {
				t.Errorf("eventContainerName() = %q, want %q", got, tt.want)
			}
		})
	}
}

func regexMapsEqual(a, b map[string][]*regexp.Regexp) bool {
	if len(a) != len(b) {
		return false
	}
	for method, aRegexes := range a {
		bRegexes, ok := b[method]
		if !ok || len(aRegexes) != len(bRegexes) {
			return false
		}
		aRegexStrings := make([]string, 0, len(aRegexes))
		for _, ar := range aRegexes {
			aRegexStrings = append(aRegexStrings, ar.String())
		}
		bRegexStrings := make([]string, 0, len(bRegexes))
		for _, br := range bRegexes {
			bRegexStrings = append(bRegexStrings, br.String())
		}
		sort.Strings(aRegexStrings)
		sort.Strings(bRegexStrings)
		for i, ar := range aRegexStrings {
			if ar != bRegexStrings[i] {
				return false
			}
		}
	}
	return true
}

func TestRefreshAllowLists(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "docker.sock")
	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", socketPath)
	if err != nil {
		t.Fatalf("listen on Docker test socket: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		_ = http.Serve(listener, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/_ping":
				w.Header().Set("Api-Version", "1.51")
			case "/v1.51/containers/json":
				if err := json.NewEncoder(w).Encode([]container.Summary{{
					ID: "container-id",
					Labels: map[string]string{
						"socket-proxy.allow.get": "/version",
					},
					NetworkSettings: &container.NetworkSettingsSummary{Networks: map[string]*network.EndpointSettings{
						"proxy-network": {IPAddress: "172.20.0.2"},
					}},
				}}); err != nil {
					t.Errorf("encode container list: %v", err)
				}
			default:
				http.NotFound(w, r)
			}
		}))
	}()

	cfg := Config{
		SocketPath: socketPath,
		AllowLists: &AllowListRegistry{
			networks: []string{"proxy-network"},
		},
	}
	refreshedAllowLists, err := cfg.RefreshAllowLists(context.Background())
	if err != nil {
		t.Fatalf("RefreshAllowLists() error = %v", err)
	}

	allowList, found := refreshedAllowLists.FindByIP("172.20.0.2")
	if !found {
		t.Fatal("allowlist was not added for container IP")
	}
	if !matchAny(allowList.AllowedRequests[http.MethodGet], "/version") {
		t.Fatal("refreshed allowlist does not contain the container label")
	}
}

func TestRefreshAllowListsErrorPreservesRegistry(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "docker.sock")
	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", socketPath)
	if err != nil {
		t.Fatalf("listen on Docker test socket: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		_ = http.Serve(listener, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/_ping":
				w.Header().Set("Api-Version", "1.51")
			case "/v1.51/containers/json":
				if err := json.NewEncoder(w).Encode([]container.Summary{{
					ID: "container-id",
					Labels: map[string]string{
						"socket-proxy.allow.get": "invalid[regex",
					},
					NetworkSettings: &container.NetworkSettingsSummary{Networks: map[string]*network.EndpointSettings{
						"proxy-network": {IPAddress: "172.20.0.3"},
					}},
				}}); err != nil {
					t.Errorf("encode container list: %v", err)
				}
			default:
				http.NotFound(w, r)
			}
		}))
	}()

	const initialRevision = 7
	cfg := Config{
		SocketPath: socketPath,
		AllowLists: &AllowListRegistry{
			revision: initialRevision,
			networks: []string{"proxy-network"},
			byIP: map[string]AllowList{
				"172.20.0.2": {ID: "existing-container-id"},
			},
		},
	}
	if _, err := cfg.RefreshAllowLists(context.Background()); err == nil {
		t.Fatal("RefreshAllowLists() unexpectedly succeeded")
	}

	allowList, found := cfg.AllowLists.FindByIP("172.20.0.2")
	if !found || allowList.ID != "existing-container-id" {
		t.Fatal("RefreshAllowLists() modified the existing allowlist after an error")
	}
	cfg.AllowLists.mutex.RLock()
	revision := cfg.AllowLists.revision
	cfg.AllowLists.mutex.RUnlock()
	if revision != initialRevision {
		t.Fatalf("revision = %d, want %d", revision, initialRevision)
	}
}

func TestRefreshDoesNotOverwriteNewerEventUpdate(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "docker.sock")
	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", socketPath)
	if err != nil {
		t.Fatalf("listen on Docker test socket: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	requestStarted := make(chan struct{})
	releaseRequest := make(chan struct{})
	var (
		containerListRequests atomic.Int32
		startOnce             sync.Once
		releaseOnce           sync.Once
	)
	release := func() {
		releaseOnce.Do(func() { close(releaseRequest) })
	}
	t.Cleanup(release)

	go func() {
		_ = http.Serve(listener, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/_ping":
				w.Header().Set("Api-Version", "1.51")
			case "/v1.51/containers/json":
				if containerListRequests.Add(1) != 1 {
					if err := json.NewEncoder(w).Encode([]container.Summary{}); err != nil {
						t.Errorf("encode container list: %v", err)
					}
					return
				}
				startOnce.Do(func() { close(requestStarted) })
				<-releaseRequest
				if err := json.NewEncoder(w).Encode([]container.Summary{{
					ID: "stopped-container-id",
					Labels: map[string]string{
						"socket-proxy.allow.get": "/version",
					},
					NetworkSettings: &container.NetworkSettingsSummary{Networks: map[string]*network.EndpointSettings{
						"proxy-network": {IPAddress: "172.20.0.2"},
					}},
				}}); err != nil {
					t.Errorf("encode container list: %v", err)
				}
			default:
				http.NotFound(w, r)
			}
		}))
	}()

	cfg := Config{
		SocketPath: socketPath,
		AllowLists: &AllowListRegistry{
			networks: []string{"proxy-network"},
			byIP: map[string]AllowList{
				"172.20.0.2": {ID: "stopped-container-id"},
			},
		},
	}
	refreshResult := make(chan error, 1)
	go func() {
		_, refreshErr := cfg.RefreshAllowLists(context.Background())
		refreshResult <- refreshErr
	}()

	select {
	case <-requestStarted:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for Docker refresh to start")
	}

	_, removedIPs, err := cfg.AllowLists.updateFromEvent(context.Background(), nil, events.Message{
		Action: events.ActionDie,
		Actor:  events.Actor{ID: "stopped-container-id"},
	})
	if err != nil {
		t.Fatalf("updateFromEvent() error = %v", err)
	}
	if !reflect.DeepEqual(removedIPs, []string{"172.20.0.2"}) {
		t.Fatalf("removed IPs = %v, want [172.20.0.2]", removedIPs)
	}

	release()
	select {
	case err := <-refreshResult:
		if err != nil {
			t.Fatalf("RefreshAllowLists() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for Docker refresh retry")
	}
	if got := containerListRequests.Load(); got != 2 {
		t.Fatalf("Docker container list requests = %d, want 2", got)
	}
	if _, found := cfg.AllowLists.FindByIP("172.20.0.2"); found {
		t.Fatal("refresh restored the allowlist removed by a newer event")
	}
}

func TestRefreshRevisionRetriesRespectTimeout(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "docker.sock")
	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", socketPath)
	if err != nil {
		t.Fatalf("listen on Docker test socket: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	const refreshTimeout = 50 * time.Millisecond
	var containerListRequests atomic.Int32
	cfg := Config{
		SocketPath: socketPath,
		AllowLists: &AllowListRegistry{
			byIP: map[string]AllowList{
				"172.20.0.2": {ID: "existing-container-id"},
			},
		},
		allowListsRefresh: allowListsRefreshState{
			timeout: refreshTimeout,
		},
	}

	go func() {
		_ = http.Serve(listener, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/_ping":
				w.Header().Set("Api-Version", "1.51")
			case "/v1.51/containers/json":
				containerListRequests.Add(1)
				cfg.AllowLists.mutex.Lock()
				cfg.AllowLists.revision++
				cfg.AllowLists.mutex.Unlock()
				if err := json.NewEncoder(w).Encode([]container.Summary{}); err != nil {
					t.Errorf("encode container list: %v", err)
				}
			default:
				http.NotFound(w, r)
			}
		}))
	}()

	if _, err := cfg.RefreshAllowLists(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("RefreshAllowLists() error = %v, want context.DeadlineExceeded", err)
	}
	maxRequests := int32(refreshTimeout/allowListsRefreshRetryBackoff) + 1
	if got := containerListRequests.Load(); got > maxRequests {
		t.Fatalf("Docker container list requests = %d, want at most %d", got, maxRequests)
	}
	if _, found := cfg.AllowLists.FindByIP("172.20.0.2"); !found {
		t.Fatal("timed-out refresh replaced the existing allowlist")
	}
}

func TestRefreshCoalescing(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "docker.sock")
	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", socketPath)
	if err != nil {
		t.Fatalf("listen on Docker test socket: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	var (
		containerListRequests atomic.Int32
		requestStarted        = make(chan struct{})
		releaseRequest        = make(chan struct{})
		startOnce             sync.Once
		releaseOnce           sync.Once
	)
	release := func() {
		releaseOnce.Do(func() { close(releaseRequest) })
	}
	t.Cleanup(release)

	go func() {
		_ = http.Serve(listener, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/_ping":
				w.Header().Set("Api-Version", "1.51")
			case "/v1.51/containers/json":
				containerListRequests.Add(1)
				startOnce.Do(func() { close(requestStarted) })
				<-releaseRequest
				http.Error(w, "Docker unavailable", http.StatusServiceUnavailable)
			default:
				http.NotFound(w, r)
			}
		}))
	}()

	cfg := Config{
		SocketPath: socketPath,
		AllowLists: &AllowListRegistry{},
	}
	firstResult := make(chan error, 1)
	go func() {
		_, refreshErr := cfg.RefreshAllowLists(context.Background())
		firstResult <- refreshErr
	}()

	select {
	case <-requestStarted:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for Docker refresh to start")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := cfg.RefreshAllowLists(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("RefreshAllowLists() error = %v, want context.DeadlineExceeded", err)
	}

	const callers = 8
	results := make(chan error, callers)
	for range callers {
		go func() {
			_, refreshErr := cfg.RefreshAllowLists(context.Background())
			results <- refreshErr
		}()
	}
	release()

	if err := <-firstResult; err == nil {
		t.Fatal("first RefreshAllowLists() unexpectedly succeeded")
	}
	for range callers {
		if err := <-results; err == nil {
			t.Fatal("shared RefreshAllowLists() unexpectedly succeeded")
		}
	}
	if got := containerListRequests.Load(); got != 1 {
		t.Fatalf("Docker container list requests = %d, want 1", got)
	}

	if _, err := cfg.RefreshAllowLists(context.Background()); err == nil {
		t.Fatal("cached RefreshAllowLists() unexpectedly succeeded")
	}
	if got := containerListRequests.Load(); got != 1 {
		t.Fatalf("Docker container list requests during cooldown = %d, want 1", got)
	}
}

func TestRefreshTimeoutClearsInFlightRefresh(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "docker.sock")
	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", socketPath)
	if err != nil {
		t.Fatalf("listen on Docker test socket: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	var containerListRequests atomic.Int32
	firstRequestCanceled := make(chan struct{})
	go func() {
		_ = http.Serve(listener, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/_ping":
				w.Header().Set("Api-Version", "1.51")
			case "/v1.51/containers/json":
				if containerListRequests.Add(1) == 1 {
					<-r.Context().Done()
					close(firstRequestCanceled)
					return
				}
				if err := json.NewEncoder(w).Encode([]container.Summary{}); err != nil {
					t.Errorf("encode container list: %v", err)
				}
			default:
				http.NotFound(w, r)
			}
		}))
	}()

	cfg := Config{
		SocketPath: socketPath,
		AllowLists: &AllowListRegistry{},
		allowListsRefresh: allowListsRefreshState{
			timeout: 100 * time.Millisecond,
		},
	}
	if _, err := cfg.RefreshAllowLists(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("RefreshAllowLists() error = %v, want context.DeadlineExceeded", err)
	}
	select {
	case <-firstRequestCanceled:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for Docker request cancellation")
	}

	// Bypass the result cooldown so the retry exercises the cleared in-flight state.
	cfg.allowListsRefresh.mutex.Lock()
	cfg.allowListsRefresh.completed = time.Time{}
	cfg.allowListsRefresh.mutex.Unlock()

	if _, err := cfg.RefreshAllowLists(context.Background()); err != nil {
		t.Fatalf("retry RefreshAllowLists() error = %v", err)
	}
	if got := containerListRequests.Load(); got != 2 {
		t.Fatalf("Docker container list requests = %d, want 2", got)
	}
}

func matchAny(regexes []*regexp.Regexp, value string) bool {
	for _, regex := range regexes {
		if regex.MatchString(value) {
			return true
		}
	}
	return false
}
