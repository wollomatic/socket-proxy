package main

import (
	"bytes"
	"net/http"
	"runtime"
	"testing"
)

func skipIfNotUnix(t *testing.T) {
	switch runtime.GOOS {
	case "linux", "darwin", "freebsd", "openbsd", "netbsd", "dragonfly", "solaris", "aix":
		// Supported Unix platforms
	default:
		t.Skip("skipping test: only runs on Unix-like systems")
	}
}

func TestValidateBindMountSource(t *testing.T) {
	skipIfNotUnix(t)

	allowedBindMounts := []string{"/home", "/var/log"}

	tests := []struct {
		name       string
		source     string
		shouldPass bool
	}{
		{"exact match", "/home", true},
		{"subdirectory", "/home/user", true},
		{"deep subdirectory", "/home/user/data", true},
		{"not allowed", "/etc", false},
		{"empty source", "", true},      // empty sources are skipped
		{"relative path", "home", true}, // relative paths are skipped
		{"var log exact", "/var/log", true},
		{"var log subdir", "/var/log/app", true},
		{"similar but different", "/home2", false},
		{"prefix but not subdir", "/home2/user", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateBindMountSource(allowedBindMounts, tt.source)
			if tt.shouldPass && err != nil {
				t.Errorf("expected %s to pass, but got error: %v", tt.source, err)
			}
			if !tt.shouldPass && err == nil {
				t.Errorf("expected %s to fail, but it passed", tt.source)
			}
		})
	}
}

func TestIsPathAllowed(t *testing.T) {
	skipIfNotUnix(t)

	tests := []struct {
		name       string
		path       string
		allowedDir string
		expected   bool
	}{
		{"exact match", "/home", "/home", true},
		{"subdirectory", "/home/user", "/home", true},
		{"deep subdirectory", "/home/user/data", "/home", true},
		{"not subdirectory", "/etc", "/home", false},
		{"similar prefix", "/home2", "/home", false},
		{"parent directory", "/", "/home", false},
		{"path traversal with ..", "/home/user/../..", "/home", false},
		{"path traversal to allowed", "/home/user/..", "/home", true},
		{"path traversal outside", "/home/../etc", "/home", false},
		{"complex path traversal", "/home/user/../../etc", "/home", false},
		{"path with dots in name", "/home/user.name", "/home", true},
		{"path with current dir", "/home/./user", "/home", true},
		{"root directory exact match", "/", "/", true},
		{"any path should be allowed when root is allowed", "/etc", "/", true},
		{"deep path should be allowed when root is allowed", "/var/log/app", "/", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateBindMountSource([]string{tt.allowedDir}, tt.path)
			if (err == nil) != tt.expected {
				t.Errorf("isPathAllowed(%s, %s) = %v, expected %v", tt.path, tt.allowedDir, err, tt.expected)
			}
		})
	}
}

func TestValidateBindMount(t *testing.T) {
	skipIfNotUnix(t)

	allowedBindMounts := []string{"/home", "/var/log"}

	tests := []struct {
		name       string
		bind       string
		shouldPass bool
	}{
		{"valid bind", "/home/user:/app", true},
		{"invalid format", "/home/user", false},
		{"not allowed source", "/etc:/app", false},
		{"allowed with options", "/home/user:/app:ro", true},
		{"var log bind", "/var/log:/logs:ro", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateBindMount(allowedBindMounts, tt.bind)
			if tt.shouldPass && err != nil {
				t.Errorf("expected %s to pass, but got error: %v", tt.bind, err)
			}
			if !tt.shouldPass && err == nil {
				t.Errorf("expected %s to fail, but it passed", tt.bind)
			}
		})
	}
}

func TestCheckBindMountRestrictions(t *testing.T) {
	skipIfNotUnix(t)

	allowedBindMounts := []string{"/home"}

	tests := []struct {
		name       string
		method     string
		path       string
		body       string
		shouldPass bool
	}{
		{
			name:       "GET request should pass",
			method:     "GET",
			path:       "/v1.40/containers/json",
			body:       "",
			shouldPass: true,
		},
		{
			name:       "POST to non-container endpoint should pass",
			method:     "POST",
			path:       "/v1.40/images/create",
			body:       "",
			shouldPass: true,
		},
		{
			name:       "container create with allowed bind",
			method:     "POST",
			path:       "/v1.40/containers/create",
			body:       `{"HostConfig":{"Binds":["/home/user:/app"]}}`,
			shouldPass: true,
		},
		{
			name:       "container create with disallowed bind",
			method:     "POST",
			path:       "/v1.40/containers/create",
			body:       `{"HostConfig":{"Binds":["/etc:/app"]}}`,
			shouldPass: false,
		},
		{
			name:       "path traversal attack",
			method:     "POST",
			path:       "/v1.40/containers/create",
			body:       `{"HostConfig":{"Binds":["/home/user/../../etc:/app"]}}`,
			shouldPass: false,
		},
		{
			name:       "container create with no binds",
			method:     "POST",
			path:       "/v1.40/containers/create",
			body:       `{"HostConfig":{}}`,
			shouldPass: true,
		},
		{
			name:       "container update with bind mount",
			method:     "POST",
			path:       "/v1.40/containers/abc123/update",
			body:       `{"HostConfig":{"Binds":["/home/user:/app"]}}`,
			shouldPass: true,
		},
		{
			name:       "service create with bind mount",
			method:     "POST",
			path:       "/v1.40/services/create",
			body:       `{"TaskTemplate":{"ContainerSpec":{"Mounts":[{"Type":"bind","Source":"/etc","Target":"/app"}]}}}`,
			shouldPass: false,
		},
		{
			name:       "v2 API should work too",
			method:     "POST",
			path:       "/v2.0/containers/create",
			body:       `{"HostConfig":{"Binds":["/etc:/app"]}}`,
			shouldPass: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(tt.method, tt.path, bytes.NewBufferString(tt.body))
			if err != nil {
				t.Fatalf("failed to create request: %v", err)
			}

			err = checkHostConfigRestrictions(allowedBindMounts, hostConfigPolicy{}, req)
			if tt.shouldPass && err != nil {
				t.Errorf("expected request to pass, but got error: %v", err)
			}
			if !tt.shouldPass && err == nil {
				t.Errorf("expected request to fail, but it passed")
			}
		})
	}
}

func TestCheckHostConfigSecurity(t *testing.T) {
	skipIfNotUnix(t)

	tests := []struct {
		name       string
		policy     hostConfigPolicy
		hostConfig containerHostConfig
		shouldPass bool
	}{
		{
			name:       "zero policy accepts everything",
			policy:     hostConfigPolicy{},
			hostConfig: containerHostConfig{Privileged: true, CapAdd: []string{"SYS_ADMIN"}, NetworkMode: "host"},
			shouldPass: true,
		},
		{
			name:       "deny privileged rejects privileged",
			policy:     hostConfigPolicy{DenyPrivileged: true},
			hostConfig: containerHostConfig{Privileged: true},
			shouldPass: false,
		},
		{
			name:       "deny privileged allows non-privileged",
			policy:     hostConfigPolicy{DenyPrivileged: true},
			hostConfig: containerHostConfig{Privileged: false},
			shouldPass: true,
		},
		{
			name:       "deny capadd rejects non-empty CapAdd",
			policy:     hostConfigPolicy{DenyCapAdd: true},
			hostConfig: containerHostConfig{CapAdd: []string{"NET_ADMIN"}},
			shouldPass: false,
		},
		{
			name:       "deny capadd allows empty CapAdd",
			policy:     hostConfigPolicy{DenyCapAdd: true},
			hostConfig: containerHostConfig{CapAdd: nil},
			shouldPass: true,
		},
		{
			name:       "deny host namespaces rejects NetworkMode=host",
			policy:     hostConfigPolicy{DenyHostNamespaces: true},
			hostConfig: containerHostConfig{NetworkMode: "host"},
			shouldPass: false,
		},
		{
			name:       "deny host namespaces rejects PidMode=host",
			policy:     hostConfigPolicy{DenyHostNamespaces: true},
			hostConfig: containerHostConfig{PidMode: "host"},
			shouldPass: false,
		},
		{
			name:       "deny host namespaces rejects IpcMode=host",
			policy:     hostConfigPolicy{DenyHostNamespaces: true},
			hostConfig: containerHostConfig{IpcMode: "host"},
			shouldPass: false,
		},
		{
			name:       "deny host namespaces rejects UTSMode=host",
			policy:     hostConfigPolicy{DenyHostNamespaces: true},
			hostConfig: containerHostConfig{UTSMode: "host"},
			shouldPass: false,
		},
		{
			name:       "deny host namespaces rejects UsernsMode=host",
			policy:     hostConfigPolicy{DenyHostNamespaces: true},
			hostConfig: containerHostConfig{UsernsMode: "host"},
			shouldPass: false,
		},
		{
			name:       "deny host namespaces rejects host: prefix",
			policy:     hostConfigPolicy{DenyHostNamespaces: true},
			hostConfig: containerHostConfig{NetworkMode: "host:eth0"},
			shouldPass: false,
		},
		{
			name:       "deny host namespaces allows bridge",
			policy:     hostConfigPolicy{DenyHostNamespaces: true},
			hostConfig: containerHostConfig{NetworkMode: "bridge"},
			shouldPass: true,
		},
		{
			name:       "deny host namespaces allows container: prefix",
			policy:     hostConfigPolicy{DenyHostNamespaces: true},
			hostConfig: containerHostConfig{NetworkMode: "container:abc123"},
			shouldPass: true,
		},
		{
			name:       "all flags compose - rejects on any violation",
			policy:     hostConfigPolicy{DenyPrivileged: true, DenyCapAdd: true, DenyHostNamespaces: true},
			hostConfig: containerHostConfig{Privileged: false, CapAdd: []string{"SYS_PTRACE"}, NetworkMode: "bridge"},
			shouldPass: false,
		},
		{
			name:       "all flags compose - accepts when none violated",
			policy:     hostConfigPolicy{DenyPrivileged: true, DenyCapAdd: true, DenyHostNamespaces: true},
			hostConfig: containerHostConfig{Privileged: false, CapAdd: nil, NetworkMode: "bridge"},
			shouldPass: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkHostConfigSecurity(tt.policy, &tt.hostConfig)
			if tt.shouldPass && err != nil {
				t.Errorf("expected to pass, got error: %v", err)
			}
			if !tt.shouldPass && err == nil {
				t.Errorf("expected to fail, but it passed")
			}
		})
	}
}

func TestCheckHostConfigRestrictionsWithPolicy(t *testing.T) {
	skipIfNotUnix(t)

	tests := []struct {
		name            string
		method          string
		path            string
		body            string
		policy          hostConfigPolicy
		allowBindMounts []string
		shouldPass      bool
	}{
		{
			name:       "container create privileged rejected",
			method:     "POST",
			path:       "/v1.40/containers/create",
			body:       `{"HostConfig":{"Privileged":true}}`,
			policy:     hostConfigPolicy{DenyPrivileged: true},
			shouldPass: false,
		},
		{
			name:       "container create non-privileged allowed",
			method:     "POST",
			path:       "/v1.40/containers/create",
			body:       `{"HostConfig":{"Privileged":false}}`,
			policy:     hostConfigPolicy{DenyPrivileged: true},
			shouldPass: true,
		},
		{
			name:       "container update with capadd rejected",
			method:     "POST",
			path:       "/v1.40/containers/abc/update",
			body:       `{"HostConfig":{"CapAdd":["SYS_ADMIN"]}}`,
			policy:     hostConfigPolicy{DenyCapAdd: true},
			shouldPass: false,
		},
		{
			name:       "container create host network rejected",
			method:     "POST",
			path:       "/v1.40/containers/create",
			body:       `{"HostConfig":{"NetworkMode":"host"}}`,
			policy:     hostConfigPolicy{DenyHostNamespaces: true},
			shouldPass: false,
		},
		{
			name:            "bind + policy: both violated picks bind error first",
			method:          "POST",
			path:            "/v1.40/containers/create",
			body:            `{"HostConfig":{"Binds":["/etc:/app"],"Privileged":true}}`,
			policy:          hostConfigPolicy{DenyPrivileged: true},
			allowBindMounts: []string{"/home"},
			shouldPass:      false,
		},
		{
			name:       "no policy, no bind mounts: parsing skipped",
			method:     "POST",
			path:       "/v1.40/containers/create",
			body:       `{"HostConfig":{"Privileged":true}}`,
			policy:     hostConfigPolicy{},
			shouldPass: true,
		},
		{
			name:       "GET request bypasses policy check",
			method:     "GET",
			path:       "/v1.40/containers/json",
			body:       "",
			policy:     hostConfigPolicy{DenyPrivileged: true, DenyCapAdd: true, DenyHostNamespaces: true},
			shouldPass: true,
		},
		{
			name:       "swarm service does not surface host namespace fields",
			method:     "POST",
			path:       "/v1.40/services/create",
			body:       `{"TaskTemplate":{"ContainerSpec":{}}}`,
			policy:     hostConfigPolicy{DenyPrivileged: true, DenyHostNamespaces: true},
			shouldPass: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(tt.method, tt.path, bytes.NewBufferString(tt.body))
			if err != nil {
				t.Fatalf("failed to create request: %v", err)
			}
			err = checkHostConfigRestrictions(tt.allowBindMounts, tt.policy, req)
			if tt.shouldPass && err != nil {
				t.Errorf("expected to pass, got error: %v", err)
			}
			if !tt.shouldPass && err == nil {
				t.Errorf("expected to fail, but it passed")
			}
		})
	}
}

func TestHostConfigPolicyIsZero(t *testing.T) {
	if !(hostConfigPolicy{}).isZero() {
		t.Error("zero policy should be isZero")
	}
	if (hostConfigPolicy{DenyPrivileged: true}).isZero() {
		t.Error("policy with DenyPrivileged should not be isZero")
	}
	if (hostConfigPolicy{DenyCapAdd: true}).isZero() {
		t.Error("policy with DenyCapAdd should not be isZero")
	}
	if (hostConfigPolicy{DenyHostNamespaces: true}).isZero() {
		t.Error("policy with DenyHostNamespaces should not be isZero")
	}
}
