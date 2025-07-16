package main

import (
	"bytes"
	"net/http"
	"testing"

	"github.com/wollomatic/socket-proxy/internal/config"
)

func TestValidateBindMountSource(t *testing.T) {
	cfg = &config.Config{
		AllowBindMountFrom: []string{"/home", "/var/log"},
	}

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
			err := validateBindMountSource(tt.source)
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
			cfg = &config.Config{
				AllowBindMountFrom: []string{tt.allowedDir},
			}
			err := validateBindMountSource(tt.path)
			if (err == nil) != tt.expected {
				t.Errorf("isPathAllowed(%s, %s) = %v, expected %v", tt.path, tt.allowedDir, err, tt.expected)
			}
		})
	}
}

func TestValidateBindMount(t *testing.T) {
	cfg = &config.Config{
		AllowBindMountFrom: []string{"/home", "/var/log"},
	}

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
			err := validateBindMount(tt.bind)
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
	cfg = &config.Config{
		AllowBindMountFrom: []string{"/home"},
	}

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

			err = checkBindMountRestrictions(req)
			if tt.shouldPass && err != nil {
				t.Errorf("expected request to pass, but got error: %v", err)
			}
			if !tt.shouldPass && err == nil {
				t.Errorf("expected request to fail, but it passed")
			}
		})
	}
}
