package main

import (
	"bytes"
	"io"
	"net/http"
	"runtime"
	"strings"
	"testing"
)

func TestNormalizeAPIPath(t *testing.T) {
	tests := map[string]string{
		"/containers/create":       "/v0/containers/create",
		"/services/create":         "/v0/services/create",
		"/v1.54/containers/create": "/v1.54/containers/create",
		"/v2/services/create":      "/v2/services/create",
	}

	for input, expected := range tests {
		if actual := normalizeAPIPath(input); actual != expected {
			t.Errorf("normalizeAPIPath(%q) = %q, expected %q", input, actual, expected)
		}
	}
}

func TestDriverDeviceSource(t *testing.T) {
	tests := []struct {
		name     string
		driver   *mountDriver
		expected string
	}{
		{name: "nil driver"},
		{name: "plain local volume", driver: &mountDriver{Name: "local"}},
		{
			name:     "local bind",
			driver:   &mountDriver{Name: "local", Options: map[string]string{"o": "bind", "device": "/host"}},
			expected: "/host",
		},
		{
			name:     "implicit local recursive bind",
			driver:   &mountDriver{Options: map[string]string{"o": "rw, rbind", "device": "/host"}},
			expected: "/host",
		},
		{
			name:   "custom driver bind options",
			driver: &mountDriver{Name: "custom", Options: map[string]string{"o": "bind", "device": "/host"}},
		},
		{
			name:   "local nfs volume",
			driver: &mountDriver{Name: "local", Options: map[string]string{"type": "nfs", "o": "addr=10.0.0.1,rw", "device": ":/export"}},
		},
		{
			name:   "local cifs volume",
			driver: &mountDriver{Name: "local", Options: map[string]string{"type": "cifs", "o": "addr=10.0.0.1,rw", "device": "//server/share"}},
		},
		{
			name:   "local block device",
			driver: &mountDriver{Name: "local", Options: map[string]string{"type": "ext4", "device": "/dev/sda1"}},
		},
		{
			name:   "bind substring is not an option",
			driver: &mountDriver{Name: "local", Options: map[string]string{"o": "bindable", "device": "/host"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := localDriverDeviceSource(tt.driver)
			if actual != tt.expected {
				t.Errorf("localDriverDeviceSource() = %q, expected %q", actual, tt.expected)
			}
		})
	}
}

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
		errorText  string
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
			name:       "unversioned container create with allowed bind",
			method:     "POST",
			path:       "/containers/create",
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
			name:       "unversioned container create with disallowed bind",
			method:     "POST",
			path:       "/containers/create",
			body:       `{"HostConfig":{"Binds":["/:/hostroot"]}}`,
			shouldPass: false,
			errorText:  "bind mount source directory not allowed",
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
			name:   "container create with disallowed local driver bind",
			method: "POST",
			path:   "/v1.54/containers/create",
			body: `{"HostConfig":{"Mounts":[{"Type":"volume","Target":"/hostroot","VolumeOptions":{"DriverConfig":` +
				`{"Name":"local","Options":{"type":"none","device":"/","o":"bind"}}}}]}}`,
			shouldPass: false,
			errorText:  "bind mount source directory not allowed",
		},
		{
			name:   "container create with allowed local driver bind",
			method: "POST",
			path:   "/v1.54/containers/create",
			body: `{"HostConfig":{"Mounts":[{"Type":"volume","Target":"/data","VolumeOptions":{"DriverConfig":` +
				`{"Name":"local","Options":{"type":"none","device":"/home/data","o":"rw,bind"}}}}]}}`,
			shouldPass: true,
		},
		{
			name:   "container create with disallowed local driver recursive bind",
			method: "POST",
			path:   "/v1.54/containers/create",
			body: `{"HostConfig":{"Mounts":[{"Type":"volume","Target":"/hostroot","VolumeOptions":{"DriverConfig":` +
				`{"Name":"local","Options":{"device":"/","o":"rw,rbind"}}}}]}}`,
			shouldPass: false,
			errorText:  "bind mount source directory not allowed",
		},
		{
			name:   "container create with relative local driver bind device",
			method: "POST",
			path:   "/v1.54/containers/create",
			body: `{"HostConfig":{"Mounts":[{"Type":"volume","Target":"/data","VolumeOptions":{"DriverConfig":` +
				`{"Name":"local","Options":{"device":"relative/path","o":"bind"}}}}]}}`,
			shouldPass: false,
			errorText:  "local volume driver bind device must be an absolute path",
		},
		{
			name:       "container create with plain named volume",
			method:     "POST",
			path:       "/v1.54/containers/create",
			body:       `{"HostConfig":{"Mounts":[{"Type":"volume","Source":"data","Target":"/data"}]}}`,
			shouldPass: true,
		},
		{
			name:   "container create with local NFS volume",
			method: "POST",
			path:   "/v1.54/containers/create",
			body: `{"HostConfig":{"Mounts":[{"Type":"volume","Target":"/data","VolumeOptions":{"DriverConfig":` +
				`{"Name":"local","Options":{"type":"nfs","device":":/export","o":"addr=10.0.0.1,rw"}}}}]}}`,
			shouldPass: true,
		},
		{
			name:   "container create with local CIFS volume",
			method: "POST",
			path:   "/v1.54/containers/create",
			body: `{"HostConfig":{"Mounts":[{"Type":"volume","Target":"/data","VolumeOptions":{"DriverConfig":` +
				`{"Name":"local","Options":{"type":"cifs","device":"//server/share","o":"addr=10.0.0.1,rw"}}}}]}}`,
			shouldPass: true,
		},
		{
			name:       "container create with volumes-from",
			method:     "POST",
			path:       "/v1.54/containers/create",
			body:       `{"HostConfig":{"VolumesFrom":["source-container:rw"]}}`,
			shouldPass: false,
			errorText:  "volumes-from is not allowed",
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
			name:       "unversioned service create with bind mount",
			method:     "POST",
			path:       "/services/create",
			body:       `{"TaskTemplate":{"ContainerSpec":{"Mounts":[{"Type":"bind","Source":"/etc","Target":"/app"}]}}}`,
			shouldPass: false,
		},
		{
			name:   "service create with disallowed local driver bind",
			method: "POST",
			path:   "/v1.54/services/create",
			body: `{"TaskTemplate":{"ContainerSpec":{"Mounts":[{"Type":"volume","Target":"/hostroot","VolumeOptions":` +
				`{"DriverConfig":{"Name":"local","Options":{"device":"/","o":"bind"}}}}]}}}`,
			shouldPass: false,
			errorText:  "bind mount source directory not allowed",
		},
		{
			name:       "unversioned service update with bind mount",
			method:     "POST",
			path:       "/services/service-id/update",
			body:       `{"TaskTemplate":{"ContainerSpec":{"Mounts":[{"Type":"bind","Source":"/etc","Target":"/app"}]}}}`,
			shouldPass: false,
		},
		{
			name:       "versioned volume create with disallowed bind",
			method:     "POST",
			path:       "/v1.54/volumes/create",
			body:       `{"Driver":"local","DriverOpts":{"type":"none","device":"/","o":"bind"}}`,
			shouldPass: false,
			errorText:  "bind mount source directory not allowed",
		},
		{
			name:       "unversioned volume create with disallowed recursive bind",
			method:     "POST",
			path:       "/volumes/create",
			body:       `{"Driver":"local","DriverOpts":{"device":"/","o":"rbind,rw"}}`,
			shouldPass: false,
		},
		{
			name:       "unversioned volume create with allowed bind",
			method:     "POST",
			path:       "/volumes/create",
			body:       `{"DriverOpts":{"type":"none","device":"/home/data","o":"bind"}}`,
			shouldPass: true,
		},
		{
			name:       "volume create with relative local bind device",
			method:     "POST",
			path:       "/volumes/create",
			body:       `{"Driver":"local","DriverOpts":{"device":"relative/path","o":"bind"}}`,
			shouldPass: false,
			errorText:  "local volume driver bind device must be an absolute path",
		},
		{
			name:       "volume create with plain local volume",
			method:     "POST",
			path:       "/v1.54/volumes/create",
			body:       `{"Name":"data","Driver":"local"}`,
			shouldPass: true,
		},
		{
			name:       "volume create with NFS volume",
			method:     "POST",
			path:       "/v1.54/volumes/create",
			body:       `{"Driver":"local","DriverOpts":{"type":"nfs","device":":/export","o":"addr=10.0.0.1,rw"}}`,
			shouldPass: true,
		},
		{
			name:       "volume create with custom driver bind options",
			method:     "POST",
			path:       "/v1.54/volumes/create",
			body:       `{"Driver":"custom","DriverOpts":{"device":"/","o":"bind"}}`,
			shouldPass: true,
		},
		{
			name:       "malformed container create is rejected",
			method:     "POST",
			path:       "/containers/create",
			body:       `{"HostConfig":`,
			shouldPass: false,
			errorText:  "failed to parse container request",
		},
		{
			name:       "malformed service create is rejected",
			method:     "POST",
			path:       "/services/create",
			body:       `{"TaskTemplate":`,
			shouldPass: false,
			errorText:  "failed to parse service request",
		},
		{
			name:       "malformed volume create is rejected",
			method:     "POST",
			path:       "/volumes/create",
			body:       `{"DriverOpts":`,
			shouldPass: false,
			errorText:  "failed to parse volume create request",
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

			err = checkBindMountRestrictions(allowedBindMounts, req)
			if tt.shouldPass && err != nil {
				t.Errorf("expected request to pass, but got error: %v", err)
			}
			if !tt.shouldPass && err == nil {
				t.Errorf("expected request to fail, but it passed")
			}
			if err != nil && tt.errorText != "" && !strings.Contains(err.Error(), tt.errorText) {
				t.Errorf("expected error to contain %q, got %q", tt.errorText, err)
			}

			restoredBody, readErr := io.ReadAll(req.Body)
			if readErr != nil {
				t.Fatalf("failed to read restored request body: %v", readErr)
			}
			if string(restoredBody) != tt.body {
				t.Errorf("request body was not restored: got %q, expected %q", restoredBody, tt.body)
			}
		})
	}
}

func TestNoBindMountRestrictionsLeavesRequestUnchanged(t *testing.T) {
	body := `{"HostConfig":`
	req, err := http.NewRequest(http.MethodPost, "/containers/create", bytes.NewBufferString(body))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	if err := checkBindMountRestrictions(nil, req); err != nil {
		t.Fatalf("expected disabled bind mount restriction to pass: %v", err)
	}
	actualBody, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("failed to read request body: %v", err)
	}
	if string(actualBody) != body {
		t.Errorf("request body changed: got %q, expected %q", actualBody, body)
	}
}
