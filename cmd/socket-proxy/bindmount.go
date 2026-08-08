package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
)

/*
The subsets of github.com/docker/docker/api/types/ are licensed under a Apache 2.0 license.

NOTICE regarding this file only:

Docker
Copyright 2012-2017 Docker, Inc.

This product includes software developed at Docker, Inc. (https://www.docker.com).

This product contains software (https://github.com/creack/pty) developed
by Keith Rarick, licensed under the MIT License.

The following is courtesy of our legal counsel:


Use and transfer of Docker may be subject to certain restrictions by the
United States and other governments.
It is your responsibility to ensure that your use and/or transfer does not
violate applicable laws.

For more information, please see https://www.bis.doc.gov

See also https://www.apache.org/dev/crypto.html and/or seek legal counsel.
*/

// mountType is the subset of github.com/docker/docker/api/types/mount.Type.
type mountType string

const (
	// mountTypeBind is the type for mounting host dir.
	mountTypeBind mountType = "bind"
)

type (
	// containerCreateRequest is the subset of github.com/docker/docker/api/types/container.CreateRequest.
	containerCreateRequest struct {
		HostConfig *containerHostConfig `json:"HostConfig,omitempty"`
	}
	// containerHostConfig is the subset of github.com/docker/docker/api/types/container.HostConfig.
	containerHostConfig struct {
		Binds  []string     // List of volume bindings for this container.
		Mounts []mountMount `json:",omitempty"` // Mounts specs used by the container.
	}
	// swarmServiceSpec is the subset of github.com/docker/docker/api/types/swarm.ServiceSpec.
	swarmServiceSpec struct {
		TaskTemplate swarmTaskSpec `json:",omitempty"`
	}
	// swarmTaskSpec is the subset of github.com/docker/docker/api/types/swarm.TaskSpec.
	swarmTaskSpec struct {
		ContainerSpec *swarmContainerSpec `json:",omitempty"`
	}
	// swarmContainerSpec is the subset of github.com/docker/docker/api/types/swarm.ContainerSpec.
	swarmContainerSpec struct {
		Mounts []mountMount `json:",omitempty"`
	}
	// mountMount is the subset of github.com/docker/docker/api/types/mount.Mount.
	mountMount struct {
		Type mountType `json:",omitempty"`
		// Source specifies the name of the mount. Depending on mount type, this
		// may be a volume name or a host path, or even ignored.
		// Source is not supported for tmpfs (must be an empty value)
		Source        string              `json:",omitempty"`
		Target        string              `json:",omitempty"`
		VolumeOptions *mountVolumeOptions `json:",omitempty"`
	}
	// mountVolumeOptions is the subset of github.com/docker/docker/api/types/mount.VolumeOptions.
	mountVolumeOptions struct {
		DriverConfig *mountDriver `json:",omitempty"`
	}
	// mountDriver is the subset of github.com/docker/docker/api/types/mount.Driver.
	mountDriver struct {
		Name    string            `json:",omitempty"`
		Options map[string]string `json:",omitempty"`
	}
)

// apiVersionSegment matches the optional Docker API version prefix, as in
// /v1.54/containers/create. The daemon serves the same endpoints without it.
var apiVersionSegment = regexp.MustCompile(`^v[0-9]+(\.[0-9]+)*$`)

// normalizeAPIPath adds a synthetic version prefix when the client omitted one,
// so that /containers/create and /v1.54/containers/create are inspected alike.
func normalizeAPIPath(path string) string {
	parts := strings.Split(path, "/")
	if len(parts) > 1 && apiVersionSegment.MatchString(parts[1]) {
		return path
	}
	return "/v0" + path
}

// driverDeviceSource returns the host path a volume mount binds to, if it uses
// the built-in local driver's bind options. "docker volume create -o
// type=none -o o=bind -o device=/host/path" makes a volume mount an ordinary
// host bind, so such a mount has to be validated like one.
func driverDeviceSource(opts *mountVolumeOptions) string {
	if opts == nil || opts.DriverConfig == nil {
		return ""
	}
	return opts.DriverConfig.Options["device"]
}

// checkBindMountRestrictions checks if bind mounts in the request are allowed.
func checkBindMountRestrictions(allowedBindMounts []string, r *http.Request) error {
	// Only check if bind mount restrictions are configured
	if len(allowedBindMounts) == 0 {
		return nil
	}

	if r.Method != http.MethodPost {
		return nil
	}

	// Check different API endpoints that can use bind mounts
	pathParts := strings.Split(normalizeAPIPath(r.URL.Path), "/")
	switch {
	case len(pathParts) >= 4 && pathParts[2] == "containers" && pathParts[3] == "create":
		// Container creation: /vX.xx/containers/create
		return checkContainer(allowedBindMounts, r)
	case len(pathParts) >= 5 && pathParts[2] == "containers" && pathParts[4] == "update":
		// Container update: /vX.xx/containers/{id}/update
		return checkContainer(allowedBindMounts, r)
	case len(pathParts) >= 4 && pathParts[2] == "services" && pathParts[3] == "create":
		// Service creation: /vX.xx/services/create
		return checkService(allowedBindMounts, r)
	case len(pathParts) >= 5 && pathParts[2] == "services" && pathParts[4] == "update":
		// Service update: /vX.xx/services/{id}/update
		return checkService(allowedBindMounts, r)
	default:
		return nil
	}
}

// checkContainer checks bind mounts in container creation requests.
func checkContainer(allowedBindMounts []string, r *http.Request) error {
	body, err := readAndRestoreBody(r)
	if err != nil {
		return err
	}

	var req containerCreateRequest
	if err := json.Unmarshal(body, &req); err != nil {
		slog.Debug("failed to parse container request", "error", err)
		return nil // Don't block if we can't parse.
	}

	return checkHostConfigBindMounts(allowedBindMounts, req.HostConfig)
}

// checkService checks bind mounts in service creation requests.
func checkService(allowedBindMounts []string, r *http.Request) error {
	body, err := readAndRestoreBody(r)
	if err != nil {
		return err
	}

	var req swarmServiceSpec
	if err := json.Unmarshal(body, &req); err != nil {
		slog.Debug("failed to parse service request", "error", err)
		return nil // Don't block if we can't parse.
	}

	if req.TaskTemplate.ContainerSpec == nil {
		return nil // No container spec, nothing to check.
	}
	return checkHostConfigBindMounts(
		allowedBindMounts,
		&containerHostConfig{
			Mounts: req.TaskTemplate.ContainerSpec.Mounts,
		},
	)
}

// checkHostConfigBindMounts checks bind mounts in HostConfig.
func checkHostConfigBindMounts(allowedBindMounts []string, hostConfig *containerHostConfig) error {
	if hostConfig == nil {
		return nil // No HostConfig, nothing to check
	}

	// Check legacy Binds field
	for _, bind := range hostConfig.Binds {
		if err := validateBindMount(allowedBindMounts, bind); err != nil {
			return err
		}
	}

	// Check modern Mounts field
	for _, mountItem := range hostConfig.Mounts {
		if mountItem.Type == mountTypeBind {
			if err := validateBindMountSource(allowedBindMounts, mountItem.Source); err != nil {
				return err
			}
		}
		// A volume mount whose driver options carry a device= is a host bind in
		// all but name, so validate its device the same way.
		if device := driverDeviceSource(mountItem.VolumeOptions); device != "" {
			if err := validateBindMountSource(allowedBindMounts, device); err != nil {
				return err
			}
		}
	}

	return nil
}

// validateBindMount validates a bind mount string in the format "source:target:options".
func validateBindMount(allowedBindMounts []string, bind string) error {
	parts := strings.Split(bind, ":")
	if len(parts) < 2 {
		return fmt.Errorf("invalid bind mount format: %s", bind)
	}
	return validateBindMountSource(allowedBindMounts, parts[0])
}

// validateBindMountSource checks if the source directory is allowed.
func validateBindMountSource(allowedBindMounts []string, source string) error {
	// Skip if source is not an absolute path (i.e. bind mount).
	if !strings.HasPrefix(source, "/") {
		return nil
	}

	source = filepath.Clean(source) // Clean the path to resolve .. and . components.
	for _, allowedDir := range allowedBindMounts {
		if allowedDir == "/" || source == allowedDir || strings.HasPrefix(source, allowedDir+"/") {
			return nil
		}
	}

	return fmt.Errorf("bind mount source directory not allowed: %s", source)
}

// readAndRestoreBody reads the request body and restores it for further processing.
func readAndRestoreBody(r *http.Request) ([]byte, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read request body: %w", err)
	}

	// Restore the body for further processing
	r.Body = io.NopCloser(bytes.NewBuffer(body))
	return body, nil
}
