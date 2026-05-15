package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
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
		Binds       []string     // List of volume bindings for this container.
		Mounts      []mountMount `json:",omitempty"` // Mounts specs used by the container.
		Privileged  bool         `json:",omitempty"` // Is the container in privileged mode.
		CapAdd      []string     `json:",omitempty"` // List of kernel capabilities to add to the container.
		NetworkMode string       `json:",omitempty"` // Network namespace ("host" gives host networking).
		PidMode     string       `json:",omitempty"` // PID namespace ("host" gives host PID).
		IpcMode     string       `json:",omitempty"` // IPC namespace ("host" gives host IPC).
		UTSMode     string       `json:",omitempty"` // UTS namespace ("host" gives host UTS).
		UsernsMode  string       `json:",omitempty"` // User namespace mode ("host" disables user namespace remapping).
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
		Source string `json:",omitempty"`
		Target string `json:",omitempty"`
	}
)

// hostConfigPolicy defines optional host config security restrictions applied
// alongside bind mount source allowlisting. The zero value means no extra
// restrictions are enforced beyond bind mount validation.
type hostConfigPolicy struct {
	DenyPrivileged     bool // reject HostConfig.Privileged == true
	DenyCapAdd         bool // reject non-empty HostConfig.CapAdd
	DenyHostNamespaces bool // reject host value for NetworkMode/PidMode/IpcMode/UTSMode/UsernsMode
}

// isZero reports whether the policy enforces no restrictions.
func (p hostConfigPolicy) isZero() bool {
	return !p.DenyPrivileged && !p.DenyCapAdd && !p.DenyHostNamespaces
}

// checkHostConfigRestrictions checks bind mount sources and host config
// security restrictions for relevant container/service API requests.
func checkHostConfigRestrictions(allowedBindMounts []string, policy hostConfigPolicy, r *http.Request) error {
	// Only check if restrictions are configured
	if len(allowedBindMounts) == 0 && policy.isZero() {
		return nil
	}

	if r.Method != http.MethodPost {
		return nil
	}

	// Check different API endpoints that can use bind mounts or set host config
	pathParts := strings.Split(r.URL.Path, "/")
	switch {
	case len(pathParts) >= 4 && pathParts[2] == "containers" && pathParts[3] == "create":
		// Container creation: /vX.xx/containers/create
		return checkContainer(allowedBindMounts, policy, r)
	case len(pathParts) >= 5 && pathParts[2] == "containers" && pathParts[4] == "update":
		// Container update: /vX.xx/containers/{id}/update
		return checkContainer(allowedBindMounts, policy, r)
	case len(pathParts) >= 4 && pathParts[2] == "services" && pathParts[3] == "create":
		// Service creation: /vX.xx/services/create
		return checkService(allowedBindMounts, policy, r)
	case len(pathParts) >= 5 && pathParts[2] == "services" && pathParts[4] == "update":
		// Service update: /vX.xx/services/{id}/update
		return checkService(allowedBindMounts, policy, r)
	default:
		return nil
	}
}

// checkContainer checks bind mounts and host config in container creation/update requests.
func checkContainer(allowedBindMounts []string, policy hostConfigPolicy, r *http.Request) error {
	body, err := readAndRestoreBody(r)
	if err != nil {
		return err
	}

	var req containerCreateRequest
	if err := json.Unmarshal(body, &req); err != nil {
		slog.Debug("failed to parse container request", "error", err)
		return nil // Don't block if we can't parse.
	}

	return checkHostConfig(allowedBindMounts, policy, req.HostConfig)
}

// checkService checks bind mounts and host config in service creation/update requests.
// Swarm services only allow specifying Mounts (not Binds) and do not expose the
// host-namespace/privileged fields, so only the Mounts list is forwarded for validation.
func checkService(allowedBindMounts []string, policy hostConfigPolicy, r *http.Request) error {
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
	return checkHostConfig(
		allowedBindMounts,
		policy,
		&containerHostConfig{
			Mounts: req.TaskTemplate.ContainerSpec.Mounts,
		},
	)
}

// checkHostConfig validates bind mount sources and host config security restrictions.
func checkHostConfig(allowedBindMounts []string, policy hostConfigPolicy, hostConfig *containerHostConfig) error {
	if hostConfig == nil {
		return nil // No HostConfig, nothing to check
	}

	if len(allowedBindMounts) > 0 {
		if err := checkHostConfigBindMounts(allowedBindMounts, hostConfig); err != nil {
			return err
		}
	}

	if !policy.isZero() {
		if err := checkHostConfigSecurity(policy, hostConfig); err != nil {
			return err
		}
	}

	return nil
}

// checkHostConfigBindMounts checks bind mounts in HostConfig.
func checkHostConfigBindMounts(allowedBindMounts []string, hostConfig *containerHostConfig) error {
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
	}

	return nil
}

// checkHostConfigSecurity rejects host config fields that punch through container isolation.
// Each check is gated by its corresponding policy flag; with the zero policy this function is a no-op.
func checkHostConfigSecurity(policy hostConfigPolicy, hostConfig *containerHostConfig) error {
	if policy.DenyPrivileged && hostConfig.Privileged {
		return fmt.Errorf("privileged containers not allowed")
	}
	if policy.DenyCapAdd && len(hostConfig.CapAdd) > 0 {
		return fmt.Errorf("adding kernel capabilities not allowed: %v", hostConfig.CapAdd)
	}
	if policy.DenyHostNamespaces {
		if mode := hostConfig.NetworkMode; isHostNamespace(mode) {
			return fmt.Errorf("host network mode not allowed: %s", mode)
		}
		if mode := hostConfig.PidMode; isHostNamespace(mode) {
			return fmt.Errorf("host PID namespace not allowed: %s", mode)
		}
		if mode := hostConfig.IpcMode; isHostNamespace(mode) {
			return fmt.Errorf("host IPC namespace not allowed: %s", mode)
		}
		if mode := hostConfig.UTSMode; isHostNamespace(mode) {
			return fmt.Errorf("host UTS namespace not allowed: %s", mode)
		}
		if mode := hostConfig.UsernsMode; isHostNamespace(mode) {
			return fmt.Errorf("host user namespace mode not allowed: %s", mode)
		}
	}
	return nil
}

// isHostNamespace reports whether a HostConfig namespace mode string requests the host namespace.
// Docker accepts both the bare "host" value and prefixed forms like "host:..." for some modes.
func isHostNamespace(mode string) bool {
	return mode == "host" || strings.HasPrefix(mode, "host:")
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
