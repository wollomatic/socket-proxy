package container

/*
This was modified from:
https://github.com/moby/moby/blob/v28.5.1/api/types/container/network_settings.go
*/

import (
	"github.com/wollomatic/socket-proxy/internal/docker/api/types/network"
)

// NetworkSettingsSummary provides a summary of container's networks
// in /containers/json
type NetworkSettingsSummary struct {
	Networks map[string]*network.EndpointSettings
}
