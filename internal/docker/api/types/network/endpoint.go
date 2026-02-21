package network

/*
This was modified from:
https://github.com/moby/moby/blob/v28.5.1/api/types/network/endpoint.go
*/

// EndpointSettings stores the network endpoint details
type EndpointSettings struct {
	// Operational data
	NetworkID           string
	EndpointID          string
	Gateway             string
	IPAddress           string
	IPPrefixLen         int
	IPv6Gateway         string
	GlobalIPv6Address   string
	GlobalIPv6PrefixLen int
}

// Copy makes a deep copy of `EndpointSettings`
func (es *EndpointSettings) Copy() *EndpointSettings {
	return new(*es)
}
