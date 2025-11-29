package container

/*
This was modified from:
https://github.com/moby/moby/blob/v28.5.1/api/types/container/options.go
*/

import "github.com/wollomatic/socket-proxy/internal/docker/api/types/filters"

// ListOptions holds parameters to list containers with.
type ListOptions struct {
	Filters filters.Args
}
