package client

/*
This was modified from:
https://github.com/moby/moby/blob/v28.5.1/client/container_list.go
*/

import (
	"context"
	"encoding/json"
	"net/url"

	"github.com/wollomatic/socket-proxy/internal/docker/api/types/container"
	"github.com/wollomatic/socket-proxy/internal/docker/api/types/filters"
)

// ContainerList returns the list of containers in the docker host.
func (cli *Client) ContainerList(ctx context.Context, options container.ListOptions) ([]container.Summary, error) {
	query := url.Values{}

	if options.Filters.Len() > 0 {
		filterJSON, err := filters.ToJSON(options.Filters)
		if err != nil {
			return nil, err
		}

		query.Set("filters", filterJSON)
	}

	resp, err := cli.get(ctx, "/containers/json", query, nil)
	defer ensureReaderClosed(resp)
	if err != nil {
		return nil, err
	}

	var containers []container.Summary
	err = json.NewDecoder(resp.Body).Decode(&containers)
	return containers, err
}
