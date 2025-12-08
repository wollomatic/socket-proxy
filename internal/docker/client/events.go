package client

/*
This was modified from:
https://github.com/moby/moby/blob/v28.5.1/client/events.go
*/

import (
	"context"
	"encoding/json"
	"net/url"

	"github.com/wollomatic/socket-proxy/internal/docker/api/types/events"
	"github.com/wollomatic/socket-proxy/internal/docker/api/types/filters"
)

// Events returns a stream of events in the daemon. It's up to the caller to close the stream
// by cancelling the context. Once the stream has been completely read an io.EOF error will
// be sent over the error channel. If an error is sent all processing will be stopped. It's up
// to the caller to reopen the stream in the event of an error by reinvoking this method.
func (cli *Client) Events(ctx context.Context, options events.ListOptions) (<-chan events.Message, <-chan error) {
	messages := make(chan events.Message)
	errs := make(chan error, 1)

	started := make(chan struct{})
	go func() {
		defer close(errs)

		query, err := buildEventsQueryParams(options)
		if err != nil {
			close(started)
			errs <- err
			return
		}

		resp, err := cli.get(ctx, "/events", query, nil)
		if err != nil {
			close(started)
			errs <- err
			return
		}
		defer resp.Body.Close()

		decoder := json.NewDecoder(resp.Body)

		close(started)
		for {
			select {
			case <-ctx.Done():
				errs <- ctx.Err()
				return
			default:
				var event events.Message
				if err := decoder.Decode(&event); err != nil {
					errs <- err
					return
				}

				select {
				case messages <- event:
				case <-ctx.Done():
					errs <- ctx.Err()
					return
				}
			}
		}
	}()
	<-started

	return messages, errs
}

func buildEventsQueryParams(options events.ListOptions) (url.Values, error) {
	query := url.Values{}

	if options.Filters.Len() > 0 {
		filterJSON, err := filters.ToJSON(options.Filters)
		if err != nil {
			return nil, err
		}
		query.Set("filters", filterJSON)
	}

	return query, nil
}
